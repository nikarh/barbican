//! Keeping nftables, and the edges' journal, equal to the state; and the parts of the state derived from others:
//! the rule set sources match with, and the list sets (blocked countries and blocking feeds).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use barbican_common::net::NetSet;
use barbican_common::nft::{Firewall, NftCommand};

use crate::app::{App, now};
use crate::rules::RuleSet;

/// How often the state is applied even when nothing asked for it (expired bans, a flushed table).
const TICK: Duration = Duration::from_secs(60);
/// Changes coming in a burst are applied together.
const DEBOUNCE: Duration = Duration::from_millis(200);

pub type Nft = Arc<Mutex<Firewall<NftCommand>>>;

pub fn new(app: &App) -> Option<Nft> {
    let config = &app.config.firewall;
    (config.enabled && !app.dry_run).then(|| {
        Arc::new(Mutex::new(Firewall::new(
            NftCommand {
                program: config.nft.clone(),
            },
            &config.table,
            config.priority,
        )))
    })
}

/// Compiles the rules again (after rules, feeds, or the allow list changed) and hands them to the sources.
pub fn rebuild_rules(app: &App) {
    let generation = app.rules_generation.fetch_add(1, Ordering::Relaxed) + 1;
    let names: Vec<&str> = app.config.sources.iter().map(|s| s.name.as_str()).collect();
    let set = {
        let Ok(state) = app.state.read() else { return };
        let now = now();
        let mut allowed = state.exempt.clone();
        allowed.extend(
            state
                .entries
                .iter()
                .filter(|e| e.allow && e.until.is_none_or(|u| u > now))
                .map(|e| e.net),
        );
        let feeds: Vec<(&str, Arc<NetSet>)> = state
            .feeds
            .iter()
            .filter(|f| f.def.enabled)
            .map(|f| (f.def.name.as_str(), Arc::clone(&f.loaded.set)))
            .collect();
        RuleSet::new(
            generation,
            state.rules.clone(),
            &names,
            &feeds,
            NetSet::new(&allowed),
        )
    };
    match set {
        Ok(set) => {
            app.rules.send_replace(Arc::new(set));
        }
        // Rules are checked when saved; one that doesn't compile any more keeps the previous set in force.
        Err(e) => {
            tracing::error!(error = %e, "Rules don't compile; the previous ones stay in force");
        }
    }
}

/// Recomputes the prefixes of the blocked countries and continents, when they or the database changed.
pub async fn refresh_countries(app: &Arc<App>) {
    let (countries, continents) = match app.state.read() {
        Ok(state) => (
            state.policy.blocked_countries.clone(),
            state.policy.blocked_continents.clone(),
        ),
        Err(_) => return,
    };
    let geo = app.geo();
    let wanted = (countries.clone(), continents.clone());
    let nets = tokio::task::spawn_blocking(move || geo.networks_of(&countries, &continents))
        .await
        .unwrap_or_default();
    tracing::info!(prefixes = nets.len(), countries = ?wanted.0, continents = ?wanted.1, "Country blocks computed");
    if let Ok(mut state) = app.state.write() {
        state.countries = Arc::new(nets);
        state.countries_of = wanted;
    }
    refresh_lists(app);
}

/// Recomputes the list sets' content (after countries or feeds changed).
pub fn refresh_lists(app: &App) {
    let lists = match app.state.read() {
        Ok(state) => state.lists(),
        Err(_) => return,
    };
    if let Ok(mut current) = app.lists.write() {
        *current = lists;
    }
    app.firewall_wake.notify_one();
}

/// Applies the state once: expires what ran out, reconciles nftables, and updates the edges' journal.
pub async fn apply(app: &Arc<App>, nft: Option<&Nft>) {
    let now = now();
    let lists = app.lists.read().map(|l| l.clone()).unwrap_or_default();
    let (desired, expired_rules) = {
        let Ok(mut state) = app.state.write() else {
            return;
        };
        let entries = state.entries.len();
        state.expire(now);
        (state.desired(now, &lists), entries != state.entries.len())
    };
    if expired_rules {
        // An allow entry that ran out no longer exempts its addresses.
        rebuild_rules(app);
    }

    if let Ok(mut journal) = app.journal.lock()
        && journal.set(&desired.block, &desired.allow, lists.reference())
    {
        app.journal_seq.send_replace(journal.seq());
    }

    let blocks = desired.block.len() as u64;
    let listed = desired.lists.len() as u64;
    let result = match nft {
        None => Ok(None),
        Some(nft) => {
            let nft = Arc::clone(nft);
            tokio::task::spawn_blocking(move || {
                let mut fw = nft
                    .lock()
                    .map_err(|_| "the firewall's lock is poisoned".to_owned())?;
                let unix = u64::try_from(now).unwrap_or(0);
                let changes = fw.reconcile(&desired, unix).map_err(|e| e.to_string())?;
                let counters = fw.counters().ok();
                Ok::<_, String>(Some((changes, counters)))
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
        }
    };
    if let Ok(mut status) = app.firewall.lock() {
        status.blocks = blocks;
        status.listed = listed;
        match result {
            Ok(Some((changes, counters))) => {
                status.applied = Some(now);
                status.error = None;
                if let Some(c) = counters {
                    status.dropped_blocked = c.blocked.packets;
                    status.dropped_listed = c.listed.packets;
                }
                if changes.added + changes.removed > 0 || changes.lists {
                    tracing::debug!(
                        added = changes.added,
                        removed = changes.removed,
                        lists = changes.lists,
                        "Firewall updated"
                    );
                }
            }
            Ok(None) => status.applied = Some(now),
            Err(e) => {
                if status.error.as_deref() != Some(e.as_str()) {
                    tracing::error!(error = %e, "Updating the firewall failed");
                }
                status.error = Some(e);
            }
        }
    }
}

/// Sets the table up. Run before the agent says it is ready, so blocks are in place before anything else starts.
pub async fn setup(app: &Arc<App>, nft: Option<&Nft>) -> Result<(), String> {
    if let Some(nft) = nft {
        let nft = Arc::clone(nft);
        tokio::task::spawn_blocking(move || {
            nft.lock()
                .map_err(|_| "the firewall's lock is poisoned".to_owned())?
                .setup()
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
    }
    apply(app, nft).await;
    match app.firewall.lock().ok().and_then(|s| s.error.clone()) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Applies the state whenever something changed, and every minute.
pub async fn run(app: Arc<App>, nft: Option<Nft>) {
    loop {
        tokio::select! {
            () = app.firewall_wake.notified() => tokio::time::sleep(DEBOUNCE).await,
            () = tokio::time::sleep(TICK) => {}
        }
        apply(&app, nft.as_ref()).await;
    }
}
