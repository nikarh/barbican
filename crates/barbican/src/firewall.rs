//! Keeping nftables, and the edges' journal, equal to the state; and the parts of the state derived from others:
//! the rule set sources match with, and the list sets (blocked countries and blocking feeds).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use barbican_common::net::{Family, NetSet};
use barbican_common::nft::{Firewall, NftCommand};

use crate::api::FirewallStatus;
use crate::app::{App, now};
use crate::feeds::Content;
use crate::rules::{AgentList, RuleSet};

/// Changes coming in a burst are applied together.
const DEBOUNCE: Duration = Duration::from_millis(200);

pub type Nft = Arc<Mutex<Firewall<NftCommand>>>;

pub fn new(app: &App) -> Option<Nft> {
    let config = &app.config.firewall;
    (config.enabled && !app.dry_run).then(|| {
        Arc::new(Mutex::new(
            Firewall::new(NftCommand::new(&config.nft), &config.table, config.priority)
                .with_ipv6(config.ipv6),
        ))
    })
}

/// Compiles the rules again (after rules, feeds, or the allow list changed) and hands them to the sources.
///
/// The rule set is handed over while the state is still read: compiling takes a while, and two rebuilds at once (a
/// feed fetched as another one is removed) would otherwise hand theirs over in either order, the older state last.
/// A change of the state waits for the handover, so the rebuild that follows it hands over last.
pub fn rebuild_rules(app: &App) {
    let names: Vec<&str> = app.config.sources.iter().map(|s| s.name.as_str()).collect();
    let Ok(state) = app.state.read() else { return };
    let generation = app.rules_generation.fetch_add(1, Ordering::Relaxed) + 1;
    let set = {
        let now = now();
        let mut allowed = state.exempt.clone();
        allowed.extend(
            state
                .entries
                .iter()
                .filter(|e| e.allow && e.until.is_none_or(|u| u > now))
                .map(|e| e.net),
        );
        for feed in &state.feeds {
            allowed.extend(feed.effect.allow.iter().copied());
        }
        let feeds: Vec<(&str, Arc<NetSet>)> = state
            .feeds
            .iter()
            .filter(|f| f.def.enabled && f.def.content != Content::Agents)
            .map(|f| (f.def.name.as_str(), Arc::clone(&f.effect.listed)))
            .collect();
        let agents: Vec<AgentList<'_>> = state
            .feeds
            .iter()
            .filter(|f| f.def.enabled)
            .filter_map(|f| Some((f.def.name.as_str(), Arc::clone(f.loaded.agents.as_ref()?))))
            .collect();
        RuleSet::new(
            generation,
            state.rules.clone(),
            &names,
            &feeds,
            &agents,
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
    // IPv6 only when the host or an edge loads it.
    let ipv6 = app.ipv6_lists.load(Ordering::SeqCst);
    let nets = tokio::task::spawn_blocking(move || geo.networks_of(&countries, &continents, ipv6))
        .await
        .unwrap_or_default();
    tracing::info!(prefixes = nets.len(), ipv6, countries = ?wanted.0, continents = ?wanted.1, "Country blocks computed");
    if let Ok(mut state) = app.state.write() {
        state.countries = Arc::new(nets);
        state.countries_of = wanted;
        state.ipv6_lists = ipv6;
    }
    refresh_lists(app);
}

/// Recomputes the list sets' content (after countries or feeds changed).
///
/// Stored while the state is still read, as [`rebuild_rules`] hands its rules over: merging the lists takes a while,
/// and two refreshes at once (countries computed as a feed is removed) would otherwise store theirs in either order,
/// and the older content would stay, here and on the edges, until the next change.
pub fn refresh_lists(app: &App) {
    let Ok(state) = app.state.read() else { return };
    let lists = state.lists();
    if let Ok(mut current) = app.lists.write() {
        *current = lists;
    }
    drop(state);
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
        (
            state.desired(now, &lists, app.config.firewall.ipv6),
            entries != state.entries.len(),
        )
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
    // What the list sets hold: without IPv6, its prefixes aren't loaded.
    let listed = if app.config.firewall.ipv6 {
        desired.lists.len()
    } else {
        desired
            .lists
            .iter()
            .filter(|n| n.family() == Family::V4)
            .count()
    } as u64;
    let result = match nft {
        None => Ok(None),
        Some(nft) => {
            let nft = Arc::clone(nft);
            tokio::task::spawn_blocking(move || {
                let mut fw = nft
                    .lock()
                    .map_err(|_| "the firewall's lock is poisoned".to_owned())?;
                let unix = u64::try_from(now).unwrap_or(0);
                let changes = fw.reconcile(&desired, unix).map_err(|e| e.to_string());
                let counters = fw.counters().ok();
                if let Some(e) = fw.take_notice() {
                    tracing::warn!(error = %e, "nftables over netlink failed; using the nft program instead");
                }
                Ok::<_, String>(Some((changes?, counters)))
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
                    set_dropped(
                        &mut status,
                        &crate::drops::record(app, crate::drops::HOST, now, c),
                    );
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

/// Shows this host's drop totals.
fn set_dropped(status: &mut FirewallStatus, d: &crate::drops::Drops) {
    status.dropped_blocked = d.total.blocked.packets;
    status.dropped_listed = d.total.listed.packets;
    status.dropped_since = Some(d.since);
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

/// Reads the drop counters, and expires bans in the state (the kernel lifts them by itself), when nothing changed.
async fn idle(app: &Arc<App>, nft: Option<&Nft>) {
    let now = now();
    if let Ok(mut state) = app.state.write() {
        state.expire_bans(now);
    }
    let Some(nft) = nft else { return };
    let nft = Arc::clone(nft);
    let counters = tokio::task::spawn_blocking(move || nft.lock().ok()?.counters().ok())
        .await
        .ok()
        .flatten();
    if let Ok(mut status) = app.firewall.lock()
        && status.error.is_none()
    {
        status.applied = Some(now);
        if let Some(c) = counters {
            set_dropped(
                &mut status,
                &crate::drops::record(app, crate::drops::HOST, now, c),
            );
        }
    }
}

/// Whether another program committed to nftables since the table was last applied (one small request asking for
/// the ruleset's generation), so that it is applied again.
async fn drifted(nft: Option<&Nft>) -> bool {
    let Some(nft) = nft else { return false };
    let nft = Arc::clone(nft);
    tokio::task::spawn_blocking(move || nft.lock().is_ok_and(|fw| fw.check()))
        .await
        .unwrap_or(false)
}

/// Applies the state whenever something changed, when an allow entry runs out (the kernel times bans out by
/// itself), and when another program changed nftables (checked every minute).
pub async fn run(app: Arc<App>, nft: Option<Nft>) {
    // How often the drop counters are read, and whether another program changed the table checked (a flushed
    // ruleset, a restarted firewall).
    let tick = Duration::from_secs(app.config.firewall.check_interval);
    // Whatever the table holds at the start.
    app.firewall_wake.notify_one();
    loop {
        let due = app
            .state
            .read()
            .ok()
            .and_then(|state| state.next_due(now()));
        let wait = due.map_or(tick, |at| {
            Duration::from_secs(u64::try_from(at - now() + 1).unwrap_or(1)).min(tick)
        });
        let woken = tokio::select! {
            () = app.firewall_wake.notified() => {
                tokio::time::sleep(DEBOUNCE).await;
                true
            }
            () = tokio::time::sleep(wait) => false,
        };
        if woken || due.is_some_and(|at| at <= now()) {
            apply(&app, nft.as_ref()).await;
        } else if drifted(nft.as_ref()).await {
            tracing::debug!("nftables changed meanwhile: reading the table back");
            apply(&app, nft.as_ref()).await;
        } else {
            idle(&app, nft.as_ref()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use barbican_common::net::Net;

    use super::*;
    use crate::db::Db;
    use crate::feeds::{FeedDef, Loaded};
    use crate::state::Feed;

    /// A feed that blocks 198.51.100.0/24.
    fn blocking_feed() -> Feed {
        let mut feed = Feed::new(FeedDef {
            id: 1,
            name: "x".to_owned(),
            url: "https://example.com/".to_owned(),
            enabled: true,
            block: true,
            allow: false,
            refresh_secs: 3_600,
            username: None,
            password: None,
            content: Content::Addresses,
            select: None,
            catalog: None,
            networks: Vec::new(),
        });
        feed.loaded = Arc::new(Loaded::from_data("198.51.100.0/24\n"));
        feed.refresh();
        feed
    }

    /// Lists refreshed all the time on another thread (countries computed, another feed fetched) never leave an
    /// older content in place: once a change's own refresh returns, the lists are the state's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "a stress test: run it locally with `cargo test -- --ignored`"]
    async fn the_lists_follow_the_last_change() {
        let app = App::new(
            toml::from_str("").unwrap(),
            Db::memory().await,
            crate::app::http_client(),
            true,
        );
        // Enough prefixes for merging them to take a while: separate /32s, not mergeable.
        let countries: Vec<Net> = (0..20_000u32)
            .map(|i| Net::host(std::net::Ipv4Addr::from(0x0b00_0000 + i * 2).into()))
            .collect();
        if let Ok(mut state) = app.state.write() {
            state.countries = Arc::new(countries);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let background = {
            let (app, stop) = (Arc::clone(&app), Arc::clone(&stop));
            std::thread::spawn(move || {
                // Now and then, as the agent's refreshes come: back to back, they would keep the state read for good.
                while !stop.load(Ordering::Relaxed) {
                    refresh_lists(&app);
                    std::thread::sleep(std::time::Duration::from_micros(500));
                }
            })
        };
        let listed = |app: &App| app.lists.read().unwrap().nets.len();
        for round in 0..30 {
            {
                let mut state = app.state.write().unwrap();
                if round % 2 == 0 {
                    state.feeds.push(blocking_feed());
                } else {
                    state.feeds.clear();
                }
            }
            refresh_lists(&app);
            let expected = 20_000 + usize::from(round % 2 == 0);
            assert_eq!(listed(&app), expected, "round {round}");
        }
        stop.store(true, Ordering::Relaxed);
        background.join().unwrap();
    }
}
