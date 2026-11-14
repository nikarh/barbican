//! Running the agent: loading the state, putting the firewall in place before saying it is ready (to systemd), then
//! the log sources, the engine, the UI, the edge API, and the periodic work.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tokio::sync::mpsc;

use crate::app::{App, now};
use crate::config::Config;
use crate::db::{self, Db};
use crate::feeds::{Content, FeedDef, Loaded, Parsed};
use crate::geo::Geo;
use crate::rules::{Policy, Rule};
use crate::state::{Bans, Feed, Trusted};
use crate::{engine, firewall, geo, source};

pub const POLICY: &str = "policy";
const SEEDED: &str = "seeded";

/// Puts the default rules and policy into a new database.
pub async fn seed(db: &Db) -> Result<(), String> {
    if db::setting(&db.pool, SEEDED)
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(());
    }
    for rule in crate::rules::defaults() {
        let json = serde_json::to_string(&rule).map_err(|e| e.to_string())?;
        db::rule_insert(&db.pool, &json)
            .await
            .map_err(|e| e.to_string())?;
    }
    let policy = serde_json::to_string(&Policy::default()).map_err(|e| e.to_string())?;
    db::set_setting(&db.pool, POLICY, &policy)
        .await
        .map_err(|e| e.to_string())?;
    db::set_setting(&db.pool, SEEDED, "1")
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The rules in the database, with their ids. A rule that no longer parses is left out (and logged).
pub async fn load_rules(db: &Db) -> Result<Vec<Rule>, db::Error> {
    let mut rules = Vec::new();
    for (id, json) in db::rules(&db.pool).await? {
        match serde_json::from_str::<Rule>(&json) {
            Ok(mut rule) => {
                rule.id = id;
                rules.push(rule);
            }
            Err(e) => tracing::error!(id, error = %e, "A stored rule can't be read; it is skipped"),
        }
    }
    Ok(rules)
}

pub async fn load_feeds(db: &Db, geo: Arc<Geo>) -> Result<Vec<Feed>, db::Error> {
    let mut feeds = Vec::new();
    for row in db::feeds(&db.pool).await? {
        let Ok(mut def) = serde_json::from_str::<FeedDef>(&row.definition) else {
            continue;
        };
        def.id = row.id;
        let data = row.data.clone().unwrap_or_default();
        let content = def.content;
        let geo = Arc::clone(&geo);
        let loaded = tokio::task::spawn_blocking(move || Loaded::from_stored(content, &data, &geo))
            .await
            .unwrap_or_default();
        feeds.push(Feed {
            loaded: Arc::new(loaded),
            fetched: row.fetched,
            succeeded: row.succeeded,
            changed: row.changed,
            // A list whose last fetch failed is tried again soon, not a whole interval later.
            failures: u32::from(row.error.is_some()),
            error: row.error,
            ..Feed::new(def)
        });
    }
    Ok(feeds)
}

/// Looks the networks of the lists of networks up again (after the ASN database changed).
pub async fn reload_network_feeds(app: &Arc<App>) {
    let Ok(rows) = db::feeds(&app.db.pool).await else {
        return;
    };
    let geo = app.geo();
    let mut reloaded = Vec::new();
    for row in rows {
        let Some(feed) = app.state.read().ok().and_then(|s| {
            s.feeds
                .iter()
                .find(|f| f.def.id == row.id && f.def.content == Content::Networks)
                .map(|f| f.def.id)
        }) else {
            continue;
        };
        let data = row.data.unwrap_or_default();
        let geo = Arc::clone(&geo);
        let loaded = tokio::task::spawn_blocking(move || {
            Loaded::from_stored(Content::Networks, &data, &geo)
        })
        .await
        .unwrap_or_default();
        reloaded.push((feed, loaded));
    }
    if reloaded.is_empty() {
        return;
    }
    if let Ok(mut state) = app.state.write() {
        for (id, loaded) in reloaded {
            if let Some(feed) = state.feeds.iter_mut().find(|f| f.def.id == id) {
                feed.loaded = Arc::new(loaded);
            }
        }
    }
    firewall::rebuild_rules(app);
    firewall::refresh_lists(app);
}

pub async fn load(app: &Arc<App>) -> Result<(), String> {
    let db = &app.db;
    let now = now();
    let rules = load_rules(db).await.map_err(|e| e.to_string())?;
    let policy = db::setting(&db.pool, POLICY)
        .await
        .map_err(|e| e.to_string())?
        .and_then(|p| serde_json::from_str::<Policy>(&p).ok())
        .unwrap_or_default();
    let bans = db::bans_active(&db.pool, now)
        .await
        .map_err(|e| e.to_string())?;
    let entries = db::entries(&db.pool).await.map_err(|e| e.to_string())?;
    let trust = db::trusted(&db.pool, now)
        .await
        .map_err(|e| e.to_string())?;
    let feeds = load_feeds(db, app.geo()).await.map_err(|e| e.to_string())?;
    if let Ok(mut state) = app.state.write() {
        state.rules = rules;
        state.policy = policy;
        state.bans = Bans::new(bans);
        state.entries = entries;
        state.trust = trust
            .into_iter()
            .map(|t| {
                (
                    t.addr.addr(),
                    Trusted {
                        user: t.user,
                        until: t.until,
                    },
                )
            })
            .collect();
        state.feeds = feeds;
        state.exempt.clone_from(&app.config.exempt.nets);
    }
    Ok(())
}

/// Makes the summary the Settings' country coverage is answered from, in the background.
fn prepare_coverage(app: &Arc<App>) {
    let geo = app.geo();
    let ipv6 = app.ipv6_lists.load(std::sync::atomic::Ordering::SeqCst);
    tokio::task::spawn_blocking(move || {
        geo.prepare_coverage(ipv6);
    });
}

pub fn open_geo(config: &Config) -> geo::Geo {
    match geo::Geo::open(config.geoip.country.as_deref(), config.geoip.asn.as_deref()) {
        Ok(geo) => geo,
        Err(e) => {
            tracing::warn!(error = %e, "The geolocation databases can't be opened");
            geo::Geo::default()
        }
    }
}

/// Downloads stale geolocation databases (it checks once a day, from the start), then recomputes what depends on
/// them.
async fn geo_updates(app: Arc<App>) {
    if !app.config.geoip.download {
        return;
    }
    loop {
        let mut changed = false;
        for (kind, path) in [
            ("country", &app.config.geoip.country),
            ("asn", &app.config.geoip.asn),
        ] {
            let Some(path) = path else { continue };
            if !geo::stale(path) {
                continue;
            }
            let result = geo::download(&app.http, kind, path).await;
            match &result {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "Geolocation database downloaded");
                    changed = true;
                }
                Err(e) => tracing::warn!(error = %e, "Downloading a geolocation database failed"),
            }
            if let Ok(mut updates) = app.geo_updates.lock() {
                let error = result.err().map(|e| e.to_string());
                if kind == "country" {
                    updates.country_error = error;
                } else {
                    updates.asn_error = error;
                }
            }
        }
        if let Ok(mut updates) = app.geo_updates.lock() {
            updates.checked = Some(now());
        }
        if changed {
            let geo = open_geo(&app.config);
            if let Ok(mut current) = app.geo.write() {
                *current = Arc::new(geo);
            }
            prepare_coverage(&app);
            firewall::refresh_countries(&app).await;
            reload_network_feeds(&app).await;
        }
        tokio::time::sleep(geo::CHECK_EVERY).await;
    }
}

/// Fetches a feed and puts its new content in force; with it, the other feeds of the same URL (lists of one
/// document, such as services of a JSON file), so that it is downloaded once.
pub async fn fetch_feed(app: &Arc<App>, id: i64) {
    let group = feed_group(app, id);
    let Some(def) = group.iter().find(|d| d.id == id).cloned() else {
        return;
    };
    // A conditional request only when every feed of the group has the copy the etag names.
    let etags: Vec<Option<String>> = db::feeds(&app.db.pool)
        .await
        .map(|rows| {
            group
                .iter()
                .map(|d| {
                    rows.iter()
                        .find(|r| r.id == d.id)
                        .and_then(|r| r.etag.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    let etag = etags
        .first()
        .cloned()
        .flatten()
        .filter(|e| etags.iter().all(|x| x.as_ref() == Some(e)));
    let now = now();
    let result = crate::feeds::fetch(&app.http, &def, etag.as_deref()).await;
    let geo = app.geo();
    // Per feed: its new contents (or none: unchanged), or the error.
    let mut outcomes: Vec<(i64, Result<Option<Loaded>, String>)> = Vec::new();
    match result {
        Ok(crate::feeds::Fetched::NotModified) => {
            for d in &group {
                let _ =
                    db::feed_fetched(&app.db.pool, d.id, now, Ok((None, etag.as_deref()))).await;
                outcomes.push((d.id, Ok(None)));
            }
        }
        Ok(crate::feeds::Fetched::New { body, etag }) => {
            let body = Arc::new(body);
            for d in &group {
                let parsed = {
                    let (body, d, geo) = (Arc::clone(&body), d.clone(), Arc::clone(&geo));
                    tokio::task::spawn_blocking(move || {
                        Parsed::of(&body, &d).map(|parsed| {
                            // Stored one entry per line, merged: smaller, and read back quickly.
                            let data = parsed.render();
                            (data, Loaded::from_parsed(parsed, &geo))
                        })
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
                };
                match parsed {
                    Ok((data, loaded)) => {
                        let count = i64::try_from(loaded.entries).unwrap_or(i64::MAX);
                        let _ = db::feed_fetched(
                            &app.db.pool,
                            d.id,
                            now,
                            Ok((Some((&data, count)), etag.as_deref())),
                        )
                        .await;
                        tracing::info!(feed = %d.name, entries = count, "Feed fetched");
                        outcomes.push((d.id, Ok(Some(loaded))));
                    }
                    Err(e) => {
                        tracing::warn!(feed = %d.name, error = %e, "A fetched feed can't be read");
                        let _ = db::feed_fetched(&app.db.pool, d.id, now, Err(&e)).await;
                        outcomes.push((d.id, Err(e)));
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(feed = %def.name, error = %e, "Fetching a feed failed");
            for d in &group {
                let _ = db::feed_fetched(&app.db.pool, d.id, now, Err(&e)).await;
                outcomes.push((d.id, Err(e.clone())));
            }
        }
    }
    record_outcomes(app, now, outcomes);
}

/// Puts what fetches brought in force.
fn record_outcomes(app: &Arc<App>, now: i64, outcomes: Vec<(i64, Result<Option<Loaded>, String>)>) {
    if let Ok(mut state) = app.state.write() {
        for (id, outcome) in outcomes {
            let Some(feed) = state.feeds.iter_mut().find(|f| f.def.id == id) else {
                continue;
            };
            feed.fetched = Some(now);
            match outcome {
                Ok(loaded) => {
                    feed.succeeded = Some(now);
                    feed.error = None;
                    feed.failures = 0;
                    if let Some(loaded) = loaded {
                        feed.loaded = Arc::new(loaded);
                        feed.changed = Some(now);
                    }
                }
                Err(e) => {
                    feed.error = Some(e);
                    feed.failures = feed.failures.saturating_add(1);
                }
            }
        }
    }
    firewall::rebuild_rules(app);
    firewall::refresh_lists(app);
}

/// The feed and the other enabled feeds of the same URL (and credentials).
fn feed_group(app: &App, id: i64) -> Vec<FeedDef> {
    app.state
        .read()
        .ok()
        .and_then(|s| {
            let def = &s.feeds.iter().find(|f| f.def.id == id)?.def;
            Some(
                s.feeds
                    .iter()
                    .filter(|f| {
                        f.def.id == id
                            || (f.def.enabled
                                && f.def.url == def.url
                                && f.def.username == def.username
                                && f.def.password == def.password)
                    })
                    .map(|f| f.def.clone())
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// The shortest time between two fetches of a feed.
pub const FEED_MIN_REFRESH: u64 = 600;

/// After a failed fetch, the first retry; each failure in a row doubles it, up to the feed's refresh.
pub const FEED_RETRY: u64 = 300;

/// When a feed is due its next fetch (`None`: it is off): right away when it was never fetched; its refresh
/// interval after its last attempt; after a failed one, sooner (5 minutes, doubled with each failure in a row, up to
/// the interval).
#[must_use]
pub fn feed_due(feed: &Feed) -> Option<i64> {
    if !feed.def.enabled {
        return None;
    }
    let every = feed.def.refresh_secs.max(FEED_MIN_REFRESH);
    let wait = if feed.failures > 0 {
        FEED_RETRY
            .saturating_mul(1u64 << (feed.failures - 1).min(20))
            .min(every)
    } else {
        every
    };
    let wait = i64::try_from(wait).unwrap_or(i64::MAX);
    Some(feed.fetched.map_or(0, |t| t.saturating_add(wait)))
}

/// Fetches feeds when they are due (and when one is added or changed).
async fn feed_updates(app: Arc<App>) {
    loop {
        let now = now();
        let (due, next): (Vec<i64>, Option<i64>) = app
            .state
            .read()
            .map(|s| {
                let due = s
                    .feeds
                    .iter()
                    .filter(|f| feed_due(f).is_some_and(|due| now >= due))
                    .map(|f| f.def.id)
                    .collect();
                let next = s
                    .feeds
                    .iter()
                    .filter_map(feed_due)
                    .filter(|d| *d > now)
                    .min();
                (due, next)
            })
            .unwrap_or_default();
        let mut done: Vec<i64> = Vec::new();
        for id in due {
            // Fetched already with another feed of its URL.
            if done.contains(&id) {
                continue;
            }
            fetch_feed(&app, id).await;
            done.extend(app.state.read().map_or_else(
                |_| Vec::new(),
                |s| {
                    s.feeds
                        .iter()
                        .filter(|f| f.fetched.is_some_and(|t| t >= now))
                        .map(|f| f.def.id)
                        .collect()
                },
            ));
        }
        if !done.is_empty() {
            continue;
        }
        // Until the next feed is due (at least a second, at most an hour), or one is added or changed.
        let wait = next.map_or(3_600, |n| (n - now).clamp(1, 3_600));
        tokio::select! {
            () = app.feeds_wake.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(wait.unsigned_abs())) => {}
        }
    }
}

/// Deletes old events once an hour.
async fn prune(app: Arc<App>) {
    loop {
        let days = app.state.read().map_or(365, |s| s.policy.retention_days);
        let hour = (now() - i64::from(days) * 86_400).div_euclid(3_600);
        match db::prune(&app.db.pool, hour).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(events = n, "Old events deleted"),
            Err(e) => tracing::warn!(error = %e, "Deleting old events failed"),
        }
        tokio::time::sleep(Duration::from_hours(1)).await;
    }
}

async fn recompute_countries(app: Arc<App>) {
    loop {
        app.countries_wake.notified().await;
        firewall::refresh_countries(&app).await;
    }
}

/// Binds a listener, trying again until it works: the agent starts before the network is configured, so an address
/// of an interface may not exist yet.
pub async fn bind(address: std::net::SocketAddr, what: &str) -> tokio::net::TcpListener {
    let mut warned = false;
    loop {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                tracing::info!(listen = %address, "{what} listening");
                return listener;
            }
            Err(e) => {
                if !warned {
                    tracing::warn!(listen = %address, error = %e, "{what} can't listen yet; trying again");
                    warned = true;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// The id of a group, from `/etc/group`.
fn group_id(name: &str) -> Option<u32> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then(|| fields.nth(1)?.parse().ok())?
    })
}

/// Listens on a unix socket that only its group may use (0660), replacing a socket left by an earlier run.
fn bind_socket(
    path: &std::path::Path,
    group: Option<&str>,
) -> Result<tokio::net::UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let listener =
        tokio::net::UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(group) = group {
        let gid = group_id(group).ok_or_else(|| format!("ui.socket_group: no group {group:?}"))?;
        std::os::unix::fs::chown(path, None, Some(gid))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(listener)
}

/// Tells systemd the agent is ready (`Type=notify`), when it runs under systemd.
fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = path.to_string_lossy().into_owned();
    let address = match path.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name.as_bytes()),
        None => SocketAddr::from_pathname(&path),
    };
    let sent =
        address.and_then(|a| UnixDatagram::unbound().and_then(|s| s.send_to_addr(b"READY=1", &a)));
    if let Err(e) = sent {
        tracing::warn!(error = %e, "Telling systemd the agent is ready failed");
    }
}

pub async fn run(config: Config, dry_run: bool) -> Result<(), String> {
    let db = Db::open(&config.database.path)
        .await
        .map_err(|e| format!("{}: {e}", config.database.path.display()))?;
    seed(&db).await?;
    let geo = open_geo(&config);
    let app = App::new(config, db, crate::app::http_client(), dry_run);
    if let Ok(mut current) = app.geo.write() {
        *current = Arc::new(geo);
    }
    prepare_coverage(&app);
    load(&app).await?;
    match crate::db::drops_load(&app.db.pool).await {
        Ok(drops) => {
            if let Ok(mut current) = app.drops.lock() {
                *current = drops;
            }
        }
        Err(e) => tracing::warn!(error = %e, "Reading the drop totals failed; counting from now"),
    }
    firewall::rebuild_rules(&app);
    firewall::refresh_countries(&app).await;

    // Blocks are back in place before anything that could let traffic in starts.
    let nft = firewall::new(&app);
    if let Err(e) = firewall::setup(&app, nft.as_ref()).await {
        return Err(format!("setting up the firewall: {e}"));
    }
    notify_ready();
    tracing::info!(
        version = crate::VERSION,
        firewall = nft.is_some(),
        sources = app.config.sources.len(),
        "Ready"
    );

    tokio::spawn(firewall::run(Arc::clone(&app), nft));
    let (tx, rx) = mpsc::channel(4_096);
    tokio::spawn(engine::Engine::new(Arc::clone(&app), app.rules.subscribe()).run(rx));
    source::start(&app, &tx).map_err(|e| e.to_string())?;
    drop(tx);
    tokio::spawn(geo_updates(Arc::clone(&app)));
    tokio::spawn(feed_updates(Arc::clone(&app)));
    tokio::spawn(prune(Arc::clone(&app)));
    tokio::spawn(recompute_countries(Arc::clone(&app)));

    let mut servers = tokio::task::JoinSet::new();
    if let Some(edge) = app.config.edge.clone() {
        let app = Arc::clone(&app);
        servers.spawn(async move { crate::edge_api::serve(app, &edge).await });
    }
    if let Some(ui) = app.config.ui.clone() {
        let app = Arc::clone(&app);
        servers.spawn(async move {
            let router = Router::new()
                .route("/api/ws", get(crate::rpc::upgrade))
                .route("/healthz", get(|| async { "ok" }))
                .fallback(crate::web::serve)
                .with_state(app);
            let Some(path) = &ui.socket else {
                return Ok(());
            };
            let listener = bind_socket(path, ui.socket_group.as_deref())?;
            // Only root, the agent's user and the socket's group: checked on every connection (see `peer`).
            let allowed = crate::peer::Allowed::of(path).map_err(|e| format!("{}: {e}", path.display()))?;
            tracing::info!(socket = %path.display(), uid = allowed.uid, gid = allowed.gid, "UI listening");
            axum::serve(crate::peer::CheckedListener::new(listener, allowed), router)
                .await
                .map_err(|e| e.to_string())
        });
    }

    let stop = async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = async { if let Some(t) = term.as_mut() { t.recv().await; } else { std::future::pending::<()>().await } } => {}
        }
    };
    tokio::select! {
        () = stop => {
            tracing::info!("Stopping; the firewall's blocks stay in place");
            source::save_cursors(&app).await;
            Ok(())
        }
        Some(result) = servers.join_next(), if !servers.is_empty() => {
            result.map_err(|e| e.to_string())?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_fetches_are_tried_again_sooner() {
        let mut feed = Feed::new(FeedDef {
            id: 1,
            name: "x".to_owned(),
            url: "https://example.com/".to_owned(),
            enabled: true,
            block: false,
            allow: false,
            refresh_secs: 6 * 3_600,
            username: None,
            password: None,
            content: Content::Addresses,
            select: None,
            catalog: None,
        });
        assert_eq!(feed_due(&feed), Some(0));
        feed.fetched = Some(1_000);
        assert_eq!(feed_due(&feed), Some(1_000 + 6 * 3_600));
        let retries: Vec<i64> = (1..=8)
            .map(|failures| {
                feed.failures = failures;
                feed_due(&feed).unwrap() - 1_000
            })
            .collect();
        assert_eq!(
            retries,
            vec![300, 600, 1_200, 2_400, 4_800, 9_600, 19_200, 21_600]
        );
        feed.def.enabled = false;
        assert_eq!(feed_due(&feed), None);
    }
}
