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
use crate::feeds::{FeedDef, Loaded};
use crate::rules::{Policy, Rule};
use crate::state::{Bans, Feed, Trusted};
use crate::{engine, firewall, geo, source};

pub const POLICY: &str = "policy";
const SEEDED: &str = "seeded";

/// Puts the default rules and policy into a new database.
async fn seed(db: &Db) -> Result<(), String> {
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

pub async fn load_feeds(db: &Db) -> Result<Vec<Feed>, db::Error> {
    let mut feeds = Vec::new();
    for row in db::feeds(&db.pool).await? {
        let Ok(mut def) = serde_json::from_str::<FeedDef>(&row.definition) else {
            continue;
        };
        def.id = row.id;
        let data = row.data.clone().unwrap_or_default();
        let loaded = tokio::task::spawn_blocking(move || Loaded::from_data(&data))
            .await
            .unwrap_or_default();
        feeds.push(Feed {
            def,
            loaded: Arc::new(loaded),
            fetched: row.fetched,
            error: row.error,
        });
    }
    Ok(feeds)
}

async fn load(app: &Arc<App>) -> Result<(), String> {
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
    let feeds = load_feeds(db).await.map_err(|e| e.to_string())?;
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

fn open_geo(config: &Config) -> geo::Geo {
    match geo::Geo::open(config.geoip.country.as_deref(), config.geoip.asn.as_deref()) {
        Ok(geo) => geo,
        Err(e) => {
            tracing::warn!(error = %e, "The geolocation databases can't be opened");
            geo::Geo::default()
        }
    }
}

/// Downloads stale geolocation databases (once a day it checks), then recomputes what depends on them.
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
            match geo::download(&app.http, kind, path).await {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "Geolocation database downloaded");
                    changed = true;
                }
                Err(e) => tracing::warn!(error = %e, "Downloading a geolocation database failed"),
            }
        }
        if changed {
            let geo = open_geo(&app.config);
            if let Ok(mut current) = app.geo.write() {
                *current = Arc::new(geo);
            }
            firewall::refresh_countries(&app).await;
        }
        tokio::time::sleep(Duration::from_hours(24)).await;
    }
}

/// Fetches one feed and puts its new content in force.
pub async fn fetch_feed(app: &Arc<App>, id: i64) {
    let Some(def) = app.state.read().ok().and_then(|s| {
        s.feeds
            .iter()
            .find(|f| f.def.id == id)
            .map(|f| f.def.clone())
    }) else {
        return;
    };
    let etag = db::feeds(&app.db.pool)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().find(|r| r.id == id))
        .and_then(|r| r.etag);
    let now = now();
    let result = crate::feeds::fetch(&app.http, &def, etag.as_deref()).await;
    let (loaded, error) = match result {
        Ok(crate::feeds::Fetched::NotModified) => {
            let _ = db::feed_fetched(&app.db.pool, id, now, Ok((None, -1, etag.as_deref()))).await;
            (None, None)
        }
        Ok(crate::feeds::Fetched::New { body, etag }) => {
            let (body, loaded) = tokio::task::spawn_blocking(move || {
                let loaded = Loaded::from_data(&body);
                // Stored merged, one prefix per line: smaller, and read back quickly.
                let data = barbican_common::edge::render_list("", &loaded.nets);
                (data, loaded)
            })
            .await
            .unwrap_or_default();
            let count = i64::try_from(loaded.nets.len()).unwrap_or(i64::MAX);
            let _ = db::feed_fetched(
                &app.db.pool,
                id,
                now,
                Ok((Some(&body), count, etag.as_deref())),
            )
            .await;
            tracing::info!(feed = %def.name, prefixes = count, "Feed fetched");
            (Some(loaded), None)
        }
        Err(e) => {
            tracing::warn!(feed = %def.name, error = %e, "Fetching a feed failed");
            let _ = db::feed_fetched(&app.db.pool, id, now, Err(&e)).await;
            (None, Some(e))
        }
    };
    if let Ok(mut state) = app.state.write()
        && let Some(feed) = state.feeds.iter_mut().find(|f| f.def.id == id)
    {
        feed.fetched = Some(now);
        feed.error = error;
        if let Some(loaded) = loaded {
            feed.loaded = Arc::new(loaded);
        }
    }
    firewall::rebuild_rules(app);
    firewall::refresh_lists(app);
}

/// Fetches feeds when they are due (and when one is added or changed).
async fn feed_updates(app: Arc<App>) {
    loop {
        let now = now();
        let due: Vec<i64> = app
            .state
            .read()
            .map(|s| {
                s.feeds
                    .iter()
                    .filter(|f| f.def.enabled)
                    .filter(|f| {
                        f.fetched.is_none_or(|t| {
                            now - t
                                >= i64::try_from(f.def.refresh_secs.max(600)).unwrap_or(i64::MAX)
                        })
                    })
                    .map(|f| f.def.id)
                    .collect()
            })
            .unwrap_or_default();
        for id in due {
            fetch_feed(&app, id).await;
        }
        tokio::select! {
            () = app.feeds_wake.notified() => {}
            () = tokio::time::sleep(Duration::from_mins(5)) => {}
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
    load(&app).await?;
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
            match (ui.listen, &ui.socket) {
                (Some(address), _) => {
                    let listener = bind(address, "UI").await;
                    axum::serve(listener, router)
                        .await
                        .map_err(|e| e.to_string())
                }
                (None, Some(path)) => {
                    let listener = bind_socket(path, ui.socket_group.as_deref())?;
                    tracing::info!(socket = %path.display(), "UI listening");
                    axum::serve(listener, router)
                        .await
                        .map_err(|e| e.to_string())
                }
                (None, None) => Ok(()),
            }
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
            Ok(())
        }
        Some(result) = servers.join_next(), if !servers.is_empty() => {
            result.map_err(|e| e.to_string())?
        }
    }
}
