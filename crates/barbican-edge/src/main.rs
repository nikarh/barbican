//! barbican-edge: applies the blocks of one or more barbican agents on a router, with nftables.
//!
//! Each upstream (an agent's edge API) is followed by a thread of its own; the main thread merges what they say
//! and reconciles the table. The last state is saved (rarely, to spare flash) and put back at boot, before the
//! upstreams are reachable, so blocks hold across reboots and while agents are down.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barbican_common::edge::{CHANGES_PATH, Changes, LIST_PATH, Mirror, merge, parse_list};
use barbican_common::net::{Net, aggregate};
use barbican_common::nft::{Desired, Firewall, NftCommand};
use serde::{Deserialize, Serialize};

mod uci;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG: &str = "/etc/config/barbican";
/// How long an upstream holds a poll; the request times out a little later.
const WAIT: u64 = 55;
/// The table is reconciled at least this often (expired blocks, a flushed ruleset).
const TICK: Duration = Duration::from_secs(60);

const HELP: &str = "\
barbican-edge: applies the blocks of barbican agents on a router, with nftables

Usage:
  barbican-edge [--config <path>]   run (configuration: a UCI file, by default /etc/config/barbican)
  barbican-edge restore             put the saved blocks in place, then exit (at boot, before the network)
  barbican-edge status              print the running agent's status (JSON)
  barbican-edge remove              remove the table, and with it every block
  barbican-edge --version
";

fn log(level: &str, message: &str) {
    let _ = writeln!(std::io::stderr(), "{level}: {message}");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone)]
struct Upstream {
    name: String,
    url: String,
    token: String,
}

#[derive(Debug, Clone)]
struct Config {
    enabled: bool,
    table: String,
    priority: i32,
    nft: String,
    /// Apply the upstreams' lists (countries, blocklists), not only their bans.
    lists: bool,
    state: PathBuf,
    status: PathBuf,
    persist_every: Duration,
    upstreams: Vec<Upstream>,
}

fn load_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sections = uci::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let main = sections
        .iter()
        .find(|s| s.kind == "barbican")
        .cloned()
        .unwrap_or_default();
    let flag = |key: &str, default: bool| {
        main.option(key)
            .map_or(default, |v| matches!(v, "1" | "on" | "true" | "yes"))
    };
    let mut upstreams = Vec::new();
    for (i, s) in sections.iter().filter(|s| s.kind == "upstream").enumerate() {
        if s.option("enabled").is_some_and(|v| v == "0") {
            continue;
        }
        let name = s.name.clone().unwrap_or_else(|| format!("upstream{i}"));
        let url = s
            .option("url")
            .ok_or_else(|| format!("upstream {name}: no url"))?
            .trim_end_matches('/')
            .to_owned();
        if !url.starts_with("http://") {
            return Err(format!(
                "upstream {name}: only http:// URLs (no TLS on the router; keep the API on the LAN)"
            ));
        }
        let token = match (s.option("token"), s.option("token_file")) {
            (Some(t), _) => t.to_owned(),
            (None, Some(f)) => std::fs::read_to_string(f)
                .map_err(|e| format!("{f}: {e}"))?
                .trim()
                .to_owned(),
            (None, None) => return Err(format!("upstream {name}: no token")),
        };
        upstreams.push(Upstream { name, url, token });
    }
    let table = main.option("table").unwrap_or("barbican").to_owned();
    if table.is_empty()
        || !table
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("table: letters, digits, '_' and '-' only".to_owned());
    }
    Ok(Config {
        enabled: flag("enabled", true),
        table,
        priority: main
            .option("priority")
            .and_then(|p| p.parse().ok())
            .unwrap_or(-190),
        nft: main.option("nft").unwrap_or("nft").to_owned(),
        lists: flag("lists", true),
        state: PathBuf::from(main.option("state").unwrap_or("/etc/barbican/state.json")),
        status: PathBuf::from(
            main.option("status")
                .unwrap_or("/var/run/barbican-edge.json"),
        ),
        persist_every: Duration::from_secs(
            main.option("persist_interval")
                .and_then(|p| p.parse().ok())
                .unwrap_or(3_600),
        ),
        upstreams,
    })
}

/// What is saved to flash: each upstream's mirror and list, and when.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    saved_at: u64,
    mirrors: BTreeMap<String, Mirror>,
    lists: BTreeMap<String, Vec<Net>>,
}

fn load_saved(path: &Path) -> Saved {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log(
                "warning",
                &format!("{}: {e}; starting empty", path.display()),
            );
            Saved::default()
        }),
        Err(_) => Saved::default(),
    }
}

fn save(path: &Path, saved: &Saved) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let partial = path.with_extension("part");
    let json = serde_json::to_vec(saved).map_err(|e| e.to_string())?;
    std::fs::write(&partial, json)
        .and_then(|()| std::fs::rename(&partial, path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Debug, Default, Clone, Serialize)]
struct UpstreamStatus {
    name: String,
    url: String,
    connected: bool,
    last_ok: Option<u64>,
    error: Option<String>,
    seq: u64,
    blocks: usize,
    allows: usize,
    listed: usize,
}

#[derive(Debug, Default, Serialize)]
struct Status {
    version: &'static str,
    updated: u64,
    table: String,
    enabled: bool,
    applied: Option<u64>,
    error: Option<String>,
    blocks: usize,
    listed: usize,
    dropped_blocked: u64,
    dropped_listed: u64,
    upstreams: Vec<UpstreamStatus>,
    /// The first blocks, for the router's UI.
    recent: Vec<StatusBlock>,
}

#[derive(Debug, Serialize)]
struct StatusBlock {
    net: Net,
    until: Option<u64>,
    upstream: String,
}

enum Message {
    Changes(usize, Changes),
    List(usize, String, Vec<Net>),
    Failed(usize, String),
}

/// Follows one upstream: long polls for changes, and fetches its list when the list's version changes.
fn follow(
    index: usize,
    upstream: &Upstream,
    mut epoch: String,
    mut seq: u64,
    mut list_version: String,
    tx: &mpsc::Sender<Message>,
) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(WAIT + 15)))
        .user_agent(format!("barbican-edge/{VERSION}"))
        .build()
        .into();
    let auth = format!("Bearer {}", upstream.token);
    let mut backoff = Duration::from_secs(2);
    loop {
        let url = format!(
            "{}{CHANGES_PATH}?epoch={epoch}&since={seq}&wait={WAIT}",
            upstream.url
        );
        let result = agent
            .get(&url)
            .header("Authorization", &auth)
            .call()
            .map_err(|e| e.to_string())
            .and_then(|mut r| r.body_mut().read_to_string().map_err(|e| e.to_string()))
            .and_then(|body| serde_json::from_str::<Changes>(&body).map_err(|e| e.to_string()));
        match result {
            Ok(changes) => {
                backoff = Duration::from_secs(2);
                epoch.clone_from(&changes.epoch);
                seq = changes.seq;
                let wanted = changes.list.version.clone();
                if tx.send(Message::Changes(index, changes)).is_err() {
                    return;
                }
                if wanted != list_version {
                    match fetch_list(&agent, upstream, &auth) {
                        Ok((version, nets)) => {
                            list_version.clone_from(&version);
                            if tx.send(Message::List(index, version, nets)).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Message::Failed(index, format!("list: {e}")));
                        }
                    }
                }
            }
            Err(e) => {
                if tx.send(Message::Failed(index, e)).is_err() {
                    return;
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

fn fetch_list(
    agent: &ureq::Agent,
    upstream: &Upstream,
    auth: &str,
) -> Result<(String, Vec<Net>), String> {
    let body = agent
        .get(format!("{}{LIST_PATH}", upstream.url))
        .header("Authorization", auth)
        .call()
        .map_err(|e| e.to_string())?
        .body_mut()
        .with_config()
        .limit(256 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    parse_list(&body).map_err(|e| e.to_string())
}

struct Edge {
    config: Config,
    firewall: Option<Firewall<NftCommand>>,
    mirrors: Vec<Mirror>,
    lists: Vec<Vec<Net>>,
    status: Status,
    dirty: bool,
    last_saved: Option<Instant>,
}

impl Edge {
    fn desired(&self) -> Desired {
        let (block, allow) = merge(self.mirrors.iter());
        let (lists, version) = if self.config.lists {
            let all: Vec<Net> = self.lists.iter().flatten().copied().collect();
            let version: Vec<&str> = self
                .mirrors
                .iter()
                .map(|m| m.list.version.as_str())
                .collect();
            (aggregate(&all), version.join(","))
        } else {
            (Vec::new(), String::new())
        };
        Desired {
            allow,
            block,
            lists: Arc::new(lists),
            lists_version: version,
        }
    }

    fn apply(&mut self) {
        let now = now();
        for m in &mut self.mirrors {
            m.expire(now);
        }
        let desired = self.desired();
        self.status.blocks = desired.block.len();
        self.status.listed = desired.lists.len();
        if let Some(fw) = &mut self.firewall {
            match fw.reconcile(&desired, now) {
                Ok(_) => {
                    self.status.applied = Some(now);
                    self.status.error = None;
                    if let Ok(c) = fw.counters() {
                        self.status.dropped_blocked = c.blocked.packets;
                        self.status.dropped_listed = c.listed.packets;
                    }
                }
                Err(e) => {
                    if self.status.error.as_deref() != Some(&e.to_string()) {
                        log("error", &format!("updating the firewall: {e}"));
                    }
                    self.status.error = Some(e.to_string());
                }
            }
        }
        self.write_status();
    }

    fn write_status(&mut self) {
        self.status.updated = now();
        for (s, m) in self.status.upstreams.iter_mut().zip(&self.mirrors) {
            s.seq = m.seq;
            s.blocks = m.blocks.len();
            s.allows = m.allows.len();
        }
        for (s, l) in self.status.upstreams.iter_mut().zip(&self.lists) {
            s.listed = l.len();
        }
        self.status.recent = self
            .mirrors
            .iter()
            .zip(&self.config.upstreams)
            .flat_map(|(m, u)| {
                m.blocks.iter().map(|(net, until)| StatusBlock {
                    net: *net,
                    until: *until,
                    upstream: u.name.clone(),
                })
            })
            .take(500)
            .collect();
        if let Ok(json) = serde_json::to_vec(&self.status) {
            let partial = self.config.status.with_extension("part");
            let _ = std::fs::write(&partial, json)
                .and_then(|()| std::fs::rename(&partial, &self.config.status));
        }
    }

    fn persist(&mut self, force: bool) {
        let due = self
            .last_saved
            .is_none_or(|t| t.elapsed() >= self.config.persist_every);
        if !self.dirty || !(due || force) {
            return;
        }
        let saved = Saved {
            saved_at: now(),
            mirrors: self
                .config
                .upstreams
                .iter()
                .zip(&self.mirrors)
                .map(|(u, m)| (u.name.clone(), m.clone()))
                .collect(),
            lists: self
                .config
                .upstreams
                .iter()
                .zip(&self.lists)
                .map(|(u, l)| (u.name.clone(), l.clone()))
                .collect(),
        };
        match save(&self.config.state, &saved) {
            Ok(()) => {
                self.dirty = false;
                self.last_saved = Some(Instant::now());
            }
            Err(e) => log("warning", &format!("saving the state: {e}")),
        }
    }

    fn handle(&mut self, message: Message) {
        let now = now();
        match message {
            Message::Changes(i, changes) => {
                let Some(mirror) = self.mirrors.get_mut(i) else {
                    return;
                };
                let first = mirror.epoch.is_empty();
                let changed = changes.full
                    || !changes.block.is_empty()
                    || !changes.unblock.is_empty()
                    || !changes.allow.is_empty()
                    || !changes.unallow.is_empty();
                if let Err(e) = mirror.apply(&changes, now) {
                    log(
                        "warning",
                        &format!(
                            "upstream {}: {e}",
                            self.config
                                .upstreams
                                .get(i)
                                .map_or("?", |u| u.name.as_str())
                        ),
                    );
                    *mirror = Mirror::default();
                }
                if let Some(s) = self.status.upstreams.get_mut(i) {
                    s.connected = true;
                    s.last_ok = Some(now);
                    s.error = None;
                }
                if changed {
                    self.dirty = true;
                }
                // The first full state after a start is saved at once: a fresh install has something to boot with.
                if first && changes.full {
                    self.persist(true);
                }
            }
            Message::List(i, _version, nets) => {
                if let Some(list) = self.lists.get_mut(i) {
                    *list = nets;
                    self.dirty = true;
                }
            }
            Message::Failed(i, error) => {
                if let Some(s) = self.status.upstreams.get_mut(i) {
                    if s.error.as_deref() != Some(error.as_str()) {
                        log("warning", &format!("upstream {}: {error}", s.name));
                    }
                    s.connected = false;
                    s.error = Some(error);
                }
            }
        }
    }
}

impl Edge {
    /// The edge as it was saved, before any upstream answered.
    fn restore(config: Config) -> Self {
        let mut saved = load_saved(&config.state);
        // A router without a clock that keeps time may boot in the past: count from when the state was saved.
        let now = now().max(saved.saved_at);
        let mirrors: Vec<Mirror> = config
            .upstreams
            .iter()
            .map(|u| {
                let mut m = saved.mirrors.remove(&u.name).unwrap_or_default();
                m.expire(now);
                m
            })
            .collect();
        let lists: Vec<Vec<Net>> = config
            .upstreams
            .iter()
            .map(|u| saved.lists.remove(&u.name).unwrap_or_default())
            .collect();
        let firewall = config.enabled.then(|| {
            Firewall::new(
                NftCommand {
                    program: config.nft.clone(),
                },
                &config.table,
                config.priority,
            )
        });
        Edge {
            status: Status {
                version: VERSION,
                table: config.table.clone(),
                enabled: config.enabled,
                upstreams: config
                    .upstreams
                    .iter()
                    .map(|u| UpstreamStatus {
                        name: u.name.clone(),
                        url: u.url.clone(),
                        ..UpstreamStatus::default()
                    })
                    .collect(),
                ..Status::default()
            },
            firewall,
            mirrors,
            lists,
            dirty: false,
            last_saved: None,
            config,
        }
    }
}

/// Starts a thread per upstream, each continuing where the saved state stopped.
fn spawn_upstreams(edge: &Edge, tx: &mpsc::Sender<Message>) -> Result<(), String> {
    for (i, upstream) in edge.config.upstreams.iter().enumerate() {
        let tx = tx.clone();
        let upstream = upstream.clone();
        let (epoch, seq) = edge
            .mirrors
            .get(i)
            .map(|m| (m.epoch.clone(), m.seq))
            .unwrap_or_default();
        let list_version = edge
            .mirrors
            .get(i)
            .map(|m| m.list.version.clone())
            .unwrap_or_default();
        // A list saved without the mirror knowing its version is fetched again.
        let list_version = if edge.lists.get(i).is_some_and(Vec::is_empty) {
            String::new()
        } else {
            list_version
        };
        std::thread::Builder::new()
            .name(format!("upstream-{i}"))
            .spawn(move || follow(i, &upstream, epoch, seq, list_version, &tx))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Puts the saved blocks in place and returns: the init script runs it before the network comes up, since the
/// daemon itself is started in the background.
fn restore(config: Config) -> Result<(), String> {
    let mut edge = Edge::restore(config);
    if let Some(fw) = &mut edge.firewall {
        fw.setup()
            .map_err(|e| format!("setting up the firewall: {e}"))?;
    }
    edge.apply();
    log(
        "info",
        &format!(
            "restored {} blocks and {} listed prefixes",
            edge.status.blocks, edge.status.listed
        ),
    );
    match edge.status.error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn run(config: Config) -> Result<(), String> {
    let mut edge = Edge::restore(config);
    if let Some(fw) = &mut edge.firewall {
        fw.setup()
            .map_err(|e| format!("setting up the firewall: {e}"))?;
    }
    // The saved blocks are back before anything else happens.
    edge.apply();
    log(
        "info",
        &format!(
            "ready: {} blocks, {} listed, {} upstreams",
            edge.status.blocks,
            edge.status.listed,
            edge.config.upstreams.len()
        ),
    );

    let (tx, rx) = mpsc::channel();
    spawn_upstreams(&edge, &tx)?;
    drop(tx);

    let mut last_apply = Instant::now();
    loop {
        match rx.recv_timeout(TICK) {
            Ok(message) => {
                edge.handle(message);
                // Whatever else arrived meanwhile, applied together.
                std::thread::sleep(Duration::from_millis(300));
                while let Ok(message) = rx.try_recv() {
                    edge.handle(message);
                }
                edge.apply();
                last_apply = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // No upstreams: keep the saved blocks applied.
                std::thread::sleep(TICK);
            }
        }
        if last_apply.elapsed() >= TICK {
            edge.apply();
            last_apply = Instant::now();
        }
        edge.persist(false);
    }
}

fn main() -> ExitCode {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        let _ = std::io::stdout().write_all(HELP.as_bytes());
        return ExitCode::SUCCESS;
    }
    if args.contains(["-V", "--version"]) {
        let _ = writeln!(std::io::stdout(), "barbican-edge {VERSION}");
        return ExitCode::SUCCESS;
    }
    let path: PathBuf = args
        .opt_value_from_str(["-c", "--config"])
        .ok()
        .flatten()
        .unwrap_or_else(|| DEFAULT_CONFIG.into());
    let command = args.subcommand().ok().flatten();
    let config = match load_config(&path) {
        Ok(c) => c,
        Err(e) => {
            log("error", &e);
            return ExitCode::FAILURE;
        }
    };
    let result = match command.as_deref() {
        None | Some("run") => run(config),
        Some("restore") => restore(config),
        Some("status") => std::fs::read(&config.status)
            .map_err(|e| {
                format!(
                    "{}: {e} (is barbican-edge running?)",
                    config.status.display()
                )
            })
            .and_then(|s| std::io::stdout().write_all(&s).map_err(|e| e.to_string())),
        Some("remove") => Firewall::new(
            NftCommand {
                program: config.nft.clone(),
            },
            &config.table,
            config.priority,
        )
        .remove()
        .map_err(|e| e.to_string()),
        Some(other) => Err(format!("unknown command {other:?}\n\n{HELP}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log("error", &e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config() {
        let dir = std::env::temp_dir().join(format!("barbican-edge-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        std::fs::write(&token, "secret-from-file\n").unwrap();
        let path = dir.join("barbican");
        std::fs::write(
            &path,
            format!(
                "config barbican 'main'\n\toption lists '0'\n\toption priority '-250'\n\n\
                 config upstream 'files'\n\toption url 'http://192.0.2.10:7380/'\n\toption token 'abc'\n\n\
                 config upstream 'pi'\n\toption url 'http://192.0.2.11:7380'\n\toption token_file '{}'\n\n\
                 config upstream 'off'\n\toption enabled '0'\n\toption url 'http://192.0.2.12:7380'\n",
                token.display()
            ),
        )
        .unwrap();
        let c = load_config(&path).unwrap();
        assert!(c.enabled && !c.lists);
        assert_eq!(c.priority, -250);
        assert_eq!(c.upstreams.len(), 2);
        assert_eq!(c.upstreams[0].url, "http://192.0.2.10:7380");
        assert_eq!(c.upstreams[1].token, "secret-from-file");
        std::fs::write(
            &path,
            "config upstream\n\toption url 'https://x'\n\toption token 'a'\n",
        )
        .unwrap();
        assert!(load_config(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saved_state_round_trip() {
        let path =
            std::env::temp_dir().join(format!("barbican-edge-state-{}.json", std::process::id()));
        let mut saved = Saved {
            saved_at: 5,
            ..Saved::default()
        };
        let mut m = Mirror::default();
        m.blocks.insert("192.0.2.1".parse().unwrap(), Some(99));
        saved.mirrors.insert("a".into(), m);
        saved
            .lists
            .insert("a".into(), vec!["198.51.100.0/24".parse().unwrap()]);
        save(&path, &saved).unwrap();
        let back = load_saved(&path);
        assert_eq!(back.saved_at, 5);
        assert_eq!(back.mirrors["a"].blocks.len(), 1);
        assert_eq!(back.lists["a"].len(), 1);
        std::fs::write(&path, "garbage").unwrap();
        assert!(load_saved(&path).mirrors.is_empty());
        std::fs::remove_file(&path).unwrap();
    }
}
