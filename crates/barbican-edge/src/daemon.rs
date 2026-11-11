//! The daemon both edge agents share: it follows one or more upstreams (agents' edge APIs), each in a thread of its
//! own, merges what they block, and keeps the firewall (a [`Backend`]) equal to it. The last state is saved (rarely,
//! to spare flash) and put back at boot, before the upstreams are reachable, so blocks hold across reboots and while
//! agents are down.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barbican_common::edge::{CHANGES_PATH, Changes, LIST_PATH, Mirror, merge, parse_list};
use barbican_common::net::{Net, aggregate};
use barbican_common::nft::Desired;
use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::uci;

pub const VERSION: &str = env!("BARBICAN_VERSION");
/// How long an upstream holds a poll; the request times out a little later.
const WAIT: u64 = 55;

/// What tells the two edge agents apart, besides their backend.
pub struct Defaults {
    pub name: &'static str,
    pub about: &'static str,
    pub config: &'static str,
    pub state: &'static str,
    pub status: &'static str,
}

fn help(d: &Defaults) -> String {
    format!(
        "{name}: {about}\n\n\
         Usage:\n  \
         {name} [--config <path>]   run (configuration: a UCI file, by default {config})\n  \
         {name} restore             put the saved blocks in place, then exit (at boot, before the network)\n  \
         {name} status              print the running agent's status (JSON)\n  \
         {name} remove              remove its firewall rules and sets, and with them every block\n  \
         {name} --version\n",
        name = d.name,
        about = d.about,
        config = d.config
    )
}

pub(crate) fn log(level: &str, message: &str) {
    let _ = writeln!(std::io::stderr(), "{level}: {message}");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub url: String,
    pub token: String,
    /// SHA-256 of the agent's TLS certificate.
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub program: &'static str,
    /// Off: follow the upstreams and save the state, but leave the firewall alone.
    pub enabled: bool,
    /// Apply the upstreams' lists (countries, blocklists), not only their bans.
    pub lists: bool,
    pub state: PathBuf,
    pub status: PathBuf,
    pub persist_every: Duration,
    /// How often the status (with the drop counters) is written, and the firewall checked for changes by other
    /// programs (a flushed ruleset, a restarted firewall): `check_interval`, in seconds.
    pub tick: Duration,
    pub upstreams: Vec<Upstream>,
    /// The `barbican` section, for the backend's own options.
    pub main: uci::Section,
}

pub fn load_config(path: &Path, defaults: &Defaults) -> Result<Config, String> {
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
        if !url.starts_with("https://") {
            return Err(format!(
                "upstream {name}: only https:// URLs (the edge API is TLS only)"
            ));
        }
        let fingerprint = s
            .option("fingerprint")
            .ok_or_else(|| {
                format!(
                    "upstream {name}: no fingerprint (barbican edge-fingerprint prints the agent's)"
                )
            })?
            .to_owned();
        crate::http::parse_fingerprint(&fingerprint)
            .map_err(|e| format!("upstream {name}: {e}"))?;
        let token = match (s.option("token"), s.option("token_file")) {
            (Some(t), _) => t.to_owned(),
            (None, Some(f)) => std::fs::read_to_string(f)
                .map_err(|e| format!("{f}: {e}"))?
                .trim()
                .to_owned(),
            (None, None) => return Err(format!("upstream {name}: no token")),
        };
        upstreams.push(Upstream {
            name,
            url,
            token,
            fingerprint,
        });
    }
    Ok(Config {
        program: defaults.name,
        // `dry_run`: run, follow and save as usual, but change nothing in the firewall (to see first what it would
        // block, and what that costs).
        enabled: flag("enabled", true) && !flag("dry_run", false),
        lists: flag("lists", true),
        state: PathBuf::from(main.option("state").unwrap_or(defaults.state)),
        status: PathBuf::from(main.option("status").unwrap_or(defaults.status)),
        persist_every: Duration::from_secs(
            main.option("persist_interval")
                .and_then(|p| p.parse().ok())
                .unwrap_or(3_600),
        ),
        tick: Duration::from_secs(
            main.option("check_interval")
                .and_then(|p| p.parse().ok())
                .filter(|&s: &u64| s > 0)
                .unwrap_or(60),
        ),
        upstreams,
        main,
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
    /// The firewall it changes, e.g. `nftables table inet barbican`.
    backend: String,
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
    /// SIGTERM or SIGINT: save the state, and stop.
    Stop,
    Changes(usize, Changes),
    List(usize, String, Vec<Net>),
    Failed(usize, String),
}

/// Follows one upstream: long polls for changes, and fetches its list when the list's version changes.
fn follow(
    program: &str,
    index: usize,
    upstream: &Upstream,
    mut epoch: String,
    mut seq: u64,
    mut list_version: String,
    tx: &mpsc::Sender<Message>,
) {
    let client = match crate::http::Client::new(
        &upstream.url,
        &upstream.fingerprint,
        &upstream.token,
        &format!("{program}/{VERSION}"),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(Message::Failed(index, e));
            return;
        }
    };
    let mut backoff = Duration::from_secs(2);
    loop {
        let path = format!("{CHANGES_PATH}?epoch={epoch}&since={seq}&wait={WAIT}");
        let result = client
            .get(&path, Duration::from_secs(WAIT + 15), 16 * 1024 * 1024)
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
                    match fetch_list(&client) {
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

fn fetch_list(client: &crate::http::Client) -> Result<(String, Vec<Net>), String> {
    let body = client.get(LIST_PATH, Duration::from_secs(120), 256 * 1024 * 1024)?;
    parse_list(&body).map_err(|e| e.to_string())
}

struct Edge {
    config: Config,
    firewall: Option<Box<dyn Backend>>,
    mirrors: Vec<Mirror>,
    lists: Vec<Vec<Net>>,
    /// The upstreams' lists merged, made again only when one of them changes.
    merged: Option<Arc<Vec<Net>>>,
    status: Status,
    dirty: bool,
    last_saved: Option<Instant>,
}

impl Edge {
    fn desired(&mut self) -> Desired {
        let (block, allow) = merge(self.mirrors.iter());
        let (lists, version) = if self.config.lists {
            let lists = self
                .merged
                .get_or_insert_with(|| {
                    let all: Vec<Net> = self.lists.iter().flatten().copied().collect();
                    Arc::new(aggregate(&all))
                })
                .clone();
            let version: Vec<&str> = self
                .mirrors
                .iter()
                .map(|m| m.list.version.as_str())
                .collect();
            (lists, version.join(","))
        } else {
            (Arc::default(), String::new())
        };
        Desired {
            allow,
            block,
            lists,
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
                Ok(()) => {
                    self.status.applied = Some(now);
                    self.status.error = None;
                    if let Some(c) = fw.counters() {
                        self.status.dropped_blocked = c.blocked.packets;
                        self.status.dropped_listed = c.listed.packets;
                    }
                }
                Err(e) => {
                    if self.status.error.as_deref() != Some(e.as_str()) {
                        log("error", &format!("updating the firewall: {e}"));
                    }
                    self.status.error = Some(e);
                }
            }
        }
        self.write_status();
    }

    /// Once a minute: forgets blocks that ran out (the kernel lifted them already), and reconciles only when another
    /// program may have changed the firewall; otherwise only the counters are read.
    fn tick(&mut self) {
        let now = now();
        for m in &mut self.mirrors {
            m.expire(now);
        }
        let Some(fw) = &mut self.firewall else {
            return;
        };
        if fw.check(now) {
            self.apply();
            return;
        }
        if let Some(c) = fw.counters() {
            self.status.dropped_blocked = c.blocked.packets;
            self.status.dropped_listed = c.listed.packets;
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

    /// How long the main loop may sleep: until the next tick, or until a pending save is due.
    fn next_wake(&self) -> Duration {
        if !self.dirty {
            return self.config.tick;
        }
        let due = self.last_saved.map_or(Duration::ZERO, |t| {
            self.config.persist_every.saturating_sub(t.elapsed())
        });
        due.clamp(Duration::from_millis(100), self.config.tick)
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

    /// Takes in what a thread said. Returns whether the firewall has to be reconciled.
    fn handle(&mut self, message: Message) -> bool {
        let now = now();
        match message {
            Message::Stop => false,
            Message::Changes(i, changes) => {
                let Some(mirror) = self.mirrors.get_mut(i) else {
                    return false;
                };
                let first = mirror.epoch.is_empty();
                let mut reset = false;
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
                    reset = true;
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
                // A long poll that ran out with nothing new changes nothing.
                changed || first || reset
            }
            Message::List(i, _version, nets) => {
                if let Some(list) = self.lists.get_mut(i) {
                    *list = nets;
                    self.dirty = true;
                    self.merged = None;
                }
                true
            }
            Message::Failed(i, error) => {
                if let Some(s) = self.status.upstreams.get_mut(i) {
                    if s.error.as_deref() != Some(error.as_str()) {
                        log("warning", &format!("upstream {}: {error}", s.name));
                    }
                    s.connected = false;
                    s.error = Some(error);
                }
                false
            }
        }
    }
}

impl Edge {
    /// The edge as it was saved, before any upstream answered.
    fn restore(config: Config, backend: Box<dyn Backend>) -> Self {
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
        let backend_name = backend.describe();
        let firewall = config.enabled.then_some(backend);
        Edge {
            status: Status {
                version: VERSION,
                backend: backend_name,
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
            merged: None,
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
        let program = edge.config.program;
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
            .spawn(move || follow(program, i, &upstream, epoch, seq, list_version, &tx))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Puts the saved blocks in place and returns: the init script runs it before the network comes up, since the
/// daemon itself is started in the background.
fn restore(config: Config, backend: Box<dyn Backend>) -> Result<(), String> {
    let mut edge = Edge::restore(config, backend);
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

fn run(config: Config, backend: Box<dyn Backend>) -> Result<(), String> {
    let mut edge = Edge::restore(config, backend);
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

    // A stop (procd's, at a reboot too) saves what changed since the last save.
    let stop = tx.clone();
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .map_err(|e| e.to_string())?;
    std::thread::Builder::new()
        .name("signals".to_owned())
        .spawn(move || {
            if signals.forever().next().is_some() {
                let _ = stop.send(Message::Stop);
            }
        })
        .map_err(|e| e.to_string())?;
    drop(tx);

    let mut last_tick = Instant::now();
    loop {
        match rx.recv_timeout(edge.next_wake()) {
            Ok(Message::Stop) => {
                edge.persist(true);
                log("info", "stopping; the blocks stay in place");
                return Ok(());
            }
            Ok(message) => {
                if edge.handle(message) {
                    // Whatever else arrived meanwhile, applied together.
                    std::thread::sleep(Duration::from_millis(300));
                    while let Ok(message) = rx.try_recv() {
                        if matches!(message, Message::Stop) {
                            edge.persist(true);
                            return Ok(());
                        }
                        edge.handle(message);
                    }
                    edge.apply();
                } else {
                    edge.write_status();
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // No upstreams: keep the saved blocks applied.
                std::thread::sleep(edge.config.tick);
            }
        }
        if last_tick.elapsed() >= edge.config.tick {
            edge.tick();
            last_tick = Instant::now();
        }
        edge.persist(false);
    }
}

/// The command line of an edge agent: `make` builds its firewall backend from the configuration.
pub fn main(
    defaults: &Defaults,
    make: fn(&Config) -> Result<Box<dyn Backend>, String>,
) -> ExitCode {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        let _ = std::io::stdout().write_all(help(defaults).as_bytes());
        return ExitCode::SUCCESS;
    }
    if args.contains(["-V", "--version"]) {
        let _ = writeln!(std::io::stdout(), "{} {VERSION}", defaults.name);
        return ExitCode::SUCCESS;
    }
    let path: PathBuf = args
        .opt_value_from_str(["-c", "--config"])
        .ok()
        .flatten()
        .unwrap_or_else(|| defaults.config.into());
    let command = args.subcommand().ok().flatten();
    let result = load_config(&path, defaults).and_then(|config| {
        let backend = make(&config)?;
        match command.as_deref() {
            None | Some("run") => run(config, backend),
            Some("restore") => restore(config, backend),
            Some("status") => std::fs::read(&config.status)
                .map_err(|e| {
                    format!(
                        "{}: {e} (is {} running?)",
                        config.status.display(),
                        defaults.name
                    )
                })
                .and_then(|s| std::io::stdout().write_all(&s).map_err(|e| e.to_string())),
            Some("remove") => {
                let mut backend = backend;
                backend.remove()
            }
            Some(other) => Err(format!("unknown command {other:?}\n\n{}", help(defaults))),
        }
    });
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

    const DEFAULTS: Defaults = Defaults {
        name: "test",
        about: "test",
        config: "/tmp/config",
        state: "/tmp/state.json",
        status: "/tmp/status.json",
    };

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
                 config upstream 'files'\n\toption url 'https://192.0.2.10:7380/'\n\toption token 'abc'\n\toption fingerprint '{fp}'\n\n\
                 config upstream 'pi'\n\toption url 'https://192.0.2.11:7380'\n\toption token_file '{}'\n\toption fingerprint '{fp}'\n\n\
                 config upstream 'off'\n\toption enabled '0'\n\toption url 'http://192.0.2.12:7380'\n",
                token.display(),
                fp = "AB".repeat(32)
            ),
        )
        .unwrap();
        let c = load_config(&path, &DEFAULTS).unwrap();
        assert!(c.enabled && !c.lists);
        let dry = dir.join("dry");
        std::fs::write(
            &dry,
            "config barbican 'main'
	option dry_run '1'
",
        )
        .unwrap();
        assert!(!load_config(&dry, &DEFAULTS).unwrap().enabled);
        assert_eq!(c.main.option("priority"), Some("-250"));
        assert_eq!(c.state, PathBuf::from("/tmp/state.json"));
        assert_eq!(c.upstreams.len(), 2);
        assert_eq!(c.upstreams[0].url, "https://192.0.2.10:7380");
        assert_eq!(c.upstreams[1].token, "secret-from-file");
        std::fs::write(
            &path,
            "config upstream\n\toption url 'https://x'\n\toption token 'a'\n\toption fingerprint 'nope'\n",
        )
        .unwrap();
        assert!(load_config(&path, &DEFAULTS).is_err());
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
