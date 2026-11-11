//! The daemon both edge agents share: it follows one or more upstreams (agents' edge APIs), each over a connection
//! of its own in a thread of its own, merges what they block, and keeps the firewall (a [`Backend`]) equal to it.
//! Agents push their changes as they happen; the daemon reports back to each what it applied and what its firewall
//! dropped. The last state is saved (rarely, to spare flash) and put back at boot, before the upstreams are
//! reachable, so blocks hold across reboots and while agents are down.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use barbican_common::edge::wire::{self, Frame, HEARTBEAT, SILENCE};
use barbican_common::edge::{Mirror, merge};
use barbican_common::net::{Net, aggregate};
use barbican_common::nft::Counters;
use barbican_common::nft::Desired;
use serde::Serialize;

use crate::backend::Backend;
use crate::saved;
use crate::uci;

pub const VERSION: &str = env!("BARBICAN_VERSION");
/// How often upstreams get a status report when nothing changed.
const REPORT_EVERY: Duration = Duration::from_secs(60);
/// The most a change or a list may take while its frames arrive.
const MAX_PENDING: usize = 256 * 1024 * 1024;

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
    /// How often the state is saved besides on a clean stop: `persist_interval` seconds, `None` (the default, 0) for
    /// only then.
    pub persist_every: Option<Duration>,
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
        crate::link::parse_fingerprint(&fingerprint)
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
        // Flash wears, and after a reboot the agents send everything again once they are reachable: by default the
        // state is saved only when the edge stops cleanly (a reboot, an upgrade), so that the blocks are back at
        // boot even if no agent is reachable yet. A number of seconds saves (what changed) that often too.
        persist_every: main
            .option("persist_interval")
            .and_then(|p| p.parse().ok())
            .filter(|&s: &u64| s > 0)
            .map(Duration::from_secs),
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

#[derive(Debug, Default, Clone, Serialize)]
struct UpstreamStatus {
    name: String,
    url: String,
    connected: bool,
    /// When the agent last sent anything (a ping, at least every 20 seconds while connected).
    last_ok: Option<u64>,
    error: Option<String>,
    /// The agent's version, as it said when this edge connected.
    agent: Option<String>,
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
    dropped_blocked_bytes: u64,
    dropped_listed_bytes: u64,
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
    /// The agent took this edge in; with its version.
    Connected(usize, String),
    /// The frames of one change, all of them.
    Changes(usize, Vec<Vec<u8>>),
    /// The frames of a list, all of them.
    List(usize, Vec<Vec<u8>>),
    Failed(usize, String),
}

/// What the daemon asks of an upstream's thread.
enum Outgoing {
    /// Frames to send.
    Frames(Vec<u8>),
    /// Connect again (the copy of the agent's state was reset): the hello says where the copy is.
    Restart,
}

/// Where the edge's copy of an agent's state is: what a hello says.
#[derive(Debug, Clone, Default)]
struct Position {
    epoch: String,
    seq: u64,
    list_version: String,
}

/// What an upstream's thread and the main loop share.
#[derive(Default)]
struct Shared {
    position: Mutex<Position>,
    /// When the agent last sent anything (unix seconds; 0: never).
    heard: AtomicU64,
}

/// The main loop's end of an upstream's thread.
struct Line {
    shared: Arc<Shared>,
    outbox: mpsc::Sender<Outgoing>,
    /// A byte written here wakes the thread up to look at `outbox`.
    wake: UnixStream,
}

impl Line {
    fn send(&self, outgoing: Outgoing) {
        if self.outbox.send(outgoing).is_ok() {
            // Non-blocking: when a byte is already waiting, the thread wakes anyway.
            let _ = (&self.wake).write(&[1]);
        }
    }

    fn set_position(&self, change: impl FnOnce(&mut Position)) {
        if let Ok(mut p) = self.shared.position.lock() {
            change(&mut p);
        }
    }
}

/// What an upstream's thread needs.
struct Follow {
    index: usize,
    upstream: Upstream,
    /// For the hello.
    enforcing: bool,
    lists: bool,
    /// The firewall loads IPv6: the agent sends none otherwise.
    ipv6: bool,
    backend: String,
    shared: Arc<Shared>,
    outbox: mpsc::Receiver<Outgoing>,
    wake: UnixStream,
    tx: mpsc::Sender<Message>,
}

/// Follows one upstream: stays connected, passes on what the agent pushes, and sends what the daemon has for it.
/// Connects again when the connection fails, backing off while it keeps failing.
fn follow(f: &Follow) {
    let client = match crate::link::Client::new(&f.upstream.url, &f.upstream.fingerprint) {
        Ok(c) => c,
        Err(e) => {
            let _ = f.tx.send(Message::Failed(f.index, e));
            return;
        }
    };
    let mut backoff = Duration::from_secs(2);
    loop {
        let mut welcomed = false;
        match session(f, &client, &mut welcomed) {
            // The daemon is stopping.
            Ok(()) => return,
            Err(e) => {
                if f.tx.send(Message::Failed(f.index, e)).is_err() {
                    return;
                }
            }
        }
        if welcomed {
            backoff = Duration::from_secs(2);
        }
        std::thread::sleep(backoff);
        // What the daemon sent meanwhile was for the connection that is gone: it reports again on the next one.
        let mut sink = [0u8; 64];
        while (&f.wake).read(&mut sink).is_ok_and(|n| n > 0) {}
        loop {
            match f.outbox.try_recv() {
                Ok(_) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        if !welcomed {
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }
}

/// One connection, until it fails (an error) or the daemon stops (`Ok`).
fn session(f: &Follow, client: &crate::link::Client, welcomed: &mut bool) -> Result<(), String> {
    let mut link = client.connect()?;
    let mut out = Vec::new();
    let position = f
        .shared
        .position
        .lock()
        .map(|p| p.clone())
        .unwrap_or_default();
    wire::Hello {
        enforcing: f.enforcing,
        lists: f.lists,
        ipv6: f.ipv6,
        epoch: &position.epoch,
        seq: position.seq,
        list_version: &position.list_version,
        token: &f.upstream.token,
        version: VERSION,
        backend: &f.backend,
    }
    .encode(&mut out);
    link.send(&out)?;
    let mut last_sent = Instant::now();
    let mut last_heard = Instant::now();
    let mut changes: Vec<Vec<u8>> = Vec::new();
    let mut list: Vec<Vec<u8>> = Vec::new();
    loop {
        while let Some(frame) = link.next_frame()? {
            last_heard = Instant::now();
            f.shared.heard.store(now(), Ordering::Relaxed);
            let decoded = wire::decode(&frame).map_err(|e| format!("from the agent: {e}"))?;
            let (complete, is_list) = match decoded {
                Frame::Welcome(w) => {
                    *welcomed = true;
                    if f.tx
                        .send(Message::Connected(f.index, w.version.to_owned()))
                        .is_err()
                    {
                        return Ok(());
                    }
                    continue;
                }
                Frame::Refuse(reason) => {
                    return Err(format!("the agent refused this edge: {reason}"));
                }
                Frame::Ping => continue,
                Frame::Changes(c) => (!c.more, false),
                Frame::List(l) => (l.last, true),
                Frame::Hello(_) | Frame::Status(_) => {
                    return Err("the agent sent what only edges send".to_owned());
                }
            };
            let pending = if is_list { &mut list } else { &mut changes };
            pending.push(frame);
            if pending.iter().map(Vec::len).sum::<usize>() > MAX_PENDING {
                return Err("a change or list too large to take in".to_owned());
            }
            if complete {
                let frames = std::mem::take(pending);
                let message = if is_list {
                    Message::List(f.index, frames)
                } else {
                    Message::Changes(f.index, frames)
                };
                if f.tx.send(message).is_err() {
                    return Ok(());
                }
            }
        }
        loop {
            match f.outbox.try_recv() {
                Ok(Outgoing::Frames(frames)) => {
                    link.send(&frames)?;
                    last_sent = Instant::now();
                }
                Ok(Outgoing::Restart) => return Err("starting over".to_owned()),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
        if last_sent.elapsed() >= HEARTBEAT {
            out.clear();
            wire::encode_ping(&mut out);
            link.send(&out)?;
            last_sent = Instant::now();
        }
        if last_heard.elapsed() >= SILENCE {
            return Err(format!(
                "no word from the agent for {} s",
                SILENCE.as_secs()
            ));
        }
        let timeout = HEARTBEAT
            .saturating_sub(last_sent.elapsed())
            .min(SILENCE.saturating_sub(last_heard.elapsed()))
            .max(Duration::from_millis(10));
        link.wait(&f.wake, timeout)?;
    }
}

/// The resident memory of this process, in bytes.
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

/// What a status report says, but its times: when it differs from the last one sent, it is sent now.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportKey {
    applied: Option<u64>,
    blocks: usize,
    listed: usize,
    dropped: Counters,
    error: Option<String>,
    upstreams: Vec<(bool, Option<String>)>,
}

struct Edge {
    config: Config,
    firewall: Option<Box<dyn Backend>>,
    mirrors: Vec<Mirror>,
    lists: Vec<Vec<Net>>,
    list_versions: Vec<String>,
    /// The upstreams' threads, once started.
    lines: Vec<Line>,
    started: Instant,
    /// What the last report sent to every upstream said, and when it was sent.
    last_report: Option<(ReportKey, Instant)>,
    /// The upstreams' lists merged, made again only when one of them changes.
    merged: Option<Arc<Vec<Net>>>,
    status: Status,
    /// The bans and allows changed since they were saved.
    dirty: bool,
    /// A list changed since the lists were saved (a few times a day: saved apart from the bans, which change all
    /// the time).
    lists_dirty: bool,
    /// Whether the firewall loads IPv6: the lists are saved without it otherwise.
    ipv6: bool,
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
            (lists, self.list_versions.join(","))
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
                        self.status.set_counters(c);
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
            self.status.set_counters(c);
        }
        self.write_status();
    }

    fn write_status(&mut self) {
        self.status.updated = now();
        for (s, line) in self.status.upstreams.iter_mut().zip(&self.lines) {
            let heard = line.shared.heard.load(Ordering::Relaxed);
            if heard > 0 {
                s.last_ok = Some(heard);
            }
        }
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
        if !(self.dirty || self.lists_dirty) {
            return self.config.tick;
        }
        let Some(every) = self.config.persist_every else {
            return self.config.tick;
        };
        let due = self
            .last_saved
            .map_or(Duration::ZERO, |t| every.saturating_sub(t.elapsed()));
        due.clamp(Duration::from_millis(100), self.config.tick)
    }

    fn persist(&mut self, force: bool) {
        let due = self
            .config
            .persist_every
            .is_some_and(|every| self.last_saved.is_none_or(|t| t.elapsed() >= every));
        if !(self.dirty || self.lists_dirty) || !(due || force) {
            return;
        }
        let names = || self.config.upstreams.iter().map(|u| u.name.clone());
        let saved = saved::Saved {
            saved_at: now(),
            mirrors: names().zip(self.mirrors.iter().cloned()).collect(),
            lists: if self.lists_dirty {
                names().zip(self.lists.iter().cloned()).collect()
            } else {
                BTreeMap::new()
            },
            list_versions: names().zip(self.list_versions.iter().cloned()).collect(),
        };
        // The state holds the time of the save, which restoring counts from: written with the lists too.
        let mut result =
            saved::encode_state(&saved).and_then(|b| saved::write(&self.config.state, &b));
        if result.is_ok() && self.lists_dirty {
            result = saved::encode_lists(&saved, self.ipv6)
                .and_then(|b| saved::write(&saved::lists_path(&self.config.state), &b));
        }
        match result {
            Ok(()) => {
                self.dirty = false;
                self.lists_dirty = false;
                self.last_saved = Some(Instant::now());
            }
            Err(e) => log("warning", &format!("saving the state: {e}")),
        }
    }

    fn upstream_name(&self, i: usize) -> &str {
        self.config
            .upstreams
            .get(i)
            .map_or("?", |u| u.name.as_str())
    }

    /// Forgets an upstream's state after it sent something that can't be applied, and has its thread connect again
    /// (to get the whole state).
    fn start_over(&mut self, i: usize, error: &str) {
        log(
            "warning",
            &format!("upstream {}: {error}", self.upstream_name(i)),
        );
        if let Some(mirror) = self.mirrors.get_mut(i) {
            *mirror = Mirror::default();
        }
        if let Some(line) = self.lines.get(i) {
            line.set_position(|p| *p = Position::default());
            line.send(Outgoing::Restart);
        }
    }

    /// Takes in what a thread said. Returns whether the firewall has to be reconciled.
    fn handle(&mut self, message: Message) -> bool {
        let now = now();
        match message {
            Message::Stop => false,
            Message::Connected(i, agent) => {
                if let Some(s) = self.status.upstreams.get_mut(i) {
                    if !s.connected {
                        log(
                            "info",
                            &format!("upstream {}: connected (barbican {agent})", s.name),
                        );
                    }
                    s.connected = true;
                    s.last_ok = Some(now);
                    s.error = None;
                    s.agent = Some(agent);
                }
                self.send_reports(Some(i));
                false
            }
            Message::Changes(i, raw) => {
                let frames: Result<Vec<_>, String> = raw
                    .iter()
                    .map(|b| match wire::decode(b) {
                        Ok(Frame::Changes(c)) => Ok(c),
                        Ok(_) => Err("not changes".to_owned()),
                        Err(e) => Err(e.to_string()),
                    })
                    .collect();
                let Some(mirror) = self.mirrors.get_mut(i) else {
                    return false;
                };
                let first = mirror.epoch.is_empty();
                let full = frames
                    .as_ref()
                    .is_ok_and(|f| f.first().is_some_and(|c| c.full));
                match frames.and_then(|f| mirror.apply(&f, now).map_err(|e| e.to_string())) {
                    Ok(changed) => {
                        let (epoch, seq) = (mirror.epoch.clone(), mirror.seq);
                        if let Some(line) = self.lines.get(i) {
                            line.set_position(|p| {
                                p.epoch = epoch;
                                p.seq = seq;
                            });
                        }
                        if changed {
                            self.dirty = true;
                        }
                        // The first full state after a start is saved at once: a fresh install has something to
                        // boot with.
                        if first && full {
                            self.persist(true);
                        }
                        changed || first
                    }
                    Err(e) => {
                        self.start_over(i, &e);
                        true
                    }
                }
            }
            Message::List(i, raw) => self.take_list(i, &raw),
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

    /// Takes in an upstream's new list. Returns whether the firewall has to be reconciled.
    fn take_list(&mut self, i: usize, raw: &[Vec<u8>]) -> bool {
        let frames: Result<Vec<_>, String> = raw
            .iter()
            .map(|b| match wire::decode(b) {
                Ok(Frame::List(l)) => Ok(l),
                Ok(_) => Err("not a list".to_owned()),
                Err(e) => Err(e.to_string()),
            })
            .collect();
        match frames.and_then(|f| wire::assemble_list(f).map_err(|e| e.to_string())) {
            Ok((version, nets)) => {
                if let (Some(list), Some(v)) =
                    (self.lists.get_mut(i), self.list_versions.get_mut(i))
                {
                    *list = nets;
                    v.clone_from(&version);
                    self.lists_dirty = true;
                    self.merged = None;
                }
                if let Some(line) = self.lines.get(i) {
                    line.set_position(|p| p.list_version = version);
                }
                true
            }
            Err(e) => {
                let error = format!("list: {e}");
                log(
                    "warning",
                    &format!("upstream {}: {error}", self.upstream_name(i)),
                );
                if let Some(line) = self.lines.get(i) {
                    line.send(Outgoing::Restart);
                }
                false
            }
        }
    }

    fn report_key(&self) -> ReportKey {
        let s = &self.status;
        ReportKey {
            applied: s.applied,
            blocks: s.blocks,
            listed: s.listed,
            dropped: s.counters(),
            error: s.error.clone(),
            upstreams: s
                .upstreams
                .iter()
                .map(|u| (u.connected, u.error.clone()))
                .collect(),
        }
    }

    /// Sends upstreams a status report: to `only` (just connected), or to all when it says something new, or the
    /// last one is a minute old.
    fn send_reports(&mut self, only: Option<usize>) {
        let key = self.report_key();
        if only.is_none()
            && self
                .last_report
                .as_ref()
                .is_some_and(|(k, at)| *k == key && at.elapsed() < REPORT_EVERY)
        {
            return;
        }
        let s = &self.status;
        let report = wire::Report {
            at: now(),
            uptime: self.started.elapsed().as_secs(),
            rss: rss(),
            applied: s.applied,
            blocks: s.blocks as u64,
            listed: s.listed as u64,
            dropped: key.dropped,
            enforcing: self.config.enabled,
        };
        let heard: Vec<u64> = self
            .lines
            .iter()
            .map(|l| l.shared.heard.load(Ordering::Relaxed))
            .collect();
        for (i, line) in self.lines.iter().enumerate() {
            let connected = s.upstreams.get(i).is_some_and(|u| u.connected);
            if !connected || only.is_some_and(|o| o != i) {
                continue;
            }
            let mut out = Vec::new();
            wire::encode_status(
                &mut out,
                &report,
                VERSION,
                &s.backend,
                s.error.as_deref().unwrap_or_default(),
                s.upstreams.iter().enumerate().map(|(j, u)| wire::Upstream {
                    name: &u.name,
                    connected: u.connected,
                    this: j == i,
                    last_contact: heard.get(j).copied().filter(|t| *t > 0),
                    error: u.error.as_deref().unwrap_or_default(),
                }),
            );
            line.send(Outgoing::Frames(out));
        }
        if only.is_none() {
            self.last_report = Some((key, Instant::now()));
        }
    }
}

impl Status {
    fn set_counters(&mut self, c: Counters) {
        self.dropped_blocked = c.blocked.packets;
        self.dropped_blocked_bytes = c.blocked.bytes;
        self.dropped_listed = c.listed.packets;
        self.dropped_listed_bytes = c.listed.bytes;
    }

    fn counters(&self) -> Counters {
        let mut c = Counters::default();
        c.blocked.packets = self.dropped_blocked;
        c.blocked.bytes = self.dropped_blocked_bytes;
        c.listed.packets = self.dropped_listed;
        c.listed.bytes = self.dropped_listed_bytes;
        c
    }
}

impl Edge {
    /// The edge as it was saved, before any upstream answered.
    fn restore(config: Config, backend: Box<dyn Backend>) -> Self {
        let ipv6 = backend.ipv6();
        let mut saved = saved::load(&config.state, ipv6, &|e| log("warning", &e));
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
        // A list saved without its version (or none) is asked for again.
        let list_versions: Vec<String> = config
            .upstreams
            .iter()
            .zip(&lists)
            .map(|(u, l)| {
                let version = saved.list_versions.remove(&u.name).unwrap_or_default();
                if l.is_empty() { String::new() } else { version }
            })
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
            list_versions,
            lines: Vec::new(),
            started: Instant::now(),
            last_report: None,
            merged: None,
            dirty: false,
            // A state written by an older version (one JSON file) is written anew, lists and all.
            lists_dirty: std::fs::read(&config.state).is_ok_and(|b| b.first() == Some(&b'{')),
            ipv6,
            last_saved: None,
            config,
        }
    }
}

/// Starts a thread per upstream, each continuing where the saved state stopped.
fn spawn_upstreams(edge: &mut Edge, tx: &mpsc::Sender<Message>) -> Result<(), String> {
    for (i, upstream) in edge.config.upstreams.iter().enumerate() {
        let position = Position {
            epoch: edge
                .mirrors
                .get(i)
                .map(|m| m.epoch.clone())
                .unwrap_or_default(),
            seq: edge.mirrors.get(i).map_or(0, |m| m.seq),
            list_version: edge.list_versions.get(i).cloned().unwrap_or_default(),
        };
        let shared = Arc::new(Shared {
            position: Mutex::new(position),
            heard: AtomicU64::new(0),
        });
        let (wake, wake_thread) = UnixStream::pair().map_err(|e| e.to_string())?;
        wake.set_nonblocking(true)
            .and_then(|()| wake_thread.set_nonblocking(true))
            .map_err(|e| e.to_string())?;
        let (outbox, inbox) = mpsc::channel();
        let task = Follow {
            index: i,
            upstream: upstream.clone(),
            enforcing: edge.config.enabled,
            lists: edge.config.lists,
            ipv6: edge.ipv6,
            backend: edge.status.backend.clone(),
            shared: Arc::clone(&shared),
            outbox: inbox,
            wake: wake_thread,
            tx: tx.clone(),
        };
        std::thread::Builder::new()
            .name(format!("upstream-{i}"))
            .spawn(move || follow(&task))
            .map_err(|e| e.to_string())?;
        edge.lines.push(Line {
            shared,
            outbox,
            wake,
        });
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
    spawn_upstreams(&mut edge, &tx)?;

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
        edge.send_reports(None);
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
}
