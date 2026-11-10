//! What every part of the agent shares.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use barbican_common::edge::Journal;
use tokio::sync::{Notify, broadcast, watch};

use crate::api::{EdgeStatus, FirewallStatus, Live, SourceStatus};
use crate::config::Config;
use crate::db::Db;
use crate::geo::Geo;
use crate::rules::RuleSet;
use crate::state::{Lists, State};

/// A source's counters, updated for every line.
#[derive(Debug, Default)]
pub struct SourceCounters {
    pub lines: std::sync::atomic::AtomicU64,
    pub parsed: std::sync::atomic::AtomicU64,
    pub last_line: std::sync::atomic::AtomicI64,
}

pub struct App {
    pub config: Config,
    pub db: Db,
    pub state: RwLock<State>,
    /// The compiled rules every source matches lines against; replaced as a whole.
    pub rules: watch::Sender<Arc<RuleSet>>,
    pub rules_generation: std::sync::atomic::AtomicU64,
    pub geo: RwLock<Arc<Geo>>,
    /// The list sets' content, as the firewall last computed it.
    pub lists: RwLock<Lists>,
    /// Wakes the firewall to apply the state again.
    pub firewall_wake: Notify,
    /// Recomputes the prefixes of blocked countries (after the policy or the database changed).
    pub countries_wake: Notify,
    pub feeds_wake: Notify,
    pub journal: Mutex<Journal>,
    /// The journal's sequence number, for edge polls waiting for news.
    pub journal_seq: watch::Sender<u64>,
    pub live: broadcast::Sender<Live>,
    pub sources: Mutex<BTreeMap<String, SourceStatus>>,
    /// Lines read and matched per source, counted without a lock.
    pub source_counters: Mutex<BTreeMap<String, Arc<SourceCounters>>>,
    pub edges: Mutex<BTreeMap<String, EdgeStatus>>,
    pub firewall: Mutex<FirewallStatus>,
    pub http: reqwest::Client,
    pub dry_run: bool,
    /// The edge API's certificate fingerprint, once it listens.
    pub edge_fingerprint: std::sync::OnceLock<String>,
}

/// The HTTP client for downloads (geolocation databases, blocklists), with rustls on ring.
#[must_use]
pub fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("barbican/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap_or_default()
}

#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl App {
    pub fn new(config: Config, db: Db, http: reqwest::Client, dry_run: bool) -> Arc<Self> {
        let epoch = format!("{:x}", now() ^ i64::from(std::process::id()) << 32);
        let (journal_seq, _) = watch::channel(0);
        let (live, _) = broadcast::channel(1_024);
        let (rules, _) = watch::channel(Arc::new(RuleSet::default()));
        let enabled = config.firewall.enabled && !dry_run;
        Arc::new(Self {
            config,
            db,
            state: RwLock::new(State::default()),
            rules,
            rules_generation: std::sync::atomic::AtomicU64::new(0),
            geo: RwLock::new(Arc::new(Geo::default())),
            lists: RwLock::new(Lists::default()),
            firewall_wake: Notify::new(),
            countries_wake: Notify::new(),
            feeds_wake: Notify::new(),
            journal: Mutex::new(Journal::new(epoch, 10_000)),
            journal_seq,
            live,
            sources: Mutex::new(BTreeMap::new()),
            source_counters: Mutex::new(BTreeMap::new()),
            edges: Mutex::new(BTreeMap::new()),
            firewall: Mutex::new(FirewallStatus {
                enabled,
                ..FirewallStatus::default()
            }),
            http,
            dry_run,
            edge_fingerprint: std::sync::OnceLock::new(),
        })
    }

    pub fn geo(&self) -> Arc<Geo> {
        self.geo.read().map(|g| Arc::clone(&g)).unwrap_or_default()
    }

    /// Sends to the UI's live subscribers, if any.
    pub fn publish(&self, live: Live) {
        let _ = self.live.send(live);
    }
}
