//! From log lines to decisions.
//!
//! Each source runs [`Prefilter::line`] on its lines: it parses the line and matches it against the shared rule set
//! without allocating, and only lines that matched a rule, or are logins, become [`Hit`]s for the engine. The engine
//! records them (one transaction per batch), keeps addresses people logged in from trusted, counts matches in each
//! rule's window, and bans when a rule's threshold is reached.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use barbican_common::net::Net;
use tokio::sync::{mpsc, watch};

use sqlx::SqliteConnection;

use crate::api::Live;
use crate::app::{App, now};
use crate::db::{self, BanRow};
use crate::geo::Info;
use crate::parse::Parser;
use crate::rules::{Action, Rule, RuleSet, Who};
use crate::signal::{Event, Hit, Kind};
use crate::state::Trusted;

/// Hits per transaction, at most.
const BATCH: usize = 512;
/// A session refreshes trust at most this often per address (sessions come with every request).
const SESSION_EVERY: i64 = 600;
/// Cached ids of `what` texts before the cache is emptied.
const WHAT_CACHE: usize = 20_000;
/// Cached geolocations before the cache is emptied.
const GEO_CACHE: usize = 50_000;

/// What a batch did, applied to the state once its transaction is committed.
#[derive(Default)]
struct Outcome {
    /// Addresses of this batch: their id, and the hits and last time not counted in the database yet.
    ips: HashMap<IpAddr, (i64, i64, i64)>,
    /// Events of this batch, counted: `(ip, hour, rule, source, what)`.
    events: HashMap<(i64, i64, i64, i64, i64), i64>,
    bans: Vec<BanRow>,
    trusts: Vec<(IpAddr, Box<str>, i64)>,
    lives: Vec<Live>,
}

/// The per-source part: parsing and matching, reusing its buffers for every line.
pub struct Prefilter {
    pub source: u16,
    parser: Parser,
    rules: watch::Receiver<Arc<RuleSet>>,
    current: Arc<RuleSet>,
    what: String,
    sessions: HashMap<IpAddr, i64>,
}

impl Prefilter {
    pub fn new(source: u16, parser: Parser, mut rules: watch::Receiver<Arc<RuleSet>>) -> Self {
        let current = Arc::clone(&rules.borrow_and_update());
        Self {
            source,
            parser,
            rules,
            current,
            what: String::new(),
            sessions: HashMap::new(),
        }
    }

    /// What the engine should get of a line logged at `at`, if anything.
    pub fn line(&mut self, line: &str, at: i64) -> Option<Hit> {
        if self.rules.has_changed().unwrap_or(false) {
            self.current = Arc::clone(&self.rules.borrow_and_update());
        }
        let (ip, event) = self.parser.parse(line)?;
        let matched = self
            .current
            .matches(self.source, ip, &event, &mut self.what);
        let login = matches!(event, Event::AuthSuccess { .. } | Event::Session { .. });
        if matched == 0 && !login {
            return None;
        }
        if login && self.current.allowed(ip) {
            return None;
        }
        if let Event::Session { .. } = event {
            let last = self.sessions.entry(ip).or_insert(i64::MIN);
            if at.saturating_sub(*last) < SESSION_EVERY {
                return None;
            }
            *last = at;
            if self.sessions.len() > 10_000 {
                self.sessions.retain(|_, t| at - *t < SESSION_EVERY);
            }
        }
        if self.what.is_empty() {
            event.write_what(&mut self.what);
        }
        Some(Hit {
            at,
            ip,
            source: self.source,
            kind: event.kind(),
            what: self.what.as_str().into(),
            user: event.user().map(Into::into),
            matched,
            generation: self.current.generation,
        })
    }
}

/// The engine's own state: windows of recent matches, and caches of database ids.
pub struct Engine {
    app: Arc<App>,
    rules: watch::Receiver<Arc<RuleSet>>,
    /// Recent rule sets by generation: hits matched against one shortly before a change still find their rules.
    sets: VecDeque<Arc<RuleSet>>,
    /// Times of matches, per rule id and banned prefix, within the rule's window.
    windows: HashMap<(i64, Net), VecDeque<i64>>,
    /// When each address last refreshed its trust in the database.
    trust_saved: HashMap<IpAddr, i64>,
    sources: HashMap<u16, i64>,
    /// Ids of `what` texts, per kind; looked up by `&str`, so without allocating.
    whats: HashMap<Kind, HashMap<Box<str>, i64>>,
    whats_len: usize,
    names: Arc<[String]>,
    geo_cache: HashMap<IpAddr, Arc<Info>>,
    /// ASNs whose names are in the database.
    asns: std::collections::HashSet<i64>,
    hits: u64,
    /// The time of the newest hit so far: windows are pruned relative to it, so history keeps its counts.
    latest: i64,
}

impl Engine {
    pub fn new(app: Arc<App>, mut rules: watch::Receiver<Arc<RuleSet>>) -> Self {
        let names = app_names(&app);
        let current = Arc::clone(&rules.borrow_and_update());
        Self {
            app,
            rules,
            sets: VecDeque::from([current]),
            windows: HashMap::new(),
            trust_saved: HashMap::new(),
            sources: HashMap::new(),
            whats: HashMap::new(),
            whats_len: 0,
            names,
            geo_cache: HashMap::new(),
            asns: std::collections::HashSet::new(),
            hits: 0,
            latest: i64::MIN,
        }
    }

    pub async fn run(mut self, mut rx: mpsc::Receiver<Hit>) {
        let mut batch = Vec::with_capacity(BATCH);
        while rx.recv_many(&mut batch, BATCH).await > 0 {
            if let Err(e) = self.process(&batch).await {
                tracing::error!(error = %e, hits = batch.len(), "Recording hits failed");
            }
            batch.clear();
        }
    }

    fn rule_set(&mut self, generation: u64) -> Option<Arc<RuleSet>> {
        if self.rules.has_changed().unwrap_or(false) {
            let set = Arc::clone(&self.rules.borrow_and_update());
            self.sets.push_front(set);
            self.sets.truncate(4);
            // Counts of rules that changed would mix with the old rules' counts.
            self.windows.clear();
        }
        self.sets
            .iter()
            .find(|s| s.generation == generation)
            .cloned()
    }

    /// Records a batch of hits, and bans what crossed a threshold. Returns the new bans.
    pub async fn process(&mut self, batch: &[Hit]) -> Result<Vec<BanRow>, db::Error> {
        let now = now();
        let mut out = Outcome::default();
        let mut tx = self.app.db.pool.begin().await?;
        for hit in batch {
            self.handle(&mut tx, &mut out, hit, now).await?;
        }
        for (id, hits, last) in out.ips.values() {
            if *hits > 0 {
                db::ip_hits(&mut tx, *id, *hits, *last).await?;
            }
        }
        for ((ip, hour, rule, source, what), count) in &out.events {
            db::event_add(&mut tx, *ip, *hour, *rule, *source, *what, *count).await?;
        }
        tx.commit().await?;

        if let Ok(mut state) = self.app.state.write() {
            for (ip, user, until) in out.trusts {
                state.trust.insert(
                    ip,
                    Trusted {
                        user: user.into(),
                        until,
                    },
                );
            }
            for ban in &out.bans {
                state.bans.push(ban.clone());
            }
        }
        if !out.bans.is_empty() {
            self.app.firewall_wake.notify_one();
        }
        for live in out.lives {
            self.app.publish(live);
        }
        self.hits += batch.len() as u64;
        if self.hits % 4_096 < batch.len() as u64 {
            self.prune(self.latest);
        }
        Ok(out.bans)
    }

    /// The country and network of an address, cached: scanners come back again and again.
    fn geo(&mut self, ip: IpAddr) -> Arc<Info> {
        if let Some(info) = self.geo_cache.get(&ip) {
            return Arc::clone(info);
        }
        let info = Arc::new(self.app.geo().lookup(ip));
        if self.geo_cache.len() >= GEO_CACHE {
            self.geo_cache.clear();
        }
        self.geo_cache.insert(ip, Arc::clone(&info));
        info
    }

    async fn handle(
        &mut self,
        tx: &mut SqliteConnection,
        out: &mut Outcome,
        hit: &Hit,
        now: i64,
    ) -> Result<(), db::Error> {
        let Some(set) = self.rule_set(hit.generation) else {
            return Ok(());
        };
        // Everything about a hit is judged at its own time (a line read late, or history being imported): whether
        // the address was banned or trusted then, and when a ban it brings starts and ends.
        let now = hit.at.min(now);
        self.latest = self.latest.max(now);
        // What the state says about the address, looked up without holding the lock across awaits.
        let (allowed, trusted, banned, trust_secs) = {
            let Ok(state) = self.app.state.read() else {
                return Ok(());
            };
            (
                state.allowed(hit.ip, now),
                state.trusted(hit.ip, now).is_some(),
                state.ban_of(hit.ip, now).is_some() || state.denied(hit.ip, now),
                state.policy.trust_secs,
            )
        };
        if allowed {
            return Ok(());
        }
        let banned = banned || out.bans.iter().any(|b| b.net.contains_ip(hit.ip));
        let info = self.geo(hit.ip);
        let asn = info.asn.map(i64::from);
        let seen = now;
        let ip_id = if let Some((id, hits, last)) = out.ips.get_mut(&hit.ip) {
            *hits += 1;
            *last = (*last).max(seen);
            *id
        } else {
            let id = db::ip_seen(
                tx,
                &db::addr_bytes(hit.ip),
                seen,
                info.country.as_deref(),
                asn,
            )
            .await?;
            out.ips.insert(hit.ip, (id, 0, seen));
            id
        };
        if let (Some(asn), Some(name)) = (asn, &info.as_name)
            && self.asns.insert(asn)
        {
            db::asn_name(tx, asn, name).await?;
        }

        if let Some(user) = &hit.user
            && matches!(hit.kind, None | Some(Kind::AuthSuccess))
        {
            let until = now.saturating_add(i64::try_from(trust_secs).unwrap_or(i64::MAX / 2));
            let saved = self.trust_saved.get(&hit.ip).copied().unwrap_or(i64::MIN);
            if now.saturating_sub(saved) >= SESSION_EVERY {
                db::trust(tx, ip_id, user, now, until).await?;
                self.trust_saved.insert(hit.ip, now);
            }
            out.trusts.push((hit.ip, user.clone(), until));
        }
        let Some(kind) = hit.kind else {
            return Ok(());
        };

        // Recorded under the first rule that matched (0 for logins no rule counts).
        let first = (hit.matched != 0)
            .then(|| set.rules.get(hit.matched.trailing_zeros() as usize))
            .flatten();
        let first_id = first.map_or(0, |c| c.rule.id);
        let source = self.source_id(tx, hit.source).await?;
        let what = self.what_id(tx, kind, &hit.what).await?;
        *out.events
            .entry((ip_id, hit.at.div_euclid(3_600), first_id, source, what))
            .or_default() += 1;
        out.lives.push(Live::Event {
            at: hit.at,
            ip: hit.ip.to_string(),
            country: info.country.clone(),
            source: self
                .names
                .get(usize::from(hit.source))
                .cloned()
                .unwrap_or_default(),
            kind,
            what: hit.what.to_string(),
            rule: first.map(|c| c.rule.name.clone()),
        });

        if trusted || banned || out.trusts.iter().any(|(ip, ..)| *ip == hit.ip) {
            return Ok(());
        }
        if let Some(rule) = self.fired(&set, hit) {
            self.ban(tx, out, hit, ip_id, &info, &rule, now).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn ban(
        &self,
        tx: &mut SqliteConnection,
        out: &mut Outcome,
        hit: &Hit,
        ip_id: i64,
        info: &Info,
        rule: &Rule,
        now: i64,
    ) -> Result<(), db::Error> {
        let net = match hit.ip {
            IpAddr::V4(_) => Net::prefix(hit.ip, rule.prefix_v4),
            IpAddr::V6(_) => Net::prefix(hit.ip, rule.prefix_v6),
        };
        let previous = u32::try_from(db::bans_of(tx, ip_id).await?).unwrap_or(u32::MAX);
        let Some(length) = self.app.state.read().ok().map(|state| {
            let listed = state.listed(hit.ip);
            let who = Who {
                country: info.country.as_deref(),
                asn: info.asn,
                listed: &listed,
            };
            state.policy.length(rule.ban, &who, previous)
        }) else {
            return Ok(());
        };
        let until = length.map(|l| now.saturating_add(i64::try_from(l).unwrap_or(i64::MAX / 2)));
        let id =
            db::ban_insert(tx, &net, Some(ip_id), Some(rule.id), &rule.name, now, until).await?;
        tracing::info!(%net, rule = %rule.name, country = ?info.country, until, "Banned");
        let row = BanRow {
            id,
            net,
            ip: Some(ip_id),
            rule: Some(rule.id),
            reason: rule.name.clone(),
            created: now,
            until,
            lifted: None,
            lifted_by: None,
        };
        out.lives.push(Live::Ban {
            ban: crate::api::ban(&row, Some(hit.ip), info.country.clone()),
        });
        out.bans.push(row);
        Ok(())
    }

    /// Counts the hit in the windows of the banning rules it matched; the first rule whose threshold it reaches.
    fn fired(&mut self, set: &RuleSet, hit: &Hit) -> Option<Rule> {
        let mut bits = hit.matched;
        let mut fired = None;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let Some(c) = set.rules.get(i) else { continue };
            let r = &c.rule;
            if r.action != Action::Ban {
                continue;
            }
            if r.threshold <= 1 {
                fired.get_or_insert_with(|| r.clone());
                continue;
            }
            let key_net = match hit.ip {
                IpAddr::V4(_) => Net::prefix(hit.ip, r.prefix_v4),
                IpAddr::V6(_) => Net::prefix(hit.ip, r.prefix_v6),
            };
            let window = i64::try_from(r.window_secs).unwrap_or(i64::MAX);
            let times = self.windows.entry((r.id, key_net)).or_default();
            times.push_back(hit.at);
            while times.front().is_some_and(|t| *t <= hit.at - window) {
                times.pop_front();
            }
            if times.len() >= r.threshold as usize {
                times.clear();
                fired.get_or_insert_with(|| r.clone());
            }
        }
        fired
    }

    fn prune(&mut self, now: i64) {
        self.windows
            .retain(|_, times| times.back().is_some_and(|t| now - t < 86_400));
        self.trust_saved.retain(|_, t| now - *t < SESSION_EVERY);
    }

    async fn source_id(
        &mut self,
        tx: &mut sqlx::SqliteConnection,
        source: u16,
    ) -> Result<i64, db::Error> {
        if let Some(id) = self.sources.get(&source) {
            return Ok(*id);
        }
        let id = match self.names.get(usize::from(source)) {
            Some(name) => db::source_id(tx, name).await?,
            None => db::source_id(tx, "?").await?,
        };
        self.sources.insert(source, id);
        Ok(id)
    }

    async fn what_id(
        &mut self,
        tx: &mut sqlx::SqliteConnection,
        kind: Kind,
        what: &str,
    ) -> Result<i64, db::Error> {
        if let Some(id) = self.whats.get(&kind).and_then(|m| m.get(what)) {
            return Ok(*id);
        }
        let id = db::what_id(tx, kind.code(), what).await?;
        if self.whats_len >= WHAT_CACHE {
            self.whats.clear();
            self.whats_len = 0;
        }
        self.whats.entry(kind).or_default().insert(what.into(), id);
        self.whats_len += 1;
        Ok(id)
    }
}

fn app_names(app: &App) -> Arc<[String]> {
    app.config.sources.iter().map(|s| s.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ParserKind};
    use crate::db::Db;

    const CONFIG: &str = r#"
        [[source]]
        name = "web"
        parser = "traefik"
        file = { path = "/dev/null" }
        [[source]]
        name = "ssh"
        parser = "sshd"
        file = { path = "/dev/null" }
        [[source]]
        name = "auth"
        parser = "authelia"
        file = { path = "/dev/null" }
    "#;

    struct Test {
        app: Arc<App>,
        engine: Engine,
        prefilters: Vec<Prefilter>,
    }

    async fn setup() -> Test {
        let config: Config = toml::from_str(CONFIG).unwrap();
        let app = App::new(config, Db::memory().await, crate::app::http_client(), true);
        let mut rules = crate::rules::defaults();
        for (i, rule) in rules.iter_mut().enumerate() {
            rule.id = i64::try_from(i).unwrap() + 1;
        }
        let allowed = barbican_common::net::NetSet::new(&app.config.exempt.nets);
        if let Ok(mut state) = app.state.write() {
            state.exempt.clone_from(&app.config.exempt.nets);
            state.rules.clone_from(&rules);
        }
        let set = RuleSet::new(1, rules, &["web", "ssh", "auth"], &[], &[], allowed).unwrap();
        let (tx, rx) = watch::channel(Arc::new(set));
        let prefilters = [ParserKind::Traefik, ParserKind::Sshd, ParserKind::Authelia]
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                Prefilter::new(
                    u16::try_from(i).unwrap(),
                    Parser::builtin(kind).unwrap(),
                    rx.clone(),
                )
            })
            .collect();
        let engine = Engine::new(Arc::clone(&app), rx);
        // Keep the sender alive for the test's duration.
        std::mem::forget(tx);
        Test {
            app,
            engine,
            prefilters,
        }
    }

    impl Test {
        async fn feed(&mut self, source: usize, lines: &[&str]) -> Vec<BanRow> {
            let at = now();
            let hits: Vec<Hit> = lines
                .iter()
                .filter_map(|l| self.prefilters[source].line(l, at))
                .collect();
            self.engine.process(&hits).await.unwrap()
        }

        async fn feed_at(&mut self, source: usize, lines: &[&str], at: i64) -> Vec<BanRow> {
            let hits: Vec<Hit> = lines
                .iter()
                .filter_map(|l| self.prefilters[source].line(l, at))
                .collect();
            self.engine.process(&hits).await.unwrap()
        }

        fn banned(&self, ip: &str) -> bool {
            self.app
                .state
                .read()
                .unwrap()
                .ban_of(ip.parse().unwrap(), now())
                .is_some()
        }

        async fn events(&self) -> i64 {
            sqlx::query_scalar!("SELECT coalesce(sum(count), 0) FROM event")
                .fetch_one(&self.app.db.pool)
                .await
                .unwrap()
        }
    }

    const WEB: usize = 0;
    const SSH: usize = 1;
    const AUTH: usize = 2;

    fn access(ip: &str, path: &str, status: u16, router: &str) -> String {
        format!(
            r#"{ip} - - [10/Nov/2026:12:00:00 +0000] "GET {path} HTTP/1.1" {status} 1 "-" "-" 1 "{router}" "-" 0ms"#
        )
    }

    #[tokio::test]
    async fn probe_bans_at_once() {
        let mut t = setup().await;
        let bans = t
            .feed(WEB, &[&access("203.0.113.5", "/.env", 404, "app@docker")])
            .await;
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].net.to_string(), "203.0.113.5");
        assert_eq!(bans[0].reason, "Exploit probes");
        assert!(bans[0].until.is_some());
        assert!(t.banned("203.0.113.5"));
        // More of the same is recorded but makes no second ban.
        let again = t
            .feed(
                WEB,
                &[&access("203.0.113.5", "/.git/config", 404, "app@docker")],
            )
            .await;
        assert_eq!(again, Vec::new());
        assert_eq!(t.events().await, 2);
    }

    #[tokio::test]
    async fn live_items_are_kept_for_subscribers_to_come() {
        let mut t = setup().await;
        // Nobody watches yet.
        t.feed(WEB, &[&access("203.0.113.5", "/.env", 404, "app@docker")])
            .await;
        let (recent, _) = t.app.live();
        assert!(matches!(&recent[0], Live::Event { ip, .. } if ip == "203.0.113.5"));
        assert!(matches!(&recent[1], Live::Ban { ban } if ban.net == "203.0.113.5"));
        // Only the latest are kept, oldest first.
        for id in 0..100 {
            t.app.publish(Live::Lift { id });
        }
        let (recent, _) = t.app.live();
        assert_eq!(recent.len(), 40);
        assert!(matches!(recent[0], Live::Lift { id: 60 }));
        assert!(matches!(recent[39], Live::Lift { id: 99 }));
    }

    #[tokio::test]
    async fn history_is_judged_at_its_own_times() {
        let mut t = setup().await;
        let long_ago = now() - 400 * 86_400;
        let bans = t
            .feed_at(
                SSH,
                &[
                    "Invalid user admin from 203.0.113.9 port 1",
                    "Invalid user oracle from 203.0.113.9 port 2",
                ],
                long_ago,
            )
            .await;
        // A year-long ban that started 400 days ago, and is over.
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].created, long_ago);
        assert_eq!(bans[0].until, Some(long_ago + 365 * 86_400));
        assert!(!t.banned("203.0.113.9"));
        // A day later the address was still banned then: no second ban, no longer one for a repeat.
        let later = t
            .feed_at(
                SSH,
                &[
                    "Invalid user test from 203.0.113.9 port 3",
                    "Invalid user guest from 203.0.113.9 port 4",
                ],
                long_ago + 86_400,
            )
            .await;
        assert_eq!(later, Vec::new());
        // A probe ten days ago: its ban is still on.
        let recent = now() - 10 * 86_400;
        let bans = t
            .feed_at(
                WEB,
                &[&access("198.51.100.3", "/.env", 404, "app@docker")],
                recent,
            )
            .await;
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].created, recent);
        assert!(t.banned("198.51.100.3"));
    }

    #[tokio::test]
    async fn ordinary_traffic_is_not_recorded() {
        let mut t = setup().await;
        let lines: Vec<String> = (0..50)
            .map(|i| {
                access(
                    "198.51.100.7",
                    &format!("/api/items/{i}"),
                    200,
                    "app@docker",
                )
            })
            .collect();
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert_eq!(t.feed(WEB, &lines).await, Vec::new());
        assert_eq!(t.events().await, 0);
    }

    #[tokio::test]
    async fn thresholds_count_within_the_window() {
        let mut t = setup().await;
        assert_eq!(
            t.feed(SSH, &["Invalid user admin from 203.0.113.9 port 1"])
                .await,
            Vec::new()
        );
        assert!(!t.banned("203.0.113.9"));
        let bans = t
            .feed(SSH, &["Invalid user oracle from 203.0.113.9 port 2"])
            .await;
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].reason, "Unknown users");
        // Another address has its own count.
        assert_eq!(
            t.feed(SSH, &["Invalid user test from 203.0.113.10 port 2"])
                .await,
            Vec::new()
        );
    }

    #[tokio::test]
    async fn trusted_and_exempt_addresses() {
        let mut t = setup().await;
        let session = r#"level=debug msg="Check authorization of subject username=alice groups=a ip=192.0.2.8 and object https://x.example.com/ (method GET).""#;
        t.feed(AUTH, &[session, session]).await;
        assert!(
            t.app
                .state
                .read()
                .unwrap()
                .trusted("192.0.2.8".parse().unwrap(), now())
                .is_some()
        );
        let trust_rows = sqlx::query_scalar!("SELECT count(*) FROM trust")
            .fetch_one(&t.app.db.pool)
            .await
            .unwrap();
        assert_eq!(trust_rows, 1);
        // A trusted address that trips a rule is recorded, not banned.
        assert_eq!(
            t.feed(WEB, &[&access("192.0.2.8", "/registerSW.js", 404, "-")])
                .await,
            Vec::new()
        );
        assert!(!t.banned("192.0.2.8"));
        assert_eq!(t.events().await, 1);
        // Exempt (private) addresses aren't even recorded.
        assert_eq!(
            t.feed(WEB, &[&access("10.0.0.5", "/.env", 404, "-")]).await,
            Vec::new()
        );
        assert_eq!(t.events().await, 1);
    }

    #[tokio::test]
    async fn failed_logins_then_success() {
        let mut t = setup().await;
        let fail = r#"level=error msg="Unsuccessful 1FA authentication attempt by user 'bob'" remote_ip=198.51.100.20"#;
        let ok = r#"level=debug msg="Successful 1FA authentication attempt made by user 'bob'" remote_ip=198.51.100.20"#;
        assert_eq!(
            t.feed(AUTH, &[fail, fail, fail, fail, ok, fail]).await,
            Vec::new()
        );
        let fail2 = r#"level=error msg="Unsuccessful 1FA authentication attempt by user 'eve'" remote_ip=203.0.113.30"#;
        let bans = t.feed(AUTH, &[fail2, fail2, fail2, fail2, fail2]).await;
        assert_eq!(
            bans.iter().map(|b| b.reason.as_str()).collect::<Vec<_>>(),
            vec!["Failed logins"]
        );
    }
}
