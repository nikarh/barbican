//! What the agent knows right now, in memory: rules, policy, active bans, the allow and deny lists, trusted
//! addresses and blocklists. The database has the same; this is what decisions and the firewall are made from.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use barbican_common::edge::ListRef;
use barbican_common::net::{Net, aggregate};
use barbican_common::nft::{Block, Desired};

use crate::db::{BanRow, EntryRow};
use crate::feeds::{FeedDef, Loaded};
use crate::rules::{Policy, Rule};

#[derive(Debug, Clone)]
pub struct Feed {
    pub def: FeedDef,
    pub loaded: Arc<Loaded>,
    /// The last attempt, failed or not.
    pub fetched: Option<i64>,
    /// The last fetch without an error.
    pub succeeded: Option<i64>,
    /// When its list last changed.
    pub changed: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trusted {
    pub user: String,
    pub until: i64,
}

/// The active bans, with single-address bans indexed by address: every hit asks whether its address is banned.
#[derive(Debug, Default)]
pub struct Bans {
    rows: Vec<BanRow>,
    /// Index into `rows` of each single-address ban (the latest one, if several).
    hosts: HashMap<IpAddr, usize>,
    /// Indexes into `rows` of prefix bans.
    nets: Vec<usize>,
}

impl Bans {
    #[must_use]
    pub fn new(rows: Vec<BanRow>) -> Self {
        let mut bans = Self {
            rows,
            ..Self::default()
        };
        bans.index();
        bans
    }

    fn index(&mut self) {
        self.hosts.clear();
        self.nets.clear();
        for (i, row) in self.rows.iter().enumerate() {
            if row.net.is_host() {
                self.hosts.insert(row.net.addr(), i);
            } else {
                self.nets.push(i);
            }
        }
    }

    pub fn push(&mut self, row: BanRow) {
        let i = self.rows.len();
        if row.net.is_host() {
            self.hosts.insert(row.net.addr(), i);
        } else {
            self.nets.push(i);
        }
        self.rows.push(row);
    }

    /// Keeps the bans `keep` says to keep.
    pub fn retain(&mut self, keep: impl FnMut(&BanRow) -> bool) {
        let before = self.rows.len();
        self.rows.retain(keep);
        if self.rows.len() != before {
            self.index();
        }
    }

    /// The ban in force at `now` that covers the address.
    #[must_use]
    pub fn of(&self, ip: IpAddr, now: i64) -> Option<&BanRow> {
        let active = |b: &&BanRow| b.until.is_none_or(|u| u > now);
        let ip = barbican_common::net::canonical(ip);
        self.hosts
            .get(&ip)
            .and_then(|i| self.rows.get(*i))
            .filter(active)
            .or_else(|| {
                self.nets
                    .iter()
                    .filter_map(|i| self.rows.get(*i))
                    .filter(active)
                    .find(|b| b.net.contains_ip(ip))
            })
    }

    pub fn iter(&self) -> std::slice::Iter<'_, BanRow> {
        self.rows.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl<'a> IntoIterator for &'a Bans {
    type Item = &'a BanRow;
    type IntoIter = std::slice::Iter<'a, BanRow>;
    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}

#[derive(Debug, Default)]
pub struct State {
    /// In the order they are tried (the compiled ones are the app's rule set).
    pub rules: Vec<Rule>,
    pub policy: Policy,
    pub bans: Bans,
    pub entries: Vec<EntryRow>,
    pub trust: HashMap<IpAddr, Trusted>,
    pub feeds: Vec<Feed>,
    /// From the configuration: never acted on.
    pub exempt: Vec<Net>,
    /// The prefixes of the blocked countries and continents, and which ones they are of.
    pub countries: Arc<Vec<Net>>,
    pub countries_of: (Vec<String>, Vec<String>),
}

/// The list sets' content and its identity.
#[derive(Debug, Clone, Default)]
pub struct Lists {
    pub nets: Arc<Vec<Net>>,
    pub version: String,
}

/// FNV-1a: a stable hash for identifying list contents (not for security).
fn fnv(bytes: impl Iterator<Item = u8>, mut hash: u64) -> u64 {
    for b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

impl State {
    /// Whether no rule may act on the address: it is exempt, or on the allow list.
    #[must_use]
    pub fn allowed(&self, ip: IpAddr, now: i64) -> bool {
        self.exempt.iter().any(|n| n.contains_ip(ip))
            || self
                .entries
                .iter()
                .any(|e| e.allow && e.until.is_none_or(|u| u > now) && e.net.contains_ip(ip))
    }

    /// The active ban that covers the address, if any.
    #[must_use]
    pub fn ban_of(&self, ip: IpAddr, now: i64) -> Option<&BanRow> {
        self.bans.of(ip, now)
    }

    /// Whether the address is on the deny list.
    #[must_use]
    pub fn denied(&self, ip: IpAddr, now: i64) -> bool {
        self.entries
            .iter()
            .any(|e| !e.allow && e.until.is_none_or(|u| u > now) && e.net.contains_ip(ip))
    }

    #[must_use]
    pub fn trusted(&self, ip: IpAddr, now: i64) -> Option<&Trusted> {
        self.trust.get(&ip).filter(|t| t.until > now)
    }

    /// The names of the enabled feeds that list the address.
    #[must_use]
    pub fn listed(&self, ip: IpAddr) -> Vec<&str> {
        self.feeds
            .iter()
            .filter(|f| f.def.enabled && f.loaded.set.contains(ip))
            .map(|f| f.def.name.as_str())
            .collect()
    }

    /// Drops bans and entries that ran out, and trust that expired.
    /// Forgets bans that ran out (the kernel lifted them already).
    pub fn expire_bans(&mut self, now: i64) {
        self.bans.retain(|b| b.until.is_none_or(|u| u > now));
        self.trust.retain(|_, t| t.until > now);
    }

    /// When the next allow entry runs out: the firewall has to drop it then, nothing times it out.
    #[must_use]
    pub fn next_due(&self, now: i64) -> Option<i64> {
        self.entries
            .iter()
            .filter(|e| e.allow)
            .filter_map(|e| e.until)
            .filter(|u| *u > now)
            .min()
    }

    pub fn expire(&mut self, now: i64) {
        self.bans.retain(|b| b.until.is_none_or(|u| u > now));
        self.entries.retain(|e| e.until.is_none_or(|u| u > now));
        self.trust.retain(|_, t| t.until > now);
    }

    /// Blocks (bans and the deny list) and allows (exempt and the allow list), as the firewall and edges get them.
    #[must_use]
    pub fn blocks_and_allows(&self, now: i64) -> (Vec<Block>, Vec<Net>) {
        let until = |u: Option<i64>| u.map(|u| u64::try_from(u).unwrap_or(0));
        let mut blocks: Vec<Block> = self
            .bans
            .iter()
            .filter(|b| b.until.is_none_or(|u| u > now))
            .map(|b| Block {
                net: b.net,
                until: until(b.until),
            })
            .collect();
        let mut allows = self.exempt.clone();
        for e in &self.entries {
            if e.until.is_some_and(|u| u <= now) {
                continue;
            }
            if e.allow {
                allows.push(e.net);
            } else {
                blocks.push(Block {
                    net: e.net,
                    until: until(e.until),
                });
            }
        }
        allows.sort();
        allows.dedup();
        (blocks, allows)
    }

    /// The list sets' content: blocked countries and the feeds that block.
    #[must_use]
    pub fn lists(&self) -> Lists {
        let mut nets: Vec<Net> = self.countries.as_ref().clone();
        let mut hash = fnv(b"barbican".iter().copied(), 0xcbf2_9ce4_8422_2325);
        for feed in self.feeds.iter().filter(|f| f.def.enabled && f.def.block) {
            nets.extend(feed.loaded.nets.iter().copied());
        }
        let nets = aggregate(&nets);
        for net in &nets {
            hash = fnv(net.to_bytes().into_iter(), hash);
        }
        Lists {
            nets: Arc::new(nets),
            version: format!("{hash:016x}"),
        }
    }

    #[must_use]
    pub fn desired(&self, now: i64, lists: &Lists) -> Desired {
        let (block, allow) = self.blocks_and_allows(now);
        Desired {
            allow,
            block,
            lists: Arc::clone(&lists.nets),
            lists_version: lists.version.clone(),
        }
    }
}

impl Lists {
    #[must_use]
    pub fn reference(&self) -> ListRef {
        ListRef {
            version: self.version.clone(),
            count: self.nets.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Net {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ban(id: i64, net: &str, until: Option<i64>) -> BanRow {
        BanRow {
            id,
            net: n(net),
            ip: None,
            rule: None,
            reason: String::new(),
            created: 0,
            until,
            lifted: None,
            lifted_by: None,
        }
    }

    fn entry(net: &str, allow: bool, until: Option<i64>) -> EntryRow {
        EntryRow {
            id: 0,
            net: n(net),
            allow,
            note: String::new(),
            created: 0,
            until,
        }
    }

    #[test]
    fn lookups() {
        let mut state = State {
            exempt: vec![n("10.0.0.0/8")],
            bans: Bans::new(vec![
                ban(1, "203.0.113.0/24", Some(100)),
                ban(2, "198.51.100.1", None),
            ]),
            entries: vec![
                entry("192.0.2.0/24", true, None),
                entry("192.0.2.128/25", false, Some(50)),
            ],
            ..State::default()
        };
        state.trust.insert(
            ip("198.51.100.9"),
            Trusted {
                user: "a".into(),
                until: 100,
            },
        );
        assert!(state.allowed(ip("10.1.2.3"), 0));
        assert!(state.allowed(ip("192.0.2.200"), 0));
        assert!(!state.allowed(ip("203.0.113.1"), 0));
        assert_eq!(state.ban_of(ip("203.0.113.77"), 50).map(|b| b.id), Some(1));
        assert_eq!(state.ban_of(ip("203.0.113.77"), 100), None);
        assert!(state.denied(ip("192.0.2.200"), 10));
        assert!(!state.denied(ip("192.0.2.200"), 60));
        assert!(state.trusted(ip("198.51.100.9"), 99).is_some());
        assert!(state.trusted(ip("198.51.100.9"), 100).is_none());

        let (blocks, allows) = state.blocks_and_allows(10);
        assert_eq!(blocks.len(), 3);
        assert_eq!(allows, vec![n("10.0.0.0/8"), n("192.0.2.0/24")]);
        state.expire(100);
        assert_eq!(state.bans.len(), 1);
        assert_eq!(state.entries.len(), 1);
        assert!(state.trust.is_empty());
    }

    #[test]
    fn lists_version_follows_content() {
        let mut state = State {
            countries: Arc::new(vec![n("198.51.100.0/24")]),
            ..State::default()
        };
        let a = state.lists();
        assert_eq!(a.version, state.lists().version);
        state.feeds.push(Feed {
            def: FeedDef {
                id: 1,
                name: "x".into(),
                url: String::new(),
                enabled: true,
                block: true,
                refresh_secs: 3_600,
                username: None,
                password: None,
            },
            loaded: Arc::new(Loaded::from_data("203.0.113.0/24\n")),
            fetched: None,
            succeeded: None,
            changed: None,
            error: None,
        });
        let b = state.lists();
        assert_ne!(a.version, b.version);
        assert_eq!(b.nets.len(), 2);
        assert_eq!(state.listed(ip("203.0.113.5")), vec!["x"]);
        state.feeds[0].def.block = false;
        assert_eq!(state.lists().version, a.version);
        assert_eq!(state.listed(ip("203.0.113.5")), vec!["x"]);
    }
}
