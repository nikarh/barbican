//! The edge protocol: how an edge agent (on a router) follows what an agent blocks.
//!
//! The edge agent polls `GET /api/edge/v1/changes?epoch=<e>&since=<seq>&wait=<secs>` with a bearer token. The agent
//! answers with [`Changes`]: everything since `seq`, or, when it can't (another epoch, which means the agent
//! restarted; or changes too old to still be in its journal), the whole state with `full` set. With nothing new it
//! holds the request for up to `wait` seconds (long polling). The combined list of countries and blocklists is
//! fetched from `GET /api/edge/v1/list` only when its `version` changed: a text body with one prefix per line.
//!
//! Times are unix seconds of the agent's clock; [`Changes::now`] says what that was when it answered, so an edge
//! with a wrong clock (a router without a battery-backed clock, before NTP) still counts the remaining time right.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::net::Net;
use crate::nft::Block;

/// Bumped on incompatible changes. An agent answers older edge agents in the protocol they ask for, or refuses.
pub const PROTOCOL_VERSION: u32 = 1;
pub const CHANGES_PATH: &str = "/api/edge/v1/changes";
pub const LIST_PATH: &str = "/api/edge/v1/list";
/// The longest an agent holds a poll.
pub const MAX_WAIT_SECS: u64 = 120;

/// A block as sent to edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeBlock {
    pub net: Net,
    /// Unix seconds of the agent's clock; `None` for never.
    pub until: Option<u64>,
}

/// The combined list's identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRef {
    pub version: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub protocol: u32,
    /// Changes when the agent restarts; ask with it next time.
    pub epoch: String,
    /// The state's sequence number; ask for what comes after it next time.
    pub seq: u64,
    /// The agent's clock when it answered.
    pub now: u64,
    /// `block` and `allow` are the whole state: forget what came before from this agent.
    pub full: bool,
    #[serde(default)]
    pub block: Vec<EdgeBlock>,
    #[serde(default)]
    pub unblock: Vec<Net>,
    #[serde(default)]
    pub allow: Vec<Net>,
    #[serde(default)]
    pub unallow: Vec<Net>,
    pub list: ListRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Block(EdgeBlock),
    Unblock(Net),
    Allow(Net),
    Unallow(Net),
}

/// The agent's side: the state edges should mirror, and the recent changes to it.
#[derive(Debug)]
pub struct Journal {
    epoch: String,
    seq: u64,
    blocks: BTreeMap<Net, Option<u64>>,
    allows: BTreeSet<Net>,
    list: ListRef,
    /// `(seq, op)`: the op that made the state `seq`.
    log: VecDeque<(u64, Op)>,
    capacity: usize,
}

impl Journal {
    /// `epoch` must differ from the agent's previous runs; `capacity` is how many changes are kept for edges that
    /// fell behind (older ones get the whole state).
    #[must_use]
    pub fn new(epoch: String, capacity: usize) -> Self {
        Self {
            epoch,
            seq: 0,
            blocks: BTreeMap::new(),
            allows: BTreeSet::new(),
            list: ListRef::default(),
            log: VecDeque::new(),
            capacity,
        }
    }

    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    fn push(&mut self, op: Op) {
        self.seq += 1;
        self.log.push_back((self.seq, op));
        while self.log.len() > self.capacity {
            self.log.pop_front();
        }
    }

    /// Replaces the state, recording the difference. Returns whether anything changed.
    pub fn set(&mut self, blocks: &[Block], allows: &[Net], list: ListRef) -> bool {
        let before = self.seq;
        let mut wanted: BTreeMap<Net, Option<u64>> = BTreeMap::new();
        for b in blocks {
            // Of several blocks of one address the longest counts, as in the firewall.
            let entry = wanted.entry(b.net).or_insert(b.until);
            *entry = match (*entry, b.until) {
                (None, _) | (_, None) => None,
                (Some(x), Some(y)) => Some(x.max(y)),
            };
        }
        let gone: Vec<Net> = self
            .blocks
            .keys()
            .filter(|n| !wanted.contains_key(n))
            .copied()
            .collect();
        for net in gone {
            self.blocks.remove(&net);
            self.push(Op::Unblock(net));
        }
        for (net, until) in wanted {
            if self.blocks.get(&net) != Some(&until) {
                self.blocks.insert(net, until);
                self.push(Op::Block(EdgeBlock { net, until }));
            }
        }
        let wanted: BTreeSet<Net> = allows.iter().copied().collect();
        let gone: Vec<Net> = self.allows.difference(&wanted).copied().collect();
        for net in gone {
            self.allows.remove(&net);
            self.push(Op::Unallow(net));
        }
        for net in wanted {
            if self.allows.insert(net) {
                self.push(Op::Allow(net));
            }
        }
        if self.list != list {
            self.list = list;
            // Not a change to mirror element by element, but polls waiting for news must see it.
            self.seq += 1;
        }
        self.seq != before
    }

    /// What an edge that has `epoch` at `since` needs.
    #[must_use]
    pub fn since(&self, epoch: &str, since: u64, now: u64) -> Changes {
        let mut changes = Changes {
            protocol: PROTOCOL_VERSION,
            epoch: self.epoch.clone(),
            seq: self.seq,
            now,
            full: false,
            block: Vec::new(),
            unblock: Vec::new(),
            allow: Vec::new(),
            unallow: Vec::new(),
            list: self.list.clone(),
        };
        // The log must reach back to the change right after `since`.
        let covered = self
            .log
            .front()
            .map_or(since == self.seq, |(first, _)| *first <= since + 1);
        if epoch != self.epoch || since > self.seq || !covered {
            changes.full = true;
            changes.block = self
                .blocks
                .iter()
                .map(|(net, until)| EdgeBlock {
                    net: *net,
                    until: *until,
                })
                .collect();
            changes.allow = self.allows.iter().copied().collect();
            return changes;
        }
        // Only the last op of each address counts.
        let mut last: HashMap<Net, &Op> = HashMap::new();
        let mut last_allow: HashMap<Net, &Op> = HashMap::new();
        for (_, op) in self.log.iter().filter(|(seq, _)| *seq > since) {
            match op {
                Op::Block(b) => {
                    last.insert(b.net, op);
                }
                Op::Unblock(net) => {
                    last.insert(*net, op);
                }
                Op::Allow(net) | Op::Unallow(net) => {
                    last_allow.insert(*net, op);
                }
            }
        }
        for op in last.values().chain(last_allow.values()) {
            match op {
                Op::Block(b) => changes.block.push(*b),
                Op::Unblock(net) => changes.unblock.push(*net),
                Op::Allow(net) => changes.allow.push(*net),
                Op::Unallow(net) => changes.unallow.push(*net),
            }
        }
        changes.block.sort_by_key(|b| b.net);
        changes.unblock.sort();
        changes.allow.sort();
        changes.unallow.sort();
        changes
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApplyError {
    #[error("the agent speaks protocol {0}, this edge agent {PROTOCOL_VERSION}")]
    Protocol(u32),
    #[error("changes of another epoch, or not following the last ones")]
    OutOfOrder,
}

/// The edge's side: its copy of one agent's state. Times are kept in the edge's own clock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mirror {
    pub epoch: String,
    pub seq: u64,
    /// Unix seconds of the edge's clock; `None` for never.
    pub blocks: BTreeMap<Net, Option<u64>>,
    pub allows: BTreeSet<Net>,
    pub list: ListRef,
}

impl Mirror {
    /// Applies changes received at `local_now` (the edge's clock).
    pub fn apply(&mut self, changes: &Changes, local_now: u64) -> Result<(), ApplyError> {
        if changes.protocol != PROTOCOL_VERSION {
            return Err(ApplyError::Protocol(changes.protocol));
        }
        let local = |until: Option<u64>| {
            until.map(|u| u.saturating_sub(changes.now).saturating_add(local_now))
        };
        if changes.full {
            self.blocks = changes
                .block
                .iter()
                .map(|b| (b.net, local(b.until)))
                .collect();
            self.allows = changes.allow.iter().copied().collect();
        } else {
            if changes.epoch != self.epoch || changes.seq < self.seq {
                return Err(ApplyError::OutOfOrder);
            }
            for net in &changes.unblock {
                self.blocks.remove(net);
            }
            for b in &changes.block {
                self.blocks.insert(b.net, local(b.until));
            }
            for net in &changes.unallow {
                self.allows.remove(net);
            }
            self.allows.extend(changes.allow.iter().copied());
        }
        self.epoch.clone_from(&changes.epoch);
        self.seq = changes.seq;
        self.list = changes.list.clone();
        Ok(())
    }

    /// Drops blocks that ran out by `local_now`.
    pub fn expire(&mut self, local_now: u64) {
        self.blocks
            .retain(|_, until| until.is_none_or(|u| u > local_now));
    }
}

/// The union of several agents' states, as the firewall should have it.
#[must_use]
pub fn merge<'a>(mirrors: impl IntoIterator<Item = &'a Mirror>) -> (Vec<Block>, Vec<Net>) {
    let mut blocks = Vec::new();
    let mut allows = HashSet::new();
    for m in mirrors {
        blocks.extend(m.blocks.iter().map(|(net, until)| Block {
            net: *net,
            until: *until,
        }));
        allows.extend(m.allows.iter().copied());
    }
    let mut allows: Vec<Net> = allows.into_iter().collect();
    allows.sort();
    (blocks, allows)
}

/// The text body of the list endpoint: a header with the version, then one prefix per line.
#[must_use]
pub fn render_list(version: &str, nets: &[Net]) -> String {
    let mut out = String::with_capacity(nets.len() * 18 + 32);
    out.push_str("# barbican list ");
    out.push_str(version);
    out.push('\n');
    for net in nets {
        out.push_str(&net.to_string());
        out.push('\n');
    }
    out
}

/// Parses [`render_list`]'s output: the version and the prefixes.
pub fn parse_list(body: &str) -> Result<(String, Vec<Net>), crate::net::ParseError> {
    let mut lines = body.lines();
    let version = lines
        .next()
        .and_then(|l| l.strip_prefix("# barbican list "))
        .ok_or_else(|| crate::net::ParseError("missing list header".to_owned()))?
        .to_owned();
    let nets = lines
        .filter(|l| !l.trim().is_empty())
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    Ok((version, nets))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    fn block(s: &str, until: Option<u64>) -> Block {
        Block { net: net(s), until }
    }

    #[test]
    fn mirror_follows_the_journal() {
        let mut journal = Journal::new("e1".to_owned(), 100);
        let mut mirror = Mirror::default();
        let list = ListRef {
            version: "v1".to_owned(),
            count: 3,
        };
        assert!(journal.set(
            &[
                block("192.0.2.1", Some(2_000)),
                block("198.51.100.0/24", None)
            ],
            &[net("10.0.0.0/8")],
            list.clone()
        ));
        let first = journal.since("", 0, 1_000);
        assert!(first.full);
        // The edge's clock is 50 seconds ahead.
        mirror.apply(&first, 1_050).unwrap();
        assert_eq!(mirror.blocks[&net("192.0.2.1")], Some(2_050));
        assert_eq!(mirror.list, list);

        assert!(!journal.set(
            &[
                block("192.0.2.1", Some(2_000)),
                block("198.51.100.0/24", None)
            ],
            &[net("10.0.0.0/8")],
            list.clone()
        ));
        assert!(journal.set(
            &[
                block("192.0.2.1", Some(5_000)),
                block("203.0.113.9", Some(3_000))
            ],
            &[],
            list.clone()
        ));
        let changes = journal.since("e1", mirror.seq, 1_100);
        assert!(!changes.full);
        assert_eq!(changes.unblock, vec![net("198.51.100.0/24")]);
        assert_eq!(changes.unallow, vec![net("10.0.0.0/8")]);
        assert_eq!(changes.block.len(), 2);
        mirror.apply(&changes, 1_100).unwrap();
        assert_eq!(mirror.blocks.len(), 2);
        assert_eq!(mirror.blocks[&net("192.0.2.1")], Some(5_000));
        assert!(mirror.allows.is_empty());

        // Nothing new: an empty answer at the same seq.
        let changes = journal.since("e1", mirror.seq, 1_200);
        assert!(!changes.full && changes.block.is_empty() && changes.unblock.is_empty());
        mirror.apply(&changes, 1_200).unwrap();

        mirror.expire(3_500);
        assert_eq!(mirror.blocks.len(), 1);
    }

    #[test]
    fn full_state_when_behind_or_restarted() {
        let mut journal = Journal::new("e2".to_owned(), 2);
        for i in 1..=5u64 {
            journal.set(
                &[block(&format!("192.0.2.{i}"), None)],
                &[],
                ListRef::default(),
            );
        }
        // Each set replaced the previous block: an unblock and a block, so the log of 2 holds the last set only.
        assert!(journal.since("e2", 6, 0).full);
        assert!(!journal.since("e2", journal.seq() - 2, 0).full);
        assert!(journal.since("e1", journal.seq(), 0).full);
        assert!(journal.since("e2", journal.seq() + 5, 0).full);
        let full = journal.since("other", 0, 0);
        assert_eq!(
            full.block,
            vec![EdgeBlock {
                net: net("192.0.2.5"),
                until: None
            }]
        );
    }

    #[test]
    fn mirror_refuses_out_of_order_changes() {
        let mut journal = Journal::new("e".to_owned(), 10);
        journal.set(&[block("192.0.2.1", None)], &[], ListRef::default());
        let mut mirror = Mirror::default();
        mirror.apply(&journal.since("", 0, 0), 0).unwrap();
        let mut stale = journal.since("e", mirror.seq, 0);
        stale.epoch = "x".to_owned();
        assert_eq!(mirror.apply(&stale, 0), Err(ApplyError::OutOfOrder));
        let mut newer = journal.since("e", mirror.seq, 0);
        newer.protocol = 99;
        assert_eq!(mirror.apply(&newer, 0), Err(ApplyError::Protocol(99)));
    }

    #[test]
    fn list_change_wakes_pollers() {
        let mut journal = Journal::new("e".to_owned(), 10);
        let seq = journal.seq();
        assert!(journal.set(
            &[],
            &[],
            ListRef {
                version: "v2".to_owned(),
                count: 1
            }
        ));
        assert!(journal.seq() > seq);
        assert_eq!(journal.since("e", seq, 0).list.version, "v2");
    }

    #[test]
    fn merge_unions_agents() {
        let mut a = Mirror::default();
        a.blocks.insert(net("192.0.2.1"), Some(10));
        a.allows.insert(net("10.0.0.0/8"));
        let mut b = Mirror::default();
        b.blocks.insert(net("192.0.2.1"), None);
        b.allows.insert(net("10.0.0.0/8"));
        let (blocks, allows) = merge([&a, &b]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(allows, vec![net("10.0.0.0/8")]);
    }

    #[test]
    fn list_round_trip() {
        let nets = vec![net("198.51.100.0/24"), net("2001:db8::/32")];
        let body = render_list("abc", &nets);
        assert_eq!(parse_list(&body).unwrap(), ("abc".to_owned(), nets));
        assert!(parse_list("198.51.100.0/24\n").is_err());
        assert!(parse_list("# barbican list x\nnope\n").is_err());
    }

    #[test]
    fn changes_json_shape() {
        let mut journal = Journal::new("e".to_owned(), 10);
        journal.set(&[block("192.0.2.1", Some(99))], &[], ListRef::default());
        let json = serde_json::to_value(journal.since("", 0, 5)).unwrap();
        assert_eq!(
            json["block"][0],
            serde_json::json!({"net": "192.0.2.1", "until": 99})
        );
        assert_eq!(json["full"], true);
        let back: Changes = serde_json::from_value(json).unwrap();
        assert_eq!(back.seq, journal.seq());
    }
}
