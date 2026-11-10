//! The nftables table barbican blocks with, and keeping its sets equal to what should be blocked.
//!
//! The table (`inet`, named by the configuration) has one chain on the prerouting hook, after connection tracking
//! (-200) and before destination NAT (-100), so it sees what arrives for the host itself, for its containers and,
//! on a router, for everything it forwards:
//!
//! 1. packets of connections the host (or a LAN client of a router) opened are accepted: replies are never blocked,
//!    so blocking a country doesn't stop the host from downloading from it;
//! 2. sources in the allow sets are accepted;
//! 3. sources in the block sets are dropped: `host4`/`host6` for single addresses and `net4`/`net6` for prefixes,
//!    whose elements carry their remaining time, so the kernel lifts a ban on time even when no agent runs;
//! 4. sources in the list sets (countries, blocklists) are dropped.
//!
//! Reconciling reads what the kernel has (`nft -j list set`) and changes only the difference, so expirations, a
//! restart or someone flushing a set are all corrected the same way.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::net::{Family, Net, collapse};

/// The version of the table's layout, in its comment. A table with another layout is replaced.
const LAYOUT: &str = "barbican layout 1";

/// Elements per `add element` command when filling a list set.
const CHUNK: usize = 2000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("running {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("nft failed: {0}")]
    Nft(String),
    #[error("unexpected output of nft: {0}")]
    Output(String),
}

/// Runs nft. A trait so that tests can record the scripts instead.
pub trait Runner {
    /// Runs a script (`nft -f -`) as one transaction.
    fn run(&self, script: &str) -> Result<(), Error>;
    /// Lists a table or one of its objects in JSON (`nft -j list <what>`), e.g. `set inet barbican host4`.
    fn list(&self, what: &str) -> Result<String, Error>;
}

/// Runs the `nft` program.
#[derive(Debug, Clone)]
pub struct NftCommand {
    pub program: String,
}

impl Default for NftCommand {
    fn default() -> Self {
        Self {
            program: "nft".to_owned(),
        }
    }
}

impl NftCommand {
    fn spawn_error(&self, source: std::io::Error) -> Error {
        Error::Spawn {
            program: self.program.clone(),
            source,
        }
    }
}

impl Runner for NftCommand {
    fn run(&self, script: &str) -> Result<(), Error> {
        let mut child = Command::new(&self.program)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| self.spawn_error(e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| self.spawn_error(e))?;
        }
        let output = child.wait_with_output().map_err(|e| self.spawn_error(e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::Nft(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    fn list(&self, what: &str) -> Result<String, Error> {
        let output = Command::new(&self.program)
            .args(["-j", "list"])
            .args(what.split_whitespace())
            .stdin(Stdio::null())
            .output()
            .map_err(|e| self.spawn_error(e))?;
        if output.status.success() {
            String::from_utf8(output.stdout).map_err(|e| Error::Output(e.to_string()))
        } else {
            Err(Error::Nft(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }
}

/// A blocked address or prefix, and when it stops being blocked (unix seconds, `None` for never).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub net: Net,
    pub until: Option<u64>,
}

/// What the table should hold.
#[derive(Debug, Clone, Default)]
pub struct Desired {
    pub allow: Vec<Net>,
    pub block: Vec<Block>,
    /// Countries and blocklists, all in one: replaced as a whole when `lists_version` changes.
    pub lists: Vec<Net>,
    /// Identifies the content of `lists`, e.g. a hash of it.
    pub lists_version: String,
}

/// What reconciling changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: usize,
    pub removed: usize,
    /// Whether the list sets were refilled.
    pub lists: bool,
}

/// Packets and bytes a rule of the chain matched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counters {
    /// Dropped for a ban.
    pub blocked: Counter,
    /// Dropped for a country or a blocklist.
    pub listed: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Set {
    Allow,
    Host,
    Net,
    List,
}

impl Set {
    const ALL: [Self; 4] = [Self::Allow, Self::Host, Self::Net, Self::List];

    fn name(self, family: Family) -> &'static str {
        match (self, family) {
            (Self::Allow, Family::V4) => "allow4",
            (Self::Allow, Family::V6) => "allow6",
            (Self::Host, Family::V4) => "host4",
            (Self::Host, Family::V6) => "host6",
            (Self::Net, Family::V4) => "net4",
            (Self::Net, Family::V6) => "net6",
            (Self::List, Family::V4) => "list4",
            (Self::List, Family::V6) => "list6",
        }
    }

    fn flags(self) -> &'static str {
        match self {
            Self::Allow | Self::List => "interval",
            Self::Host => "timeout",
            Self::Net => "interval, timeout",
        }
    }

    fn has_timeout(self) -> bool {
        matches!(self, Self::Host | Self::Net)
    }
}

const FAMILIES: [Family; 2] = [Family::V4, Family::V6];

fn type_of(family: Family) -> &'static str {
    match family {
        Family::V4 => "ipv4_addr",
        Family::V6 => "ipv6_addr",
    }
}

fn saddr(family: Family) -> &'static str {
    match family {
        Family::V4 => "ip saddr",
        Family::V6 => "ip6 saddr",
    }
}

/// An element as the kernel has it: its key in nft's syntax, and the seconds until it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    key: String,
    expires: Option<u64>,
}

/// How far the kernel's remaining time may drift from the wanted one before the element is replaced.
fn tolerance(remaining: u64) -> u64 {
    (remaining / 100).max(60)
}

/// The table and the way to change it.
pub struct Firewall<R: Runner> {
    runner: R,
    table: String,
    priority: i32,
    lists_version: Option<String>,
}

impl<R: Runner> Firewall<R> {
    pub fn new(runner: R, table: &str, priority: i32) -> Self {
        Self {
            runner,
            table: table.to_owned(),
            priority,
            lists_version: None,
        }
    }

    pub fn table(&self) -> &str {
        &self.table
    }

    fn definition(&self) -> String {
        let t = &self.table;
        let mut s = format!("table inet {t} {{\n  comment \"{LAYOUT}\"\n");
        for set in Set::ALL {
            for family in FAMILIES {
                let _ = writeln!(
                    s,
                    "  set {} {{ type {}; flags {}; }}",
                    set.name(family),
                    type_of(family),
                    set.flags()
                );
            }
        }
        let _ = writeln!(
            s,
            "  chain prerouting {{ type filter hook prerouting priority {}; policy accept; }}\n}}",
            self.priority
        );
        let _ = writeln!(s, "flush chain inet {t} prerouting");
        let mut rule = |r: &str| {
            let _ = writeln!(s, "add rule inet {t} prerouting {r}");
        };
        rule("ct direction reply accept");
        for family in FAMILIES {
            rule(&format!(
                "{} @{} accept",
                saddr(family),
                Set::Allow.name(family)
            ));
        }
        for family in FAMILIES {
            for set in [Set::Host, Set::Net] {
                rule(&format!(
                    "{} @{} counter drop comment \"blocked\"",
                    saddr(family),
                    set.name(family)
                ));
            }
        }
        for family in FAMILIES {
            rule(&format!(
                "{} @{} counter drop comment \"listed\"",
                saddr(family),
                Set::List.name(family)
            ));
        }
        s
    }

    /// Creates the table, or brings its chain up to date and keeps its sets. A table of another layout (or another
    /// priority) is replaced, and the next [`Self::reconcile`] fills it again.
    pub fn setup(&mut self) -> Result<(), Error> {
        let definition = self.definition();
        match self.runner.run(&definition) {
            Ok(()) => Ok(()),
            Err(Error::Nft(_)) => {
                self.lists_version = None;
                self.runner.run(&format!(
                    "table inet {t}\ndelete table inet {t}\n{definition}",
                    t = self.table
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Removes the table, and with it every block.
    pub fn remove(&mut self) -> Result<(), Error> {
        self.lists_version = None;
        self.runner.run(&format!(
            "table inet {t}\ndelete table inet {t}\n",
            t = self.table
        ))
    }

    fn elements(&self, set: Set, family: Family) -> Result<Vec<Element>, Error> {
        let json = self
            .runner
            .list(&format!("set inet {} {}", self.table, set.name(family)))?;
        parse_elements(&json)
    }

    /// Changes the sets to hold what `desired` says, as one transaction. `now` is the current unix time, which the
    /// remaining time of each block is counted from. When the table is missing (or broken), it is set up again
    /// first.
    pub fn reconcile(&mut self, desired: &Desired, now: u64) -> Result<Changes, Error> {
        match self.reconcile_once(desired, now) {
            Err(Error::Nft(_)) => {
                self.setup()?;
                self.reconcile_once(desired, now)
            }
            other => other,
        }
    }

    fn reconcile_once(&mut self, desired: &Desired, now: u64) -> Result<Changes, Error> {
        let wanted = wanted(desired, now);
        let mut script = String::new();
        let mut changes = Changes::default();
        let t = self.table.clone();
        for family in FAMILIES {
            for set in [Set::Allow, Set::Host, Set::Net] {
                let name = set.name(family);
                let kernel = self.elements(set, family)?;
                let want = wanted.get(&(set, family));
                let (add, remove) = diff(
                    want.map_or(&[][..], Vec::as_slice),
                    &kernel,
                    set.has_timeout(),
                );
                if !remove.is_empty() {
                    let _ = writeln!(
                        script,
                        "destroy element inet {t} {name} {{ {} }}",
                        remove.join(", ")
                    );
                }
                if !add.is_empty() {
                    let _ = writeln!(
                        script,
                        "add element inet {t} {name} {{ {} }}",
                        add.join(", ")
                    );
                }
                changes.added += add.len();
                changes.removed += remove.len();
            }
        }
        let lists_changed = self.lists_version.as_deref() != Some(desired.lists_version.as_str());
        if lists_changed {
            for family in FAMILIES {
                let name = Set::List.name(family);
                let _ = writeln!(script, "flush set inet {t} {name}");
                let nets: Vec<String> = desired
                    .lists
                    .iter()
                    .filter(|n| n.family() == family && !n.is_never_blocked())
                    .map(ToString::to_string)
                    .collect();
                for chunk in nets.chunks(CHUNK) {
                    let _ = writeln!(
                        script,
                        "add element inet {t} {name} {{ {} }}",
                        chunk.join(", ")
                    );
                }
            }
        }
        if !script.is_empty() {
            self.runner.run(&script)?;
        }
        if lists_changed {
            self.lists_version = Some(desired.lists_version.clone());
            changes.lists = true;
        }
        Ok(changes)
    }

    /// What the drop rules matched since the table was created.
    pub fn counters(&self) -> Result<Counters, Error> {
        let json = self
            .runner
            .list(&format!("chain inet {} prerouting", self.table))?;
        parse_counters(&json)
    }
}

/// An element in nft's syntax, with its remaining time when it has one.
fn element(net: &Net, remaining: Option<u64>) -> String {
    match remaining {
        Some(secs) => format!("{net} timeout {secs}s"),
        None => net.to_string(),
    }
}

/// Elements with their remaining seconds, per set.
type Wanted = HashMap<(Set, Family), Vec<(Net, Option<u64>)>>;

/// What each set should hold.
fn wanted(desired: &Desired, now: u64) -> Wanted {
    let mut out = Wanted::new();

    let allow: Vec<(Net, ())> = desired.allow.iter().map(|n| (*n, ())).collect();
    for (net, ()) in collapse(allow, |(), ()| std::cmp::Ordering::Equal) {
        out.entry((Set::Allow, net.family()))
            .or_default()
            .push((net, None));
    }

    // The longest of the blocks of the same address or prefix wins; `None` (never lifted) is the longest.
    let longest = |a: &Option<u64>, b: &Option<u64>| match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => y.cmp(x),
    };
    let mut hosts: HashMap<Net, Option<u64>> = HashMap::new();
    let mut nets = Vec::new();
    for block in &desired.block {
        if block.net.is_never_blocked() {
            continue;
        }
        let remaining = match block.until {
            Some(until) if until <= now => continue,
            Some(until) => Some(until - now),
            None => None,
        };
        if block.net.is_host() {
            let entry = hosts.entry(block.net).or_insert(remaining);
            if longest(&remaining, entry).is_lt() {
                *entry = remaining;
            }
        } else {
            nets.push((block.net, remaining));
        }
    }
    for (net, remaining) in hosts {
        out.entry((Set::Host, net.family()))
            .or_default()
            .push((net, remaining));
    }
    // Interval sets refuse overlapping elements: the widest prefix stays. One it contains, blocked for longer,
    // comes back on a later reconcile once the wider one has expired.
    for (net, remaining) in collapse(nets, longest) {
        out.entry((Set::Net, net.family()))
            .or_default()
            .push((net, remaining));
    }
    // A stable order, so the same state always gives the same script.
    for elements in out.values_mut() {
        elements.sort_by_key(|(net, _)| *net);
    }
    out
}

/// The elements to add and the keys to remove so that the kernel's set holds `want`.
fn diff(
    want: &[(Net, Option<u64>)],
    kernel: &[Element],
    timeouts: bool,
) -> (Vec<String>, Vec<String>) {
    let have: HashMap<&str, Option<u64>> =
        kernel.iter().map(|e| (e.key.as_str(), e.expires)).collect();
    let mut add = Vec::new();
    let mut remove = Vec::new();
    let mut wanted_keys = std::collections::HashSet::new();
    for (net, remaining) in want {
        let key = net.to_string();
        let remaining = if timeouts { *remaining } else { None };
        match have.get(key.as_str()) {
            None => add.push(element(net, remaining)),
            Some(expires) => {
                let same = match (remaining, expires) {
                    (None, None) => true,
                    (Some(r), Some(e)) => r.abs_diff(*e) <= tolerance(r),
                    _ => false,
                };
                if !same {
                    remove.push(key.clone());
                    add.push(element(net, remaining));
                }
            }
        }
        wanted_keys.insert(key);
    }
    for e in kernel {
        if !wanted_keys.contains(&e.key) {
            remove.push(e.key.clone());
        }
    }
    (add, remove)
}

fn nft_items(json: &str) -> Result<Vec<Value>, Error> {
    let value: Value = serde_json::from_str(json).map_err(|e| Error::Output(e.to_string()))?;
    match value.get("nftables") {
        Some(Value::Array(items)) => Ok(items.clone()),
        _ => Err(Error::Output("no nftables array".to_owned())),
    }
}

/// An element's key from its JSON value: an address, a prefix or a range.
fn element_key(value: &Value) -> Option<String> {
    match value {
        Value::String(addr) => Some(
            addr.parse::<Net>()
                .map_or_else(|_| addr.clone(), |n| n.to_string()),
        ),
        Value::Object(map) => {
            if let Some(prefix) = map.get("prefix") {
                let addr = prefix.get("addr")?.as_str()?;
                let len = prefix.get("len")?.as_u64()?;
                Some(format!("{addr}/{len}").parse::<Net>().ok()?.to_string())
            } else if let Some(Value::Array(range)) = map.get("range") {
                match range.as_slice() {
                    [Value::String(from), Value::String(to)] => Some(format!("{from}-{to}")),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_elements(json: &str) -> Result<Vec<Element>, Error> {
    let mut out = Vec::new();
    for item in nft_items(json)? {
        let Some(elems) = item
            .get("set")
            .and_then(|s| s.get("elem"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for elem in elems {
            // With a timeout an element is {"elem": {"val": ..., "timeout": s, "expires": s}}.
            let (value, expires) = match elem.get("elem") {
                Some(inner) => (
                    inner.get("val").unwrap_or(&Value::Null),
                    inner.get("expires").and_then(Value::as_u64),
                ),
                None => (elem, None),
            };
            match element_key(value) {
                Some(key) => out.push(Element { key, expires }),
                None => return Err(Error::Output(format!("unknown set element {elem}"))),
            }
        }
    }
    Ok(out)
}

fn parse_counters(json: &str) -> Result<Counters, Error> {
    let mut counters = Counters::default();
    for item in nft_items(json)? {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let comment = rule.get("comment").and_then(Value::as_str);
        let target = match comment {
            Some("blocked") => &mut counters.blocked,
            Some("listed") => &mut counters.listed,
            _ => continue,
        };
        for expr in rule
            .get("expr")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(counter) = expr.get("counter") {
                target.packets += counter.get("packets").and_then(Value::as_u64).unwrap_or(0);
                target.bytes += counter.get("bytes").and_then(Value::as_u64).unwrap_or(0);
            }
        }
    }
    Ok(counters)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records scripts and answers listings from a map of what to list to JSON.
    #[derive(Default)]
    struct Fake {
        scripts: RefCell<Vec<String>>,
        sets: RefCell<HashMap<String, String>>,
        fail_next: RefCell<bool>,
    }

    impl Runner for &Fake {
        fn run(&self, script: &str) -> Result<(), Error> {
            if self.fail_next.replace(false) {
                return Err(Error::Nft("File exists".to_owned()));
            }
            self.scripts.borrow_mut().push(script.to_owned());
            Ok(())
        }

        fn list(&self, what: &str) -> Result<String, Error> {
            Ok(self.sets.borrow().get(what).cloned().unwrap_or_else(|| {
                r#"{"nftables": [{"metainfo": {}}, {"set": {"name": "x"}}]}"#.to_owned()
            }))
        }
    }

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    #[test]
    fn setup_defines_the_table() {
        let fake = Fake::default();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        fw.setup().unwrap();
        let script = fake.scripts.borrow()[0].clone();
        assert!(script.contains("set host4 { type ipv4_addr; flags timeout; }"));
        assert!(script.contains("set net6 { type ipv6_addr; flags interval, timeout; }"));
        assert!(script.contains("type filter hook prerouting priority -190; policy accept;"));
        let rules: Vec<&str> = script
            .lines()
            .filter(|l| l.starts_with("add rule"))
            .collect();
        assert_eq!(
            rules[0],
            "add rule inet barbican prerouting ct direction reply accept"
        );
        assert_eq!(
            rules[1],
            "add rule inet barbican prerouting ip saddr @allow4 accept"
        );
        assert!(rules[3].contains("ip saddr @host4 counter drop"));
        assert!(
            rules
                .last()
                .unwrap()
                .contains("ip6 saddr @list6 counter drop comment \"listed\"")
        );
    }

    #[test]
    fn setup_replaces_a_conflicting_table() {
        let fake = Fake::default();
        *fake.fail_next.borrow_mut() = true;
        let mut fw = Firewall::new(&fake, "barbican", -190);
        fw.setup().unwrap();
        let script = fake.scripts.borrow()[0].clone();
        assert!(
            script.starts_with(
                "table inet barbican\ndelete table inet barbican\ntable inet barbican {"
            )
        );
    }

    #[test]
    fn reconcile_adds_what_is_missing() {
        let fake = Fake::default();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let desired = Desired {
            allow: vec![net("192.0.2.0/24"), net("192.0.2.9")],
            block: vec![
                Block {
                    net: net("198.51.100.7"),
                    until: Some(1_000 + 3_600),
                },
                Block {
                    net: net("198.51.100.7"),
                    until: Some(1_000 + 60),
                },
                Block {
                    net: net("2001:db8::1"),
                    until: None,
                },
                Block {
                    net: net("203.0.113.0/24"),
                    until: Some(1_000 + 600),
                },
                Block {
                    net: net("203.0.113.5"),
                    until: Some(500),
                },
                Block {
                    net: net("127.0.0.1"),
                    until: None,
                },
            ],
            lists: vec![
                net("198.51.100.0/25"),
                net("2001:db8:1::/48"),
                net("0.0.0.0/0"),
            ],
            lists_version: "v1".to_owned(),
        };
        let changes = fw.reconcile(&desired, 1_000).unwrap();
        let script = fake.scripts.borrow()[0].clone();
        assert!(
            script.contains("add element inet barbican allow4 { 192.0.2.0/24 }\n"),
            "{script}"
        );
        assert!(
            script.contains("add element inet barbican host4 { 198.51.100.7 timeout 3600s }\n"),
            "{script}"
        );
        assert!(
            script.contains("add element inet barbican host6 { 2001:db8::1 }\n"),
            "{script}"
        );
        assert!(
            script.contains("add element inet barbican net4 { 203.0.113.0/24 timeout 600s }\n"),
            "{script}"
        );
        assert!(!script.contains("203.0.113.5"), "expired: {script}");
        assert!(!script.contains("127.0.0.1"), "never blocked: {script}");
        assert!(script.contains(
            "flush set inet barbican list4\nadd element inet barbican list4 { 198.51.100.0/25 }\n"
        ));
        assert!(script.contains("add element inet barbican list6 { 2001:db8:1::/48 }\n"));
        assert!(!script.contains("0.0.0.0/0"));
        assert_eq!(
            changes,
            Changes {
                added: 4,
                removed: 0,
                lists: true
            }
        );

        // The same lists again aren't rewritten.
        let changes = fw.reconcile(&desired, 1_000).unwrap();
        assert!(!changes.lists);
        assert!(!fake.scripts.borrow()[1].contains("list4"));
    }

    #[test]
    fn reconcile_removes_and_renews() {
        let fake = Fake::default();
        fake.sets.borrow_mut().insert(
            "set inet barbican host4".to_owned(),
            r#"{"nftables": [{"metainfo": {"version": "1.1.1"}}, {"set": {"family": "inet", "name": "host4",
                "table": "barbican", "type": "ipv4_addr", "flags": ["timeout"], "elem": [
                {"elem": {"val": "198.51.100.1", "timeout": 3600, "expires": 3590}},
                {"elem": {"val": "198.51.100.2", "timeout": 3600, "expires": 100}},
                {"elem": {"val": "198.51.100.3", "timeout": 3600, "expires": 3000}},
                "198.51.100.4"
            ]}}]}"#
                .to_owned(),
        );
        fake.sets.borrow_mut().insert(
            "set inet barbican net4".to_owned(),
            r#"{"nftables": [{"set": {"name": "net4", "elem": [
                {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "timeout": 60, "expires": 30}},
                {"range": ["192.0.2.10", "192.0.2.20"]}
            ]}}]}"#
                .to_owned(),
        );
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let desired = Desired {
            block: vec![
                // Still right.
                Block {
                    net: net("198.51.100.1"),
                    until: Some(10_000 + 3_600),
                },
                // Was renewed: the kernel's time is far too short.
                Block {
                    net: net("198.51.100.2"),
                    until: Some(10_000 + 3_600),
                },
                // Made permanent.
                Block {
                    net: net("198.51.100.3"),
                    until: None,
                },
                Block {
                    net: net("203.0.113.0/24"),
                    until: Some(10_000 + 40),
                },
            ],
            lists_version: String::new(),
            ..Desired::default()
        };
        let changes = fw.reconcile(&desired, 10_000).unwrap();
        let script = fake.scripts.borrow()[0].clone();
        assert!(
            script.contains(
                "destroy element inet barbican host4 { 198.51.100.2, 198.51.100.3, 198.51.100.4 }\n"
            ),
            "{script}"
        );
        assert!(
            script.contains(
                "add element inet barbican host4 { 198.51.100.2 timeout 3600s, 198.51.100.3 }\n"
            ),
            "{script}"
        );
        assert!(
            script.contains("destroy element inet barbican net4 { 192.0.2.10-192.0.2.20 }\n"),
            "{script}"
        );
        assert!(!script.contains("203.0.113.0/24"), "{script}");
        assert_eq!(changes.added, 2);
        assert_eq!(changes.removed, 4);
    }

    #[test]
    fn wider_prefix_wins_in_interval_sets() {
        let desired = Desired {
            block: vec![
                Block {
                    net: net("203.0.113.0/26"),
                    until: Some(10_000),
                },
                Block {
                    net: net("203.0.113.0/24"),
                    until: Some(2_000),
                },
                Block {
                    net: net("203.0.113.128/25"),
                    until: None,
                },
            ],
            ..Desired::default()
        };
        let wanted = wanted(&desired, 1_000);
        assert_eq!(
            wanted[&(Set::Net, Family::V4)],
            vec![(net("203.0.113.0/24"), Some(1_000))]
        );
    }

    #[test]
    fn counters() {
        let json = r#"{"nftables": [{"metainfo": {}}, {"chain": {"name": "prerouting"}},
            {"rule": {"expr": [{"match": {}}, {"accept": null}]}},
            {"rule": {"comment": "blocked", "expr": [{"match": {}}, {"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}},
            {"rule": {"comment": "blocked", "expr": [{"counter": {"packets": 2, "bytes": 100}}]}},
            {"rule": {"comment": "listed", "expr": [{"counter": {"packets": 7, "bytes": 420}}]}}]}"#;
        let counters = parse_counters(json).unwrap();
        assert_eq!(
            counters.blocked,
            Counter {
                packets: 5,
                bytes: 280
            }
        );
        assert_eq!(
            counters.listed,
            Counter {
                packets: 7,
                bytes: 420
            }
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_elements("not json").is_err());
        assert!(parse_elements(r#"{"nftables": [{"set": {"elem": [{"weird": 1}]}}]}"#).is_err());
    }
}
