//! iptables and ipset, for routers whose kernel has no nftables (Asuswrt-Merlin's 2.6 and 4.1 kernels, older
//! OpenWrt).
//!
//! Sets (`<prefix>-host4` and so on) hold what is blocked; a chain (`BARBICAN`), jumped to first thing in the mangle
//! table's PREROUTING (before NAT), does what the nftables table does: packets of connections opened from inside
//! return, allowed sources return, blocked and listed sources are dropped.
//!
//! The kernel times elements out, as with nftables, but at most after 2147483 seconds (24.8 days): longer bans get
//! that, and reconciling renews them while the agent runs. List sets are filled in a new set and swapped in, so there
//! is no moment without them.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use barbican_common::net::{Family, Net};
use barbican_common::nft::{Counter, Counters, Desired};

use crate::backend::{Backend, name};
use crate::daemon::Config;

/// The longest timeout an ipset element takes, in seconds.
pub const MAX_TIMEOUT: u64 = 2_147_483;
const MAX_ELEMENTS: u32 = 1_048_576;

/// Runs a program: a trait so that tests can record the commands instead.
pub trait Exec: Send {
    /// Runs `program` with `args` and `stdin`; its output, or what it said on stderr.
    fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<String, String>;
}

pub struct System;

impl Exec for System {
    fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("running {program}: {e}"))?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes())
                .map_err(|e| format!("{program}: {e}"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| format!("{program}: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(format!(
                "{program} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Allow,
    Host,
    Net,
    List,
}

impl Kind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Host => "host",
            Self::Net => "net",
            Self::List => "list",
        }
    }

    fn create(self, family: Family) -> String {
        let family = match family {
            Family::V4 => "inet",
            Family::V6 => "inet6",
        };
        match self {
            Self::Allow => format!("hash:net family {family} maxelem 65536"),
            Self::Host => format!("hash:ip family {family} timeout 0 maxelem {MAX_ELEMENTS}"),
            Self::Net => format!("hash:net family {family} timeout 0 maxelem {MAX_ELEMENTS}"),
            Self::List => format!("hash:net family {family} maxelem {MAX_ELEMENTS}"),
        }
    }
}

const KINDS: [Kind; 4] = [Kind::Allow, Kind::Host, Kind::Net, Kind::List];

pub struct Ipset<E: Exec> {
    exec: E,
    ipset: String,
    iptables: String,
    /// `None`: IPv6 isn't handled (most such routers have it off).
    ip6tables: Option<String>,
    prefix: String,
    chain: String,
    lists_version: Option<String>,
}

impl<E: Exec> Ipset<E> {
    pub fn new(
        exec: E,
        prefix: &str,
        chain: &str,
        ipset: &str,
        iptables: &str,
        ip6tables: Option<&str>,
    ) -> Self {
        Self {
            exec,
            ipset: ipset.to_owned(),
            iptables: iptables.to_owned(),
            ip6tables: ip6tables.map(str::to_owned),
            prefix: prefix.to_owned(),
            chain: chain.to_owned(),
            lists_version: None,
        }
    }

    fn families(&self) -> Vec<Family> {
        if self.ip6tables.is_some() {
            vec![Family::V4, Family::V6]
        } else {
            vec![Family::V4]
        }
    }

    fn set(&self, kind: Kind, family: Family) -> String {
        let v = match family {
            Family::V4 => "4",
            Family::V6 => "6",
        };
        format!("{}-{}{v}", self.prefix, kind.suffix())
    }

    fn tables(&self, family: Family) -> Option<&str> {
        match family {
            Family::V4 => Some(&self.iptables),
            Family::V6 => self.ip6tables.as_deref(),
        }
    }

    fn iptables(&self, family: Family, args: &[&str]) -> Result<String, String> {
        let program = self.tables(family).ok_or("no ip6tables")?;
        let mut all = vec!["-t", "mangle"];
        all.extend_from_slice(args);
        // Another program changing the rules holds the xtables lock; old iptables (1.4) has no -w to wait for it.
        let mut tries = 0;
        loop {
            match self.exec.run(program, &all, None) {
                Err(e)
                    if e.contains("xtables lock")
                        || e.contains("Resource temporarily unavailable") =>
                {
                    tries += 1;
                    if tries >= 25 {
                        return Err(e);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                other => return other,
            }
        }
    }

    fn hooked(&self, family: Family) -> bool {
        self.iptables(family, &["-C", "PREROUTING", "-j", &self.chain])
            .is_ok()
    }

    fn create_sets(&self) -> Result<(), String> {
        let mut script = String::new();
        for family in self.families() {
            for kind in KINDS {
                let _ = writeln!(
                    script,
                    "create {} {}",
                    self.set(kind, family),
                    kind.create(family)
                );
            }
        }
        self.exec
            .run(&self.ipset, &["restore", "-exist"], Some(&script))
            .map(|_| ())
    }

    fn unhook(&self, family: Family) {
        while self.hooked(family) {
            if self
                .iptables(family, &["-D", "PREROUTING", "-j", &self.chain])
                .is_err()
            {
                break;
            }
        }
        let _ = self.iptables(family, &["-F", &self.chain]);
        let _ = self.iptables(family, &["-X", &self.chain]);
    }

    fn destroy_sets(&self) {
        for family in self.families() {
            for kind in KINDS {
                let _ = self
                    .exec
                    .run(&self.ipset, &["destroy", &self.set(kind, family)], None);
            }
        }
    }

    /// Elements of a set with their remaining seconds, from `ipset save`.
    fn elements(&self, set: &str) -> Result<HashMap<String, Option<u64>>, String> {
        let out = self.exec.run(&self.ipset, &["save", set], None)?;
        Ok(parse_save(&out, set))
    }
}

/// `add <set> <element>[ timeout <n>]` lines of `ipset save`.
fn parse_save(out: &str, set: &str) -> HashMap<String, Option<u64>> {
    let mut elements = HashMap::new();
    for line in out.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("add") || words.next() != Some(set) {
            continue;
        }
        let Some(element) = words.next() else {
            continue;
        };
        let key = element
            .parse::<Net>()
            .map_or_else(|_| element.to_owned(), |n| n.to_string());
        let mut timeout = None;
        while let Some(word) = words.next() {
            if word == "timeout" {
                timeout = words.next().and_then(|t| t.parse().ok()).filter(|t| *t > 0);
            }
        }
        elements.insert(key, timeout);
    }
    elements
}

/// How far the kernel's remaining time may drift from the wanted one before the element is renewed.
fn tolerance(remaining: u64) -> u64 {
    (remaining / 100).max(60)
}

/// Adds and removes so that a set holds `want` (elements with their remaining seconds).
fn diff(
    script: &mut String,
    set: &str,
    want: &BTreeMap<Net, Option<u64>>,
    have: &HashMap<String, Option<u64>>,
) -> usize {
    let mut changes = 0;
    let mut wanted = std::collections::HashSet::new();
    for (net, remaining) in want {
        let key = net.to_string();
        let same = match (remaining, have.get(&key)) {
            (None, Some(None)) => true,
            (Some(r), Some(Some(e))) => r.abs_diff(*e) <= tolerance(*r),
            _ => false,
        };
        if !same {
            // With -exist, adding what is there replaces its timeout.
            match remaining {
                Some(r) => {
                    let _ = writeln!(script, "add {set} {key} timeout {r}");
                }
                None => {
                    let _ = writeln!(script, "add {set} {key}");
                }
            }
            changes += 1;
        }
        wanted.insert(key);
    }
    for key in have.keys() {
        if !wanted.contains(key) {
            let _ = writeln!(script, "del {set} {key}");
            changes += 1;
        }
    }
    changes
}

impl<E: Exec> Backend for Ipset<E> {
    fn describe(&self) -> String {
        format!(
            "iptables chain mangle {} and ipsets {}-*",
            self.chain, self.prefix
        )
    }

    fn setup(&mut self) -> Result<(), String> {
        self.lists_version = None;
        if self.create_sets().is_err() {
            // Sets of another type (an older version of this agent): replaced.
            for family in self.families() {
                self.unhook(family);
            }
            self.destroy_sets();
            self.create_sets()?;
        }
        for family in self.families() {
            let chain = self.chain.clone();
            let _ = self.iptables(family, &["-N", &chain]);
            self.iptables(family, &["-F", &chain])?;
            let mut rules: Vec<Vec<String>> = vec![
                vec!["-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ];
            let set_rule = |kind: Kind, target: &str| {
                vec![
                    "-m".to_owned(),
                    "set".to_owned(),
                    "--match-set".to_owned(),
                    self.set(kind, family),
                    "src".to_owned(),
                    "-j".to_owned(),
                    target.to_owned(),
                ]
            };
            rules.push(set_rule(Kind::Allow, "RETURN"));
            rules.push(set_rule(Kind::Host, "DROP"));
            rules.push(set_rule(Kind::Net, "DROP"));
            rules.push(set_rule(Kind::List, "DROP"));
            for rule in rules {
                let mut args = vec!["-A", chain.as_str()];
                args.extend(rule.iter().map(String::as_str));
                self.iptables(family, &args)?;
            }
            if !self.hooked(family) {
                self.iptables(family, &["-I", "PREROUTING", "1", "-j", &chain])?;
            }
        }
        Ok(())
    }

    fn reconcile(&mut self, desired: &Desired, now: u64) -> Result<(), String> {
        // A firewall restart (the router's own) drops the jump, or everything.
        if self.families().into_iter().any(|f| !self.hooked(f)) {
            self.setup()?;
        }
        let mut hosts: BTreeMap<Net, Option<u64>> = BTreeMap::new();
        let mut nets: BTreeMap<Net, Option<u64>> = BTreeMap::new();
        for block in &desired.block {
            if block.net.is_never_blocked() {
                continue;
            }
            let remaining = match block.until {
                Some(until) if until <= now => continue,
                Some(until) => Some((until - now).min(MAX_TIMEOUT)),
                None => None,
            };
            let target = if block.net.is_host() {
                &mut hosts
            } else {
                &mut nets
            };
            let entry = target.entry(block.net).or_insert(remaining);
            *entry = match (*entry, remaining) {
                (None, _) | (_, None) => None,
                (Some(a), Some(b)) => Some(a.max(b)),
            };
        }
        let allows: BTreeMap<Net, Option<u64>> = desired.allow.iter().map(|n| (*n, None)).collect();
        let mut script = String::new();
        for family in self.families() {
            let of = |m: &BTreeMap<Net, Option<u64>>| -> BTreeMap<Net, Option<u64>> {
                m.iter()
                    .filter(|(n, _)| n.family() == family)
                    .map(|(n, r)| (*n, *r))
                    .collect()
            };
            for (kind, want) in [
                (Kind::Allow, of(&allows)),
                (Kind::Host, of(&hosts)),
                (Kind::Net, of(&nets)),
            ] {
                let set = self.set(kind, family);
                let have = self.elements(&set)?;
                diff(&mut script, &set, &want, &have);
            }
        }
        if self.lists_version.as_deref() != Some(desired.lists_version.as_str()) {
            for family in self.families() {
                let set = self.set(Kind::List, family);
                let fresh = format!("{set}-new");
                let _ = writeln!(script, "create {fresh} {}", Kind::List.create(family));
                let _ = writeln!(script, "flush {fresh}");
                for net in desired
                    .lists
                    .iter()
                    .filter(|n| n.family() == family && !n.is_never_blocked())
                {
                    let _ = writeln!(script, "add {fresh} {net}");
                }
                let _ = writeln!(script, "swap {fresh} {set}");
                let _ = writeln!(script, "destroy {fresh}");
            }
        }
        if !script.is_empty() {
            self.exec
                .run(&self.ipset, &["restore", "-exist"], Some(&script))?;
        }
        self.lists_version = Some(desired.lists_version.clone());
        Ok(())
    }

    fn counters(&mut self) -> Option<Counters> {
        let mut counters = Counters::default();
        for family in self.families() {
            let out = self
                .iptables(family, &["-L", &self.chain, "-v", "-x", "-n"])
                .ok()?;
            let host = self.set(Kind::Host, family);
            let net = self.set(Kind::Net, family);
            let list = self.set(Kind::List, family);
            for line in out.lines() {
                let mut words = line.split_whitespace();
                let (Some(packets), Some(bytes)) = (words.next(), words.next()) else {
                    continue;
                };
                let (Ok(packets), Ok(bytes)) = (packets.parse::<u64>(), bytes.parse::<u64>())
                else {
                    continue;
                };
                let target =
                    if line.contains(&format!(" {host} ")) || line.contains(&format!(" {net} ")) {
                        &mut counters.blocked
                    } else if line.contains(&format!(" {list} ")) {
                        &mut counters.listed
                    } else {
                        continue;
                    };
                *target = Counter {
                    packets: target.packets + packets,
                    bytes: target.bytes + bytes,
                };
            }
        }
        Some(counters)
    }

    fn remove(&mut self) -> Result<(), String> {
        for family in self.families() {
            self.unhook(family);
        }
        self.destroy_sets();
        self.lists_version = None;
        Ok(())
    }
}

/// The ipset backend, from the `prefix`, `chain`, `ipset`, `iptables` and `ip6tables` options (`ip6tables` only
/// when `ipv6` is `1`).
pub fn backend(config: &Config) -> Result<Box<dyn Backend>, String> {
    let prefix = name(config, "prefix", "barbican")?;
    let chain = name(config, "chain", "BARBICAN")?;
    let option =
        |key: &str, default: &'static str| config.main.option(key).unwrap_or(default).to_owned();
    let ipv6 = config.main.option("ipv6").is_some_and(|v| v == "1");
    let ip6tables = ipv6.then(|| option("ip6tables", "ip6tables"));
    Ok(Box::new(Ipset::new(
        System,
        &prefix,
        &chain,
        &option("ipset", "ipset"),
        &option("iptables", "iptables"),
        ip6tables.as_deref(),
    )))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use barbican_common::nft::Block;

    use super::*;

    /// Records commands; answers `ipset save` from a map, `-C` (is the jump there) as told.
    #[derive(Clone, Default)]
    struct Fake {
        log: Arc<Mutex<Vec<String>>>,
        saves: Arc<Mutex<HashMap<String, String>>>,
        hooked: Arc<Mutex<bool>>,
    }

    impl Exec for Fake {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
            let line = format!("{program} {}", args.join(" "));
            self.log.lock().unwrap().push(match stdin {
                Some(s) => format!("{line} <<\n{s}"),
                None => line,
            });
            match args {
                ["save", set] => Ok(self.saves.lock().unwrap().get(*set).cloned().unwrap_or_default()),
                ["-t", "mangle", "-C", ..] => {
                    if *self.hooked.lock().unwrap() {
                        Ok(String::new())
                    } else {
                        Err("no".into())
                    }
                }
                ["-t", "mangle", "-I", ..] => {
                    *self.hooked.lock().unwrap() = true;
                    Ok(String::new())
                }
                ["-t", "mangle", "-L", ..] => Ok(" pkts bytes target prot opt in out source destination\n\
                    \x20   1    60 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0 ctdir REPLY\n\
                    \x20   3   180 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 match-set barbican-host4 src \n\
                    \x20   2   100 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 match-set barbican-net4 src \n\
                    \x20   7   420 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 match-set barbican-list4 src \n"
                    .to_owned()),
                _ => Ok(String::new()),
            }
        }
    }

    fn n(s: &str) -> Net {
        s.parse().unwrap()
    }

    fn ipset(fake: &Fake) -> Ipset<Fake> {
        Ipset::new(
            fake.clone(),
            "barbican",
            "BARBICAN",
            "ipset",
            "iptables",
            None,
        )
    }

    #[test]
    fn setup_creates_sets_and_rules() {
        let fake = Fake::default();
        ipset(&fake).setup().unwrap();
        let log = fake.log.lock().unwrap().join("\n");
        assert!(
            log.contains("create barbican-host4 hash:ip family inet timeout 0 maxelem 1048576"),
            "{log}"
        );
        assert!(
            log.contains("iptables -t mangle -A BARBICAN -m conntrack --ctdir REPLY -j RETURN"),
            "{log}"
        );
        assert!(
            log.contains(
                "iptables -t mangle -A BARBICAN -m set --match-set barbican-allow4 src -j RETURN"
            ),
            "{log}"
        );
        assert!(
            log.contains(
                "iptables -t mangle -A BARBICAN -m set --match-set barbican-list4 src -j DROP"
            ),
            "{log}"
        );
        assert!(
            log.contains("iptables -t mangle -I PREROUTING 1 -j BARBICAN"),
            "{log}"
        );
        assert!(!log.contains("barbican-host6"));
    }

    #[test]
    fn reconcile_diffs_and_caps_timeouts() {
        let fake = Fake::default();
        *fake.hooked.lock().unwrap() = true;
        fake.saves.lock().unwrap().insert(
            "barbican-host4".into(),
            "create barbican-host4 hash:ip family inet hashsize 1024 maxelem 1048576 timeout 0\n\
             add barbican-host4 198.51.100.1 timeout 3590\n\
             add barbican-host4 198.51.100.2 timeout 100\n\
             add barbican-host4 198.51.100.9\n"
                .into(),
        );
        let mut b = ipset(&fake);
        let desired = Desired {
            allow: vec![n("10.0.0.0/8")],
            block: vec![
                Block {
                    net: n("198.51.100.1"),
                    until: Some(10_000 + 3_600),
                },
                Block {
                    net: n("198.51.100.2"),
                    until: Some(10_000 + 3_600),
                },
                Block {
                    net: n("198.51.100.3"),
                    until: Some(10_000 + 365 * 86_400),
                },
                Block {
                    net: n("203.0.113.0/24"),
                    until: None,
                },
                Block {
                    net: n("203.0.113.0/25"),
                    until: Some(10_000 + 60),
                },
                Block {
                    net: n("192.0.2.5"),
                    until: Some(500),
                },
            ],
            lists: Arc::new(vec![n("198.18.0.0/15")]),
            lists_version: "v1".into(),
        };
        b.reconcile(&desired, 10_000).unwrap();
        let log = fake.log.lock().unwrap().join("\n");
        let script = log.split("ipset restore -exist <<\n").last().unwrap();
        assert!(!script.contains("198.51.100.1 "), "{script}");
        assert!(
            script.contains("add barbican-host4 198.51.100.2 timeout 3600\n"),
            "{script}"
        );
        assert!(
            script.contains(&format!(
                "add barbican-host4 198.51.100.3 timeout {MAX_TIMEOUT}\n"
            )),
            "{script}"
        );
        assert!(
            script.contains("del barbican-host4 198.51.100.9\n"),
            "{script}"
        );
        assert!(
            script.contains("add barbican-net4 203.0.113.0/24\n"),
            "{script}"
        );
        assert!(
            script.contains("add barbican-net4 203.0.113.0/25 timeout 60\n"),
            "{script}"
        );
        assert!(!script.contains("192.0.2.5"), "expired: {script}");
        assert!(
            script.contains("add barbican-allow4 10.0.0.0/8\n"),
            "{script}"
        );
        assert!(
            script.contains("create barbican-list4-new hash:net"),
            "{script}"
        );
        assert!(script.contains("add barbican-list4-new 198.18.0.0/15\nswap barbican-list4-new barbican-list4\ndestroy barbican-list4-new\n"), "{script}");

        // The same lists aren't swapped again.
        fake.log.lock().unwrap().clear();
        b.reconcile(&desired, 10_000).unwrap();
        assert!(!fake.log.lock().unwrap().join("\n").contains("swap"));
    }

    #[test]
    fn reconcile_sets_up_again_when_unhooked() {
        let fake = Fake::default();
        let mut b = ipset(&fake);
        b.reconcile(&Desired::default(), 0).unwrap();
        assert!(
            fake.log
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("-I PREROUTING 1 -j BARBICAN"))
        );
    }

    #[test]
    fn counters() {
        let fake = Fake::default();
        let c = ipset(&fake).counters().unwrap();
        assert_eq!(
            c.blocked,
            Counter {
                packets: 5,
                bytes: 280
            }
        );
        assert_eq!(
            c.listed,
            Counter {
                packets: 7,
                bytes: 420
            }
        );
    }

    #[test]
    fn save_output() {
        let out = "create s hash:net family inet\nadd s 198.51.100.0/24 timeout 99\nadd s 192.0.2.1\nadd other 1.2.3.4\n";
        let parsed = parse_save(out, "s");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["198.51.100.0/24"], Some(99));
        assert_eq!(parsed["192.0.2.1"], None);
    }
}
