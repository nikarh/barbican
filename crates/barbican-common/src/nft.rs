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
//! The list sets hold address ranges, not the prefixes the lists are made of: an interval set keeps any range as
//! one element (two keys, its first address and the one after its last), as much kernel memory as one prefix, and a
//! run of adjacent prefixes that is no prefix itself (`192.0.2.0/24` and `192.0.3.0/24` and `192.0.4.0/24`) is
//! one range. Countries' prefixes merge into about half as many ranges. The same addresses are dropped either way.
//!
//! The table and its chain are made with the `nft` program. Elements are changed over netlink, straight in the
//! kernel's `nf_tables`: `nft` reads every element of every set into its cache before it changes anything, which takes
//! seconds once a list set holds hundreds of thousands of prefixes. Over netlink a change is one small
//! transaction whatever the lists hold.
//!
//! Reconciling changes only the difference between what should be blocked and what the kernel has. What the kernel
//! has is read back (`NFT_MSG_GETSETELEM` of the ban and allow sets) at the start, and again only when something
//! else committed to `nf_tables`: the kernel counts every commit in the ruleset's generation, which `nft` checks its
//! own cache with too. Otherwise it is what this process wrote, less what timed out. [`Firewall::check`] asks for
//! the generation alone (one small request), so checking every minute costs next to nothing, and a restart, a
//! flushed ruleset or a hand-edited set is corrected within that minute.
//!
//! The list sets are never read back as a rule: they change by the difference (in ranges) to what was written
//! last, and a set of one element (`lists_version`, written in the same transaction) tells after a restart whether
//! they hold the wanted version already. When they hold something else (another version, or what a version that
//! loaded prefixes wrote), they are read back once and changed by the difference to that.
//!
//! When netlink fails (an unexpected kernel), everything goes through `nft` as before: reads with `nft -j list set`
//! on each reconcile, changes as an `nft -f` script.

mod kernel;
mod wire;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde_json::Value;

pub use kernel::Kernel;

use crate::net::{Family, Net, Range, collapse, ranges};

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
    #[error("netlink: {0}")]
    Netlink(String),
}

/// Runs nft. A trait so that tests can record the scripts instead.
pub trait Runner {
    /// Runs a script (`nft -f -`) as one transaction.
    fn run(&self, script: &str) -> Result<(), Error>;
    /// Lists a table or one of its objects in JSON (`nft -j list <what>`), e.g. `set inet barbican host4`.
    fn list(&self, what: &str) -> Result<String, Error>;
    /// The kernel's `nf_tables` over netlink, when this runner reaches it.
    fn netlink(&self) -> Option<&dyn Netlink> {
        None
    }
}

/// `nf_tables` over netlink. A trait so that tests can record the messages instead. Requests are built by a
/// function of the first sequence number to use.
pub trait Netlink {
    /// Applies a transaction: a batch whose messages each ask for an acknowledgement.
    fn transact(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<(), Error>;
    /// The messages a dump request answers with.
    fn dump(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error>;
    /// The first of them only.
    fn dump_first(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error>;
    /// Whether only this process committed to `nf_tables` since the last call. When not, the caller reads its
    /// table back.
    fn unchanged(&self) -> bool;
    /// Whether anything else committed since this process last knew what its table holds, without forgetting it.
    fn changed(&self) -> bool;
}

impl Netlink for Kernel {
    fn transact(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<(), Error> {
        Kernel::transact(self, build)
    }

    fn dump(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
        Kernel::dump(self, build)
    }

    fn dump_first(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
        Kernel::dump_first(self, build)
    }

    fn unchanged(&self) -> bool {
        Kernel::unchanged(self)
    }

    fn changed(&self) -> bool {
        Kernel::changed(self)
    }
}

/// Runs the `nft` program, and changes elements over netlink.
#[derive(Debug, Clone)]
pub struct NftCommand {
    program: String,
    kernel: Kernel,
}

impl Default for NftCommand {
    fn default() -> Self {
        Self::new("nft")
    }
}

impl NftCommand {
    #[must_use]
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_owned(),
            kernel: Kernel::default(),
        }
    }

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

    fn netlink(&self) -> Option<&dyn Netlink> {
        Some(&self.kernel)
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
    /// Countries and blocklists, all in one: replaced as a whole when `lists_version` changes. Shared, since it
    /// can be large and changes rarely. Sorted by address and without overlaps, as [`crate::net::aggregate`]
    /// makes them, they turn into the list sets' ranges in one pass (they are sorted first otherwise).
    pub lists: Arc<Vec<Net>>,
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

    fn is_interval(self) -> bool {
        !matches!(self, Self::Host)
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

/// What identifies an element of a set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    /// An address or a prefix: what barbican puts in the ban and allow sets.
    Net(Net),
    /// A range that is no prefix: what barbican puts in the list sets (along with ranges that are prefixes, which
    /// are read back as [`Self::Net`]).
    Range(Range),
    /// Anything else, as `nft -j` writes it: removed by `nft`.
    Text(String),
    /// Anything else, as the kernel's elements (key, interval end): removed over netlink.
    Raw(Vec<(wire::Key, bool)>),
}

impl Key {
    /// In nft's syntax, for a script. `None` for what only netlink can name.
    fn text(&self) -> Option<String> {
        match self {
            Self::Net(net) => Some(net.to_string()),
            Self::Range(range) => Some(range.to_string()),
            Self::Text(text) => Some(text.clone()),
            Self::Raw(_) => None,
        }
    }
}

/// An element as the kernel has it, and the seconds until it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Element {
    key: Key,
    expires: Option<u64>,
}

/// How far the kernel's remaining time may drift from the wanted one before the element is replaced.
fn tolerance(remaining: u64) -> u64 {
    (remaining / 100).max(60)
}

/// What a set holds: each element and when it times out (unix seconds).
type Have = HashMap<Key, Option<u64>>;

/// What the kernel holds, as far as this process knows.
type Model = HashMap<(Set, Family), Have>;

/// The changes to one set.
#[derive(Debug, Default)]
struct SetChanges {
    remove: Vec<Key>,
    add: Vec<(Net, Option<u64>)>,
    /// Ranges to add (list sets), after `add`.
    ranges: Vec<Range>,
    /// Emptied first (list sets).
    flush: bool,
}

/// The changes of one reconcile.
#[derive(Debug, Default)]
struct Plan {
    sets: Vec<((Set, Family), SetChanges)>,
    /// The new mark of the lists, when they change.
    lists: Option<u32>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.lists.is_none()
    }
}

/// The set holding one element: a hash of the version of what the list sets hold, written in the same transaction
/// as they are. Reading a large set back takes seconds; this tells whether it holds what it should already (after
/// a restart), so that it isn't filled again. It tells how they were loaded too ([`loaded_mark`]): sets loaded
/// otherwise (as prefixes, by an older version) don't hold the elements a difference would be taken from.
const LISTS_MARK: &str = "lists_version";

/// The version of lists read back: no real one.
const UNKNOWN_LISTS: &str = "\0read back";

/// The mark of a version of the lists: its 32-bit FNV-1a hash.
fn lists_mark(version: &str) -> u32 {
    version.bytes().fold(0x811c_9dc5, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

/// The mark of a version of the lists as loaded: as ranges, and without IPv6 the same lists load otherwise.
fn loaded_mark(version: &str, ipv6: bool) -> u32 {
    let ipv6 = if ipv6 { "" } else { " without IPv6" };
    lists_mark(&format!("{version} as ranges{ipv6}"))
}

/// The prefixes of a family that go into its list set: none of IPv6 when it is off.
fn listed(lists: &[Net], family: Family, ipv6: bool) -> impl Iterator<Item = Net> + '_ {
    let on = ipv6 || family == Family::V4;
    lists
        .iter()
        .filter(move |n| on && n.family() == family && !n.is_never_blocked())
        .copied()
}

/// The ranges of a family's list set: its prefixes in the lists, merged.
fn list_ranges(lists: &[Net], family: Family, ipv6: bool) -> Vec<Range> {
    ranges(listed(lists, family, ipv6))
}

/// What is in `new` and not in `old`, and what is in `old` and not in `new`: one pass over both, sorted.
fn list_diff(old: &[Range], new: &[Range]) -> (Vec<Range>, Vec<Range>) {
    let (mut add, mut remove) = (Vec::new(), Vec::new());
    let (mut old, mut new) = (old.iter().peekable(), new.iter().peekable());
    loop {
        match (old.peek(), new.peek()) {
            (Some(o), Some(n)) if o == n => {
                old.next();
                new.next();
            }
            (Some(o), Some(n)) if o < n => {
                remove.push(**o);
                old.next();
            }
            (_, Some(n)) => {
                add.push(**n);
                new.next();
            }
            (Some(o), None) => {
                remove.push(**o);
                old.next();
            }
            (None, None) => break,
        }
    }
    (add, remove)
}

/// What the list sets hold, as far as this process knows.
#[derive(Debug, Clone)]
enum Loaded {
    /// The ranges of these lists, as written by this process.
    Lists(Arc<Vec<Net>>),
    /// The elements read back from the kernel, sorted: whatever wrote them.
    Elements(Vec<Range>),
}

impl Loaded {
    /// The elements of a family's set.
    fn ranges(&self, family: Family, ipv6: bool) -> Cow<'_, [Range]> {
        match self {
            Self::Lists(lists) => Cow::Owned(list_ranges(lists, family, ipv6)),
            Self::Elements(elements) => {
                let from = elements.partition_point(|r| r.family() < family);
                let to = elements.partition_point(|r| r.family() <= family);
                Cow::Borrowed(elements.get(from..to).unwrap_or(&[]))
            }
        }
    }
}

/// The table and the way to change it.
pub struct Firewall<R: Runner> {
    runner: R,
    table: String,
    priority: i32,
    /// The version and content the list sets hold, when known.
    lists: Option<(String, Loaded)>,
    /// What the kernel holds, while it is known (changes go over netlink, and nothing else committed since).
    model: Option<Model>,
    /// The last netlink failure reported, and one not reported yet.
    netlink_failure: Option<String>,
    notice: Option<String>,
    /// Whether IPv6 is blocked at all. Off, nothing of IPv6 goes into the kernel (the sets stay, empty): on a host
    /// without IPv6, its list prefixes would take as much kernel memory as IPv4's for traffic that never comes.
    ipv6: bool,
}

impl<R: Runner> Firewall<R> {
    pub fn new(runner: R, table: &str, priority: i32) -> Self {
        Self {
            runner,
            table: table.to_owned(),
            priority,
            lists: None,
            model: None,
            netlink_failure: None,
            notice: None,
            ipv6: true,
        }
    }

    /// Whether IPv6 is blocked (on by default). See [`Self::ipv6`].
    #[must_use]
    pub fn with_ipv6(mut self, on: bool) -> Self {
        self.ipv6 = on;
        self
    }

    /// Whether IPv6 is blocked.
    #[must_use]
    pub fn ipv6(&self) -> bool {
        self.ipv6
    }

    fn mark(&self, version: &str) -> u32 {
        loaded_mark(version, self.ipv6)
    }

    pub fn table(&self) -> &str {
        &self.table
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Why netlink failed and `nft` was used instead, once for each new reason.
    pub fn take_notice(&mut self) -> Option<String> {
        self.notice.take()
    }

    fn netlink_failed(&mut self, error: String) {
        self.model = None;
        if self.netlink_failure.as_deref() != Some(error.as_str()) {
            self.notice = Some(error.clone());
            self.netlink_failure = Some(error);
        }
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
        let _ = writeln!(s, "  set {LISTS_MARK} {{ type mark; }}");
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
        self.model = None;
        let definition = self.definition();
        match self.runner.run(&definition) {
            Ok(()) => Ok(()),
            Err(Error::Nft(_)) => {
                self.lists = None;
                self.runner.run(&format!(
                    "table inet {t}\ndelete table inet {t}\n{definition}",
                    t = self.table
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the table may differ from what it should hold, so that [`Self::reconcile`] is due: something else
    /// committed to `nf_tables` since this process last knew what the table holds, or that can't be told (no
    /// netlink). Cheap enough to ask every minute.
    pub fn check(&self) -> bool {
        match (&self.model, self.runner.netlink()) {
            (Some(_), Some(netlink)) => netlink.changed(),
            _ => true,
        }
    }

    /// Removes the table, and with it every block.
    pub fn remove(&mut self) -> Result<(), Error> {
        self.lists = None;
        self.model = None;
        self.runner.run(&format!(
            "table inet {t}\ndelete table inet {t}\n",
            t = self.table
        ))
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
        let mut wanted = wanted(desired, now);
        if !self.ipv6 {
            wanted.retain(|(_, family), _| *family == Family::V4);
        }
        if self.runner.netlink().is_some() {
            match self.reconcile_netlink(&wanted, desired, now) {
                Err(Error::Netlink(e)) => self.netlink_failed(e),
                other => {
                    if other.is_err() {
                        self.model = None;
                    }
                    return other;
                }
            }
        }
        self.reconcile_cli(&wanted, desired, now)
    }

    /// What should change, given what the kernel has (`kernel`, per ban and allow set).
    fn plan<'m>(
        &self,
        wanted: &Wanted,
        desired: &Desired,
        now: u64,
        kernel: &dyn Fn(Set, Family) -> Result<Cow<'m, Have>, Error>,
    ) -> Result<(Plan, Changes), Error> {
        let mut plan = Plan::default();
        let mut changes = Changes::default();
        for family in FAMILIES {
            for set in [Set::Allow, Set::Host, Set::Net] {
                let have = kernel(set, family)?;
                let want = wanted.get(&(set, family));
                let (add, remove) = diff(
                    want.map_or(&[][..], Vec::as_slice),
                    &have,
                    set.has_timeout(),
                    now,
                );
                changes.added += add.len();
                changes.removed += remove.len();
                if !add.is_empty() || !remove.is_empty() {
                    plan.sets.push((
                        (set, family),
                        SetChanges {
                            remove,
                            add,
                            ..SetChanges::default()
                        },
                    ));
                }
            }
        }
        let applied = self.lists.as_ref();
        if applied.map(|(version, _)| version) != Some(&desired.lists_version) {
            for family in FAMILIES {
                // From what they hold, only the difference; or else filled anew.
                let new = list_ranges(&desired.lists, family, self.ipv6);
                let set = match applied {
                    Some((_, old)) => {
                        let (add, remove) = list_diff(&old.ranges(family, self.ipv6), &new);
                        SetChanges {
                            remove: remove.into_iter().map(Key::Range).collect(),
                            ranges: add,
                            ..SetChanges::default()
                        }
                    }
                    None => SetChanges {
                        ranges: new,
                        flush: true,
                        ..SetChanges::default()
                    },
                };
                if set.flush || !set.ranges.is_empty() || !set.remove.is_empty() {
                    plan.sets.push(((Set::List, family), set));
                }
            }
            plan.lists = Some(self.mark(&desired.lists_version));
            changes.lists = true;
        }
        Ok((plan, changes))
    }

    fn reconcile_cli(
        &mut self,
        wanted: &Wanted,
        desired: &Desired,
        now: u64,
    ) -> Result<Changes, Error> {
        let (plan, changes) = self.plan(wanted, desired, now, &|set, family| {
            Ok(Cow::Owned(
                self.elements(set, family)?
                    .into_iter()
                    .map(|e| (e.key, e.expires.map(|s| now + s)))
                    .collect(),
            ))
        })?;
        let t = &self.table;
        let mut script = String::new();
        for ((set, family), c) in &plan.sets {
            let name = set.name(*family);
            if c.flush {
                let _ = writeln!(script, "flush set inet {t} {name}");
            }
            let remove: Vec<String> = c.remove.iter().filter_map(Key::text).collect();
            for chunk in remove.chunks(CHUNK) {
                let _ = writeln!(
                    script,
                    "destroy element inet {t} {name} {{ {} }}",
                    chunk.join(", ")
                );
            }
            let add: Vec<String> = c
                .add
                .iter()
                .map(|(net, remaining)| element(net, *remaining))
                .chain(c.ranges.iter().map(Range::to_string))
                .collect();
            for chunk in add.chunks(CHUNK) {
                let _ = writeln!(
                    script,
                    "add element inet {t} {name} {{ {} }}",
                    chunk.join(", ")
                );
            }
        }
        if let Some(mark) = plan.lists {
            let _ = writeln!(
                script,
                "flush set inet {t} {LISTS_MARK}\nadd element inet {t} {LISTS_MARK} {{ {mark} }}"
            );
        }
        if !script.is_empty() {
            self.runner.run(&script)?;
        }
        if changes.lists {
            self.lists = Some((
                desired.lists_version.clone(),
                Loaded::Lists(Arc::clone(&desired.lists)),
            ));
        }
        Ok(changes)
    }

    fn elements(&self, set: Set, family: Family) -> Result<Vec<Element>, Error> {
        let json = self
            .runner
            .list(&format!("set inet {} {}", self.table, set.name(family)))?;
        parse_elements(&json)
    }

    fn netlink(&self) -> Result<&dyn Netlink, Error> {
        self.runner
            .netlink()
            .ok_or_else(|| Error::Netlink("not available".to_owned()))
    }

    /// The elements of a set, read over netlink.
    fn netlink_elements(&self, set: Set, family: Family) -> Result<Vec<Element>, Error> {
        let name = set.name(family);
        let dump = self.netlink()?.dump(&|seq| {
            let mut w = wire::Writer::new(seq);
            w.get_elements(&self.table, name);
            w.into_bytes()
        })?;
        let elems = wire::parse_elements(&dump)
            .ok_or_else(|| Error::Netlink(format!("unexpected elements of {name}")))?;
        Ok(assemble(elems, set.is_interval()))
    }

    /// Reads back what the ban and allow sets hold, and whether the list sets hold what they should.
    fn read_back(&mut self, desired: &Desired, now: u64) -> Result<Model, Error> {
        let mut model = Model::new();
        let mut has = Vec::new();
        for family in FAMILIES {
            for set in [Set::Allow, Set::Host, Set::Net] {
                let elements = self.netlink_elements(set, family)?;
                model.insert(
                    (set, family),
                    elements
                        .into_iter()
                        .map(|e| (e.key, e.expires.map(|s| now + s)))
                        .collect(),
                );
            }
            // A list set isn't read (that is what is slow), only whether it has elements at all.
            let name = Set::List.name(family);
            let first = self.netlink()?.dump_first(&|seq| {
                let mut w = wire::Writer::new(seq);
                w.get_elements(&self.table, name);
                w.into_bytes()
            })?;
            has.push((
                family,
                wire::parse_elements(&first).is_some_and(|e| !e.is_empty()),
            ));
        }
        // What the list sets hold is what the mark says was written with them, as long as they aren't empty when
        // that wasn't (flushed, or in a table made again).
        let dump = self.netlink()?.dump(&|seq| {
            let mut w = wire::Writer::new(seq);
            w.get_elements(&self.table, LISTS_MARK);
            w.into_bytes()
        });
        let mark = match dump {
            Ok(dump) => {
                wire::parse_elements(&dump).and_then(|e| e.first().and_then(|e| e.key.as_u32()))
            }
            // A table made before the mark was: its lists are filled anew.
            Err(Error::Nft(_)) => None,
            Err(e) => return Err(e),
        };
        let ipv6 = self.ipv6;
        let holds = |version: &str, lists: &[Net]| {
            mark == Some(loaded_mark(version, ipv6))
                && has
                    .iter()
                    .all(|(family, has)| *has == listed(lists, *family, ipv6).next().is_some())
        };
        self.lists = match self.lists.take() {
            Some((version, Loaded::Lists(lists))) if holds(&version, &lists) => {
                Some((version, Loaded::Lists(lists)))
            }
            _ if holds(&desired.lists_version, &desired.lists) => Some((
                desired.lists_version.clone(),
                Loaded::Lists(Arc::clone(&desired.lists)),
            )),
            _ => None,
        };
        // Lists of unknown content (written by an older version, as prefixes, or changed while not running) are
        // read back, so that only the difference is written: replacing them as a whole, the kernel holds the old
        // and the new elements and a record of each change until the end of the transaction, more memory than a
        // small router has for a few hundred thousand prefixes. Slow (seconds), but only then. Each element is
        // kept as it is (prefixes that the lists now make one range of are removed, and the range added).
        if self.lists.is_none() && has.iter().any(|(_, has)| *has) {
            let mut held = Vec::new();
            for (family, has) in &has {
                if *has {
                    held.extend(
                        self.netlink_elements(Set::List, *family)?
                            .into_iter()
                            .filter_map(|e| match e.key {
                                Key::Net(net) => Some(Range::of(&net)),
                                Key::Range(range) => Some(range),
                                _ => None,
                            }),
                    );
                }
            }
            held.sort_unstable();
            self.lists = Some((UNKNOWN_LISTS.to_owned(), Loaded::Elements(held)));
        }
        Ok(model)
    }

    fn reconcile_netlink(
        &mut self,
        wanted: &Wanted,
        desired: &Desired,
        now: u64,
    ) -> Result<Changes, Error> {
        let unchanged = self.netlink()?.unchanged();
        let mut model = match self.model.take() {
            Some(model) if unchanged => model,
            _ => self.read_back(desired, now)?,
        };
        let (plan, changes) = self.plan(wanted, desired, now, &|set, family| {
            Ok(model
                .get(&(set, family))
                .map_or_else(|| Cow::Owned(Have::new()), Cow::Borrowed))
        })?;
        if !plan.is_empty() {
            let table = self.table.clone();
            self.netlink()?.transact(&|seq| batch(&table, &plan, seq))?;
        }
        for ((set, family), c) in plan.sets {
            if set == Set::List {
                continue;
            }
            let entries = model.entry((set, family)).or_default();
            for key in c.remove {
                entries.remove(&key);
            }
            for (net, remaining) in c.add {
                entries.insert(Key::Net(net), remaining.map(|r| now + r));
            }
        }
        // Forget what timed out.
        for entries in model.values_mut() {
            entries.retain(|_, until| until.is_none_or(|u| u > now));
        }
        self.model = Some(model);
        if changes.lists {
            self.lists = Some((
                desired.lists_version.clone(),
                Loaded::Lists(Arc::clone(&desired.lists)),
            ));
        }
        Ok(changes)
    }

    /// What the drop rules matched since the table was created.
    pub fn counters(&mut self) -> Result<Counters, Error> {
        if self.runner.netlink().is_some() {
            match self.netlink_counters() {
                Err(Error::Netlink(e)) => self.netlink_failed(e),
                other => return other,
            }
        }
        let json = self
            .runner
            .list(&format!("chain inet {} prerouting", self.table))?;
        parse_counters(&json)
    }

    fn netlink_counters(&self) -> Result<Counters, Error> {
        let dump = self.netlink()?.dump(&|seq| {
            let mut w = wire::Writer::new(seq);
            w.get_rules(&self.table, "prerouting");
            w.into_bytes()
        })?;
        let mut counters = Counters::default();
        for (comment, packets, bytes) in wire::parse_rule_counters(&dump) {
            let target = match comment.as_str() {
                "blocked" => &mut counters.blocked,
                "listed" => &mut counters.listed,
                _ => continue,
            };
            target.packets += packets;
            target.bytes += bytes;
        }
        Ok(counters)
    }
}

/// The kernel's elements of a key, as nft writes them: a set of single addresses has one per address, an
/// interval set two per prefix (see [`wire::interval`]).
fn elems(
    key: &Key,
    interval: bool,
    timeout: Option<u64>,
) -> Option<(wire::Elem, Option<wire::Elem>)> {
    let timeout_ms = timeout.map(|s| s.saturating_mul(1000));
    match key {
        Key::Net(net) if interval => Some(wire::interval(net, timeout_ms)),
        Key::Net(net) => {
            let mut e = wire::Elem::key(wire::Key::of(net.addr()));
            e.timeout_ms = timeout_ms;
            Some((e, None))
        }
        Key::Range(range) if interval => Some(wire::range(range, timeout_ms)),
        Key::Raw(raw) => {
            let mut it = raw.iter().map(|(key, end)| {
                let mut e = wire::Elem::key(*key);
                e.end = *end;
                e
            });
            Some((it.next()?, it.next()))
        }
        Key::Range(_) | Key::Text(_) => None,
    }
}

/// The transaction of a plan.
fn batch(table: &str, plan: &Plan, seq: u32) -> Vec<u8> {
    let mut w = wire::Writer::new(seq);
    w.batch_begin();
    for ((set, family), c) in &plan.sets {
        let name = set.name(*family);
        let interval = set.is_interval();
        if c.flush {
            w.flush(table, name);
        }
        // An element being added is destroyed first: one that timed out a moment ago may still be there, and
        // adding what is there would keep its old timeout.
        let renewed = c
            .add
            .iter()
            .filter(|_| set.has_timeout())
            .map(|(net, _)| Key::Net(*net));
        let remove: Vec<_> = c
            .remove
            .iter()
            .cloned()
            .chain(renewed)
            .filter_map(|key| elems(&key, interval, None))
            .collect();
        w.elements(false, table, name, &remove);
        let mut add: Vec<_> = Vec::with_capacity(c.add.len() + 1);
        // Like nft, an interval set filled from empty starts with the end of an interval below the first one.
        let first = c
            .add
            .first()
            .map(|(net, _)| Range::of(net))
            .or_else(|| c.ranges.first().copied());
        if c.flush
            && interval
            && let Some(first) = first
            && first.bounds().0 != 0
        {
            let zero = match family {
                Family::V4 => std::net::IpAddr::from([0u8; 4]),
                Family::V6 => std::net::IpAddr::from([0u8; 16]),
            };
            let mut e = wire::Elem::key(wire::Key::of(zero));
            e.end = true;
            add.push((e, None));
        }
        add.extend(
            c.add
                .iter()
                .filter_map(|(net, remaining)| elems(&Key::Net(*net), interval, *remaining)),
        );
        add.extend(c.ranges.iter().map(|range| wire::range(range, None)));
        w.elements(true, table, name, &add);
    }
    if let Some(mark) = plan.lists {
        w.flush(table, LISTS_MARK);
        let elem = wire::Elem::key(wire::Key::of_u32(mark));
        w.elements(true, table, LISTS_MARK, &[(elem, None)]);
    }
    w.batch_end();
    w.into_bytes()
}

/// Elements from the kernel's: in an interval set, each start with the end after it, a prefix when it is one and a
/// range otherwise.
fn assemble(mut elems: Vec<wire::Elem>, interval: bool) -> Vec<Element> {
    let expires = |e: &wire::Elem| e.expires_ms.map(|ms| ms / 1000);
    if !interval {
        return elems
            .iter()
            .map(|e| Element {
                key: Key::Net(Net::host(e.key.ip())),
                expires: expires(e),
            })
            .collect();
    }
    // Ascending; of a start and an end at the same address (adjacent intervals) the end first.
    elems.sort_by_key(|e| (e.key, !e.end));
    let range = |start: &wire::Elem, end: Option<&wire::Elem>| Element {
        key: match wire::interval_range(start.key, end.map(|e| e.key)) {
            Some(range) => range.to_net().map_or(Key::Range(range), Key::Net),
            None => Key::Raw(
                std::iter::once((start.key, false))
                    .chain(end.map(|e| (e.key, true)))
                    .collect(),
            ),
        },
        expires: expires(start),
    };
    let mut out = Vec::new();
    let mut start: Option<&wire::Elem> = None;
    let mut iter = elems.iter().peekable();
    while let Some(e) = iter.next() {
        if e.end {
            // An end without its start (nft's below the first interval, or one whose start timed out) is no
            // element of its own.
            if let Some(s) = start.take() {
                out.push(range(s, Some(e)));
            }
        } else {
            if let Some(s) = start.take() {
                // Two starts in a row: the first is removed on its own.
                out.push(Element {
                    key: Key::Raw(vec![(s.key, false)]),
                    expires: expires(s),
                });
            }
            if iter.peek().is_none() {
                // The last start without an end reaches the top of the address space.
                out.push(range(e, None));
            } else {
                start = Some(e);
            }
        }
    }
    out
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

/// The elements to add and the keys to remove so that the kernel's set (`have`, with when each element times out)
/// holds `want` (sorted, with remaining seconds) at `now`.
fn diff(
    want: &[(Net, Option<u64>)],
    have: &Have,
    timeouts: bool,
    now: u64,
) -> (Vec<(Net, Option<u64>)>, Vec<Key>) {
    let live = |until: &Option<u64>| until.is_none_or(|u| u > now);
    let mut add = Vec::new();
    let mut remove = Vec::new();
    for (net, remaining) in want {
        let key = Key::Net(*net);
        let remaining = if timeouts { *remaining } else { None };
        match have.get(&key).filter(|until| live(until)) {
            None => add.push((*net, remaining)),
            Some(until) => {
                let same = match (remaining, until) {
                    (None, None) => true,
                    (Some(r), Some(u)) => r.abs_diff(u - now) <= tolerance(r),
                    _ => false,
                };
                if !same {
                    remove.push(key);
                    add.push((*net, remaining));
                }
            }
        }
    }
    for (key, until) in have {
        let wanted = match key {
            Key::Net(net) => want.binary_search_by_key(net, |(n, _)| *n).is_ok(),
            _ => false,
        };
        if live(until) && !wanted {
            remove.push(key.clone());
        }
    }
    remove.sort();
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
                Some(key) => out.push(Element {
                    key: match key.parse::<Range>() {
                        Ok(range) => range.to_net().map_or(Key::Range(range), Key::Net),
                        Err(_) => Key::Text(key),
                    },
                    expires,
                }),
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
            lists: std::sync::Arc::new(vec![
                net("198.51.100.0/25"),
                net("2001:db8:1::/48"),
                net("0.0.0.0/0"),
            ]),
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

    /// `nf_tables` over netlink, faked: dumps answered from a map of set names to replies, transactions recorded.
    #[derive(Default)]
    struct FakeNetlink {
        dumps: RefCell<HashMap<String, Vec<u8>>>,
        dumped: RefCell<Vec<String>>,
        batches: RefCell<Vec<Vec<u8>>>,
        unchanged: std::cell::Cell<bool>,
        fail: RefCell<Option<Error>>,
    }

    impl Netlink for FakeNetlink {
        fn transact(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<(), Error> {
            if let Some(e) = self.fail.borrow_mut().take() {
                return Err(e);
            }
            self.batches.borrow_mut().push(build(7));
            Ok(())
        }

        fn dump(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
            if let Some(e) = self.fail.borrow_mut().take() {
                return Err(e);
            }
            let request = build(1);
            let message = wire::Messages(&request).next().unwrap();
            let set = String::from_utf8(wire::message_set(&message).unwrap().to_vec()).unwrap();
            self.dumped.borrow_mut().push(set.clone());
            Ok(self.dumps.borrow().get(&set).cloned().unwrap_or_default())
        }

        fn dump_first(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
            self.dump(build)
        }

        fn unchanged(&self) -> bool {
            self.unchanged.get()
        }

        fn changed(&self) -> bool {
            !self.unchanged.get()
        }
    }

    #[derive(Default)]
    struct WithNetlink {
        cli: Fake,
        nl: FakeNetlink,
    }

    impl Runner for &WithNetlink {
        fn run(&self, script: &str) -> Result<(), Error> {
            (&self.cli).run(script)
        }

        fn list(&self, what: &str) -> Result<String, Error> {
            (&self.cli).list(what)
        }

        fn netlink(&self) -> Option<&dyn Netlink> {
            Some(&self.nl)
        }
    }

    /// `(message type, set, element)` of each element of a transaction, `"flush"` for a flush.
    fn changes_of(batch: &[u8]) -> Vec<(u8, String, String)> {
        let mut out = Vec::new();
        for m in wire::Messages(batch) {
            let Some(kind) = m.nft() else { continue };
            let set = String::from_utf8(wire::message_set(&m).unwrap().to_vec()).unwrap();
            let elems = wire::message_elements(&m).unwrap();
            if elems.is_empty() {
                out.push((kind, set.clone(), "flush".to_owned()));
            }
            for e in elems {
                let mut text = e.key.ip().to_string();
                if e.end {
                    text.push_str(" end");
                }
                if e.open {
                    text.push_str(" open");
                }
                if let Some(ms) = e.timeout_ms {
                    let _ = write!(text, " {ms}ms");
                }
                out.push((kind, set.clone(), text));
            }
        }
        out
    }

    const ADD: u8 = 12;
    const DESTROY: u8 = 30;
    const FLUSH: u8 = 14;

    fn ch(kind: u8, set: &str, elem: &str) -> (u8, String, String) {
        (kind, set.to_owned(), elem.to_owned())
    }

    #[test]
    fn reconciles_over_netlink() {
        let fake = WithNetlink::default();
        // The kernel's net4 holds 198.51.100.0/25 (599 s left) and nft's end at 0.0.0.0.
        fake.nl
            .dumps
            .borrow_mut()
            .insert("net4".to_owned(), wire::tests::hex(wire::tests::NET4_DUMP));
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let mut desired = Desired {
            allow: vec![net("192.0.2.0/24")],
            block: vec![
                Block {
                    net: net("198.51.100.0/25"),
                    until: Some(10_000 + 600),
                },
                Block {
                    net: net("2001:db8::1"),
                    until: Some(10_000 + 60),
                },
            ],
            lists: Arc::new(vec![net("203.0.113.0/24"), net("240.0.0.0/4")]),
            lists_version: "v1".to_owned(),
        };
        let changes = fw.reconcile(&desired, 10_000).unwrap();
        assert_eq!(
            changes,
            Changes {
                added: 2,
                removed: 0,
                lists: true
            }
        );
        // Everything was read back: the ban and allow sets, and whether the list sets have anything.
        assert_eq!(
            *fake.nl.dumped.borrow(),
            [
                "allow4",
                "host4",
                "net4",
                "list4",
                "allow6",
                "host6",
                "net6",
                "list6",
                "lists_version"
            ]
        );
        assert!(fake.cli.scripts.borrow().is_empty());
        let batch = fake.nl.batches.borrow()[0].clone();
        assert_eq!(
            changes_of(&batch),
            [
                ch(ADD, "allow4", "192.0.2.0"),
                ch(ADD, "allow4", "192.0.3.0 end"),
                // Destroyed first: one that timed out a moment ago may not be gone yet.
                ch(DESTROY, "host6", "2001:db8::1"),
                ch(ADD, "host6", "2001:db8::1 60000ms"),
                ch(FLUSH, "list4", "flush"),
                // nft's end below the first interval of a set filled from empty.
                ch(ADD, "list4", "0.0.0.0 end"),
                ch(ADD, "list4", "203.0.113.0"),
                ch(ADD, "list4", "203.0.114.0 end"),
                ch(ADD, "list4", "240.0.0.0 open"),
                ch(FLUSH, "list6", "flush"),
                // The mark of what the lists hold, a host-order u32 (here written as an address).
                ch(FLUSH, "lists_version", "flush"),
                ch(
                    ADD,
                    "lists_version",
                    &std::net::IpAddr::from(loaded_mark("v1", true).to_ne_bytes()).to_string()
                ),
            ]
        );

        // Nobody else changed the table: nothing is read, nothing written.
        fake.nl.unchanged.set(true);
        assert!(!fw.check());
        fake.nl.dumped.borrow_mut().clear();
        let changes = fw.reconcile(&desired, 10_030).unwrap();
        assert_eq!(changes, Changes::default());
        assert!(fake.nl.dumped.borrow().is_empty());
        assert_eq!(fake.nl.batches.borrow().len(), 1);

        // A ban is one small transaction.
        desired.block.push(Block {
            net: net("198.51.100.7"),
            until: Some(10_000 + 3_600),
        });
        fw.reconcile(&desired, 10_040).unwrap();
        assert!(fake.nl.dumped.borrow().is_empty());
        assert_eq!(
            changes_of(&fake.nl.batches.borrow()[1]),
            [
                ch(DESTROY, "host4", "198.51.100.7"),
                ch(ADD, "host4", "198.51.100.7 3560000ms")
            ]
        );

        // Lifted, and the IPv6 ban timed out in the kernel meanwhile: only the lift is written.
        desired.block.pop();
        fw.reconcile(&desired, 10_100).unwrap();
        assert_eq!(
            changes_of(&fake.nl.batches.borrow()[2]),
            [ch(DESTROY, "host4", "198.51.100.7")]
        );

        // Someone else changed the table: it is read back.
        fake.nl.unchanged.set(false);
        assert!(fw.check());
        fw.reconcile(&desired, 10_100).unwrap();
        assert_eq!(fake.nl.dumped.borrow().len(), 9);
    }

    /// A dump of the mark set holding the mark of `version`, loaded with IPv6.
    fn mark_dump(version: &str) -> Vec<u8> {
        raw_mark_dump(loaded_mark(version, true))
    }

    fn raw_mark_dump(mark: u32) -> Vec<u8> {
        let mut w = wire::Writer::new(0);
        let elem = wire::Elem::key(wire::Key::of_u32(mark));
        w.elements(true, "barbican", LISTS_MARK, &[(elem, None)]);
        w.into_bytes()
    }

    #[test]
    fn without_ipv6_nothing_of_it_is_written() {
        let fake = WithNetlink::default();
        let mut fw = Firewall::new(&fake, "barbican", -190).with_ipv6(false);
        let desired = Desired {
            block: vec![
                Block {
                    net: net("198.51.100.7"),
                    until: None,
                },
                Block {
                    net: net("2001:db8::7"),
                    until: None,
                },
            ],
            allow: vec![net("2001:db8:1::/48")],
            lists: Arc::new(vec![net("203.0.113.0/24"), net("2001:db8:2::/48")]),
            lists_version: "v1".to_owned(),
        };
        fw.reconcile(&desired, 1_000).unwrap();
        let written = changes_of(&fake.nl.batches.borrow()[0]);
        assert!(
            written
                .iter()
                .all(|c| !c.1.ends_with('6') || c.2 == "flush"),
            "{written:?}"
        );
        assert!(written.contains(&ch(ADD, "host4", "198.51.100.7")));
        assert!(written.contains(&ch(ADD, "list4", "203.0.113.0")));
        // The same lists loaded with IPv6 have another mark: a restart with it on fills them again.
        assert_ne!(fw.mark("v1"), loaded_mark("v1", true));
    }

    #[test]
    fn lists_change_by_their_difference() {
        let fake = WithNetlink::default();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let mut desired = Desired {
            lists: Arc::new(vec![net("198.51.100.0/24"), net("203.0.113.0/24")]),
            lists_version: "v1".to_owned(),
            ..Desired::default()
        };
        fw.reconcile(&desired, 1_000).unwrap();
        fake.nl.unchanged.set(true);
        desired.lists = Arc::new(vec![net("192.0.2.0/24"), net("203.0.113.0/24")]);
        desired.lists_version = "v2".to_owned();
        let changes = fw.reconcile(&desired, 1_000).unwrap();
        assert!(changes.lists);
        let batch = fake.nl.batches.borrow()[1].clone();
        let list4: Vec<_> = changes_of(&batch)
            .into_iter()
            .filter(|c| c.1 == "list4")
            .collect();
        assert_eq!(
            list4,
            [
                ch(DESTROY, "list4", "198.51.100.0"),
                ch(DESTROY, "list4", "198.51.101.0 end"),
                ch(ADD, "list4", "192.0.2.0"),
                ch(ADD, "list4", "192.0.3.0 end"),
            ]
        );
    }

    fn range(s: &str) -> Range {
        s.parse().unwrap()
    }

    /// Adjacent prefixes that are no prefix together, one alone, a run up to the top of IPv4, and an IPv6 run.
    fn runs() -> Vec<Net> {
        crate::net::aggregate(&[
            net("192.0.2.0/24"),
            net("192.0.3.0/24"),
            net("192.0.4.0/24"),
            net("198.51.100.0/25"),
            net("250.0.0.0/7"),
            net("252.0.0.0/6"),
            net("2001:db8::/32"),
            net("2001:db9::/32"),
            net("2001:dba::/32"),
        ])
    }

    #[test]
    fn lists_load_as_ranges() {
        let fake = WithNetlink::default();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let mut desired = Desired {
            lists: Arc::new(runs()),
            lists_version: "v1".to_owned(),
            ..Desired::default()
        };
        fw.reconcile(&desired, 1_000).unwrap();
        let lists: Vec<_> = changes_of(&fake.nl.batches.borrow()[0])
            .into_iter()
            .filter(|c| c.1 == "list4" || c.1 == "list6")
            .collect();
        assert_eq!(
            lists,
            [
                ch(FLUSH, "list4", "flush"),
                ch(ADD, "list4", "0.0.0.0 end"),
                ch(ADD, "list4", "192.0.2.0"),
                ch(ADD, "list4", "192.0.5.0 end"),
                ch(ADD, "list4", "198.51.100.0"),
                ch(ADD, "list4", "198.51.100.128 end"),
                ch(ADD, "list4", "250.0.0.0 open"),
                ch(FLUSH, "list6", "flush"),
                ch(ADD, "list6", ":: end"),
                ch(ADD, "list6", "2001:db8::"),
                ch(ADD, "list6", "2001:dbb:: end"),
            ]
        );

        // A prefix that joins a range: the range is replaced, the rest stays.
        fake.nl.unchanged.set(true);
        let mut lists = runs();
        lists.push(net("192.0.5.0/24"));
        desired.lists = Arc::new(crate::net::aggregate(&lists));
        desired.lists_version = "v2".to_owned();
        fw.reconcile(&desired, 1_000).unwrap();
        let lists: Vec<_> = changes_of(&fake.nl.batches.borrow()[1])
            .into_iter()
            .filter(|c| c.1 == "list4" || c.1 == "list6")
            .collect();
        assert_eq!(
            lists,
            [
                ch(DESTROY, "list4", "192.0.2.0"),
                ch(DESTROY, "list4", "192.0.5.0 end"),
                ch(ADD, "list4", "192.0.2.0"),
                ch(ADD, "list4", "192.0.6.0 end"),
            ]
        );
    }

    #[test]
    fn lists_load_as_ranges_with_nft() {
        let fake = Fake::default();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let mut desired = Desired {
            lists: Arc::new(runs()),
            lists_version: "v1".to_owned(),
            ..Desired::default()
        };
        fw.reconcile(&desired, 1_000).unwrap();
        let script = fake.scripts.borrow()[0].clone();
        assert!(
            script.contains(
                "flush set inet barbican list4\nadd element inet barbican list4 { 192.0.2.0-192.0.4.255, \
                 198.51.100.0/25, 250.0.0.0-255.255.255.255 }\n"
            ),
            "{script}"
        );
        assert!(
            script.contains(
                "add element inet barbican list6 { 2001:db8::-2001:dba:ffff:ffff:ffff:ffff:ffff:ffff }\n"
            ),
            "{script}"
        );
        let mut lists = runs();
        lists.push(net("192.0.5.0/24"));
        desired.lists = Arc::new(crate::net::aggregate(&lists));
        desired.lists_version = "v2".to_owned();
        fw.reconcile(&desired, 1_000).unwrap();
        let script = fake.scripts.borrow()[1].clone();
        assert!(
            script.contains(
                "destroy element inet barbican list4 { 192.0.2.0-192.0.4.255 }\n\
                 add element inet barbican list4 { 192.0.2.0-192.0.5.255 }\n"
            ),
            "{script}"
        );
        assert!(!script.contains("list6"), "{script}");
    }

    /// A dump of a list set holding these elements as nft writes them into an empty set.
    fn list_dump(set: &str, elements: &[(wire::Elem, Option<wire::Elem>)]) -> Vec<u8> {
        let mut w = wire::Writer::new(0);
        let mut zero = wire::Elem::key(wire::Key::of("0.0.0.0".parse().unwrap()));
        zero.end = true;
        let mut all = vec![(zero, None)];
        all.extend_from_slice(elements);
        w.elements(true, "barbican", set, &all);
        w.into_bytes()
    }

    #[test]
    fn prefixes_loaded_by_an_older_version_become_ranges() {
        let fake = WithNetlink::default();
        // The same version of the lists, loaded as prefixes (and marked so) by an older version.
        let lists = vec![
            net("192.0.2.0/24"),
            net("192.0.3.0/24"),
            net("198.51.100.0/25"),
        ];
        let old: Vec<_> = lists.iter().map(|n| wire::interval(n, None)).collect();
        fake.nl
            .dumps
            .borrow_mut()
            .insert("list4".to_owned(), list_dump("list4", &old));
        fake.nl
            .dumps
            .borrow_mut()
            .insert(LISTS_MARK.to_owned(), raw_mark_dump(lists_mark("v1")));
        let desired = Desired {
            lists: Arc::new(lists),
            lists_version: "v1".to_owned(),
            ..Desired::default()
        };
        let mut fw = Firewall::new(&fake, "barbican", -190);
        assert!(fw.reconcile(&desired, 1_000).unwrap().lists);
        // Read back, and the two adjacent prefixes replaced by their range in one transaction; the third is the
        // same element as a range and stays.
        assert_eq!(
            fake.nl
                .dumped
                .borrow()
                .iter()
                .filter(|s| *s == "list4")
                .count(),
            2
        );
        let lists: Vec<_> = changes_of(&fake.nl.batches.borrow()[0])
            .into_iter()
            .filter(|c| c.1.starts_with("list"))
            .collect();
        assert_eq!(
            lists,
            [
                ch(DESTROY, "list4", "192.0.2.0"),
                ch(DESTROY, "list4", "192.0.3.0 end"),
                ch(DESTROY, "list4", "192.0.3.0"),
                ch(DESTROY, "list4", "192.0.4.0 end"),
                ch(ADD, "list4", "192.0.2.0"),
                ch(ADD, "list4", "192.0.4.0 end"),
                ch(FLUSH, "lists_version", "flush"),
                ch(
                    ADD,
                    "lists_version",
                    &std::net::IpAddr::from(loaded_mark("v1", true).to_ne_bytes()).to_string()
                ),
            ]
        );
        // From then on the mark says they are loaded.
        fake.nl.dumps.borrow_mut().insert(
            "list4".to_owned(),
            list_dump(
                "list4",
                &[
                    wire::range(&range("192.0.2.0-192.0.3.255"), None),
                    wire::interval(&net("198.51.100.0/25"), None),
                ],
            ),
        );
        fake.nl
            .dumps
            .borrow_mut()
            .insert(LISTS_MARK.to_owned(), mark_dump("v1"));
        let mut fw = Firewall::new(&fake, "barbican", -190);
        assert!(!fw.reconcile(&desired, 1_000).unwrap().lists);
        assert_eq!(fake.nl.batches.borrow().len(), 1);
    }

    #[test]
    fn list_ranges_diff() {
        let r = |l: &[&str]| l.iter().map(|s| range(s)).collect::<Vec<_>>();
        let old = r(&[
            "192.0.2.0/24",
            "198.51.100.0-198.51.100.191",
            "203.0.113.9",
            "240.0.0.0/4",
        ]);
        let new = r(&[
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
        ]);
        let (add, remove) = list_diff(&old, &new);
        assert_eq!(add, r(&["198.51.100.0/24", "203.0.113.0/24"]));
        assert_eq!(remove, r(&["198.51.100.0-198.51.100.191", "203.0.113.9"]));
        assert_eq!(list_diff(&old, &old), (vec![], vec![]));
        assert_eq!(list_diff(&[], &new), (new.clone(), vec![]));
        assert_eq!(list_diff(&new, &[]), (vec![], new.clone()));
        // Lists without IPv6 when it is off; never blocked prefixes out before they are joined.
        let lists = [
            net("10.0.0.0/8"),
            net("127.0.0.0/8"),
            net("128.0.0.0/8"),
            net("2001:db8::/32"),
        ];
        assert_eq!(
            list_ranges(&lists, Family::V4, false),
            r(&["10.0.0.0/8", "128.0.0.0/8"])
        );
        assert_eq!(list_ranges(&lists, Family::V6, false), []);
        assert_eq!(list_ranges(&lists, Family::V6, true), r(&["2001:db8::/32"]));
    }

    /// Times making ranges of 300 000 prefixes, the difference of two versions, and the transaction loading them.
    /// `cargo test --release -p barbican-common lists_at_scale -- --ignored --nocapture`; with
    /// `BARBICAN_BENCH_PREFIXES=<file>`, of the prefixes in a file instead.
    #[test]
    #[ignore = "a benchmark: run in a release build"]
    fn lists_at_scale() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // Like a country list: prefixes of /20 to /24, often next to each other, and some IPv6 /56s.
        let mut generate = |count: usize| {
            let mut nets = Vec::with_capacity(count);
            let mut at = 0x0100_0000u32;
            while nets.len() < count {
                let v = next();
                let len = 20 + u8::try_from(v % 5).unwrap();
                let size = 1u32 << (32 - u32::from(len));
                at = at.next_multiple_of(size);
                nets.push(Net::prefix(std::net::Ipv4Addr::from(at).into(), len));
                at += size;
                if v >> 8 & 1 == 0 {
                    at += 256 * u32::try_from(v >> 16 & 63).unwrap();
                }
                if (v >> 24).trailing_zeros() >= 2 {
                    let ip = std::net::Ipv6Addr::from(
                        0x2001_0db8_u128 << 96 | u128::from(at >> 8) << 72,
                    );
                    nets.push(Net::prefix(ip.into(), 56));
                }
            }
            nets
        };
        // Or the prefixes of a file, one per line.
        let nets = match std::env::var("BARBICAN_BENCH_PREFIXES") {
            Ok(path) => std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter_map(|l| l.parse().ok())
                .collect(),
            Err(_) => generate(320_000),
        };
        let nets = crate::net::aggregate(&nets);
        let mut changed = nets.clone();
        // A later version: every 100th prefix gone, another every 100th added.
        let mut i = 0;
        changed.retain(|_| {
            i += 1;
            i % 100 != 0
        });
        changed.extend(
            nets.iter()
                .step_by(100)
                .map(|n| Net::prefix(n.addr(), n.prefix_len().saturating_sub(1))),
        );
        let changed = crate::net::aggregate(&changed);

        let started = std::time::Instant::now();
        let v4 = list_ranges(&nets, Family::V4, true);
        let v6 = list_ranges(&nets, Family::V6, true);
        let ranges_took = started.elapsed();
        let started = std::time::Instant::now();
        let new4 = list_ranges(&changed, Family::V4, true);
        let (add, remove) = list_diff(&v4, &new4);
        let diff_took = started.elapsed();
        let plan = Plan {
            sets: vec![(
                (Set::List, Family::V4),
                SetChanges {
                    ranges: v4.clone(),
                    flush: true,
                    ..SetChanges::default()
                },
            )],
            lists: Some(1),
        };
        let started = std::time::Instant::now();
        let bytes = batch("barbican", &plan, 0);
        let batch_took = started.elapsed();
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "{} prefixes ({} IPv4) -> {} IPv4 + {} IPv6 ranges in {ranges_took:?}; \
             a version with {} prefixes: {} ranges, +{} -{} in {diff_took:?}; \
             the transaction loading the IPv4 ranges: {} KiB in {batch_took:?}\n",
                nets.len(),
                nets.iter().filter(|n| n.family() == Family::V4).count(),
                v4.len(),
                v6.len(),
                changed.len(),
                new4.len(),
                add.len(),
                remove.len(),
                bytes.len() / 1024,
            ),
        );
        assert!(v4.len() < nets.len());
    }

    #[test]
    fn lists_in_place_after_a_restart_are_kept() {
        let desired = Desired {
            lists: Arc::new(vec![net("198.51.100.0/24")]),
            lists_version: "v1".to_owned(),
            ..Desired::default()
        };
        let fake = WithNetlink::default();
        let has = wire::tests::hex(wire::tests::NET4_DUMP);
        fake.nl.dumps.borrow_mut().insert("list4".to_owned(), has);
        fake.nl
            .dumps
            .borrow_mut()
            .insert(LISTS_MARK.to_owned(), mark_dump("v1"));
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let changes = fw.reconcile(&desired, 1_000).unwrap();
        assert!(!changes.lists);
        assert!(fake.nl.batches.borrow().is_empty());

        // Another version: what the list sets hold is read back (here 198.51.100.0/25), and only the difference
        // written.
        fake.nl.dumped.borrow_mut().clear();
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let other = Desired {
            lists_version: "v2".to_owned(),
            ..desired.clone()
        };
        assert!(fw.reconcile(&other, 1_000).unwrap().lists);
        assert_eq!(
            fake.nl
                .dumped
                .borrow()
                .iter()
                .filter(|s| *s == "list4")
                .count(),
            2
        );
        let batch = fake.nl.batches.borrow()[0].clone();
        let list4: Vec<_> = changes_of(&batch)
            .into_iter()
            .filter(|c| c.1 == "list4")
            .collect();
        assert_eq!(
            list4,
            [
                ch(DESTROY, "list4", "198.51.100.0"),
                ch(DESTROY, "list4", "198.51.100.128 end"),
                ch(ADD, "list4", "198.51.100.0"),
                ch(ADD, "list4", "198.51.101.0 end"),
            ]
        );

        // So is a list set that is empty while its mark says it isn't (flushed by hand).
        fake.nl.dumps.borrow_mut().remove("list4");
        let mut fw = Firewall::new(&fake, "barbican", -190);
        assert!(fw.reconcile(&desired, 1_000).unwrap().lists);
    }

    #[test]
    fn falls_back_to_nft_when_netlink_fails() {
        let fake = WithNetlink::default();
        *fake.nl.fail.borrow_mut() = Some(Error::Netlink(
            "nf_tables refused: Invalid argument".to_owned(),
        ));
        let mut fw = Firewall::new(&fake, "barbican", -190);
        let desired = Desired {
            block: vec![Block {
                net: net("198.51.100.7"),
                until: None,
            }],
            ..Desired::default()
        };
        fw.reconcile(&desired, 1_000).unwrap();
        assert!(
            fake.cli.scripts.borrow()[0]
                .contains("add element inet barbican host4 { 198.51.100.7 }")
        );
        assert_eq!(
            fw.take_notice().as_deref(),
            Some("nf_tables refused: Invalid argument")
        );
        assert_eq!(fw.take_notice(), None);
        // The same failure again isn't told again.
        *fake.nl.fail.borrow_mut() = Some(Error::Netlink(
            "nf_tables refused: Invalid argument".to_owned(),
        ));
        fw.reconcile(&desired, 1_000).unwrap();
        assert_eq!(fw.take_notice(), None);
        // Netlink works again.
        fw.reconcile(&desired, 1_000).unwrap();
        assert_eq!(fake.nl.batches.borrow().len(), 1);
    }

    #[test]
    fn sets_up_again_when_the_table_is_gone() {
        let fake = WithNetlink::default();
        *fake.nl.fail.borrow_mut() = Some(Error::Nft(
            "nf_tables: No such file or directory".to_owned(),
        ));
        let mut fw = Firewall::new(&fake, "barbican", -190);
        fw.reconcile(&Desired::default(), 1_000).unwrap();
        assert!(fake.cli.scripts.borrow()[0].starts_with("table inet barbican {"));
        assert_eq!(fw.take_notice(), None);
    }

    #[test]
    fn assembles_intervals() {
        let elems = wire::parse_elements(&wire::tests::hex(wire::tests::NET4_DUMP)).unwrap();
        assert_eq!(
            assemble(elems, true),
            [Element {
                key: Key::Net(net("198.51.100.0/25")),
                expires: Some(599)
            }]
        );
        let key = |s: &str| wire::Key::of(s.parse().unwrap());
        let start = |s: &str| wire::Elem::key(key(s));
        let end = |s: &str| {
            let mut e = wire::Elem::key(key(s));
            e.end = true;
            e
        };
        // Adjacent intervals, a range that is no prefix, and one up to the top.
        let elems = vec![
            start("240.0.0.0"),
            end("192.0.2.21"),
            start("192.0.2.10"),
            end("198.51.101.0"),
            start("198.51.100.0"),
            end("198.51.100.0"),
            start("198.51.99.0"),
        ];
        let keys: Vec<Key> = assemble(elems, true).into_iter().map(|e| e.key).collect();
        assert_eq!(
            keys,
            [
                Key::Range("192.0.2.10-192.0.2.20".parse().unwrap()),
                Key::Net(net("198.51.99.0/24")),
                Key::Net(net("198.51.100.0/24")),
                Key::Net(net("240.0.0.0/4")),
            ]
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_elements("not json").is_err());
        assert!(parse_elements(r#"{"nftables": [{"set": {"elem": [{"weird": 1}]}}]}"#).is_err());
    }
}
