//! Addresses and prefixes as barbican stores, sends and blocks them.

use std::cmp::Ordering;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An address or a prefix, normalized: host bits are zero, and an IPv4-mapped IPv6 address (`::ffff:192.0.2.1`)
/// is the IPv4 address it maps. Written as `192.0.2.1` or `192.0.2.0/24`, without `/32` or `/128` for one address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Net(IpNet);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not an IP address or prefix: {0:?}")]
pub struct ParseError(pub String);

/// The address, IPv4 when it is an IPv4-mapped IPv6 address.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

impl Net {
    /// One address.
    #[must_use]
    pub fn host(ip: IpAddr) -> Self {
        Self(IpNet::from(canonical(ip)))
    }

    /// The prefix of `len` bits that `ip` is in. A length beyond the family's maximum is clamped to it.
    #[must_use]
    pub fn prefix(ip: IpAddr, len: u8) -> Self {
        let net = match canonical(ip) {
            IpAddr::V4(ip) => IpNet::V4(Ipv4Net::new_assert(ip, len.min(32))),
            IpAddr::V6(ip) => IpNet::V6(Ipv6Net::new_assert(ip, len.min(128))),
        };
        Self(net.trunc())
    }

    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.0.network()
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.0.prefix_len()
    }

    #[must_use]
    pub fn family(&self) -> Family {
        match self.0 {
            IpNet::V4(_) => Family::V4,
            IpNet::V6(_) => Family::V6,
        }
    }

    /// Whether this is a single address (`/32`, `/128`).
    #[must_use]
    pub fn is_host(&self) -> bool {
        self.0.prefix_len() == self.0.max_prefix_len()
    }

    #[must_use]
    pub fn contains(&self, other: &Net) -> bool {
        self.0.contains(&other.0)
    }

    #[must_use]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.0.contains(&canonical(ip))
    }

    #[must_use]
    pub fn inner(&self) -> IpNet {
        self.0
    }

    /// The address bytes (4 or 16) followed by the prefix length, the compact form the agent stores.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = match self.0 {
            IpNet::V4(n) => n.network().octets().to_vec(),
            IpNet::V6(n) => n.network().octets().to_vec(),
        };
        bytes.push(self.prefix_len());
        bytes
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [a, b, c, d, len] => Some(Self::prefix(Ipv4Addr::new(*a, *b, *c, *d).into(), *len)),
            [rest @ .., len] if rest.len() == 16 => {
                let octets: [u8; 16] = rest.try_into().ok()?;
                Some(Self::prefix(Ipv6Addr::from(octets).into(), *len))
            }
            _ => None,
        }
    }

    /// Addresses that are never blocked, whatever a rule or a list says: loopback, unspecified, link-local,
    /// multicast and broadcast addresses. Blocking them would only break the host itself.
    #[must_use]
    pub fn is_never_blocked(&self) -> bool {
        let ip = self.addr();
        let special = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_broadcast()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_unicast_link_local()
            }
        };
        // A prefix that contains any of them, e.g. 0.0.0.0/0, is refused as a whole.
        special || self.prefix_len() == 0
    }
}

impl From<IpAddr> for Net {
    fn from(ip: IpAddr) -> Self {
        Self::host(ip)
    }
}

impl FromStr for Net {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let error = || ParseError(s.to_owned());
        if let Some((addr, len)) = s.split_once('/') {
            let addr: IpAddr = addr.parse().map_err(|_| error())?;
            let len: u8 = len.parse().map_err(|_| error())?;
            let canonical_addr = canonical(addr);
            // A mapped address's prefix counts the 96 bits of ::ffff:0:0/96.
            let len = if addr == canonical_addr {
                len
            } else {
                len.checked_sub(96).ok_or_else(error)?
            };
            let max = if canonical_addr.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(error());
            }
            Ok(Self::prefix(canonical_addr, len))
        } else {
            s.parse::<IpAddr>().map(Self::host).map_err(|_| error())
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_host() {
            write!(f, "{}", self.addr())
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl fmt::Debug for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Net {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Drops every entry that another entry's prefix contains, so that what is left can go into an nftables interval
/// set, which refuses overlapping elements. Of entries for the same prefix, `prefer` chooses which one stays (it
/// gets the kept one first).
pub fn collapse<T>(
    mut entries: Vec<(Net, T)>,
    prefer: impl Fn(&T, &T) -> Ordering,
) -> Vec<(Net, T)> {
    // Shorter prefixes first, so containers are seen before what they contain; then the preferred value first.
    entries.sort_by(|(a, x), (b, y)| {
        (a.family(), a.prefix_len(), a.addr())
            .cmp(&(b.family(), b.prefix_len(), b.addr()))
            .then_with(|| prefer(x, y))
    });
    let mut kept: Vec<(Net, T)> = Vec::with_capacity(entries.len());
    for (net, value) in entries {
        if kept.iter().any(|(k, _)| k.contains(&net)) {
            continue;
        }
        kept.push((net, value));
    }
    kept
}

/// A set of prefixes to look addresses up in quickly: merged into sorted, disjoint ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merged<T: Copy + Ord>(mut ranges: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && next(last.1).is_none_or(|after| start <= after)
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|(start, _)| *start <= x);
    i > 0 && ranges.get(i - 1).is_some_and(|(_, end)| x <= *end)
}

impl NetSet {
    #[must_use]
    pub fn new(nets: &[Net]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for net in nets {
            match net.0 {
                IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
                IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
            }
        }
        Self {
            v4: merged(v4, |x: u32| x.checked_add(1)),
            v6: merged(v6, |x: u128| x.checked_add(1)),
        }
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match canonical(ip) {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => find(&self.v6, u128::from(v6)),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Merges prefixes into the fewest that cover the same addresses (adjacent ones joined, contained ones dropped).
#[must_use]
pub fn aggregate(nets: &[Net]) -> Vec<Net> {
    let inner: Vec<IpNet> = nets.iter().map(Net::inner).collect();
    IpNet::aggregate(&inner).into_iter().map(Net).collect()
}

/// Addresses of one family from the first to the last, both included: what an nftables interval set holds as one
/// element, whether or not it is a prefix. Ordered by family, then first address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Range {
    family: Family,
    first: u128,
    last: u128,
}

impl Family {
    /// The bits of an address.
    #[must_use]
    pub fn bits(self) -> u32 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    /// The highest address, as a number.
    #[must_use]
    pub fn top(self) -> u128 {
        match self {
            Self::V4 => u128::from(u32::MAX),
            Self::V6 => u128::MAX,
        }
    }

    fn ip(self, n: u128) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::from(u32::try_from(n).unwrap_or(u32::MAX))),
            Self::V6 => IpAddr::V6(Ipv6Addr::from(n)),
        }
    }
}

fn bits_of(ip: IpAddr) -> (Family, u128) {
    match ip {
        IpAddr::V4(v4) => (Family::V4, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (Family::V6, u128::from(v6)),
    }
}

impl Range {
    /// From the first to the last address (IPv4-mapped ones as IPv4), when both are of one family and in order.
    #[must_use]
    pub fn new(first: IpAddr, last: IpAddr) -> Option<Self> {
        let (family, first) = bits_of(canonical(first));
        let (other, last) = bits_of(canonical(last));
        if family == other {
            Self::from_bounds(family, first, last)
        } else {
            None
        }
    }

    /// From the first to the last address as numbers, when they are in order and of the family's size.
    #[must_use]
    pub fn from_bounds(family: Family, first: u128, last: u128) -> Option<Self> {
        (first <= last && last <= family.top()).then_some(Self {
            family,
            first,
            last,
        })
    }

    /// The addresses of a prefix.
    #[must_use]
    pub fn of(net: &Net) -> Self {
        match net.0 {
            IpNet::V4(n) => Self {
                family: Family::V4,
                first: u128::from(u32::from(n.network())),
                last: u128::from(u32::from(n.broadcast())),
            },
            IpNet::V6(n) => Self {
                family: Family::V6,
                first: u128::from(n.network()),
                last: u128::from(n.broadcast()),
            },
        }
    }

    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// The first and the last address as numbers.
    #[must_use]
    pub fn bounds(&self) -> (u128, u128) {
        (self.first, self.last)
    }

    #[must_use]
    pub fn first(&self) -> IpAddr {
        self.family.ip(self.first)
    }

    #[must_use]
    pub fn last(&self) -> IpAddr {
        self.family.ip(self.last)
    }

    /// The prefix that covers exactly these addresses, when there is one.
    #[must_use]
    pub fn to_net(&self) -> Option<Net> {
        let size = self.last - self.first;
        // A prefix: the size is 2^k (k host bits) and the first address is aligned to it.
        if self.first & size != 0 || size.checked_add(1).is_some_and(|s| !s.is_power_of_two()) {
            return None;
        }
        let host_bits = if size == u128::MAX {
            128
        } else {
            (size + 1).trailing_zeros()
        };
        let len = u8::try_from(self.family.bits() - host_bits).ok()?;
        Some(Net::prefix(self.first(), len))
    }
}

impl From<Net> for Range {
    fn from(net: Net) -> Self {
        Self::of(&net)
    }
}

/// A prefix as a prefix (or an address), anything else as nft writes a range: `192.0.2.10-192.0.2.20`.
impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_net() {
            Some(net) => write!(f, "{net}"),
            None => write!(f, "{}-{}", self.first(), self.last()),
        }
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Range {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.split_once('-') {
            Some((first, last)) => {
                let ip = |a: &str| {
                    a.trim()
                        .parse::<IpAddr>()
                        .map_err(|_| ParseError(s.to_owned()))
                };
                Self::new(ip(first)?, ip(last)?).ok_or_else(|| ParseError(s.to_owned()))
            }
            None => s.parse::<Net>().map(Self::from),
        }
    }
}

/// The fewest ranges that hold the addresses of `nets`: prefixes that touch or overlap are joined, so that a run
/// of adjacent prefixes that is no prefix itself becomes one range. Sorted (by family, then address).
///
/// One pass when the prefixes come sorted by address (as [`aggregate`] gives them); they are sorted otherwise.
pub fn ranges(nets: impl IntoIterator<Item = Net>) -> Vec<Range> {
    let mut out = Vec::new();
    let mut sorted = true;
    for net in nets {
        sorted &= join(&mut out, Range::of(&net));
    }
    if !sorted {
        let mut all = std::mem::take(&mut out);
        all.sort_unstable();
        for range in all {
            join(&mut out, range);
        }
    }
    out
}

/// Joins `range` to the last of `out` when they touch or overlap, appends it otherwise. `false` when it comes
/// before the last (the input isn't sorted).
fn join(out: &mut Vec<Range>, range: Range) -> bool {
    if let Some(last) = out.last_mut() {
        if (range.family, range.first) < (last.family, last.first) {
            out.push(range);
            return false;
        }
        // `last.last + 1`; nothing comes after the top of the address space.
        if range.family == last.family
            && last
                .last
                .checked_add(1)
                .is_none_or(|after| range.first <= after)
        {
            last.last = last.last.max(range.last);
            return true;
        }
    }
    out.push(range);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_normalizes() {
        assert_eq!(net("192.0.2.7").to_string(), "192.0.2.7");
        assert_eq!(net("192.0.2.7/32").to_string(), "192.0.2.7");
        assert_eq!(net("192.0.2.77/24").to_string(), "192.0.2.0/24");
        assert_eq!(net("::ffff:192.0.2.1").to_string(), "192.0.2.1");
        assert_eq!(net("::ffff:192.0.2.1/120").to_string(), "192.0.2.0/24");
        assert_eq!(net("2001:db8::1/48").to_string(), "2001:db8::/48");
        assert_eq!(net(" 2001:db8::1 ").to_string(), "2001:db8::1");
        assert!("192.0.2.0/33".parse::<Net>().is_err());
        assert!("::ffff:192.0.2.1/90".parse::<Net>().is_err());
        assert!("example.com".parse::<Net>().is_err());
        assert!("192.0.2.0/x".parse::<Net>().is_err());
    }

    #[test]
    fn prefix_of_an_address() {
        let ip: IpAddr = "2001:db8:1:2:3::9".parse().unwrap();
        assert_eq!(Net::prefix(ip, 64).to_string(), "2001:db8:1:2::/64");
        assert_eq!(Net::prefix(ip, 200).to_string(), "2001:db8:1:2:3::9");
    }

    #[test]
    fn bytes_round_trip() {
        for s in [
            "192.0.2.1",
            "198.51.100.0/24",
            "2001:db8::/32",
            "2001:db8::5",
        ] {
            let n = net(s);
            let bytes = n.to_bytes();
            assert_eq!(Net::from_bytes(&bytes), Some(n), "{s}");
        }
        assert_eq!(net("192.0.2.1").to_bytes().len(), 5);
        assert_eq!(Net::from_bytes(&[1, 2, 3]), None);
    }

    #[test]
    fn never_blocked() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "ff02::1",
            "0.0.0.0/0",
            "::/0",
        ] {
            assert!(net(s).is_never_blocked(), "{s}");
        }
        for s in ["192.0.2.1", "10.1.2.3", "2001:db8::1", "198.51.100.0/24"] {
            assert!(!net(s).is_never_blocked(), "{s}");
        }
    }

    #[test]
    fn serde_as_strings() {
        let json = serde_json::to_string(&vec![net("192.0.2.0/24"), net("2001:db8::1")]).unwrap();
        assert_eq!(json, r#"["192.0.2.0/24","2001:db8::1"]"#);
        let back: Vec<Net> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vec![net("192.0.2.0/24"), net("2001:db8::1")]);
        assert!(serde_json::from_str::<Net>(r#""nope""#).is_err());
    }

    #[test]
    fn collapse_drops_contained_prefixes() {
        let kept = collapse(
            vec![
                (net("192.0.2.5"), 3),
                (net("192.0.2.0/24"), 1),
                (net("192.0.2.0/24"), 9),
                (net("198.51.100.0/25"), 2),
                (net("198.51.100.128/25"), 4),
                (net("2001:db8::/64"), 5),
                (net("2001:db8::1"), 6),
            ],
            |a, b| b.cmp(a),
        );
        assert_eq!(
            kept,
            vec![
                (net("192.0.2.0/24"), 9),
                (net("198.51.100.0/25"), 2),
                (net("198.51.100.128/25"), 4),
                (net("2001:db8::/64"), 5),
            ]
        );
    }

    #[test]
    fn net_set() {
        let set = NetSet::new(&[
            net("198.51.100.0/25"),
            net("198.51.100.128/25"),
            net("203.0.113.7"),
            net("2001:db8::/32"),
            net("255.255.255.255"),
        ]);
        for ip in [
            "198.51.100.0",
            "198.51.100.200",
            "198.51.100.255",
            "203.0.113.7",
            "2001:db8:ffff::1",
            "::ffff:203.0.113.7",
            "255.255.255.255",
        ] {
            assert!(set.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "198.51.101.0",
            "203.0.113.6",
            "203.0.113.8",
            "2001:db9::1",
            "0.0.0.0",
        ] {
            assert!(!set.contains(ip.parse().unwrap()), "{ip}");
        }
        assert!(NetSet::new(&[]).is_empty());
        assert_eq!(set.v4.len(), 3);
    }

    #[test]
    fn aggregates() {
        let merged = aggregate(&[
            net("198.51.100.0/25"),
            net("198.51.100.128/25"),
            net("198.51.100.7"),
            net("203.0.113.0/24"),
        ]);
        assert_eq!(merged, vec![net("198.51.100.0/24"), net("203.0.113.0/24")]);
    }

    fn range(s: &str) -> Range {
        s.parse().unwrap()
    }

    #[test]
    fn ranges_of_prefixes() {
        // Adjacent prefixes that make no prefix together, a contained one, a gap, and the top of the space.
        let r = ranges(aggregate(&[
            net("192.0.2.0/24"),
            net("192.0.3.0/24"),
            net("192.0.4.0/24"),
            net("192.0.3.7"),
            net("198.51.100.0/25"),
            net("198.51.100.128/26"),
            net("203.0.113.9"),
            net("240.0.0.0/4"),
            net("2001:db8::/33"),
            net("2001:db8:8000::/33"),
            net("2001:db9::/32"),
            net("ffff::/16"),
        ]));
        assert_eq!(
            r,
            [
                range("192.0.2.0-192.0.4.255"),
                range("198.51.100.0-198.51.100.191"),
                range("203.0.113.9"),
                range("240.0.0.0/4"),
                range("2001:db8::-2001:db9:ffff:ffff:ffff:ffff:ffff:ffff"),
                range("ffff::/16"),
            ]
        );
        assert_eq!(r[0].to_string(), "192.0.2.0-192.0.4.255");
        assert_eq!(r[1].to_string(), "198.51.100.0-198.51.100.191");
        assert_eq!(r[2].to_string(), "203.0.113.9");
        assert_eq!(r[3].to_string(), "240.0.0.0/4");
        assert_eq!(r[3].last(), "255.255.255.255".parse::<IpAddr>().unwrap());
        assert_eq!(r[5].bounds().1, u128::MAX);
        // Prefixes that run up to the top and an IPv6 one after them aren't joined across families.
        let r = ranges([net("255.255.255.0/24"), net("255.255.255.255"), net("::/1")]);
        assert_eq!(r, [range("255.255.255.0/24"), range("::/1")]);
        // Unsorted, overlapping: sorted first, same result.
        let r = ranges([
            net("2001:db8::/32"),
            net("198.51.100.128/25"),
            net("198.51.100.0/24"),
            net("192.0.2.0/24"),
            net("198.51.101.0/24"),
        ]);
        assert_eq!(
            r,
            [
                range("192.0.2.0/24"),
                range("198.51.100.0/23"),
                range("2001:db8::/32")
            ]
        );
        assert_eq!(ranges([]), []);
    }

    #[test]
    fn range_conversions() {
        assert_eq!(range("192.0.2.0/24").to_net(), Some(net("192.0.2.0/24")));
        assert_eq!(
            range("192.0.2.0-192.0.2.255").to_net(),
            Some(net("192.0.2.0/24"))
        );
        assert_eq!(range("192.0.2.1-192.0.2.2").to_net(), None);
        assert_eq!(range("192.0.2.2-192.0.2.5").to_net(), None);
        assert_eq!(range("0.0.0.0/0").to_net(), Some(net("0.0.0.0/0")));
        assert_eq!(range("::/0").to_net(), Some(net("::/0")));
        assert_eq!(
            range("::ffff:192.0.2.1-192.0.2.9").to_string(),
            "192.0.2.1-192.0.2.9"
        );
        assert!("192.0.2.9-192.0.2.1".parse::<Range>().is_err());
        assert!("192.0.2.1-2001:db8::1".parse::<Range>().is_err());
        assert!(Range::from_bounds(Family::V4, 0, 1 << 32).is_none());
    }

    /// Ranges hold exactly the addresses of the prefixes, and are as few as can be: disjoint, not adjacent.
    #[test]
    fn ranges_hold_what_the_prefixes_hold() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut nets = Vec::new();
        for _ in 0..2_000 {
            let v = next();
            // Within 192.0.0.0/12 and 2001:db8::/112, so that they meet and overlap often.
            let ip4 = Ipv4Addr::from(0xc000_0000 | (u32::try_from(v & 0xf_ffff).unwrap()));
            nets.push(Net::prefix(
                ip4.into(),
                18 + u8::try_from(v >> 20 & 15).unwrap(),
            ));
            let ip6 = Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(v >> 32 & 0xffff));
            nets.push(Net::prefix(
                ip6.into(),
                116 + u8::try_from(v >> 48 & 15).unwrap().min(12),
            ));
        }
        let nets = aggregate(&nets);
        let r = ranges(nets.iter().copied());
        assert!(r.len() < nets.len());
        for w in r.windows(2) {
            let ((a, b), (c, _)) = (w[0].bounds(), w[1].bounds());
            if w[0].family() == w[1].family() {
                assert!(a <= b && b + 1 < c, "{:?} {:?}", w[0], w[1]);
            }
        }
        let set = NetSet::new(&nets);
        let held = |ip: IpAddr| {
            let (family, n) = bits_of(ip);
            r.iter()
                .any(|r| r.family() == family && r.bounds().0 <= n && n <= r.bounds().1)
        };
        for _ in 0..20_000 {
            let v = next();
            let ip4 = IpAddr::V4(Ipv4Addr::from(
                0xc000_0000 | u32::try_from(v & 0xf_ffff).unwrap(),
            ));
            let ip6 = IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_u128 << 96 | u128::from(v >> 32 & 0xffff),
            ));
            assert_eq!(held(ip4), set.contains(ip4), "{ip4}");
            assert_eq!(held(ip6), set.contains(ip6), "{ip6}");
        }
    }
}
