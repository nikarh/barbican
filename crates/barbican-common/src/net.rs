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

/// Merges prefixes into the fewest that cover the same addresses (adjacent ones joined, contained ones dropped).
#[must_use]
pub fn aggregate(nets: &[Net]) -> Vec<Net> {
    let inner: Vec<IpNet> = nets.iter().map(Net::inner).collect();
    IpNet::aggregate(&inner).into_iter().map(Net).collect()
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
    fn aggregates() {
        let merged = aggregate(&[
            net("198.51.100.0/25"),
            net("198.51.100.128/25"),
            net("198.51.100.7"),
            net("203.0.113.0/24"),
        ]);
        assert_eq!(merged, vec![net("198.51.100.0/24"), net("203.0.113.0/24")]);
    }
}
