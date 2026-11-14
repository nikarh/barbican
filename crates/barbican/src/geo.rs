//! Countries and networks (ASNs) of addresses, from databases in the MaxMind DB format, and the prefixes of whole
//! countries and continents to block. DB-IP's free "Lite" databases (CC BY 4.0) can be downloaded once a month.

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use barbican_common::net::{Family, Net, Range, aggregate};
use maxminddb::{Reader, WithinOptions, geoip2};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Info {
    pub country: Option<String>,
    pub continent: Option<String>,
    pub asn: Option<u32>,
    pub as_name: Option<String>,
}

#[derive(Default)]
pub struct Geo {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

/// How much a set of prefixes covers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Prefixes, after merging adjacent and contained ones: what a firewall set holds.
    pub prefixes: u64,
    /// IPv4 addresses.
    pub v4_addresses: u64,
    /// IPv6 space in /48 networks (the usual size of one site's allocation), rounded down.
    pub v6_networks: u64,
}

impl Extent {
    /// Of merged prefixes.
    #[cfg(test)]
    fn of(nets: &[Net]) -> Self {
        let mut extent = Self {
            prefixes: nets.len() as u64,
            ..Self::default()
        };
        let mut v6: u128 = 0;
        for net in nets {
            let len = u32::from(net.prefix_len());
            match net.family() {
                Family::V4 => extent.v4_addresses += 1u64 << (32 - len.min(32)),
                Family::V6 => {
                    v6 = v6.saturating_add(1u128.checked_shl(128 - len).unwrap_or(u128::MAX));
                }
            }
        }
        extent.v6_networks = u64::try_from(v6 >> 80).unwrap_or(u64::MAX);
        extent
    }
}

/// The extent of networks given in address order, counted as they come: adjacent ones are joined into runs, and
/// each run counts the fewest prefixes that cover it, as [`aggregate`] would merge them. Nothing is kept but the
/// run in progress.
#[derive(Debug, Default)]
struct Tally {
    extent: Extent,
    v6: u128,
    /// The family, first and last address of the run in progress.
    run: Option<(Family, u128, u128)>,
}

impl Tally {
    fn add(&mut self, net: &Net) {
        let (first, last) = Range::of(net).bounds();
        let family = net.family();
        if let Some((f, start, end)) = self.run
            && f == family
            && first <= end.saturating_add(1)
            && first >= start
        {
            self.run = Some((f, start, end.max(last)));
            return;
        }
        self.close();
        self.run = Some((family, first, last));
    }

    fn close(&mut self) {
        let Some((family, first, last)) = self.run.take() else {
            return;
        };
        self.extent.prefixes += prefixes_between(family, first, last);
        let size = (last - first).saturating_add(1);
        match family {
            Family::V4 => {
                self.extent.v4_addresses += u64::try_from(size).unwrap_or(u64::MAX);
            }
            Family::V6 => self.v6 = self.v6.saturating_add(size),
        }
    }

    fn finish(mut self) -> Extent {
        self.close();
        self.extent.v6_networks = u64::try_from(self.v6 >> 80).unwrap_or(u64::MAX);
        self.extent
    }
}

/// The fewest prefixes that cover the addresses from `first` to `last` (both included).
fn prefixes_between(family: Family, mut first: u128, last: u128) -> u64 {
    // Whether a block of 2^k addresses from `first` goes past `last`.
    let too_big = |first: u128, k: u32| {
        if k == 128 {
            last - first != u128::MAX
        } else {
            (1u128 << k) - 1 > last - first
        }
    };
    let mut n = 0;
    loop {
        // The largest block that starts at `first`, aligned to its size, and ends by `last`.
        let mut k = if first == 0 {
            family.bits()
        } else {
            first.trailing_zeros().min(family.bits())
        };
        while k > 0 && too_big(first, k) {
            k -= 1;
        }
        n += 1;
        if k == 128 {
            return n;
        }
        match first.checked_add(1u128 << k) {
            Some(next) if next <= last => first = next,
            _ => return n,
        }
    }
}

/// How much blocking some countries and continents takes, each on its own and together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The countries asked for, with the continent the database places them on.
    pub countries: Vec<(String, Option<String>, Extent)>,
    pub continents: Vec<(String, Extent)>,
    /// All of them together, overlaps counted once: what [`Geo::networks_of`] blocks.
    pub total: Extent,
    pub known: Extent,
}

/// What a database says about itself (its metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbInfo {
    /// Its type, e.g. `DBIP-Country-Lite` or `GeoLite2-ASN`.
    pub kind: String,
    /// Its English description.
    pub description: Option<String>,
    /// When it was built (unix time).
    pub built: i64,
}

fn info(reader: &Reader<Vec<u8>>) -> DbInfo {
    let m = reader.metadata();
    DbInfo {
        kind: m.database_type.clone(),
        description: m
            .description
            .get("en")
            .or_else(|| m.description.values().next())
            .cloned(),
        built: i64::try_from(m.build_epoch).unwrap_or(i64::MAX),
    }
}

impl std::fmt::Debug for Geo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Geo")
            .field("country", &self.country.is_some())
            .field("asn", &self.asn.is_some())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {message}")]
    Open { path: PathBuf, message: String },
    #[error("downloading {url}: {message}")]
    Download { url: String, message: String },
}

fn open(path: &Path) -> Result<Option<Reader<Vec<u8>>>, Error> {
    if !path.exists() {
        return Ok(None);
    }
    Reader::open_readfile(path)
        .map(Some)
        .map_err(|e| Error::Open {
            path: path.to_owned(),
            message: e.to_string(),
        })
}

impl Geo {
    /// Opens the databases that exist; a missing one leaves its part out.
    pub fn open(country: Option<&Path>, asn: Option<&Path>) -> Result<Self, Error> {
        Ok(Self {
            country: country.map(open).transpose()?.flatten(),
            asn: asn.map(open).transpose()?.flatten(),
        })
    }

    #[must_use]
    pub fn has_countries(&self) -> bool {
        self.country.is_some()
    }

    #[must_use]
    pub fn has_asns(&self) -> bool {
        self.asn.is_some()
    }

    /// The country database in use.
    #[must_use]
    pub fn country_info(&self) -> Option<DbInfo> {
        self.country.as_ref().map(info)
    }

    /// The ASN database in use.
    #[must_use]
    pub fn asn_info(&self) -> Option<DbInfo> {
        self.asn.as_ref().map(info)
    }

    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Info {
        let mut info = Info::default();
        if let Some(reader) = &self.country
            && let Ok(result) = reader.lookup(ip)
            && let Ok(Some(record)) = result.decode::<geoip2::Country>()
        {
            info.country = record.country.iso_code.map(str::to_owned);
            info.continent = record.continent.code.map(str::to_owned);
        }
        if let Some(reader) = &self.asn
            && let Ok(result) = reader.lookup(ip)
            && let Ok(Some(record)) = result.decode::<geoip2::Asn>()
        {
            info.asn = record.autonomous_system_number;
            info.as_name = record.autonomous_system_organization.map(str::to_owned);
        }
        info
    }

    /// Every prefix of these countries (ISO codes) and continents (two-letter codes), merged; of IPv6 too only with
    /// `ipv6`.
    #[must_use]
    pub fn networks_of(&self, countries: &[String], continents: &[String], ipv6: bool) -> Vec<Net> {
        let Some(reader) = &self.country else {
            return Vec::new();
        };
        if countries.is_empty() && continents.is_empty() {
            return Vec::new();
        }
        let wanted = |country: Option<&str>, continent: Option<&str>| {
            country.is_some_and(|c| countries.iter().any(|w| w.eq_ignore_ascii_case(c)))
                || continent.is_some_and(|c| continents.iter().any(|w| w.eq_ignore_ascii_case(c)))
        };
        // Most networks share a few records: decode each record once.
        let mut decided: HashMap<usize, bool> = HashMap::new();
        let mut nets = Vec::new();
        let Ok(within) = reader.networks(WithinOptions::default()) else {
            return Vec::new();
        };
        for item in within.flatten() {
            let Some(offset) = item.offset() else {
                continue;
            };
            if !ipv6 && item.network().is_ok_and(|n| n.ip().is_ipv6()) {
                continue;
            }
            let take = *decided.entry(offset).or_insert_with(|| {
                item.decode::<geoip2::Country>()
                    .ok()
                    .flatten()
                    .is_some_and(|r| wanted(r.country.iso_code, r.continent.code))
            });
            if !take {
                continue;
            }
            if let Ok(network) = item.network() {
                let net = Net::prefix(network.ip(), network.prefix());
                // IPv4 also appears inside IPv6 databases as ::ffff:0:0/96 and ::/96; the IPv4 networks are listed
                // on their own.
                if net.family() == Family::V6 && is_ipv4_alias(&network.ip()) {
                    continue;
                }
                nets.push(net);
            }
        }
        aggregate(&nets)
    }

    /// How much blocking these countries and continents takes (each, and all together), or `None` without a country
    /// database. One pass over the database (well under a second), counting as it goes: nothing is kept.
    #[must_use]
    pub fn coverage(&self, countries: &[String], continents: &[String]) -> Option<Coverage> {
        // A country and a continent.
        type Place = (Option<String>, Option<String>);
        let reader = self.country.as_ref()?;
        let is =
            |value: Option<&str>, code: &str| value.is_some_and(|v| v.eq_ignore_ascii_case(code));
        let mut country_tallies: Vec<Tally> = countries.iter().map(|_| Tally::default()).collect();
        let mut country_continents: Vec<Option<String>> = vec![None; countries.len()];
        let mut continent_tallies: Vec<Tally> =
            continents.iter().map(|_| Tally::default()).collect();
        let (mut total, mut known) = (Tally::default(), Tally::default());
        // A country and a continent of each record: most networks share a few records.
        let mut records: HashMap<usize, Option<Place>> = HashMap::new();
        let within = reader.networks(WithinOptions::default()).ok()?;
        for item in within.flatten() {
            let Some(offset) = item.offset() else {
                continue;
            };
            let place = records.entry(offset).or_insert_with(|| {
                item.decode::<geoip2::Country>()
                    .ok()
                    .flatten()
                    .map(|r| {
                        (
                            r.country.iso_code.map(str::to_owned),
                            r.continent.code.map(str::to_owned),
                        )
                    })
                    .filter(|(country, continent)| country.is_some() || continent.is_some())
            });
            let (Some((country, continent)), Ok(network)) = (place.as_ref(), item.network()) else {
                continue;
            };
            let net = Net::prefix(network.ip(), network.prefix());
            if net.family() == Family::V6 && is_ipv4_alias(&network.ip()) {
                continue;
            }
            known.add(&net);
            let mut any = false;
            for ((code, tally), seen) in countries
                .iter()
                .zip(&mut country_tallies)
                .zip(&mut country_continents)
            {
                if is(country.as_deref(), code) {
                    tally.add(&net);
                    if seen.is_none() {
                        seen.clone_from(continent);
                    }
                    any = true;
                }
            }
            for (code, tally) in continents.iter().zip(&mut continent_tallies) {
                if is(continent.as_deref(), code) {
                    tally.add(&net);
                    any = true;
                }
            }
            if any {
                total.add(&net);
            }
        }
        Some(Coverage {
            countries: countries
                .iter()
                .cloned()
                .zip(country_continents)
                .zip(country_tallies)
                .map(|((code, continent), tally)| (code, continent, tally.finish()))
                .collect(),
            continents: continents
                .iter()
                .cloned()
                .zip(continent_tallies)
                .map(|(code, tally)| (code, tally.finish()))
                .collect(),
            total: total.finish(),
            known: known.finish(),
        })
    }
}

fn is_ipv4_alias(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[..6] == [0, 0, 0, 0, 0, 0] || s[..6] == [0, 0, 0, 0, 0, 0xffff] || s[0] == 0x2002
        }
        IpAddr::V4(_) => false,
    }
}

/// The URL of DB-IP's Lite database (`country` or `asn`) of a month.
fn dbip_url(kind: &str, year: i64, month: u32) -> String {
    format!("https://download.db-ip.com/free/dbip-{kind}-lite-{year}-{month:02}.mmdb.gz")
}

/// The year and month of a unix time.
fn year_month(unix: u64) -> (i64, u32) {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, u32::try_from(month).unwrap_or(1))
}

/// How old a downloaded database gets before the next download: DB-IP publishes a new one every month.
pub const MAX_AGE: Duration = Duration::from_hours(31 * 24);

/// How often the agent looks for databases due a download.
pub const CHECK_EVERY: Duration = Duration::from_hours(24);

/// When a database file was last written (unix time), if it exists.
#[must_use]
pub fn written(path: &Path) -> Option<i64> {
    let t = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(secs).ok()
}

/// Whether a database file is missing or older than [`MAX_AGE`].
#[must_use]
pub fn stale(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_none_or(|age| age > MAX_AGE)
}

/// Downloads DB-IP's Lite database (`country` or `asn`) of this month (or the previous one, early in a month) to
/// `path`, replacing it only once the new file is complete and opens.
pub async fn download(client: &reqwest::Client, kind: &str, path: &Path) -> Result<(), Error> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (year, month) = year_month(now);
    let (prev_year, prev_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    let mut last_error = None;
    for url in [
        dbip_url(kind, year, month),
        dbip_url(kind, prev_year, prev_month),
    ] {
        match fetch(client, &url).await {
            Ok(gz) => return store(&url, &gz, path),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Download {
        url: String::new(),
        message: "no URL".to_owned(),
    }))
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, Error> {
    let error = |message: String| Error::Download {
        url: url.to_owned(),
        message,
    };
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| error(e.to_string()))?;
    if !response.status().is_success() {
        return Err(error(response.status().to_string()));
    }
    let bytes = response.bytes().await.map_err(|e| error(e.to_string()))?;
    Ok(bytes.to_vec())
}

fn store(url: &str, gz: &[u8], path: &Path) -> Result<(), Error> {
    let error = |message: String| Error::Download {
        url: url.to_owned(),
        message,
    };
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut data)
        .map_err(|e| error(e.to_string()))?;
    Reader::from_source(data.as_slice()).map_err(|e| error(format!("not a MaxMind DB: {e}")))?;
    let partial = path.with_extension("part");
    std::fs::write(&partial, &data)
        .and_then(|()| std::fs::rename(&partial, path))
        .map_err(|e| error(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months() {
        assert_eq!(year_month(0), (1970, 1));
        // 2026-11-10
        assert_eq!(year_month(1_794_355_200), (2026, 11));
        // 2024-02-29
        assert_eq!(year_month(1_709_164_800), (2024, 2));
        // 2025-12-31 23:59:59
        assert_eq!(year_month(1_767_225_599), (2025, 12));
        assert_eq!(
            dbip_url("asn", 2026, 3),
            "https://download.db-ip.com/free/dbip-asn-lite-2026-03.mmdb.gz"
        );
    }

    #[test]
    fn without_databases() {
        let geo = Geo::open(Some(Path::new("/nonexistent/a.mmdb")), None).unwrap();
        assert_eq!(geo.lookup("192.0.2.1".parse().unwrap()), Info::default());
        assert_eq!(geo.country_info(), None);
        assert_eq!(written(Path::new("/nonexistent/a.mmdb")), None);
        assert_eq!(
            geo.networks_of(&["CN".to_owned()], &[], true),
            Vec::<Net>::new()
        );
    }

    #[test]
    fn extents() {
        let nets: Vec<Net> = [
            "192.0.2.0/24",
            "198.51.100.7",
            "2001:db8::/32",
            "2001:db8:1::/64",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(
            Extent::of(&nets),
            Extent {
                prefixes: 4,
                v4_addresses: 257,
                v6_networks: 65_536,
            }
        );
        assert_eq!(
            Extent::of(&["2001::/16".parse().unwrap()]).v6_networks,
            1 << 32
        );
        assert_eq!(
            Extent::of(&["0.0.0.0/0".parse().unwrap()]).v4_addresses,
            1 << 32
        );
        assert_eq!(geo_without().coverage(&["CN".to_owned()], &[]), None);
    }

    /// Counted as networks come, in address order, a tally is the extent of the merged prefixes.
    #[test]
    fn tally_is_the_extent_of_merged_prefixes() {
        let sets: [&[&str]; 4] = [
            // Two halves of a /24 and the next /24: one /23 (not a prefix boundary: 192.0.2.0 is odd) and so on.
            &[
                "192.0.2.0/25",
                "192.0.2.128/25",
                "192.0.3.0/24",
                "198.51.100.7",
                "198.51.100.8",
            ],
            &["10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8"],
            &[
                "0.0.0.0/1",
                "128.0.0.0/1",
                "2001:db8::/33",
                "2001:db8:8000::/33",
                "2001:db9::/48",
            ],
            &[
                "203.0.113.1",
                "203.0.113.2",
                "203.0.113.3",
                "203.0.113.4",
                "2001:db8::1",
                "2001:db8::2",
            ],
        ];
        for set in sets {
            let nets: Vec<Net> = set.iter().map(|s| s.parse().unwrap()).collect();
            let mut tally = Tally::default();
            for net in &nets {
                tally.add(net);
            }
            assert_eq!(tally.finish(), Extent::of(&aggregate(&nets)), "{set:?}");
        }
        assert_eq!(prefixes_between(Family::V6, 0, u128::MAX), 1);
        assert_eq!(prefixes_between(Family::V4, 0, u128::from(u32::MAX)), 1);
        // 1-6: 1, 2-3, 4-5, 6.
        assert_eq!(prefixes_between(Family::V4, 1, 6), 4);
    }

    fn geo_without() -> Geo {
        Geo::open(Some(Path::new("/nonexistent/a.mmdb")), None).unwrap()
    }

    /// With a real country database: `BARBICAN_TEST_GEO=<dir with dbip-country-lite.mmdb>`.
    #[test]
    fn coverage_with_a_database() {
        let Ok(dir) = std::env::var("BARBICAN_TEST_GEO") else {
            return;
        };
        let geo = Geo::open(
            Some(&PathBuf::from(dir).join("dbip-country-lite.mmdb")),
            None,
        )
        .unwrap();
        let countries = ["CN".to_owned(), "DE".to_owned()];
        let continents = ["SA".to_owned()];
        let start = std::time::Instant::now();
        let first = geo.coverage(&countries, &continents).unwrap();
        let read = start.elapsed();
        let start = std::time::Instant::now();
        let again = geo.coverage(&countries, &continents).unwrap();
        let read_again = start.elapsed();
        assert_eq!(first, again);
        assert_eq!(
            first.total.prefixes,
            geo.networks_of(&countries, &continents, true).len() as u64
        );
        let (_, continent, cn) = &first.countries[0];
        assert_eq!(continent.as_deref(), Some("AS"));
        // China has more than 300 million IPv4 addresses, the whole space 2^32.
        assert!(cn.v4_addresses > 300_000_000, "{cn:?}");
        assert!(first.known.v4_addresses > 3_000_000_000 && first.known.v4_addresses < 1 << 32);
        let sum: u64 = first
            .countries
            .iter()
            .map(|c| c.2.v4_addresses)
            .sum::<u64>()
            + first.continents[0].1.v4_addresses;
        assert_eq!(first.total.v4_addresses, sum);
        assert!(
            read < Duration::from_secs(1) && read_again < Duration::from_secs(1),
            "read {read:?}, then {read_again:?}"
        );
    }

    /// With real databases: `BARBICAN_TEST_GEO=<dir with dbip-country-lite.mmdb and dbip-asn-lite.mmdb>`.
    #[test]
    fn with_databases() {
        let Ok(dir) = std::env::var("BARBICAN_TEST_GEO") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let geo = Geo::open(
            Some(&dir.join("dbip-country-lite.mmdb")),
            Some(&dir.join("dbip-asn-lite.mmdb")),
        )
        .unwrap();
        let info = geo.lookup("1.1.1.1".parse().unwrap());
        assert!(info.asn == Some(13335), "{info:?}");
        let country = geo.country_info().unwrap();
        assert!(country.kind.contains("Country"), "{country:?}");
        assert!(country.built > 1_600_000_000, "{country:?}");
        assert!(geo.asn_info().unwrap().kind.contains("ASN"));
        let start = std::time::Instant::now();
        let nets = geo.networks_of(&["CN".to_owned()], &["SA".to_owned()], true);
        let v4 = nets
            .iter()
            .filter(|n| n.family() == barbican_common::net::Family::V4)
            .count();
        let elapsed = start.elapsed();
        assert!(v4 > 1_000, "{v4}");
        assert!(nets.iter().all(|n| !is_ipv4_alias(&n.addr())));
        let probe: IpAddr = "1.0.1.1".parse().unwrap(); // in China
        assert_eq!(geo.lookup(probe).country.as_deref(), Some("CN"));
        assert!(nets.iter().any(|n| n.contains_ip(probe)));
        assert!(
            !nets
                .iter()
                .any(|n| n.contains_ip("1.1.1.1".parse().unwrap()))
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "{elapsed:?}, {} prefixes",
            nets.len()
        );
    }
}
