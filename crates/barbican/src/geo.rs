//! Countries and networks (ASNs) of addresses, from databases in the MaxMind DB format, and the prefixes of whole
//! countries and continents to block. DB-IP's free "Lite" databases (CC BY 4.0) can be downloaded once a month.

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use barbican_common::net::{Net, aggregate};
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

    /// Every prefix of these countries (ISO codes) and continents (two-letter codes), merged.
    #[must_use]
    pub fn networks_of(&self, countries: &[String], continents: &[String]) -> Vec<Net> {
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
                if net.family() == barbican_common::net::Family::V6 && is_ipv4_alias(&network.ip())
                {
                    continue;
                }
                nets.push(net);
            }
        }
        aggregate(&nets)
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

/// Whether a database file is missing or older than a month.
#[must_use]
pub fn stale(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_none_or(|age| age > Duration::from_hours(31 * 24))
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
        assert_eq!(geo.networks_of(&["CN".to_owned()], &[]), Vec::<Net>::new());
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
        let start = std::time::Instant::now();
        let nets = geo.networks_of(&["CN".to_owned()], &["SA".to_owned()]);
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
