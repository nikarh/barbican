//! Lists from the internet ("feeds"): plain lists of addresses and prefixes, fetched now and then. A feed either
//! blocks what it lists as a whole, or allows it (never banned, accepted before any drop: e.g. a CDN's proxies, whose
//! addresses carry everyone's traffic), or is only data for rules (their `listed` condition) and the UI.

use std::time::Duration;

use barbican_common::net::{Net, NetSet, aggregate};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct FeedDef {
    /// 0 for a feed not saved yet.
    #[serde(default)]
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
    /// What rules' `listed` condition and the UI call it.
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// Block every address it lists. Otherwise the list is only data for rules and the UI.
    pub block: bool,
    /// Allow every address it lists, as the allow list does: never banned, and accepted before any drop rule here
    /// and on the edges. Not together with `block`.
    #[serde(default)]
    pub allow: bool,
    #[cfg_attr(test, ts(type = "number"))]
    pub refresh_secs: u64,
    /// HTTP basic authentication, for lists behind an account (e.g. a CrowdSec blocklist integration).
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Well-known public lists the UI offers to add.
#[must_use]
pub fn presets() -> Vec<FeedDef> {
    let preset = |name: &str, url: &str, block: bool, hours: u64| FeedDef {
        id: 0,
        name: name.to_owned(),
        url: url.to_owned(),
        enabled: true,
        block,
        allow: false,
        refresh_secs: hours * 3_600,
        username: None,
        password: None,
    };
    vec![
        preset(
            "Spamhaus DROP",
            "https://www.spamhaus.org/drop/drop_v4.json",
            true,
            12,
        ),
        preset(
            "Spamhaus DROP (IPv6)",
            "https://www.spamhaus.org/drop/drop_v6.json",
            true,
            12,
        ),
        preset(
            "FireHOL level 1",
            "https://iplists.firehol.org/files/firehol_level1.netset",
            true,
            6,
        ),
        preset(
            "blocklist.de",
            "https://lists.blocklist.de/lists/all.txt",
            false,
            6,
        ),
        preset(
            "Tor exit nodes",
            "https://check.torproject.org/torbulkexitlist",
            false,
            6,
        ),
        // A site behind Cloudflare's proxy is reached from Cloudflare's addresses, not its visitors'; some of them
        // are placed in Asia, Africa or South America by the geolocation databases, whatever data centre uses them.
        FeedDef {
            allow: true,
            ..preset("Cloudflare", "https://www.cloudflare.com/ips-v4", false, 24)
        },
        FeedDef {
            allow: true,
            ..preset(
                "Cloudflare (IPv6)",
                "https://www.cloudflare.com/ips-v6",
                false,
                24,
            )
        },
    ]
}

/// The addresses and prefixes in a list's body, merged, and how many lines were not understood. Understood are
/// lines of plain addresses or prefixes, with comments after `#` or `;`, CSV or whitespace-separated columns (the
/// first that is an address), and JSON lines with a `cidr` or `ip` field.
#[must_use]
pub fn parse_list(body: &str) -> (Vec<Net>, usize) {
    let mut nets = Vec::new();
    let mut unknown = 0;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        let net = if line.starts_with('{') {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| {
                    ["cidr", "ip", "net", "prefix"].iter().find_map(|k| {
                        v.get(*k)
                            .and_then(serde_json::Value::as_str)
                            .and_then(|s| s.parse::<Net>().ok())
                    })
                })
        } else {
            let content = line.split(['#', ';']).next().unwrap_or("");
            content
                .split(|c: char| c.is_whitespace() || c == ',' || c == '"')
                .find_map(|token| token.parse::<Net>().ok())
        };
        match net {
            Some(net) if !net.is_never_blocked() => nets.push(net),
            Some(_) => {}
            // JSON metadata lines (Spamhaus ends with one) don't count as garbage.
            None if line.starts_with('{') => {}
            None => unknown += 1,
        }
    }
    (aggregate(&nets), unknown)
}

/// A feed's contents, ready for lookups.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub nets: Vec<Net>,
    pub set: std::sync::Arc<NetSet>,
}

impl Loaded {
    #[must_use]
    pub fn from_data(data: &str) -> Self {
        let (nets, _) = parse_list(data);
        let set = std::sync::Arc::new(NetSet::new(&nets));
        Self { nets, set }
    }
}

pub enum Fetched {
    NotModified,
    New { body: String, etag: Option<String> },
}

/// Fetches a feed, conditionally when its etag is known.
pub async fn fetch(
    client: &reqwest::Client,
    def: &FeedDef,
    etag: Option<&str>,
) -> Result<Fetched, String> {
    let mut request = client.get(&def.url).timeout(Duration::from_secs(120));
    if let Some(user) = &def.username {
        request = request.basic_auth(user, def.password.as_deref());
    }
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let response = request.send().await.map_err(|e| chain(&e))?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Fetched::NotModified);
    }
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.text().await.map_err(|e| chain(&e))?;
    Ok(Fetched::New { body, etag })
}

/// An error with its causes ("error sending request: …: connection refused"): reqwest's own message says little.
fn chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_formats() {
        let body = "\
# FireHOL style
198.51.100.0/24
203.0.113.5 ; Spamhaus style comment
; SBL123
192.0.2.1, 2026-01-01, scanner
\"192.0.2.2\",\"x\"
{\"cidr\":\"2001:db8::/32\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}
{\"type\":\"metadata\",\"timestamp\":1,\"size\":2,\"records\":3}
0.0.0.0/8
127.0.0.1
garbage line

";
        let (nets, unknown) = parse_list(body);
        let shown: Vec<String> = nets.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            vec![
                "192.0.2.1",
                "192.0.2.2",
                "198.51.100.0/24",
                "203.0.113.5",
                "2001:db8::/32"
            ]
        );
        assert_eq!(unknown, 1);
        let loaded = Loaded::from_data(body);
        assert!(loaded.set.contains("192.0.2.2".parse().unwrap()));
        assert!(!loaded.set.contains("192.0.2.3".parse().unwrap()));
    }

    #[test]
    fn presets_are_valid() {
        for p in presets() {
            assert!(p.url.starts_with("https://"));
            assert!(p.refresh_secs >= 3_600);
        }
    }
}
