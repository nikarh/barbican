//! Lists from the internet ("feeds"), fetched now and then. Most list addresses and prefixes: such a feed either
//! blocks what it lists as a whole, or allows it (never banned, accepted before any drop: e.g. a CDN's proxies, whose
//! addresses carry everyone's traffic), or is only data for rules (their `listed` condition) and the UI. A list of
//! networks (autonomous systems) stands for every prefix the ASN database gives them. A list of user agents is data
//! for rules (their `agents` condition) only.

pub mod catalog;

use std::sync::Arc;
use std::time::Duration;

use barbican_common::net::{Net, NetSet, aggregate};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use ts_rs::TS;

use crate::geo::Geo;

/// What a feed lists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Content {
    /// Addresses and prefixes.
    #[default]
    Addresses,
    /// Networks (autonomous systems) by number: every prefix the ASN database gives them.
    Networks,
    /// User agents (names of crawlers and bots), for rules only.
    Agents,
}

/// The catalog entry a feed was added from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct CatalogRef {
    pub source: String,
    pub item: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct FeedDef {
    /// 0 for a feed not saved yet.
    #[serde(default)]
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
    /// What rules' `listed` and `agents` conditions and the UI call it.
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
    #[serde(default)]
    pub content: Content,
    /// In a JSON document, where the list is: a JSON pointer (`/services/Googlebot`). Every address in the strings
    /// under it counts. Unset: the whole document.
    #[serde(default)]
    pub select: Option<String>,
    /// The catalog entry it was added from, if it was.
    #[serde(default)]
    pub catalog: Option<CatalogRef>,
}

/// What a list's body holds, as read with its feed's definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Nets(Vec<Net>),
    Asns(Vec<u32>),
    Agents(Vec<String>),
}

impl Parsed {
    /// Reads a fetched body.
    pub fn of(body: &str, def: &FeedDef) -> Result<Self, String> {
        match def.content {
            Content::Addresses => parse_addresses(body, def.select.as_deref()).map(Self::Nets),
            Content::Networks => Ok(Self::Asns(parse_asns(body))),
            Content::Agents => Ok(Self::Agents(parse_agents(body))),
        }
    }

    /// One entry per line: what the database keeps, and [`Loaded::from_stored`] reads back.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Nets(nets) => {
                for net in nets {
                    out.push_str(&net.to_string());
                    out.push('\n');
                }
            }
            Self::Asns(asns) => {
                for asn in asns {
                    out.push_str("AS");
                    out.push_str(&asn.to_string());
                    out.push('\n');
                }
            }
            Self::Agents(agents) => {
                for agent in agents {
                    out.push_str(agent);
                    out.push('\n');
                }
            }
        }
        out
    }

    fn len(&self) -> usize {
        match self {
            Self::Nets(v) => v.len(),
            Self::Asns(v) => v.len(),
            Self::Agents(v) => v.len(),
        }
    }
}

/// The addresses of a list: in a JSON document (under `select`, if given), every string that is an address or a
/// prefix; otherwise line by line, as [`parse_list`] reads them.
fn parse_addresses(body: &str, select: Option<&str>) -> Result<Vec<Net>, String> {
    let trimmed = body.trim_start();
    let document = if select.is_some() || trimmed.starts_with('{') || trimmed.starts_with('[') {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(value) => Some(value),
            Err(e) if select.is_some() => return Err(format!("not a JSON document: {e}")),
            // JSON lines (Spamhaus's lists) are read line by line.
            Err(_) => None,
        }
    } else {
        None
    };
    let Some(document) = document else {
        return Ok(parse_list(body).0);
    };
    let root = match select {
        Some(pointer) => document
            .pointer(pointer)
            .ok_or_else(|| format!("nothing at {pointer} in the document"))?,
        None => &document,
    };
    let mut nets = Vec::new();
    collect_nets(root, &mut nets);
    Ok(aggregate(&nets))
}

fn collect_nets(value: &serde_json::Value, nets: &mut Vec<Net>) {
    match value {
        serde_json::Value::String(s) => {
            if let Ok(net) = s.trim().parse::<Net>()
                && !net.is_never_blocked()
            {
                nets.push(net);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|v| collect_nets(v, nets)),
        serde_json::Value::Object(map) => map.values().for_each(|v| collect_nets(v, nets)),
        _ => {}
    }
}

/// Networks by number, one per line (`AS13335`, `13335`, or the first column of a CSV), sorted, without repeats.
#[must_use]
pub fn parse_asns(body: &str) -> Vec<u32> {
    let mut asns: Vec<u32> = body
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            let first = line
                .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '#')
                .next()?
                .trim_matches('"');
            let digits = first
                .strip_prefix("AS")
                .or_else(|| first.strip_prefix("as"))
                .unwrap_or(first);
            digits.parse::<u32>().ok().filter(|asn| *asn != 0)
        })
        .collect();
    asns.sort_unstable();
    asns.dedup();
    asns
}

/// User agents: the `User-agent:` lines of a robots.txt, or one per line. Wildcards, robots.txt's own tokens
/// (`__usage...`) and names shorter than three characters are left out.
#[must_use]
pub fn parse_agents(body: &str) -> Vec<String> {
    let robots = body.lines().any(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("user-agent:")
    });
    let mut agents: Vec<String> = body
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let name = if robots {
                let (key, value) = line.split_once(':')?;
                if !key.trim().eq_ignore_ascii_case("user-agent") {
                    return None;
                }
                value.trim()
            } else {
                line
            };
            (name.chars().count() >= 3 && !name.contains('*') && !name.starts_with("__"))
                .then(|| name.to_owned())
        })
        .collect();
    agents.sort_by_key(|a| a.to_ascii_lowercase());
    agents.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    agents
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

/// User agents to look for in requests' `User-Agent` header: any of the names, as a whole word, in any case.
#[derive(Debug)]
pub struct Agents {
    regex: regex::Regex,
}

impl Agents {
    #[must_use]
    pub fn new(names: &[String]) -> Option<Self> {
        if names.is_empty() {
            return None;
        }
        let alternatives: Vec<String> = names.iter().map(|n| regex::escape(n)).collect();
        let pattern = format!(
            "(?i)(?:^|[^a-z0-9])(?:{})(?:[^a-z0-9]|$)",
            alternatives.join("|")
        );
        regex::RegexBuilder::new(&pattern)
            .size_limit(1 << 24)
            .build()
            .ok()
            .map(|regex| Self { regex })
    }

    #[must_use]
    pub fn matches(&self, user_agent: &str) -> bool {
        self.regex.is_match(user_agent)
    }
}

/// A feed's contents, ready for lookups.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    /// The addresses it stands for: those it lists, or its networks' prefixes.
    pub nets: Vec<Net>,
    pub set: Arc<NetSet>,
    /// Entries in the list: prefixes, networks or user agents.
    pub entries: usize,
    pub agents: Option<Arc<Agents>>,
}

impl Loaded {
    /// From what the database keeps (one entry per line, see [`Parsed::render`]); networks are looked up in `geo`.
    #[must_use]
    pub fn from_stored(content: Content, data: &str, geo: &Geo) -> Self {
        let parsed = match content {
            Content::Addresses => Parsed::Nets(parse_list(data).0),
            Content::Networks => Parsed::Asns(parse_asns(data)),
            Content::Agents => Parsed::Agents(parse_agents(data)),
        };
        Self::from_parsed(parsed, geo)
    }

    #[must_use]
    pub fn from_parsed(parsed: Parsed, geo: &Geo) -> Self {
        let entries = parsed.len();
        let (nets, agents) = match parsed {
            Parsed::Nets(nets) => (nets, None),
            Parsed::Asns(asns) => (geo.networks_of_asns(&asns), None),
            Parsed::Agents(names) => (Vec::new(), Agents::new(&names).map(Arc::new)),
        };
        let set = Arc::new(NetSet::new(&nets));
        Self {
            nets,
            set,
            entries,
            agents,
        }
    }

    /// From a list of addresses, as stored.
    #[cfg(test)]
    #[must_use]
    pub fn from_data(data: &str) -> Self {
        Self::from_stored(Content::Addresses, data, &Geo::default())
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

    fn def(content: Content, select: Option<&str>) -> FeedDef {
        FeedDef {
            id: 0,
            name: "x".to_owned(),
            url: "https://example.com/".to_owned(),
            enabled: true,
            block: false,
            allow: false,
            refresh_secs: 3_600,
            username: None,
            password: None,
            content,
            select: select.map(str::to_owned),
            catalog: None,
        }
    }

    #[test]
    fn json_documents() {
        let body = r#"{"services": {
            "Bot A": {"source_url": "https://example.com/a.json", "ipv4": ["192.0.2.0/25", "192.0.2.128/25"],
                      "ipv6": ["2001:db8::/48"]},
            "Bot/B": {"ipv4": ["198.51.100.7"], "ipv6": []}
        }, "prefixes": [{"ipv4Prefix": "127.0.0.0/8"}]}"#;
        let shown = |p: Parsed| match p {
            Parsed::Nets(n) => n.iter().map(ToString::to_string).collect::<Vec<_>>(),
            _ => unreachable!(),
        };
        // Everything in the document, merged; loopback left out.
        assert_eq!(
            shown(Parsed::of(body, &def(Content::Addresses, None)).unwrap()),
            vec!["192.0.2.0/24", "198.51.100.7", "2001:db8::/48"]
        );
        assert_eq!(
            shown(Parsed::of(body, &def(Content::Addresses, Some("/services/Bot A"))).unwrap()),
            vec!["192.0.2.0/24", "2001:db8::/48"]
        );
        assert_eq!(
            shown(Parsed::of(body, &def(Content::Addresses, Some("/services/Bot~1B"))).unwrap()),
            vec!["198.51.100.7"]
        );
        assert!(Parsed::of(body, &def(Content::Addresses, Some("/services/C"))).is_err());
        assert!(Parsed::of("192.0.2.1\n", &def(Content::Addresses, Some("/x"))).is_err());
    }

    #[test]
    fn networks() {
        let body = "ASN,Entity\n1442,\"Hosting, Inc.\"\nAS64500 # documentation\n\nas64501\n1442,again\nnope\n";
        let parsed = Parsed::of(body, &def(Content::Networks, None)).unwrap();
        assert_eq!(parsed, Parsed::Asns(vec![1442, 64500, 64501]));
        assert_eq!(parse_asns(&parsed.render()), vec![1442, 64500, 64501]);
        // Without an ASN database, networks stand for no addresses.
        let loaded = Loaded::from_stored(Content::Networks, &parsed.render(), &Geo::default());
        assert_eq!((loaded.entries, loaded.nets.len()), (3, 0));
    }

    #[test]
    fn agents() {
        let robots = "User-agent: __usage_ai-training\nUser-agent: GPTBot\nuser-agent: Claude-Web\n\
                      User-agent: AI2Bot\nUser-agent: *\nUser-agent: YaK\nDisallow: /\n";
        let names = parse_agents(robots);
        assert_eq!(names, vec!["AI2Bot", "Claude-Web", "GPTBot", "YaK"]);
        assert_eq!(
            parse_agents("Bytespider\n# comment\nGPTBot\ngptbot\n"),
            vec!["Bytespider", "GPTBot"]
        );
        let agents = Agents::new(&names).unwrap();
        assert!(agents.matches("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"));
        assert!(agents.matches("claude-web/1.0"));
        assert!(agents.matches("YaK/1.0"));
        // Names count as whole words only.
        assert!(!agents.matches("Mozilla/5.0 (X11; Linux x86_64) Yakbrowser/1"));
        assert!(!agents.matches("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"));
        let loaded = Loaded::from_stored(Content::Agents, "GPTBot\nCCBot\n", &Geo::default());
        assert_eq!(loaded.entries, 2);
        assert!(loaded.agents.unwrap().matches("CCBot/2.0"));
    }
}
