//! Rules (what counts as abuse, and what to do about it) and the ban policy (for how long). Both are edited in the
//! UI and stored in the database; the defaults below are what a new database starts with.

use regex::Regex;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use ts_rs::TS;

use crate::signal::{Event, Kind};

pub const HOUR: u64 = 3_600;
pub const DAY: u64 = 24 * HOUR;

/// What a rule does when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Ban the address (or its prefix).
    Ban,
    /// Only record what matched, for the UI and for other rules' `listed` conditions.
    Record,
}

/// How long a rule's ban lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BanLength {
    /// The policy's length (with its country lengths and escalation).
    Default,
    /// This long, before the policy's country lengths and escalation.
    Secs {
        #[cfg_attr(test, ts(type = "number"))]
        secs: u64,
    },
    /// Until lifted by hand.
    Forever,
}

/// What an event must look like for a rule to count it. Unset conditions match anything; regular expressions match
/// anywhere in the text unless anchored, and one starting with `!` matches what the rest doesn't match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct Conditions {
    /// HTTP: the path, with the query.
    pub path: Option<String>,
    /// HTTP: the method.
    pub method: Option<String>,
    /// HTTP: one of these statuses.
    pub status: Vec<u16>,
    /// HTTP: whether the proxy had a route (a known host) for the request.
    pub routed: Option<bool>,
    /// HTTP: the user agent.
    pub user_agent: Option<String>,
    /// Logins: the user name.
    pub user: Option<String>,
    /// The event as the UI shows it (`GET example.com/x → 404`, a user name, a probe's description).
    pub what: Option<String>,
    /// The address is in one of these blocklists (feeds), by name.
    pub listed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// 0 for a rule not saved yet.
    #[serde(default)]
    #[cfg_attr(test, ts(type = "number"))]
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    pub kind: Kind,
    /// Sources (by name) the rule looks at; empty for all.
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub conditions: Conditions,
    /// How many matching events within `window_secs` make the rule fire; 1 fires on the first.
    pub threshold: u32,
    #[cfg_attr(test, ts(type = "number"))]
    pub window_secs: u64,
    pub action: Action,
    pub ban: BanLength,
    /// The prefix length banned for IPv4 (32: the address only).
    pub prefix_v4: u8,
    /// The prefix length banned for IPv6 (64: the usual size of one customer's network).
    pub prefix_v6: u8,
}

/// Ban length for addresses of a network (an autonomous system), e.g. a VPN or relay many people share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct AsnLength {
    pub asn: u32,
    #[cfg_attr(test, ts(type = "number"))]
    pub secs: u64,
}

/// Ban length for addresses a blocklist (feed) lists, by its name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct ListLength {
    pub list: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub secs: u64,
}

/// What the policy needs to know about a banned address.
#[derive(Debug, Clone, Copy, Default)]
pub struct Who<'a> {
    pub country: Option<&'a str>,
    pub asn: Option<u32>,
    /// The blocklists that list it.
    pub listed: &'a [&'a str],
}

/// Ban length for addresses of a country.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase")]
pub struct CountryLength {
    /// ISO 3166-1 alpha-2 code, e.g. `LV`.
    pub country: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(TS), ts(export, export_to = "model.ts"))]
#[serde(rename_all = "camelCase", default)]
pub struct Policy {
    /// A rule's ban, unless the rule or a country says otherwise.
    #[cfg_attr(test, ts(type = "number"))]
    pub ban_secs: u64,
    /// Ban lengths for addresses of these countries, instead of the rule's or the default.
    pub country_lengths: Vec<CountryLength>,
    /// Ban lengths for addresses of these networks (ASNs), e.g. shared VPN or relay egress.
    pub asn_lengths: Vec<AsnLength>,
    /// Ban lengths for addresses these blocklists list, e.g. a list of a relay's egress addresses.
    pub list_lengths: Vec<ListLength>,
    /// Each earlier ban of the same address multiplies the length by this (1: no escalation).
    pub repeat_multiplier: u32,
    /// Escalation stops here.
    #[cfg_attr(test, ts(type = "number"))]
    pub max_ban_secs: u64,
    /// How long an address someone logged in from is trusted (no rule acts on it).
    #[cfg_attr(test, ts(type = "number"))]
    pub trust_secs: u64,
    /// Countries (ISO codes) blocked as a whole.
    pub blocked_countries: Vec<String>,
    /// Continents blocked as a whole: AF, AN, AS, EU, NA, OC, SA.
    pub blocked_continents: Vec<String>,
    /// Events older than this are deleted; bans and their addresses stay.
    pub retention_days: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            ban_secs: 90 * DAY,
            country_lengths: Vec::new(),
            asn_lengths: Vec::new(),
            list_lengths: Vec::new(),
            repeat_multiplier: 2,
            max_ban_secs: 365 * DAY,
            trust_secs: 30 * DAY,
            blocked_countries: Vec::new(),
            blocked_continents: Vec::new(),
            retention_days: 365,
        }
    }
}

impl Policy {
    /// How long a ban by `rule` lasts for an address that was banned `previous` times before. Of the lengths
    /// for its country, its network and the blocklists that list it, the shortest replaces the rule's.
    /// `None`: until lifted.
    #[must_use]
    pub fn length(&self, rule: BanLength, who: &Who<'_>, previous: u32) -> Option<u64> {
        let base = match rule {
            BanLength::Forever => return None,
            BanLength::Default => self.ban_secs,
            BanLength::Secs { secs } => secs,
        };
        let country = who.country.and_then(|c| {
            self.country_lengths
                .iter()
                .find(|l| l.country.eq_ignore_ascii_case(c))
                .map(|l| l.secs)
        });
        let asn = who
            .asn
            .and_then(|a| self.asn_lengths.iter().find(|l| l.asn == a).map(|l| l.secs));
        let list = self
            .list_lengths
            .iter()
            .filter(|l| who.listed.contains(&l.list.as_str()))
            .map(|l| l.secs)
            .min();
        let base = [country, asn, list]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(base);
        let factor = u64::from(self.repeat_multiplier.max(1)).saturating_pow(previous.min(32));
        Some(base.saturating_mul(factor).min(self.max_ban_secs.max(base)))
    }
}

/// Paths only scanners ask for: secrets and repositories left in the web root, PHP and CGI on sites that run neither,
/// admin panels of software that isn't there, path traversal, and injection attempts.
pub const PROBE_PATHS: &str = r"(?i)/\.(?:env|git|svn|hg|aws|ssh|docker|vscode|idea|ds_store|htaccess|htpasswd|npmrc|bash_history|kube)(?:[./?]|$)|\.(?:php\d?|phtml|asp|aspx|jsp|cgi|pl|bak|sql|old|swp)(?:\?|$)|/(?:wp-|wordpress|xmlrpc|phpmyadmin|pma/|myadmin|adminer|cgi-bin|vendor/phpunit|phpunit|eval-stdin|boaform|hnap1|gponform|setup\.cgi|bin/(?:ba)?sh|sbin/init)|/(?:actuator|debug/pprof|server-status|server-info|solr/|jenkins|manager/html|hudson|telescope|_profiler|druid/|nacos|geoserver|owa/|ecp/|autodiscover|remote/login|global-protect|dana-na|sslvpn|developmentserver|cf_scripts)|\.\./|%2e%2e|/etc/passwd|<script|onerror=|union.+select|\$\{jndi|/proc/self";

/// HTTP methods real clients use.
pub const STANDARD_METHODS: &str = r"^(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT)$";

fn rule(name: &str, description: &str, kind: Kind) -> Rule {
    Rule {
        id: 0,
        name: name.to_owned(),
        description: description.to_owned(),
        enabled: true,
        kind,
        sources: Vec::new(),
        conditions: Conditions::default(),
        threshold: 1,
        window_secs: HOUR,
        action: Action::Ban,
        ban: BanLength::Default,
        prefix_v4: 32,
        prefix_v6: 64,
    }
}

/// The rules a new database starts with.
#[must_use]
pub fn defaults() -> Vec<Rule> {
    vec![
        Rule {
            conditions: Conditions {
                path: Some(PROBE_PATHS.to_owned()),
                ..Conditions::default()
            },
            ban: BanLength::Secs { secs: 365 * DAY },
            ..rule(
                "Exploit probes",
                "Paths only vulnerability scanners ask for: .env and .git files, PHP and CGI scripts, admin panels \
                 of software that isn't there, path traversal, injection.",
                Kind::Http,
            )
        },
        Rule {
            conditions: Conditions {
                routed: Some(false),
                ..Conditions::default()
            },
            ban: BanLength::Secs { secs: 365 * DAY },
            ..rule(
                "No known host",
                "Requests the proxy has no route for: the server's bare address or a host it doesn't serve. Only \
                 scanners of the whole internet send them.",
                Kind::Http,
            )
        },
        Rule {
            conditions: Conditions {
                method: Some(format!("!{STANDARD_METHODS}")),
                ..Conditions::default()
            },
            ..rule(
                "Unusual methods",
                "HTTP methods no browser or app sends.",
                Kind::Http,
            )
        },
        Rule {
            conditions: Conditions {
                status: vec![401, 403, 404],
                ..Conditions::default()
            },
            threshold: 40,
            window_secs: 10 * 60,
            ..rule(
                "Many errors",
                "Many requests refused or not found in a short time: guessing paths or credentials.",
                Kind::Http,
            )
        },
        Rule {
            threshold: 5,
            window_secs: 10 * 60,
            ..rule(
                "Failed logins",
                "Wrong passwords, several times in a short time.",
                Kind::AuthFailure,
            )
        },
        Rule {
            conditions: Conditions {
                user: Some("^(?:root|admin|administrator)$".to_owned()),
                ..Conditions::default()
            },
            ban: BanLength::Secs { secs: 365 * DAY },
            ..rule(
                "Root logins",
                "Logins as root or admin, which no service here allows.",
                Kind::AuthFailure,
            )
        },
        Rule {
            threshold: 2,
            ban: BanLength::Secs { secs: 365 * DAY },
            ..rule(
                "Unknown users",
                "Logins as users that don't exist, the way scanners guess.",
                Kind::InvalidUser,
            )
        },
        Rule {
            ban: BanLength::Secs { secs: 365 * DAY },
            ..rule(
                "Protocol probes",
                "Garbage instead of a protocol, or ancient algorithms only scanners still offer.",
                Kind::Probe,
            )
        },
    ]
}

/// The most rules a rule set holds: which ones matched a line is a 64-bit mask.
pub const MAX_RULES: usize = 64;

/// A condition's pattern: a regular expression, or with `!` before it, its negation.
#[derive(Debug)]
struct Matcher {
    regex: Regex,
    negated: bool,
}

impl Matcher {
    fn new(pattern: &str) -> Result<Self, regex::Error> {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        Ok(Self {
            regex: Regex::new(pattern)?,
            negated,
        })
    }

    fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text) != self.negated
    }
}

/// A rule ready to match events.
#[derive(Debug)]
pub struct Compiled {
    pub rule: Rule,
    path: Option<Matcher>,
    method: Option<Matcher>,
    user_agent: Option<Matcher>,
    user: Option<Matcher>,
    what: Option<Matcher>,
    /// Bits of the rule set's feeds the `listed` condition names; 0 without the condition.
    listed: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("rule {rule:?}, {field}: {message}")]
pub struct InvalidRule {
    pub rule: String,
    pub field: &'static str,
    pub message: String,
}

impl Compiled {
    /// `feeds` are the names of the rule set's feeds, in bit order.
    pub fn new(rule: Rule, feeds: &[&str]) -> Result<Self, InvalidRule> {
        let invalid = |field: &'static str, message: String| InvalidRule {
            rule: rule.name.clone(),
            field,
            message,
        };
        let compile = |field: &'static str, pattern: &Option<String>| {
            pattern
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(Matcher::new)
                .transpose()
                .map_err(|e| invalid(field, e.to_string()))
        };
        let c = &rule.conditions;
        if rule.threshold == 0 {
            return Err(invalid("threshold", "must be at least 1".to_owned()));
        }
        if !(8..=32).contains(&rule.prefix_v4) || !(16..=128).contains(&rule.prefix_v6) {
            return Err(invalid(
                "prefix",
                "IPv4 prefixes from 8 to 32, IPv6 from 16 to 128".to_owned(),
            ));
        }
        let http_only = c.path.is_some()
            || c.method.is_some()
            || c.user_agent.is_some()
            || !c.status.is_empty()
            || c.routed.is_some();
        if http_only && rule.kind != Kind::Http {
            return Err(invalid(
                "conditions",
                "path, method, status, route and user agent are for HTTP rules".to_owned(),
            ));
        }
        // A feed that doesn't exist (any more) matches nothing; the rule then never fires.
        let mut listed = 0;
        for name in &c.listed {
            if let Some(i) = feeds.iter().position(|f| f == name) {
                listed |= 1u64 << i.min(63);
            }
        }
        Ok(Self {
            path: compile("path", &c.path)?,
            method: compile("method", &c.method)?,
            user_agent: compile("userAgent", &c.user_agent)?,
            user: compile("user", &c.user)?,
            what: compile("what", &c.what)?,
            listed,
            rule,
        })
    }

    /// Whether the rule counts this event, given the bits of the feeds that list its address. `what` writes the
    /// event's description, for rules with a `what` condition (into a buffer the caller reuses).
    fn matches(&self, event: &Event<'_>, listed: u64, what: &mut String) -> bool {
        let c = &self.rule.conditions;
        if !c.listed.is_empty() && self.listed & listed == 0 {
            return false;
        }
        let test = |m: &Option<Matcher>, text: Option<&str>| {
            m.as_ref()
                .is_none_or(|m| text.is_some_and(|t| m.is_match(t)))
        };
        if let Event::Http(h) = event {
            if !c.status.is_empty() && !c.status.contains(&h.status) {
                return false;
            }
            if c.routed.is_some_and(|routed| h.routed != Some(routed)) {
                return false;
            }
            if !test(&self.path, Some(h.path))
                || !test(&self.method, Some(h.method))
                || !test(&self.user_agent, h.user_agent)
            {
                return false;
            }
        }
        if !test(&self.user, event.user()) {
            return false;
        }
        if let Some(m) = &self.what {
            if what.is_empty() {
                event.write_what(what);
            }
            return m.is_match(what);
        }
        true
    }
}

/// Everything that decides, line by line, whether a line matters: the rules, what they apply to, and the addresses
/// no rule acts on. Immutable: a new one replaces it when rules, feeds or lists change, and log sources share it.
#[derive(Debug, Default)]
pub struct RuleSet {
    /// Changes with every new rule set, so the engine knows which rules a hit's bits refer to.
    pub generation: u64,
    pub rules: Vec<Compiled>,
    /// Per source index: the bits of the rules that look at that source.
    by_source: Vec<u64>,
    /// Per kind (by `Kind::code`): the bits of the enabled rules of that kind.
    by_kind: [u64; 6],
    /// Exempt addresses and the allow list.
    allowed: barbican_common::net::NetSet,
    /// Feeds, in bit order, for `listed` conditions.
    feeds: Vec<std::sync::Arc<barbican_common::net::NetSet>>,
    /// Whether any rule has a `listed` condition (otherwise feeds aren't looked up at all).
    any_listed: bool,
}

impl RuleSet {
    /// `sources` are the configured sources' names in index order; `feeds` the enabled feeds' names and contents.
    pub fn new(
        generation: u64,
        rules: Vec<Rule>,
        sources: &[&str],
        feeds: &[(&str, std::sync::Arc<barbican_common::net::NetSet>)],
        allowed: barbican_common::net::NetSet,
    ) -> Result<Self, InvalidRule> {
        let feed_names: Vec<&str> = feeds.iter().take(MAX_RULES).map(|(n, _)| *n).collect();
        let compiled = rules
            .into_iter()
            .take(MAX_RULES)
            .map(|r| Compiled::new(r, &feed_names))
            .collect::<Result<Vec<_>, _>>()?;
        let mut by_source = vec![0u64; sources.len()];
        let mut by_kind = [0u64; 6];
        for (i, c) in compiled.iter().enumerate() {
            if !c.rule.enabled {
                continue;
            }
            let bit = 1u64 << i;
            if let Some(k) = usize::try_from(c.rule.kind.code())
                .ok()
                .and_then(|k| by_kind.get_mut(k))
            {
                *k |= bit;
            }
            for (s, name) in by_source.iter_mut().zip(sources) {
                if c.rule.sources.is_empty() || c.rule.sources.iter().any(|r| r == name) {
                    *s |= bit;
                }
            }
        }
        Ok(Self {
            generation,
            any_listed: compiled
                .iter()
                .any(|c| !c.rule.conditions.listed.is_empty()),
            rules: compiled,
            by_source,
            by_kind,
            allowed,
            feeds: feeds
                .iter()
                .take(MAX_RULES)
                .map(|(_, set)| std::sync::Arc::clone(set))
                .collect(),
        })
    }

    /// Whether no rule acts on the address (exempt, or on the allow list).
    #[must_use]
    pub fn allowed(&self, ip: std::net::IpAddr) -> bool {
        self.allowed.contains(ip)
    }

    /// The bits of the rules that count this event from source `source`. `what` is a buffer for the event's
    /// description, reused across lines; it is cleared first, and holds the description if a rule needed it.
    #[must_use]
    pub fn matches(
        &self,
        source: u16,
        ip: std::net::IpAddr,
        event: &Event<'_>,
        what: &mut String,
    ) -> u64 {
        what.clear();
        let Some(kind) = event.kind() else { return 0 };
        let by_kind = usize::try_from(kind.code())
            .ok()
            .and_then(|k| self.by_kind.get(k))
            .copied()
            .unwrap_or(0);
        let mut candidates = by_kind
            & self
                .by_source
                .get(usize::from(source))
                .copied()
                .unwrap_or(0);
        if candidates == 0 || self.allowed.contains(ip) {
            return 0;
        }
        let listed = if self.any_listed {
            self.feeds
                .iter()
                .enumerate()
                .filter(|(_, set)| set.contains(ip))
                .fold(0u64, |mask, (i, _)| mask | 1u64 << i)
        } else {
            0
        };
        let mut matched = 0;
        while candidates != 0 {
            let i = candidates.trailing_zeros();
            candidates &= candidates - 1;
            if let Some(rule) = self.rules.get(i as usize)
                && rule.matches(event, listed, what)
            {
                matched |= 1u64 << i;
            }
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use barbican_common::net::NetSet;

    use super::*;
    use crate::signal::Http;

    fn http<'a>(method: &'a str, path: &'a str, status: u16, routed: Option<bool>) -> Event<'a> {
        Event::Http(Http {
            method,
            path,
            status,
            routed,
            ..Http::default()
        })
    }

    fn default_rule(name: &str) -> Rule {
        defaults().into_iter().find(|r| r.name == name).unwrap()
    }

    /// A rule set of one rule over sources `web` and `ssh`.
    fn set(rule: Rule) -> RuleSet {
        let feeds = [(
            "tor",
            Arc::new(NetSet::new(&["203.0.113.0/24".parse().unwrap()])),
        )];
        let allowed = NetSet::new(&["10.0.0.0/8".parse().unwrap()]);
        RuleSet::new(1, vec![rule], &["web", "ssh"], &feeds, allowed).unwrap()
    }

    fn hit(set: &RuleSet, source: u16, ip: &str, event: &Event<'_>) -> bool {
        let mut what = String::new();
        set.matches(source, ip.parse().unwrap(), event, &mut what) != 0
    }

    const WEB: u16 = 0;
    const SSH: u16 = 1;
    const IP: &str = "198.51.100.1";

    #[test]
    fn defaults_compile() {
        let set = RuleSet::new(1, defaults(), &["a"], &[], NetSet::default()).unwrap();
        assert_eq!(set.rules.len(), defaults().len());
    }

    #[test]
    fn exploit_probes() {
        let r = set(default_rule("Exploit probes"));
        for path in [
            "/.env",
            "/.env.production",
            "/www/.git/config",
            "/.git/HEAD",
            "/wp-login.php",
            "/index.php?x=1",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/cgi-bin/luci",
            "/debug/pprof/",
            "/static/lang/custom/sbin/init",
            "/actuator/health",
            "/a/../../etc/passwd",
            "/product?q=%3Cimg%20src=1%20onerror=alert(1)%3E",
            "/x?${jndi:ldap://x}",
        ] {
            assert!(
                hit(&r, WEB, IP, &http("GET", path, 404, Some(true))),
                "{path}"
            );
        }
        for path in [
            "/",
            "/favicon.ico",
            "/api/v2/torrents/info?category=x",
            "/assets/index-abc.js",
            "/environment",
            "/robots.txt",
            "/.well-known/acme-challenge/x",
            "/photos/2024/IMG.jpg",
        ] {
            assert!(
                !hit(&r, WEB, IP, &http("GET", path, 200, Some(true))),
                "{path}"
            );
        }
    }

    #[test]
    fn unusual_methods() {
        let r = set(default_rule("Unusual methods"));
        for m in [
            "CONNECT",
            "CFKQ",
            "NPHV",
            "GETROUTERINFO",
            "SSTP_DUPLEX_POST",
            "JPFR",
            "KGFR",
            "TOLQ",
            "WEWP",
        ] {
            assert!(hit(&r, WEB, IP, &http(m, "/", 405, Some(true))), "{m}");
        }
        for m in [
            "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "PROPFIND", "MKCOL",
            "REPORT", "UNLOCK",
        ] {
            assert!(!hit(&r, WEB, IP, &http(m, "/", 200, Some(true))), "{m}");
        }
    }

    #[test]
    fn conditions() {
        let r = set(default_rule("No known host"));
        assert!(hit(&r, WEB, IP, &http("GET", "/", 404, Some(false))));
        assert!(!hit(&r, WEB, IP, &http("GET", "/", 404, Some(true))));
        assert!(!hit(&r, WEB, IP, &http("GET", "/", 404, None)));
        assert!(!hit(&r, WEB, IP, &Event::Probe { what: "x" }));
        // Allowed addresses match nothing.
        assert!(!hit(
            &r,
            WEB,
            "10.1.1.1",
            &http("GET", "/", 404, Some(false))
        ));

        let root = set(default_rule("Root logins"));
        assert!(hit(
            &root,
            SSH,
            IP,
            &Event::AuthFailure { user: Some("root") }
        ));
        assert!(!hit(
            &root,
            SSH,
            IP,
            &Event::AuthFailure {
                user: Some("rooted")
            }
        ));
        assert!(!hit(&root, SSH, IP, &Event::AuthFailure { user: None }));

        let mut rule = default_rule("Failed logins");
        rule.sources = vec!["ssh".into()];
        rule.conditions.listed = vec!["tor".into()];
        let r = set(rule);
        let fail = Event::AuthFailure { user: None };
        assert!(hit(&r, SSH, "203.0.113.4", &fail));
        assert!(!hit(&r, SSH, IP, &fail));
        assert!(!hit(&r, WEB, "203.0.113.4", &fail));

        let mut rule = default_rule("Failed logins");
        rule.conditions.listed = vec!["gone".into()];
        assert!(!hit(&set(rule), SSH, "203.0.113.4", &fail));

        let mut rule = default_rule("Failed logins");
        rule.enabled = false;
        assert!(!hit(&set(rule), SSH, IP, &fail));

        let mut rule = default_rule("Protocol probes");
        rule.conditions.what = Some("!banner".into());
        let r = set(rule);
        assert!(hit(
            &r,
            SSH,
            IP,
            &Event::Probe {
                what: "protocol error"
            }
        ));
        let mut what = String::new();
        assert_eq!(
            r.matches(
                SSH,
                IP.parse().unwrap(),
                &Event::Probe {
                    what: "invalid banner"
                },
                &mut what
            ),
            0
        );
        assert_eq!(what, "invalid banner");
    }

    #[test]
    fn masks() {
        let mut rules = defaults();
        rules[1].sources = vec!["ssh".into()];
        let set = RuleSet::new(1, rules, &["web", "ssh"], &[], NetSet::default()).unwrap();
        let mut what = String::new();
        let ip = IP.parse().unwrap();
        // "/.env" without a route: exploit probes (bit 0); "no known host" (bit 1) only looks at ssh.
        let event = http("GET", "/.env", 404, Some(false));
        // Bit 3: "many errors" counts 404s.
        assert_eq!(set.matches(WEB, ip, &event, &mut what), 0b1001);
        assert_eq!(set.matches(SSH, ip, &event, &mut what), 0b1011);
        assert_eq!(set.matches(7, ip, &event, &mut what), 0);
        assert_eq!(
            set.matches(WEB, ip, &Event::Session { user: "a" }, &mut what),
            0
        );
    }

    #[test]
    fn invalid_rules() {
        let compile = |rule| Compiled::new(rule, &[]);
        let mut rule = default_rule("Exploit probes");
        rule.conditions.path = Some("(".into());
        assert_eq!(compile(rule).unwrap_err().field, "path");
        let mut rule = default_rule("Exploit probes");
        rule.threshold = 0;
        assert!(compile(rule).is_err());
        let mut rule = default_rule("Exploit probes");
        rule.prefix_v4 = 4;
        assert!(compile(rule).is_err());
        let mut rule = default_rule("Failed logins");
        rule.conditions.path = Some("x".into());
        assert_eq!(compile(rule).unwrap_err().field, "conditions");
    }

    fn country(code: &str) -> Who<'_> {
        Who {
            country: Some(code),
            ..Who::default()
        }
    }

    #[test]
    fn shared_networks() {
        let policy = Policy {
            ban_secs: 90 * DAY,
            country_lengths: vec![CountryLength {
                country: "CA".into(),
                secs: 2 * HOUR,
            }],
            asn_lengths: vec![AsnLength {
                asn: 64_500,
                secs: HOUR,
            }],
            list_lengths: vec![ListLength {
                list: "relay".into(),
                secs: 30 * 60,
            }],
            repeat_multiplier: 2,
            ..Policy::default()
        };
        let asn = Who {
            country: Some("CA"),
            asn: Some(64_500),
            listed: &[],
        };
        assert_eq!(policy.length(BanLength::Default, &asn, 0), Some(HOUR));
        assert_eq!(policy.length(BanLength::Default, &asn, 1), Some(2 * HOUR));
        let relay = Who {
            country: None,
            asn: Some(1),
            listed: &["tor", "relay"],
        };
        assert_eq!(
            policy.length(BanLength::Secs { secs: 365 * DAY }, &relay, 0),
            Some(30 * 60)
        );
        let other = Who {
            country: Some("DE"),
            asn: Some(1),
            listed: &["tor"],
        };
        assert_eq!(policy.length(BanLength::Default, &other, 0), Some(90 * DAY));
    }

    #[test]
    fn lengths() {
        let policy = Policy {
            ban_secs: 90 * DAY,
            country_lengths: vec![CountryLength {
                country: "LV".into(),
                secs: HOUR,
            }],
            repeat_multiplier: 2,
            max_ban_secs: 365 * DAY,
            ..Policy::default()
        };
        assert_eq!(
            policy.length(BanLength::Default, &Who::default(), 0),
            Some(90 * DAY)
        );
        assert_eq!(
            policy.length(BanLength::Default, &country("lv"), 0),
            Some(HOUR)
        );
        assert_eq!(
            policy.length(BanLength::Secs { secs: 365 * DAY }, &country("LV"), 0),
            Some(HOUR)
        );
        assert_eq!(
            policy.length(BanLength::Default, &country("LV"), 3),
            Some(8 * HOUR)
        );
        assert_eq!(
            policy.length(BanLength::Default, &country("DE"), 2),
            Some(360 * DAY)
        );
        assert_eq!(
            policy.length(BanLength::Default, &country("DE"), 3),
            Some(365 * DAY)
        );
        assert_eq!(
            policy.length(BanLength::Secs { secs: 400 * DAY }, &Who::default(), 0),
            Some(400 * DAY)
        );
        assert_eq!(policy.length(BanLength::Forever, &country("LV"), 0), None);
        assert_eq!(
            policy.length(BanLength::Default, &Who::default(), 1000),
            Some(365 * DAY)
        );
    }

    #[test]
    fn json_shape() {
        let json = serde_json::to_value(default_rule("Exploit probes")).unwrap();
        assert_eq!(
            json["ban"],
            serde_json::json!({"type": "secs", "secs": 365 * DAY})
        );
        assert_eq!(json["kind"], "http");
        let back: Rule = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "Exploit probes");
        let policy: Policy = serde_json::from_str(r#"{"banSecs": 60}"#).unwrap();
        assert_eq!(policy.ban_secs, 60);
        assert_eq!(policy.trust_secs, 30 * DAY);
    }
}
