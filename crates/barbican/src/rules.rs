//! Rules (what counts as abuse, and what to do about it) and the ban policy (for how long). Both are edited in the
//! UI and stored in the database; the defaults below are what a new database starts with.

use std::collections::BTreeMap;

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
    /// How long a ban by `rule` lasts for an address of `country` that was banned `previous` times before.
    /// `None`: until lifted.
    #[must_use]
    pub fn length(&self, rule: BanLength, country: Option<&str>, previous: u32) -> Option<u64> {
        let base = match rule {
            BanLength::Forever => return None,
            BanLength::Default => self.ban_secs,
            BanLength::Secs { secs } => secs,
        };
        let base = country
            .and_then(|c| {
                self.country_lengths
                    .iter()
                    .find(|l| l.country.eq_ignore_ascii_case(c))
            })
            .map_or(base, |l| l.secs);
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

/// A rule ready to match events.
#[derive(Debug)]
pub struct Compiled {
    pub rule: Rule,
    path: Option<Matcher>,
    method: Option<Matcher>,
    user_agent: Option<Matcher>,
    user: Option<Matcher>,
    what: Option<Matcher>,
}

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

#[derive(Debug, thiserror::Error)]
#[error("rule {rule:?}, {field}: {message}")]
pub struct InvalidRule {
    pub rule: String,
    pub field: &'static str,
    pub message: String,
}

impl Compiled {
    pub fn new(rule: Rule) -> Result<Self, InvalidRule> {
        let compile = |field: &'static str, pattern: &Option<String>| {
            pattern
                .as_deref()
                .filter(|p| !p.is_empty())
                .map(Matcher::new)
                .transpose()
                .map_err(|e| InvalidRule {
                    rule: rule.name.clone(),
                    field,
                    message: e.to_string(),
                })
        };
        let c = &rule.conditions;
        let compiled = Self {
            path: compile("path", &c.path)?,
            method: compile("method", &c.method)?,
            user_agent: compile("userAgent", &c.user_agent)?,
            user: compile("user", &c.user)?,
            what: compile("what", &c.what)?,
            rule,
        };
        if compiled.rule.threshold == 0 {
            return Err(InvalidRule {
                rule: compiled.rule.name,
                field: "threshold",
                message: "must be at least 1".to_owned(),
            });
        }
        if compiled.rule.prefix_v4 > 32
            || compiled.rule.prefix_v6 > 128
            || compiled.rule.prefix_v4 < 8
            || compiled.rule.prefix_v6 < 16
        {
            return Err(InvalidRule {
                rule: compiled.rule.name,
                field: "prefix",
                message: "IPv4 prefixes from 8 to 32, IPv6 from 16 to 128".to_owned(),
            });
        }
        Ok(compiled)
    }

    /// Whether the rule counts this event from this source. `listed` names the blocklists the address is in.
    #[must_use]
    pub fn matches(&self, source: &str, event: &Event, listed: &[&str]) -> bool {
        let r = &self.rule;
        if !r.enabled || event.kind() != Some(r.kind) {
            return false;
        }
        if !r.sources.is_empty() && !r.sources.iter().any(|s| s == source) {
            return false;
        }
        let c = &r.conditions;
        if !c.listed.is_empty() && !c.listed.iter().any(|l| listed.contains(&l.as_str())) {
            return false;
        }
        let test = |regex: &Option<Matcher>, text: Option<&str>| {
            regex
                .as_ref()
                .is_none_or(|re| text.is_some_and(|t| re.is_match(t)))
        };
        if let Event::Http(h) = event {
            if !c.status.is_empty() && !c.status.contains(&h.status) {
                return false;
            }
            if c.routed.is_some_and(|routed| h.routed != Some(routed)) {
                return false;
            }
            if !test(&self.path, Some(&h.path)) || !test(&self.method, Some(&h.method)) {
                return false;
            }
            if !test(&self.user_agent, h.user_agent.as_deref()) {
                return false;
            }
        } else if self.path.is_some()
            || self.method.is_some()
            || self.user_agent.is_some()
            || !c.status.is_empty()
            || c.routed.is_some()
        {
            return false;
        }
        test(&self.user, event.user())
            && (self.what.is_none() || test(&self.what, Some(&event.what())))
    }
}

/// Every country's length, by code; for the UI.
#[must_use]
pub fn country_lengths(policy: &Policy) -> BTreeMap<String, u64> {
    policy
        .country_lengths
        .iter()
        .map(|l| (l.country.to_ascii_uppercase(), l.secs))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Http;

    fn http(method: &str, path: &str, status: u16, routed: Option<bool>) -> Event {
        Event::Http(Http {
            method: method.into(),
            path: path.into(),
            status,
            routed,
            ..Http::default()
        })
    }

    fn by_name(name: &str) -> Compiled {
        Compiled::new(defaults().into_iter().find(|r| r.name == name).unwrap()).unwrap()
    }

    #[test]
    fn defaults_compile() {
        for rule in defaults() {
            Compiled::new(rule).unwrap();
        }
    }

    #[test]
    fn exploit_probes() {
        let r = by_name("Exploit probes");
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
                r.matches("web", &http("GET", path, 404, Some(true)), &[]),
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
                !r.matches("web", &http("GET", path, 200, Some(true)), &[]),
                "{path}"
            );
        }
    }

    #[test]
    fn unusual_methods() {
        let r = by_name("Unusual methods");
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
            assert!(r.matches("web", &http(m, "/", 405, Some(true)), &[]), "{m}");
        }
        for m in [
            "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "PROPFIND", "MKCOL",
            "REPORT", "UNLOCK",
        ] {
            assert!(
                !r.matches("web", &http(m, "/", 200, Some(true)), &[]),
                "{m}"
            );
        }
    }

    #[test]
    fn conditions() {
        let r = by_name("No known host");
        assert!(r.matches("web", &http("GET", "/", 404, Some(false)), &[]));
        assert!(!r.matches("web", &http("GET", "/", 404, Some(true)), &[]));
        assert!(!r.matches("web", &http("GET", "/", 404, None), &[]));
        assert!(!r.matches("web", &Event::Probe { what: "x".into() }, &[]));

        let root = by_name("Root logins");
        assert!(root.matches(
            "ssh",
            &Event::AuthFailure {
                user: Some("root".into())
            },
            &[]
        ));
        assert!(!root.matches(
            "ssh",
            &Event::AuthFailure {
                user: Some("rooted".into())
            },
            &[]
        ));
        assert!(!root.matches("ssh", &Event::AuthFailure { user: None }, &[]));

        let mut rule = by_name("Failed logins").rule;
        rule.sources = vec!["ssh".into()];
        rule.conditions.listed = vec!["tor".into()];
        let r = Compiled::new(rule).unwrap();
        let fail = Event::AuthFailure { user: None };
        assert!(r.matches("ssh", &fail, &["tor"]));
        assert!(!r.matches("ssh", &fail, &[]));
        assert!(!r.matches("web", &fail, &["tor"]));

        let mut rule = by_name("Failed logins").rule;
        rule.conditions.path = Some("x".into());
        assert!(!Compiled::new(rule).unwrap().matches("ssh", &fail, &[]));

        let mut rule = by_name("Failed logins").rule;
        rule.enabled = false;
        assert!(!Compiled::new(rule).unwrap().matches("ssh", &fail, &[]));
    }

    #[test]
    fn invalid_rules() {
        let mut rule = by_name("Exploit probes").rule;
        rule.conditions.path = Some("(".into());
        assert_eq!(Compiled::new(rule).unwrap_err().field, "path");
        let mut rule = by_name("Exploit probes").rule;
        rule.threshold = 0;
        assert!(Compiled::new(rule).is_err());
        let mut rule = by_name("Exploit probes").rule;
        rule.prefix_v4 = 4;
        assert!(Compiled::new(rule).is_err());
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
        assert_eq!(policy.length(BanLength::Default, None, 0), Some(90 * DAY));
        assert_eq!(policy.length(BanLength::Default, Some("lv"), 0), Some(HOUR));
        assert_eq!(
            policy.length(BanLength::Secs { secs: 365 * DAY }, Some("LV"), 0),
            Some(HOUR)
        );
        assert_eq!(
            policy.length(BanLength::Default, Some("LV"), 3),
            Some(8 * HOUR)
        );
        assert_eq!(
            policy.length(BanLength::Default, Some("DE"), 2),
            Some(360 * DAY)
        );
        assert_eq!(
            policy.length(BanLength::Default, Some("DE"), 3),
            Some(365 * DAY)
        );
        assert_eq!(
            policy.length(BanLength::Secs { secs: 400 * DAY }, None, 0),
            Some(400 * DAY)
        );
        assert_eq!(policy.length(BanLength::Forever, Some("LV"), 0), None);
        assert_eq!(
            policy.length(BanLength::Default, None, 1000),
            Some(365 * DAY)
        );
    }

    #[test]
    fn json_shape() {
        let json = serde_json::to_value(by_name("Exploit probes").rule).unwrap();
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
