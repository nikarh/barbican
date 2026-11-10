//! A parser from a regular expression, for logs barbican has no parser for. The group `ip` is the address; the
//! others depend on the kind: `method`, `path`, `status`, `host` for HTTP requests, `user` for logins, `what` for
//! probes.

use std::net::IpAddr;

use regex::Regex;

use crate::config::RegexKind;
use crate::signal::{Event, Http};

#[derive(Debug)]
pub struct Pattern {
    regex: Regex,
    kind: RegexKind,
}

impl Pattern {
    pub fn new(pattern: &str, kind: RegexKind) -> Result<Self, String> {
        let regex = Regex::new(pattern).map_err(|e| e.to_string())?;
        if !regex.capture_names().flatten().any(|n| n == "ip") {
            return Err("the pattern needs a group named `ip`".to_owned());
        }
        Ok(Self { regex, kind })
    }

    pub fn parse(&self, line: &str) -> Option<(IpAddr, Event)> {
        let captures = self.regex.captures(line)?;
        let group = |name: &str| {
            captures
                .name(name)
                .map(|m| m.as_str().to_owned())
                .filter(|s| !s.is_empty())
        };
        let ip = super::ip(&group("ip")?)?;
        let event = match self.kind {
            RegexKind::Http => Event::Http(Http {
                method: group("method").unwrap_or_default(),
                path: group("path").unwrap_or_default(),
                status: group("status").and_then(|s| s.parse().ok()).unwrap_or(0),
                host: group("host"),
                routed: None,
                user_agent: group("agent"),
            }),
            RegexKind::AuthFailure => Event::AuthFailure {
                user: group("user"),
            },
            RegexKind::AuthSuccess => Event::AuthSuccess {
                user: group("user").unwrap_or_default(),
            },
            RegexKind::InvalidUser => Event::InvalidUser {
                user: group("user").unwrap_or_default(),
            },
            RegexKind::Probe => Event::Probe {
                what: group("what").unwrap_or_else(|| line.to_owned()),
            },
        };
        Some((ip, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_by_kind() {
        let p = Pattern::new(
            r"login failed for (?P<user>\S+) from (?P<ip>\S+)",
            RegexKind::AuthFailure,
        )
        .unwrap();
        assert_eq!(
            p.parse("2026 app: login failed for carol from 198.51.100.2"),
            Some((
                "198.51.100.2".parse().unwrap(),
                Event::AuthFailure {
                    user: Some("carol".into())
                }
            ))
        );
        assert_eq!(p.parse("unrelated"), None);

        let p = Pattern::new(
            r#"^(?P<ip>\S+) .*"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d+)"#,
            RegexKind::Http,
        )
        .unwrap();
        let (_, e) = p
            .parse(r#"192.0.2.3 - - [x] "GET /admin HTTP/1.1" 403 12"#)
            .unwrap();
        assert_eq!(e.what(), "GET /admin → 403");

        assert!(Pattern::new("no ip group", RegexKind::Probe).is_err());
        assert!(Pattern::new("(?P<ip>", RegexKind::Probe).is_err());
    }
}
