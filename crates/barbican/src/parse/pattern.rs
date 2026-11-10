//! A parser from a regular expression, for logs barbican has no parser for. The group `ip` is the address; the
//! others depend on the kind: `method`, `path`, `status`, `host`, `agent` for HTTP requests, `user` for logins,
//! `what` for probes.

use std::net::IpAddr;

use regex::{CaptureLocations, Regex};

use crate::config::RegexKind;
use crate::signal::{Event, Http};

#[derive(Debug)]
pub struct Pattern {
    regex: Regex,
    kind: RegexKind,
    locations: CaptureLocations,
    /// Group indexes: ip, method, path, status, host, agent, user, what.
    groups: [Option<usize>; 8],
}

const NAMES: [&str; 8] = [
    "ip", "method", "path", "status", "host", "agent", "user", "what",
];

impl Pattern {
    pub fn new(pattern: &str, kind: RegexKind) -> Result<Self, String> {
        let regex = Regex::new(pattern).map_err(|e| e.to_string())?;
        let groups = NAMES.map(|name| regex.capture_names().position(|n| n == Some(name)));
        if groups[0].is_none() {
            return Err("the pattern needs a group named `ip`".to_owned());
        }
        let locations = regex.capture_locations();
        Ok(Self {
            regex,
            kind,
            locations,
            groups,
        })
    }

    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        self.regex.captures_read(&mut self.locations, line)?;
        let locations = &self.locations;
        let [ip, method, path, status, host, agent, user, what] = self
            .groups
            .map(|g| super::group(locations, g, line).filter(|s| !s.is_empty()));
        let ip = super::ip(ip?)?;
        let event = match self.kind {
            RegexKind::Http => Event::Http(Http {
                method: method.unwrap_or(""),
                path: path.unwrap_or(""),
                status: status.and_then(|s| s.parse().ok()).unwrap_or(0),
                host,
                routed: None,
                router: None,
                user_agent: agent,
            }),
            RegexKind::AuthFailure => Event::AuthFailure { user },
            RegexKind::AuthSuccess => Event::AuthSuccess {
                user: user.unwrap_or(""),
            },
            RegexKind::InvalidUser => Event::InvalidUser {
                user: user.unwrap_or(""),
            },
            RegexKind::Probe => Event::Probe {
                what: what.unwrap_or(line),
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
        let mut p = Pattern::new(
            r"login failed for (?P<user>\S+) from (?P<ip>\S+)",
            RegexKind::AuthFailure,
        )
        .unwrap();
        let (ip, event) = p
            .parse("2026 app: login failed for carol from 198.51.100.2")
            .unwrap();
        assert_eq!(
            (ip.to_string(), event),
            (
                "198.51.100.2".to_owned(),
                Event::AuthFailure {
                    user: Some("carol")
                }
            )
        );
        assert!(p.parse("unrelated").is_none());

        let mut p = Pattern::new(
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
