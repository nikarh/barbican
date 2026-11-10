//! OpenSSH's sshd, from its own messages (`Invalid user admin from 192.0.2.1 port 4242`), with or without a
//! syslog prefix (`sshd[123]: `). Messages without an address (most `kex_exchange_identification` errors) can't be
//! told apart by who sent them and are skipped.
//!
//! Each message is recognized by a literal prefix first, so most lines never reach a regular expression.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::{CaptureLocations, Regex};

use crate::signal::Event;

#[derive(Debug, Clone, Copy)]
enum What {
    InvalidUser,
    Failure,
    Success,
    Probe(&'static str),
}

struct Message {
    prefixes: &'static [&'static str],
    regex: Regex,
    what: What,
    ip: Option<usize>,
    user: Option<usize>,
}

type Spec = (&'static [&'static str], &'static str, What);

/// The messages that mean something, each with groups `ip` and, when it names one, `user`.
const SPECS: [Spec; 11] = [
    (
        &["Invalid user "],
        r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port \d+)?\s*$",
        What::InvalidUser,
    ),
    (
        &["Failed "],
        r"^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+",
        What::Failure,
    ),
    (
        &[
            "Disconnected from authenticating user ",
            "Connection closed by authenticating user ",
        ],
        r"^(?:Disconnected from|Connection closed by) authenticating user (?P<user>.*?) (?P<ip>\S+) port \d+ \[preauth\]",
        What::Failure,
    ),
    (
        &["error: maximum authentication attempts exceeded "],
        r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+",
        What::Failure,
    ),
    (
        &[
            "PAM: Authentication failure ",
            "error: PAM: Authentication failure ",
        ],
        r"^(?:error: )?PAM: Authentication failure for (?:illegal user )?(?P<user>.*?) from (?P<ip>\S+)",
        What::Failure,
    ),
    (
        &["Accepted "],
        r"^Accepted \S+ for (?P<user>.*?) from (?P<ip>\S+) port \d+",
        What::Success,
    ),
    (
        &["banner exchange: "],
        r"^banner exchange: Connection from (?P<ip>\S+) port \d+: invalid format",
        What::Probe("invalid banner"),
    ),
    (
        &["Bad protocol version identification "],
        r"^Bad protocol version identification .* from (?P<ip>\S+)",
        What::Probe("bad protocol version"),
    ),
    (
        &["Did not receive identification string "],
        r"^Did not receive identification string from (?P<ip>\S+)",
        What::Probe("no identification"),
    ),
    (
        &["Unable to negotiate with "],
        r"^Unable to negotiate with (?P<ip>\S+) port \d+: no matching [a-z ]+ found",
        What::Probe("no matching algorithms"),
    ),
    (
        &["ssh_dispatch_run_fatal: "],
        r"^ssh_dispatch_run_fatal: Connection from (?:authenticating user \S+ )?(?P<ip>\S+) port \d+: (?:invalid|message authentication code incorrect|Connection corrupted)",
        What::Probe("protocol error"),
    ),
];

static MESSAGES: LazyLock<Vec<Message>> = LazyLock::new(|| {
    SPECS
        .into_iter()
        .filter_map(|(prefixes, pattern, what)| {
            let regex = Regex::new(pattern).ok()?;
            let index = |name| regex.capture_names().position(|n| n == Some(name));
            Some(Message {
                prefixes,
                ip: index("ip"),
                user: index("user"),
                regex,
                what,
            })
        })
        .collect()
});

#[derive(Debug, Default)]
pub struct Sshd {
    /// One per message, created on first use.
    locations: Vec<Option<CaptureLocations>>,
}

/// The message without a syslog prefix: `Nov 10 15:42:51 host sshd-session[42]: <message>`.
fn message(line: &str) -> &str {
    let Some(at) = line.find("sshd") else {
        return line;
    };
    if at > 0 && line.as_bytes().get(at - 1) != Some(&b' ') {
        return line;
    }
    let rest = line.get(at..).unwrap_or("");
    let Some(colon) = rest.find(": ") else {
        return line;
    };
    let tag = rest.get(..colon).unwrap_or("");
    let tail = tag
        .trim_start_matches("sshd")
        .trim_start_matches("-session");
    if tail.is_empty() || (tail.starts_with('[') && tail.ends_with(']')) {
        rest.get(colon + 2..).unwrap_or(line)
    } else {
        line
    }
}

impl Sshd {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let text = message(line);
        let messages = &*MESSAGES;
        if self.locations.len() != messages.len() {
            self.locations = messages.iter().map(|_| None).collect();
        }
        let (m, locations) = messages
            .iter()
            .zip(self.locations.iter_mut())
            .find(|(m, _)| m.prefixes.iter().any(|p| text.starts_with(p)))?;
        let locations = locations.get_or_insert_with(|| m.regex.capture_locations());
        m.regex.captures_read(locations, text)?;
        let ip = super::ip(super::group(locations, m.ip, text)?)?;
        let user = super::group(locations, m.user, text);
        let event = match m.what {
            What::InvalidUser => Event::InvalidUser {
                user: user.unwrap_or(""),
            },
            What::Failure => Event::AuthFailure { user },
            What::Success => Event::AuthSuccess {
                user: user.unwrap_or(""),
            },
            What::Probe(what) => Event::Probe { what },
        };
        Some((ip, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, String)> {
        let mut parser = Sshd::default();
        parser
            .parse(line)
            .map(|(ip, e)| (ip.to_string(), format!("{e:?}")))
    }

    #[allow(clippy::unnecessary_wraps, reason = "compared with p()'s result")]
    fn some(ip: &str, event: &str) -> Option<(String, String)> {
        Some((ip.to_owned(), event.to_owned()))
    }

    #[test]
    fn messages() {
        assert_eq!(
            p("Invalid user admin from 203.0.113.9 port 51234"),
            some("203.0.113.9", r#"InvalidUser { user: "admin" }"#)
        );
        assert_eq!(
            p("Invalid user  from 203.0.113.9 port 51234"),
            some("203.0.113.9", r#"InvalidUser { user: "" }"#)
        );
        assert_eq!(
            p("Disconnected from authenticating user root 198.51.100.3 port 4011 [preauth]"),
            some("198.51.100.3", r#"AuthFailure { user: Some("root") }"#)
        );
        assert_eq!(
            p("Failed password for invalid user oracle from 2001:db8::5 port 22 ssh2"),
            some("2001:db8::5", r#"AuthFailure { user: Some("oracle") }"#)
        );
        assert_eq!(
            p("Accepted publickey for backups from 192.0.2.25 port 50432 ssh2: RSA SHA256:abc"),
            some("192.0.2.25", r#"AuthSuccess { user: "backups" }"#)
        );
        assert_eq!(
            p("banner exchange: Connection from 203.0.113.77 port 61000: invalid format"),
            some("203.0.113.77", r#"Probe { what: "invalid banner" }"#)
        );
        assert_eq!(
            p(
                "Unable to negotiate with 203.0.113.78 port 22: no matching key exchange method found. Their offer: x"
            ),
            some(
                "203.0.113.78",
                r#"Probe { what: "no matching algorithms" }"#
            )
        );
    }

    #[test]
    fn syslog_prefix() {
        assert_eq!(
            p("Nov 10 15:42:51 host sshd-session[4242]: Invalid user ubnt from 203.0.113.1 port 1"),
            some("203.0.113.1", r#"InvalidUser { user: "ubnt" }"#)
        );
        assert_eq!(
            p("sshd: Invalid user a from 203.0.113.1 port 1").map(|x| x.0),
            Some("203.0.113.1".to_owned())
        );
        assert_eq!(
            message("Invalid user sshd from 192.0.2.1 port 1"),
            "Invalid user sshd from 192.0.2.1 port 1"
        );
    }

    #[test]
    fn reuses_one_parser() {
        let mut parser = Sshd::default();
        for i in 1..=3 {
            let line = format!("Invalid user u{i} from 192.0.2.{i} port 1");
            let (ip, event) = parser.parse(&line).unwrap();
            assert_eq!(ip.to_string(), format!("192.0.2.{i}"));
            assert_eq!(event.user(), Some(format!("u{i}").as_str()));
        }
    }

    #[test]
    fn skips_the_rest() {
        assert_eq!(
            p("Connection from 203.0.113.1 port 1 on 172.20.0.2 port 22 rdomain \"\""),
            None
        );
        assert_eq!(
            p("kex_exchange_identification: Connection closed by remote host"),
            None
        );
        assert_eq!(
            p("Received disconnect from 192.0.2.25 port 50432:11: disconnected by user"),
            None
        );
        // An invalid user is only counted once: the "connection closed" that follows is skipped.
        assert_eq!(
            p("Connection closed by invalid user admin 203.0.113.9 port 51234 [preauth]"),
            None
        );
    }
}
