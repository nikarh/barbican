//! OpenSSH's sshd, from its own messages (`Invalid user admin from 192.0.2.1 port 4242`), with or without a
//! syslog prefix (`sshd[123]: `). Messages without an address (most `kex_exchange_identification` errors) can't be
//! told apart by who sent them and are skipped.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;

use crate::signal::Event;

#[derive(Debug, Clone, Copy)]
enum What {
    InvalidUser,
    Failure,
    Success,
    Probe(&'static str),
}

/// The messages that mean something, each with groups `user` (when it names one) and `ip`.
static MESSAGES: LazyLock<Vec<(Regex, What)>> = LazyLock::new(|| {
    let patterns: [(&str, What); 11] = [
        (
            r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port \d+)?\s*$",
            What::InvalidUser,
        ),
        (
            r"^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+",
            What::Failure,
        ),
        (
            r"^(?:Disconnected from|Connection closed by) authenticating user (?P<user>.*?) (?P<ip>\S+) port \d+ \[preauth\]",
            What::Failure,
        ),
        (
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+",
            What::Failure,
        ),
        (
            r"^(?:error: )?PAM: Authentication failure for (?:illegal user )?(?P<user>.*?) from (?P<ip>\S+)",
            What::Failure,
        ),
        (
            r"^Accepted \S+ for (?P<user>.*?) from (?P<ip>\S+) port \d+",
            What::Success,
        ),
        (
            r"^banner exchange: Connection from (?P<ip>\S+) port \d+: invalid format",
            What::Probe("invalid banner"),
        ),
        (
            r"^Bad protocol version identification .* from (?P<ip>\S+)",
            What::Probe("bad protocol version"),
        ),
        (
            r"^Did not receive identification string from (?P<ip>\S+)",
            What::Probe("no identification"),
        ),
        (
            r"^Unable to negotiate with (?P<ip>\S+) port \d+: no matching (?P<what>[a-z ]+?) found",
            What::Probe("no matching algorithms"),
        ),
        (
            r"^ssh_dispatch_run_fatal: Connection from (?:authenticating user \S+ )?(?P<ip>\S+) port \d+: (?:invalid|message authentication code incorrect|Connection corrupted)",
            What::Probe("protocol error"),
        ),
    ];
    patterns
        .into_iter()
        .filter_map(|(p, what)| Regex::new(p).ok().map(|r| (r, what)))
        .collect()
});

/// `sshd[123]: `, `sshd-session[123]: `, and a syslog timestamp and host before them.
static PREFIX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(?:.*?\bsshd(?:-session)?(?:\[\d+\])?: )").ok());

pub fn parse(line: &str) -> Option<(IpAddr, Event)> {
    let message = PREFIX
        .as_ref()
        .and_then(|p| p.find(line))
        .map_or(line, |m| line.get(m.end()..).unwrap_or(line));
    for (regex, what) in MESSAGES.iter() {
        let Some(captures) = regex.captures(message) else {
            continue;
        };
        let ip = super::ip(captures.name("ip")?.as_str())?;
        let user = captures.name("user").map(|u| u.as_str().to_owned());
        let event = match what {
            What::InvalidUser => Event::InvalidUser {
                user: user.unwrap_or_default(),
            },
            What::Failure => Event::AuthFailure { user },
            What::Success => Event::AuthSuccess {
                user: user.unwrap_or_default(),
            },
            What::Probe(what) => Event::Probe {
                what: (*what).to_owned(),
            },
        };
        return Some((ip, event));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, Event)> {
        parse(line).map(|(ip, e)| (ip.to_string(), e))
    }

    #[test]
    fn messages() {
        assert_eq!(
            p("Invalid user admin from 203.0.113.9 port 51234"),
            Some((
                "203.0.113.9".into(),
                Event::InvalidUser {
                    user: "admin".into()
                }
            ))
        );
        assert_eq!(
            p("Invalid user  from 203.0.113.9 port 51234"),
            Some((
                "203.0.113.9".into(),
                Event::InvalidUser {
                    user: String::new()
                }
            ))
        );
        assert_eq!(
            p("Disconnected from authenticating user root 198.51.100.3 port 4011 [preauth]"),
            Some((
                "198.51.100.3".into(),
                Event::AuthFailure {
                    user: Some("root".into())
                }
            ))
        );
        assert_eq!(
            p("Failed password for invalid user oracle from 2001:db8::5 port 22 ssh2"),
            Some((
                "2001:db8::5".into(),
                Event::AuthFailure {
                    user: Some("oracle".into())
                }
            ))
        );
        assert_eq!(
            p("Accepted publickey for backups from 192.0.2.25 port 50432 ssh2: RSA SHA256:abc"),
            Some((
                "192.0.2.25".into(),
                Event::AuthSuccess {
                    user: "backups".into()
                }
            ))
        );
        assert_eq!(
            p("banner exchange: Connection from 203.0.113.77 port 61000: invalid format"),
            Some((
                "203.0.113.77".into(),
                Event::Probe {
                    what: "invalid banner".into()
                }
            ))
        );
        assert_eq!(
            p(
                "Unable to negotiate with 203.0.113.78 port 22: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1"
            ),
            Some((
                "203.0.113.78".into(),
                Event::Probe {
                    what: "no matching algorithms".into()
                }
            ))
        );
    }

    #[test]
    fn syslog_prefix() {
        assert_eq!(
            p("Nov 10 15:42:51 host sshd-session[4242]: Invalid user ubnt from 203.0.113.1 port 1"),
            Some((
                "203.0.113.1".into(),
                Event::InvalidUser {
                    user: "ubnt".into()
                }
            ))
        );
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
        // The disconnect after a closed session isn't preauth.
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
