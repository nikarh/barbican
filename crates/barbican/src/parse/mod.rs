//! Parsers: from a log line to an address and what it did. A line a parser doesn't know is skipped.

use std::net::IpAddr;

use crate::config::{ParserKind, Source};
use crate::signal::Event;

mod authelia;
mod pattern;
mod sshd;
mod traefik;

pub use pattern::Pattern;

#[derive(Debug)]
pub enum Parser {
    Traefik,
    Sshd,
    Authelia,
    Regex(Pattern),
}

#[derive(Debug, thiserror::Error)]
#[error("source {source_name:?}: {message}")]
pub struct Error {
    pub source_name: String,
    pub message: String,
}

impl Parser {
    pub fn for_source(source: &Source) -> Result<Self, Error> {
        Ok(match source.parser {
            ParserKind::Traefik => Self::Traefik,
            ParserKind::Sshd => Self::Sshd,
            ParserKind::Authelia => Self::Authelia,
            ParserKind::Regex => {
                let error = |message: String| Error {
                    source_name: source.name.clone(),
                    message,
                };
                let (Some(pattern), Some(kind)) = (&source.pattern, source.kind) else {
                    return Err(error(
                        "a regex source needs `pattern` and `kind`".to_owned(),
                    ));
                };
                Self::Regex(Pattern::new(pattern, kind).map_err(error)?)
            }
        })
    }

    pub fn parse(&self, line: &str) -> Option<(IpAddr, Event)> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (ip, event) = match self {
            Self::Traefik => traefik::parse(line),
            Self::Sshd => sshd::parse(line),
            Self::Authelia => authelia::parse(line),
            Self::Regex(pattern) => pattern.parse(line),
        }?;
        Some((barbican_common::net::canonical(ip), event))
    }
}

/// An address as logs write it: bare, in brackets, or with a port.
pub(crate) fn ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    // 192.0.2.1:443 (one colon, so not IPv6).
    if s.matches(':').count() == 1 {
        return s.split(':').next()?.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(ip("192.0.2.1"), "192.0.2.1".parse().ok());
        assert_eq!(ip("192.0.2.1:8443"), "192.0.2.1".parse().ok());
        assert_eq!(ip("[2001:db8::1]:22"), "2001:db8::1".parse().ok());
        assert_eq!(ip("2001:db8::1"), "2001:db8::1".parse().ok());
        assert_eq!(ip("example.com"), None);
    }

    #[test]
    fn mapped_addresses_become_ipv4() {
        let (ip, _) = Parser::Sshd
            .parse("Invalid user admin from ::ffff:192.0.2.9 port 4242")
            .unwrap();
        assert_eq!(ip, "192.0.2.9".parse::<IpAddr>().unwrap());
    }
}
