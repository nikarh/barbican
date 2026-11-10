//! Parsers: from a log line to an address and what it did. A line a parser doesn't know is skipped.
//!
//! Every line of every source goes through a parser, so they don't allocate: events borrow from the line, or,
//! when a field had to be unescaped, from a buffer the parser keeps, and regex captures go into reused buffers.
//! A parser is therefore used by one task at a time (`&mut self`).

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
    Traefik(traefik::Traefik),
    Sshd(sshd::Sshd),
    Authelia(authelia::Authelia),
    Regex(Pattern),
}

#[derive(Debug, thiserror::Error)]
#[error("source {source_name:?}: {message}")]
pub struct Error {
    pub source_name: String,
    pub message: String,
}

impl Parser {
    #[must_use]
    pub fn builtin(kind: ParserKind) -> Option<Self> {
        match kind {
            ParserKind::Traefik => Some(Self::Traefik(traefik::Traefik::default())),
            ParserKind::Sshd => Some(Self::Sshd(sshd::Sshd::default())),
            ParserKind::Authelia => Some(Self::Authelia(authelia::Authelia::default())),
            ParserKind::Regex => None,
        }
    }

    pub fn for_source(source: &Source) -> Result<Self, Error> {
        if let Some(parser) = Self::builtin(source.parser) {
            return Ok(parser);
        }
        let error = |message: String| Error {
            source_name: source.name.clone(),
            message,
        };
        let (Some(pattern), Some(kind)) = (&source.pattern, source.kind) else {
            return Err(error(
                "a regex source needs `pattern` and `kind`".to_owned(),
            ));
        };
        Ok(Self::Regex(Pattern::new(pattern, kind).map_err(error)?))
    }

    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (ip, event) = match self {
            Self::Traefik(p) => p.parse(line),
            Self::Sshd(p) => p.parse(line),
            Self::Authelia(p) => p.parse(line),
            Self::Regex(p) => p.parse(line),
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
    if s.bytes().filter(|b| *b == b':').count() == 1 {
        return s.split(':').next()?.parse().ok();
    }
    None
}

/// A JSON string that borrows from the line when it has no escapes. (`Cow<str>` inside an `Option` is always
/// copied by serde.)
#[derive(Debug)]
pub(crate) struct Text<'a>(pub std::borrow::Cow<'a, str>);

impl std::ops::Deref for Text<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl<'de: 'a, 'a> serde::Deserialize<'de> for Text<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Text<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(Text(std::borrow::Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Text(std::borrow::Cow::Owned(v.to_owned())))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// The text of capture group `group` after `regex.captures_read(locations, text)`.
pub(crate) fn group<'t>(
    locations: &regex::CaptureLocations,
    group: Option<usize>,
    text: &'t str,
) -> Option<&'t str> {
    let (start, end) = locations.get(group?)?;
    text.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_borrows_without_escapes() {
        #[derive(serde::Deserialize)]
        struct T<'a> {
            #[serde(borrow)]
            a: Option<Text<'a>>,
            #[serde(borrow)]
            b: Option<Text<'a>>,
        }
        let t: T<'_> = serde_json::from_str(r#"{"a":"plain","b":"e\u0026"}"#).unwrap();
        assert!(matches!(
            t.a,
            Some(Text(std::borrow::Cow::Borrowed("plain")))
        ));
        assert!(matches!(t.b, Some(Text(std::borrow::Cow::Owned(ref s))) if s == "e&"));
    }

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
        let mut parser = Parser::builtin(ParserKind::Sshd).unwrap();
        let (ip, _) = parser
            .parse("Invalid user admin from ::ffff:192.0.2.9 port 4242")
            .unwrap();
        assert_eq!(ip, "192.0.2.9".parse::<IpAddr>().unwrap());
    }
}
