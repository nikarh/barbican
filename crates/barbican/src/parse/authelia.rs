//! Authelia, in its text (logfmt) or JSON log format: failed and successful logins, and, at the debug level, every
//! authorization of a signed-in user, which keeps that user's address trusted.
//!
//! Text lines aren't split into all their fields: only `msg` and `remote_ip` are looked for.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::{CaptureLocations, Regex};
use serde::Deserialize;

use crate::signal::Event;

static UNSUCCESSFUL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Unsuccessful .*authentication attempt (?:made )?by user '([^']*)'").ok()
});
static SUCCESSFUL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Successful .*authentication attempt (?:made )?by user '([^']*)'").ok()
});
const SUBJECT: &str = "Check authorization of subject username=";

#[derive(Debug, Default)]
pub struct Authelia {
    locations: Option<CaptureLocations>,
    /// An unescaped JSON `msg`.
    buffer: String,
}

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow, default)]
    msg: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    remote_ip: Option<super::Text<'a>>,
}

/// The value of `key=` in a logfmt line: up to the closing quote (escapes left in) or the next space.
fn logfmt<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(found) = line.get(from..)?.find(key) {
        let at = from + found;
        from = at + key.len();
        let starts_token = at == 0
            || line
                .as_bytes()
                .get(at - 1)
                .is_some_and(u8::is_ascii_whitespace);
        if !starts_token || line.as_bytes().get(from) != Some(&b'=') {
            continue;
        }
        let rest = line.get(from + 1..)?;
        if let Some(quoted) = rest.strip_prefix('"') {
            let bytes = quoted.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                match bytes.get(i) {
                    Some(b'\\') => i += 2,
                    Some(b'"') => return quoted.get(..i),
                    _ => i += 1,
                }
            }
            return Some(quoted);
        }
        return rest.split_whitespace().next().or(Some(""));
    }
    None
}

impl Authelia {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let (msg, remote_ip): (&'s str, Option<&'s str>) = if line.starts_with('{') {
            let parsed: Line<'s> = serde_json::from_str(line).ok()?;
            // Addresses have nothing to escape.
            let remote_ip = match parsed.remote_ip.map(|t| t.0) {
                Some(Cow::Borrowed(ip)) => Some(ip),
                _ => None,
            };
            let msg = match parsed.msg?.0 {
                Cow::Borrowed(m) => m,
                Cow::Owned(m) => {
                    self.buffer = m;
                    self.buffer.as_str()
                }
            };
            (msg, remote_ip)
        } else {
            (logfmt(line, "msg")?, logfmt(line, "remote_ip"))
        };

        if let Some(rest) = msg.strip_prefix(SUBJECT) {
            // `<user> groups=<groups> ip=<ip> and object ...`
            let (user, rest) = rest.split_once(' ')?;
            if user.is_empty() {
                return None;
            }
            let ip = rest.split(' ').find_map(|t| t.strip_prefix("ip="))?;
            return Some((super::ip(ip)?, Event::Session { user }));
        }
        let ip = super::ip(remote_ip?)?;
        let (regex, failure) = if msg.starts_with("Unsuccessful ") {
            (UNSUCCESSFUL.as_ref()?, true)
        } else if msg.starts_with("Successful ") {
            (SUCCESSFUL.as_ref()?, false)
        } else {
            return None;
        };
        let locations = self
            .locations
            .get_or_insert_with(|| regex.capture_locations());
        regex.captures_read(locations, msg)?;
        let user = super::group(locations, Some(1), msg)?;
        Some((
            ip,
            if failure {
                Event::AuthFailure {
                    user: (!user.is_empty()).then_some(user),
                }
            } else {
                Event::AuthSuccess { user }
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, String)> {
        let mut parser = Authelia::default();
        parser
            .parse(line)
            .map(|(ip, e)| (ip.to_string(), format!("{e:?}")))
    }

    #[test]
    fn text_format() {
        assert_eq!(
            p(
                r#"time="2026-10-12T21:00:59Z" level=error msg="Unsuccessful 1FA authentication attempt by user 'alice'" method=POST path=/api/firstfactor remote_ip=203.0.113.20 stack="a\nb""#
            ),
            Some((
                "203.0.113.20".into(),
                r#"AuthFailure { user: Some("alice") }"#.into()
            ))
        );
        assert_eq!(
            p(
                r#"time="2026-10-12T21:01:10Z" level=debug msg="Successful 1FA authentication attempt made by user 'alice'" method=POST path=/api/firstfactor remote_ip=192.0.2.8"#
            ),
            Some((
                "192.0.2.8".into(),
                r#"AuthSuccess { user: "alice" }"#.into()
            ))
        );
        assert_eq!(
            p(
                r#"time="2026-10-12T21:01:10Z" level=debug msg="Check authorization of subject username=alice groups=admins,media ip=192.0.2.8 and object https://app.example.com/ (method GET)." method=GET path=/api/authz/forward-auth remote_ip=172.20.0.3"#
            ),
            Some(("192.0.2.8".into(), r#"Session { user: "alice" }"#.into()))
        );
        assert_eq!(
            p(
                r#"level=debug msg="Check authorization of subject username= groups= ip=203.0.113.1 and object https://a.example.com/ (method GET).""#
            ),
            None
        );
        assert_eq!(
            p(
                r#"level=debug msg="Mark 1FA authentication attempt made by user 'alice'" remote_ip=192.0.2.8"#
            ),
            None
        );
    }

    #[test]
    fn json_format() {
        assert_eq!(
            p(
                r#"{"level":"error","msg":"Unsuccessful 2FA TOTP authentication attempt by user 'bob'","remote_ip":"2001:db8::9","time":"2026-01-01T00:00:00Z"}"#
            ),
            Some((
                "2001:db8::9".into(),
                r#"AuthFailure { user: Some("bob") }"#.into()
            ))
        );
        assert_eq!(
            p(
                r#"{"msg":"Unsuccessful 1FA authentication attempt by user 'böb'","remote_ip":"192.0.2.1"}"#
            ),
            Some((
                "192.0.2.1".into(),
                r#"AuthFailure { user: Some("böb") }"#.into()
            ))
        );
    }

    #[test]
    fn logfmt_values() {
        let line = r#"a=1 b="two words" c="esc \"q\"" xmsg=no msg=yes d="#;
        assert_eq!(logfmt(line, "a"), Some("1"));
        assert_eq!(logfmt(line, "b"), Some("two words"));
        assert_eq!(logfmt(line, "c"), Some(r#"esc \"q\""#));
        assert_eq!(logfmt(line, "msg"), Some("yes"));
        assert_eq!(logfmt(line, "d"), Some(""));
        assert_eq!(logfmt(line, "e"), None);
    }
}
