//! `SuperTokens` sign-ins. `SuperTokens` logs nothing about them with the client's address (its core is called by the
//! app's backend, and the backend SDKs log neither outcomes nor addresses), so the app logs them itself, with an
//! override of the sign-in API that writes one JSON line per attempt (see the documentation of sources):
//!
//! ```text
//! {"event":"supertokens.signin","status":"WRONG_CREDENTIALS_ERROR","user":"alice@example.com","ip":"203.0.113.5"}
//! ```
//!
//! Anything before the `{` (a logger's prefix) is skipped. `OK` is a successful login, `WRONG_CREDENTIALS_ERROR` a
//! failed one (`SuperTokens` doesn't say whether the user exists); other statuses aren't logins that failed.

use std::borrow::Cow;
use std::net::IpAddr;

use serde::Deserialize;

use crate::signal::Event;

const EVENT: &str = "supertokens.signin";

#[derive(Debug, Default)]
pub struct Supertokens {
    /// An unescaped user name.
    buffer: String,
}

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow)]
    event: super::Text<'a>,
    #[serde(borrow)]
    status: super::Text<'a>,
    #[serde(borrow, default)]
    user: Option<super::Text<'a>>,
    #[serde(borrow)]
    ip: super::Text<'a>,
}

impl Supertokens {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        if !line.contains(EVENT) {
            return None;
        }
        let json = line.get(line.find('{')?..)?.trim_end();
        let parsed: Line<'s> = serde_json::from_str(json).ok()?;
        if *parsed.event != *EVENT {
            return None;
        }
        let ip = match parsed.ip.0 {
            Cow::Borrowed(ip) => super::ip(ip)?,
            Cow::Owned(_) => return None,
        };
        let success = match &*parsed.status {
            "OK" => true,
            "WRONG_CREDENTIALS_ERROR" => false,
            _ => return None,
        };
        let user: Option<&'s str> = match parsed.user.map(|u| u.0) {
            Some(Cow::Borrowed(u)) => Some(u),
            Some(Cow::Owned(u)) => {
                self.buffer = u;
                Some(self.buffer.as_str())
            }
            None => None,
        }
        .filter(|u| !u.is_empty());
        let event = if success {
            Event::AuthSuccess { user: user? }
        } else {
            Event::AuthFailure { user }
        };
        Some((ip, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, String)> {
        let mut parser = Supertokens::default();
        parser
            .parse(line)
            .map(|(ip, e)| (ip.to_string(), format!("{e:?}")))
    }

    fn ok(ip: &str, event: &str) -> (String, String) {
        (ip.to_owned(), event.to_owned())
    }

    #[test]
    fn sign_ins() {
        assert_eq!(
            p(
                r#"{"event":"supertokens.signin","status":"WRONG_CREDENTIALS_ERROR","user":"alice@example.com","ip":"203.0.113.5"}"#
            ),
            Some(ok(
                "203.0.113.5",
                r#"AuthFailure { user: Some("alice@example.com") }"#
            ))
        );
        assert_eq!(
            p(
                r#"{"event":"supertokens.signin","status":"OK","user":"alice@example.com","ip":"2001:db8::5"}"#
            ),
            Some(ok(
                "2001:db8::5",
                r#"AuthSuccess { user: "alice@example.com" }"#
            ))
        );
        // Behind a logger's prefix, in another order, with escapes.
        assert_eq!(
            p(
                r#"2026-11-18T16:00:00.000Z info: {"ip":"198.51.100.2","user":"böb@example.com","status":"WRONG_CREDENTIALS_ERROR","event":"supertokens.signin"}"#
            ),
            Some(ok(
                "198.51.100.2",
                r#"AuthFailure { user: Some("böb@example.com") }"#
            ))
        );
    }

    #[test]
    fn what_isnt_a_login() {
        for line in [
            r#"{"event":"supertokens.signin","status":"SIGN_IN_NOT_ALLOWED","user":"a@example.com","ip":"203.0.113.5"}"#,
            r#"{"event":"supertokens.signin","status":"OK","ip":"203.0.113.5"}"#,
            r#"{"event":"supertokens.signin","status":"OK","user":"a@example.com","ip":""}"#,
            r#"{"event":"supertokens.signup","status":"OK","user":"a@example.com","ip":"203.0.113.5"}"#,
            r#"{"event":"other","note":"supertokens.signin","status":"OK","user":"a","ip":"203.0.113.5"}"#,
            r#"com.supertokens {t: "2026-11-18T16:00:00.000Z", message: "middleware: Started", file: "x.js:1", sdkVer: "23.0.0"}"#,
        ] {
            assert_eq!(p(line), None, "{line}");
        }
    }
}
