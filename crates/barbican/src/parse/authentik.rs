//! authentik's server log (JSON): the events it creates for logins (`"event": "Created Event"`, with `action`
//! `login` or `login_failed`), and identification stages' unknown user names (`"event": "invalid_login"`, `action`
//! `invalid_identifier`).
//!
//! ```text
//! {"action": "login_failed", "client_ip": "203.0.113.9", "context": {..., "username": "alice"}, "event": "Created Event", ..., "user": {"email": "alice@example.com", "pk": 5, "username": "alice"}}
//! ```
//!
//! A failed login names what was typed in `context.username`. authentik that pretends unknown users exist (a
//! password stage after the identification stage) gives them a user without a `pk`: those are unknown users.

use std::borrow::Cow;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer};

use crate::signal::Event;

#[derive(Debug, Default)]
pub struct Authentik {
    /// An unescaped user name.
    buffer: String,
}

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow, default)]
    event: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    action: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    client_ip: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    identifier: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    context: Option<Context<'a>>,
    #[serde(borrow, default)]
    user: Option<User<'a>>,
}

#[derive(Deserialize)]
struct Context<'a> {
    #[serde(borrow, default)]
    username: Option<super::Text<'a>>,
}

#[derive(Deserialize)]
struct User<'a> {
    #[serde(borrow, default)]
    username: Option<super::Text<'a>>,
    /// `Some(true)`: the user has no primary key (`"pk": null`), so doesn't exist.
    #[serde(default, rename = "pk", deserialize_with = "is_null")]
    no_pk: Option<bool>,
}

fn is_null<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<bool>, D::Error> {
    Ok(Some(
        Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_none(),
    ))
}

enum What {
    Success,
    Failure,
    Unknown,
}

impl Authentik {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        // Most lines are requests: skip them without parsing.
        if !line.starts_with('{')
            || !(line.contains("\"Created Event\"") || line.contains("\"invalid_login\""))
        {
            return None;
        }
        let parsed: Line<'s> = serde_json::from_str(line).ok()?;
        // Addresses have nothing to escape; authentik writes 255.255.255.255 when it doesn't know one.
        let ip = match parsed.client_ip?.0 {
            Cow::Borrowed(ip) => super::ip(ip)?,
            Cow::Owned(_) => return None,
        };
        if ip.is_unspecified() || ip == IpAddr::from([255, 255, 255, 255]) {
            return None;
        }
        let (event, action) = (parsed.event?, parsed.action?);
        let (what, user) = match (&*event, &*action) {
            ("Created Event", "login") => (What::Success, parsed.user?.username),
            ("Created Event", "login_failed") => {
                let unknown = parsed.user.as_ref().is_some_and(|u| u.no_pk == Some(true));
                let typed = parsed.context.and_then(|c| c.username);
                let user = typed.or_else(|| parsed.user.and_then(|u| u.username));
                (
                    if unknown {
                        What::Unknown
                    } else {
                        What::Failure
                    },
                    user,
                )
            }
            ("invalid_login", "invalid_identifier") => (What::Unknown, parsed.identifier),
            _ => return None,
        };
        let user: Option<&'s str> = match user.map(|u| u.0) {
            Some(Cow::Borrowed(u)) => Some(u),
            Some(Cow::Owned(u)) => {
                self.buffer = u;
                Some(self.buffer.as_str())
            }
            None => None,
        }
        .filter(|u| !u.is_empty());
        let event = match what {
            What::Success => Event::AuthSuccess { user: user? },
            What::Failure => Event::AuthFailure { user },
            What::Unknown => Event::InvalidUser {
                user: user.unwrap_or(""),
            },
        };
        Some((ip, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, String)> {
        let mut parser = Authentik::default();
        parser
            .parse(line)
            .map(|(ip, e)| (ip.to_string(), format!("{e:?}")))
    }

    fn ok(ip: &str, event: &str) -> (String, String) {
        (ip.to_owned(), event.to_owned())
    }

    #[test]
    fn logins() {
        assert_eq!(
            p(
                r#"{"action": "login_failed", "auth_via": "unauthenticated", "client_ip": "203.0.113.9", "context": {"http_request": {"args": {}, "method": "POST", "path": "/api/v3/flows/executor/default-authentication-flow/", "request_id": "d1c0", "user_agent": "Mozilla/5.0"}, "password": "********************", "stage": {"app": "authentik_stages_password", "model_name": "passwordstage", "name": "default-authentication-password", "pk": "3f7a"}, "username": "alice"}, "event": "Created Event", "host": "auth.example.com", "level": "info", "logger": "authentik.events.models", "pid": 12345, "request_id": "d1c0", "timestamp": "2026-11-18T16:02:11.123456", "user": {"email": "alice@example.com", "pk": 5, "username": "alice"}}"#
            ),
            Some(ok("203.0.113.9", r#"AuthFailure { user: Some("alice") }"#))
        );
        assert_eq!(
            p(
                r#"{"action": "login", "auth_via": "unauthenticated", "client_ip": "2001:db8::9", "context": {"auth_method": "password", "auth_method_args": {}, "http_request": {"args": {}, "method": "GET", "path": "/api/v3/flows/executor/default-authentication-flow/"}}, "event": "Created Event", "host": "auth.example.com", "level": "info", "logger": "authentik.events.models", "pid": 12345, "timestamp": "2026-11-18T16:04:20.000000", "user": {"email": "alice@example.com", "pk": 5, "username": "alice"}}"#
            ),
            Some(ok("2001:db8::9", r#"AuthSuccess { user: "alice" }"#))
        );
        // Older releases: the anonymous user, and what was typed in the context.
        assert_eq!(
            p(
                r#"{"action": "login_failed", "client_ip": "203.0.113.9", "context": {"username": "bob", "password": "********************"}, "event": "Created Event", "logger": "authentik.events.models", "user": {"email": "", "pk": 1, "username": "AnonymousUser"}}"#
            ),
            Some(ok("203.0.113.9", r#"AuthFailure { user: Some("bob") }"#))
        );
    }

    #[test]
    fn unknown_users() {
        assert_eq!(
            p(
                r#"{"action": "invalid_identifier", "auth_via": "unauthenticated", "client_ip": "203.0.113.9", "context": {"stage": {"app": "authentik_stages_identification", "model_name": "identificationstage", "name": "default-authentication-identification", "pk": "1"}}, "event": "invalid_login", "host": "auth.example.com", "identifier": "mallory", "level": "info", "logger": "authentik.flows.stage", "pid": 12345, "stage": "default-authentication-identification", "timestamp": "2026-11-18T16:02:11.000000"}"#
            ),
            Some(ok("203.0.113.9", r#"InvalidUser { user: "mallory" }"#))
        );
        // Pretending the user exists: a user without a primary key.
        assert_eq!(
            p(
                r#"{"action": "login_failed", "client_ip": "203.0.113.9", "context": {"username": "mallory"}, "event": "Created Event", "user": {"authenticated_as": {"email": "", "is_anonymous": true, "pk": 1, "username": "AnonymousUser"}, "email": "mallory", "pk": null, "username": "mallory"}}"#
            ),
            Some(ok("203.0.113.9", r#"InvalidUser { user: "mallory" }"#))
        );
    }

    #[test]
    fn what_isnt_a_login() {
        for line in [
            r#"{"action": "authorize_application", "client_ip": "203.0.113.9", "event": "Created Event", "user": {"pk": 5, "username": "alice"}}"#,
            r#"{"action": "login", "client_ip": "255.255.255.255", "event": "Created Event", "user": {"pk": 5, "username": "alice"}}"#,
            r#"{"auth_via": "session", "event": "/api/v3/core/users/me/", "host": "auth.example.com", "level": "info", "logger": "authentik.asgi", "method": "GET", "remote": "203.0.113.9", "status": 200}"#,
            r#"{"action": "login", "event": "Created Event", "user": {"pk": 5, "username": "alice"}}"#,
            "{\"event\": \"Created Event\"",
            "not json \"Created Event\"",
        ] {
            assert_eq!(p(line), None, "{line}");
        }
    }

    #[test]
    fn escaped_names() {
        assert_eq!(
            p(
                r#"{"action": "login_failed", "client_ip": "203.0.113.9", "context": {"username": "jörg"}, "event": "Created Event", "user": {"pk": 7, "username": "jörg"}}"#
            ),
            Some(ok("203.0.113.9", r#"AuthFailure { user: Some("jörg") }"#))
        );
    }
}
