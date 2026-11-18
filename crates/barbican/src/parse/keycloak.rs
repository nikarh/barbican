//! Keycloak's login events, as its `jboss-logging` event listener logs them (category `org.keycloak.events`), in
//! the plain console format or as JSON (`--log-console-output=json`, where they are the `message`):
//!
//! ```text
//! type="LOGIN_ERROR", realmId="...", realmName="demo", clientId="app", userId="null", ipAddress="203.0.113.7", error="user_not_found", ..., username="mallory"
//! ```
//!
//! Releases before 23.0.5 write the values without quotes. Failed logins are logged at `WARN`; successful ones at
//! `DEBUG` unless the listener's success level is raised (`--spi-events-listener--jboss-logging--success-level=info`).
//!
//! The fields Keycloak itself writes (`type`, `ipAddress`, `error`) come before the details, whose order isn't
//! fixed; the first occurrence of each is taken, so a user name can't pose as one of them.

use std::borrow::Cow;
use std::net::IpAddr;

use serde::Deserialize;

use crate::signal::Event;

#[derive(Debug, Default)]
pub struct Keycloak {
    /// An unescaped JSON `message`.
    buffer: String,
}

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow, default)]
    message: Option<super::Text<'a>>,
}

/// The value of `key` in an event, walking its pairs from the start: `key="value"` (up to a quote, not after a
/// backslash, that is followed by `, ` or the end) or `key=value` (up to `, `). What a quoted value holds is never
/// taken for a pair.
fn field<'a>(event: &'a str, key: &str) -> Option<&'a str> {
    let mut rest = event;
    loop {
        let (name, after) = rest.split_once('=')?;
        let (value, next) = if let Some(quoted) = after.strip_prefix('"') {
            let bytes = quoted.as_bytes();
            let mut i = 0;
            loop {
                let Some(end) = quoted.get(i..).and_then(|q| q.find('"')).map(|e| i + e) else {
                    break (quoted, "");
                };
                let escaped = end > 0 && bytes.get(end - 1) == Some(&b'\\');
                let after = quoted.get(end + 1..).unwrap_or("");
                if !escaped && (after.is_empty() || after.starts_with(", ")) {
                    break (quoted.get(..end).unwrap_or(""), after);
                }
                i = end + 1;
            }
        } else {
            after.split_once(", ").map_or((after, ""), |(v, _)| {
                (v, after.get(v.len()..).unwrap_or(""))
            })
        };
        if name == key {
            return Some(value);
        }
        rest = next.strip_prefix(", ")?;
    }
}

/// A value Keycloak writes for nothing.
fn set(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "null")
}

impl Keycloak {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let event: &'s str = if line.starts_with('{') {
            if !line.contains("LOGIN") {
                return None;
            }
            let parsed: Line<'s> = serde_json::from_str(line).ok()?;
            match parsed.message?.0 {
                Cow::Borrowed(m) => m,
                Cow::Owned(m) => {
                    self.buffer = m;
                    self.buffer.as_str()
                }
            }
        } else {
            let at = line.find("type=")?;
            let before = line.get(..at)?;
            if !(before.is_empty() || before.ends_with(' ')) {
                return None;
            }
            line.get(at..)?
        };
        let kind = field(event, "type")?;
        let ip = super::ip(field(event, "ipAddress")?)?;
        let user = || set(field(event, "username")).or_else(|| set(field(event, "userId")));
        let event = match (kind, set(field(event, "error"))) {
            ("LOGIN", None) => Event::AuthSuccess { user: user()? },
            ("LOGIN_ERROR", Some("user_not_found")) => Event::InvalidUser {
                user: set(field(event, "username")).unwrap_or(""),
            },
            ("LOGIN_ERROR", Some("invalid_user_credentials" | "user_temporarily_disabled")) => {
                Event::AuthFailure { user: user() }
            }
            // Guessing a client's secret.
            ("CLIENT_LOGIN_ERROR", Some("invalid_client_credentials")) => Event::AuthFailure {
                user: set(field(event, "clientId")),
            },
            _ => return None,
        };
        Some((ip, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, String)> {
        let mut parser = Keycloak::default();
        parser
            .parse(line)
            .map(|(ip, e)| (ip.to_string(), format!("{e:?}")))
    }

    fn ok(ip: &str, event: &str) -> (String, String) {
        (ip.to_owned(), event.to_owned())
    }

    #[test]
    fn plain_format() {
        assert_eq!(
            p(
                r#"2026-11-18 16:02:11,123 WARN  [org.keycloak.events] (executor-thread-3) type="LOGIN_ERROR", realmId="8c1b3f0e-1d2c-4b7a-9f00-1a2b3c4d5e6f", realmName="demo", clientId="app", userId="null", ipAddress="203.0.113.7", error="user_not_found", auth_method="openid-connect", auth_type="code", redirect_uri="https://app.example.com/cb", code_id="5f2e", username="mallory", authSessionParentId="5f2e", authSessionTabId="Xq3""#
            ),
            Some(ok("203.0.113.7", r#"InvalidUser { user: "mallory" }"#))
        );
        assert_eq!(
            p(
                r#"2026-11-18 16:02:15,456 WARN  [org.keycloak.events] (executor-thread-3) type="LOGIN_ERROR", realmId="8c1b", realmName="demo", clientId="app", userId="0b6c", ipAddress="203.0.113.7", error="invalid_user_credentials", auth_method="openid-connect", auth_type="code", redirect_uri="https://app.example.com/cb", code_id="5f2e", username="alice", authSessionParentId="5f2e", authSessionTabId="Xq3""#
            ),
            Some(ok("203.0.113.7", r#"AuthFailure { user: Some("alice") }"#))
        );
        assert_eq!(
            p(
                r#"2026-11-18 16:03:01,002 WARN  [org.keycloak.events] (executor-thread-5) type="LOGIN_ERROR", realmId="8c1b", realmName="demo", clientId="app", userId="0b6c", ipAddress="2001:db8::7", error="user_temporarily_disabled", auth_method="openid-connect", username="alice""#
            ),
            Some(ok("2001:db8::7", r#"AuthFailure { user: Some("alice") }"#))
        );
        assert_eq!(
            p(
                r#"2026-11-18 16:04:20,789 INFO  [org.keycloak.events] (executor-thread-7) type="LOGIN", realmId="8c1b", realmName="demo", clientId="app", userId="0b6c", sessionId="a1d4", ipAddress="192.0.2.8", auth_method="openid-connect", auth_type="code", redirect_uri="https://app.example.com/cb", consent="no_consent_required", code_id="a1d4", username="alice", authSessionParentId="a1d4", authSessionTabId="Xq3""#
            ),
            Some(ok("192.0.2.8", r#"AuthSuccess { user: "alice" }"#))
        );
        assert_eq!(
            p(
                r#"2026-11-18 16:05:00,000 WARN  [org.keycloak.events] (executor-thread-1) type="CLIENT_LOGIN_ERROR", realmId="8c1b", realmName="demo", clientId="backend", userId="null", ipAddress="198.51.100.3", error="invalid_client_credentials", grant_type="client_credentials""#
            ),
            Some(ok(
                "198.51.100.3",
                r#"AuthFailure { user: Some("backend") }"#
            ))
        );
    }

    #[test]
    fn older_releases_without_quotes() {
        assert_eq!(
            p(
                "12:00:00,000 WARN  [org.keycloak.events] (default task-1) type=LOGIN_ERROR, realmId=demo, clientId=app, userId=null, ipAddress=203.0.113.9, error=user_not_found, auth_method=openid-connect, redirect_uri=https://app.example.com/cb, username=admin"
            ),
            Some(ok("203.0.113.9", r#"InvalidUser { user: "admin" }"#))
        );
        assert_eq!(
            p(
                "2023-01-01 12:00:00,000 WARN  [org.keycloak.events] (executor-thread-1) type=LOGIN_ERROR, realmId=demo, clientId=app, userId=0b6c, ipAddress=203.0.113.9, error=invalid_user_credentials, auth_method=openid-connect, username=bob"
            ),
            Some(ok("203.0.113.9", r#"AuthFailure { user: Some("bob") }"#))
        );
        // Without a user name, the user's id.
        assert_eq!(
            p(
                "2023-01-01 12:00:00,000 DEBUG [org.keycloak.events] (executor-thread-1) type=LOGIN, realmId=demo, clientId=app, userId=0b6c, ipAddress=192.0.2.8, auth_method=openid-connect"
            ),
            Some(ok("192.0.2.8", r#"AuthSuccess { user: "0b6c" }"#))
        );
    }

    #[test]
    fn json_format() {
        assert_eq!(
            p(
                r#"{"timestamp":"2026-11-18T16:02:11.123+02:00","sequence":8812,"loggerClassName":"org.jboss.logging.Logger","loggerName":"org.keycloak.events","level":"WARN","message":"type=\"LOGIN_ERROR\", realmId=\"8c1b\", realmName=\"demo\", clientId=\"app\", userId=\"null\", ipAddress=\"203.0.113.7\", error=\"user_not_found\", auth_method=\"openid-connect\", username=\"mallory\"","threadName":"executor-thread-3","threadId":45,"mdc":{},"ndc":"","hostName":"keycloak","processName":"QuarkusEntryPoint","processId":1}"#
            ),
            Some(ok("203.0.113.7", r#"InvalidUser { user: "mallory" }"#))
        );
        // ECS.
        assert_eq!(
            p(
                r#"{"@timestamp":"2026-11-18T16:02:11.123Z","log.logger":"org.keycloak.events","log.level":"WARN","message":"type=\"LOGIN_ERROR\", realmId=\"8c1b\", clientId=\"app\", userId=\"0b6c\", ipAddress=\"203.0.113.7\", error=\"invalid_user_credentials\", username=\"alice\"","process.thread.name":"executor-thread-3"}"#
            ),
            Some(ok("203.0.113.7", r#"AuthFailure { user: Some("alice") }"#))
        );
    }

    #[test]
    fn what_isnt_a_login() {
        for line in [
            r#"2026-11-18 16:02:11,123 WARN  [org.keycloak.events] (executor-thread-3) type="LOGIN_ERROR", realmId="8c1b", clientId="app", userId="null", ipAddress="203.0.113.7", error="expired_code", username="alice""#,
            r#"2026-11-18 16:02:11,123 WARN  [org.keycloak.events] (executor-thread-3) type="CODE_TO_TOKEN_ERROR", realmId="8c1b", clientId="app", userId="null", ipAddress="203.0.113.7", error="invalid_code""#,
            r#"2026-11-18 16:02:11,123 INFO  [org.keycloak.events] (executor-thread-3) type="LOGOUT", realmId="8c1b", clientId="app", userId="0b6c", ipAddress="203.0.113.7""#,
            "2026-11-18 16:00:00,000 INFO  [io.quarkus] (main) Keycloak 26.4.0 on JVM started in 9.1s. Listening on: http://0.0.0.0:8080",
            r#"2026-11-18 16:00:00,000 INFO  [x] (main) subtype="LOGIN", ipAddress="203.0.113.7""#,
            r#"{"loggerName":"io.quarkus","message":"Keycloak started, LOGIN page ready"}"#,
        ] {
            assert_eq!(p(line), None, "{line}");
        }
    }

    #[test]
    fn user_names_dont_pose_as_fields() {
        // A user name with a quote is escaped; one that tries to look like the address comes after the real one.
        assert_eq!(
            p(
                r#"WARN  [org.keycloak.events] (t) type="LOGIN_ERROR", realmId="r", clientId="app", userId="0b6c", ipAddress="203.0.113.7", error="invalid_user_credentials", username="a\", ipAddress=\"192.0.2.1""#
            ),
            Some(ok(
                "203.0.113.7",
                r#"AuthFailure { user: Some("a\\\", ipAddress=\\\"192.0.2.1") }"#
            ))
        );
        assert_eq!(field(r#"a="x, y", b="2""#, "a"), Some("x, y"));
        assert_eq!(field(r#"a="x\", b=\"y", b="2""#, "b"), Some("2"));
        assert_eq!(field("xa=1, a=2", "a"), Some("2"));
        assert_eq!(field("a=1, b=", "b"), Some(""));
        assert_eq!(field("a=1", "b"), None);
    }
}
