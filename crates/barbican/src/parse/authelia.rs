//! Authelia, in its text (logfmt) or JSON log format: failed and successful logins, and, at the debug level, every
//! authorization of a signed-in user, which keeps that user's address trusted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::signal::Event;

static UNSUCCESSFUL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Unsuccessful .*authentication attempt (?:made )?by user '(?P<user>[^']*)'").ok()
});
static SUCCESSFUL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Successful .*authentication attempt (?:made )?by user '(?P<user>[^']*)'").ok()
});
static SUBJECT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Check authorization of subject username=(?P<user>\S+) groups=\S* ip=(?P<ip>\S+) ")
        .ok()
});

pub fn parse(line: &str) -> Option<(IpAddr, Event)> {
    let fields = if line.starts_with('{') {
        json_fields(line)?
    } else {
        logfmt(line)
    };
    let msg = fields.get("msg")?;
    if let Some(c) = SUBJECT.as_ref().and_then(|r| r.captures(msg)) {
        let ip = super::ip(c.name("ip")?.as_str())?;
        return Some((
            ip,
            Event::Session {
                user: c.name("user")?.as_str().to_owned(),
            },
        ));
    }
    let ip = super::ip(fields.get("remote_ip")?)?;
    if let Some(c) = UNSUCCESSFUL.as_ref().and_then(|r| r.captures(msg)) {
        let user = c
            .name("user")
            .map(|u| u.as_str().to_owned())
            .filter(|u| !u.is_empty());
        return Some((ip, Event::AuthFailure { user }));
    }
    if let Some(c) = SUCCESSFUL.as_ref().and_then(|r| r.captures(msg)) {
        return Some((
            ip,
            Event::AuthSuccess {
                user: c.name("user")?.as_str().to_owned(),
            },
        ));
    }
    None
}

fn json_fields(line: &str) -> Option<HashMap<String, String>> {
    let value: Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    Some(
        object
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
            .collect(),
    )
}

/// `key=value key="quoted \"value\""` pairs.
fn logfmt(line: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let key: String =
            std::iter::from_fn(|| chars.next_if(|c| *c != '=' && !c.is_whitespace())).collect();
        if key.is_empty() && chars.peek().is_none() {
            break;
        }
        if chars.next_if_eq(&'=').is_none() {
            if chars.peek().is_none() {
                break;
            }
            continue;
        }
        let mut value = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => break,
                    c => value.push(c),
                }
            }
        } else {
            value.extend(std::iter::from_fn(|| chars.next_if(|c| !c.is_whitespace())));
        }
        fields.insert(key, value);
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Option<(String, Event)> {
        parse(line).map(|(ip, e)| (ip.to_string(), e))
    }

    #[test]
    fn text_format() {
        assert_eq!(
            p(
                r#"time="2026-10-12T21:00:59Z" level=error msg="Unsuccessful 1FA authentication attempt by user 'alice'" method=POST path=/api/firstfactor remote_ip=203.0.113.20 stack="a\nb""#
            ),
            Some((
                "203.0.113.20".into(),
                Event::AuthFailure {
                    user: Some("alice".into())
                }
            ))
        );
        assert_eq!(
            p(
                r#"time="2026-10-12T21:01:10Z" level=debug msg="Successful 1FA authentication attempt made by user 'alice'" method=POST path=/api/firstfactor remote_ip=192.0.2.8"#
            ),
            Some((
                "192.0.2.8".into(),
                Event::AuthSuccess {
                    user: "alice".into()
                }
            ))
        );
        assert_eq!(
            p(
                r#"time="2026-10-12T21:01:10Z" level=debug msg="Check authorization of subject username=alice groups=admins,media ip=192.0.2.8 and object https://app.example.com/ (method GET)." method=GET path=/api/authz/forward-auth remote_ip=172.20.0.3"#
            ),
            Some((
                "192.0.2.8".into(),
                Event::Session {
                    user: "alice".into()
                }
            ))
        );
        // Anonymous requests aren't sessions.
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
                Event::AuthFailure {
                    user: Some("bob".into())
                }
            ))
        );
    }

    #[test]
    fn logfmt_values() {
        let f = logfmt(r#"a=1 b="two words" c="esc \"q\"" bare d="#);
        assert_eq!(f["a"], "1");
        assert_eq!(f["b"], "two words");
        assert_eq!(f["c"], "esc \"q\"");
        assert_eq!(f["d"], "");
    }
}
