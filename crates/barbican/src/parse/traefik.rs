//! Traefik's access log, in either of its formats: the common log format (Traefik's default, with its own extra
//! fields) or JSON (`accessLog.format: json`). Only JSON has the request's host, and the user agent only when
//! Traefik is told to keep the header.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::signal::{Event, Http};

/// `<client> - <user> [<time>] "<method> <path> <proto>" <status> <size> "<referer>" "<agent>" <count> "<router>"
/// "<backend>" <duration>ms`. Garbage request lines (no protocol) still match.
static CLF: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) (\S+)(?: [^"]*)?" (\d{1,3}) \S+ "[^"]*" "([^"]*)" \d+ "([^"]*)""#,
    )
    .ok()
});

pub fn parse(line: &str) -> Option<(IpAddr, Event)> {
    if line.starts_with('{') {
        parse_json(line)
    } else {
        parse_clf(line)
    }
}

fn dash(s: &str) -> Option<String> {
    (!s.is_empty() && s != "-").then(|| s.to_owned())
}

fn parse_clf(line: &str) -> Option<(IpAddr, Event)> {
    let captures = CLF.as_ref()?.captures(line)?;
    let ip = super::ip(captures.get(1)?.as_str())?;
    let router = captures.get(6)?.as_str();
    Some((
        ip,
        Event::Http(Http {
            method: captures.get(2)?.as_str().to_owned(),
            path: captures.get(3)?.as_str().to_owned(),
            status: captures.get(4)?.as_str().parse().ok()?,
            host: None,
            routed: Some(dash(router).is_some()),
            user_agent: dash(captures.get(5)?.as_str()),
        }),
    ))
}

fn parse_json(line: &str) -> Option<(IpAddr, Event)> {
    let value: Value = serde_json::from_str(line).ok()?;
    let text = |key: &str| value.get(key).and_then(Value::as_str);
    let ip = super::ip(text("ClientHost").or_else(|| text("ClientAddr"))?)?;
    let status = value
        .get("DownstreamStatus")
        .or_else(|| value.get("OriginStatus"))
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok())?;
    let router = text("RouterName").unwrap_or("");
    let path = text("RequestPath").unwrap_or("");
    Some((
        ip,
        Event::Http(Http {
            method: text("RequestMethod").unwrap_or("").to_owned(),
            path: path.to_owned(),
            status,
            host: text("RequestHost").and_then(dash),
            routed: Some(!router.is_empty()),
            user_agent: text("request_User-Agent").and_then(dash),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(line: &str) -> (IpAddr, Http) {
        match parse(line) {
            Some((ip, Event::Http(h))) => (ip, h),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn common_log_format() {
        let (ip, h) = http(
            r#"203.0.113.5 - - [19/Oct/2026:12:17:57 +0000] "GET /www/.git/config HTTP/1.1" 404 19 "-" "-" 161616 "-" "-" 0ms"#,
        );
        assert_eq!(ip.to_string(), "203.0.113.5");
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/www/.git/config");
        assert_eq!(h.status, 404);
        assert_eq!(h.routed, Some(false));
        assert_eq!(h.user_agent, None);

        let (_, h) = http(
            r#"198.51.100.4 - - [02/Nov/2026:16:07:32 +0000] "GET /api/v2/sync/maindata?rid=602 HTTP/1.1" 200 100 "-" "Mozilla/5.0 (X11)" 123719 "torrents@docker" "http://172.20.0.163:8080" 1ms"#,
        );
        assert_eq!(h.path, "/api/v2/sync/maindata?rid=602");
        assert_eq!(h.routed, Some(true));
        assert_eq!(h.user_agent.as_deref(), Some("Mozilla/5.0 (X11)"));

        // A request line without a protocol, as scanners send.
        let (_, h) = http(
            r#"2001:db8::7 - - [09/Nov/2026:02:07:04 +0000] "CFKQ /" 405 0 "-" "-" 1 "-" "-" 0ms"#,
        );
        assert_eq!(h.method, "CFKQ");

        assert!(
            parse("2026-11-10T15:42:51Z DBG github.com/traefik/... Service selected by WRR")
                .is_none()
        );
    }

    #[test]
    fn json_format() {
        let (ip, h) = http(
            r#"{"ClientHost":"192.0.2.44","RequestMethod":"POST","RequestPath":"/xmlrpc.php","RequestHost":"example.com","DownstreamStatus":404,"RouterName":"blog@docker","request_User-Agent":"curl/8"}"#,
        );
        assert_eq!(ip.to_string(), "192.0.2.44");
        assert_eq!(h.host.as_deref(), Some("example.com"));
        assert_eq!(h.routed, Some(true));
        assert_eq!(h.user_agent.as_deref(), Some("curl/8"));

        let (_, h) = http(
            r#"{"ClientAddr":"192.0.2.44:5555","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":404}"#,
        );
        assert_eq!(h.routed, Some(false));
        assert!(parse(r#"{"level":"debug","msg":"x"}"#).is_none());
    }
}
