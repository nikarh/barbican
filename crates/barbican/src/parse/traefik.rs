//! Traefik's access log, in either of its formats: the common log format (Traefik's default, with its own extra
//! fields) or JSON (`accessLog.format: json`). Only JSON has the request's host, and the user agent only when
//! Traefik is told to keep the header.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::{CaptureLocations, Regex};
use serde::Deserialize;

use crate::signal::{Event, Http};

/// `<client> - <user> [<time>] "<method> <path> <proto>" <status> <size> "<referer>" "<agent>" <count> "<router>"
/// "<backend>" <duration>ms`. Garbage request lines (no protocol) still match; aborted requests have status 0.
static CLF: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) (\S+)(?: [^"]*)?" (\d{1,3}) \S+ "[^"]*" "([^"]*)" \d+ "([^"]*)""#,
    )
    .ok()
});

#[derive(Debug, Default)]
pub struct Traefik {
    locations: Option<CaptureLocations>,
    /// Unescaped JSON fields: path, host, agent, method.
    buffers: [String; 4],
}

/// A JSON line; the fields borrow from the line unless they had escapes.
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Line<'a> {
    #[serde(borrow, default)]
    ClientHost: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    ClientAddr: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    RequestMethod: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    RequestPath: Option<super::Text<'a>>,
    #[serde(borrow, default)]
    RequestHost: Option<super::Text<'a>>,
    #[serde(default)]
    DownstreamStatus: Option<u16>,
    #[serde(default)]
    OriginStatus: Option<u16>,
    #[serde(borrow, default)]
    RouterName: Option<super::Text<'a>>,
    #[serde(borrow, default, rename = "request_User-Agent")]
    user_agent: Option<super::Text<'a>>,
}

fn dash(s: &str) -> Option<&str> {
    (!s.is_empty() && s != "-").then_some(s)
}

/// The text of a field: the line's own when it had no escapes, otherwise a copy in `buffer`.
fn text<'s>(field: Option<super::Text<'s>>, buffer: &'s mut String) -> Option<&'s str> {
    match field?.0 {
        Cow::Borrowed(s) => Some(s),
        Cow::Owned(s) => {
            *buffer = s;
            Some(buffer.as_str())
        }
    }
}

impl Traefik {
    pub fn parse<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        if line.starts_with('{') {
            self.parse_json(line)
        } else {
            self.parse_clf(line)
        }
    }

    fn parse_clf<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let regex = CLF.as_ref()?;
        let locations = self
            .locations
            .get_or_insert_with(|| regex.capture_locations());
        regex.captures_read(locations, line)?;
        let g = |i| super::group(locations, Some(i), line);
        let ip = super::ip(g(1)?)?;
        Some((
            ip,
            Event::Http(Http {
                method: g(2)?,
                path: g(3)?,
                status: g(4)?.parse().ok()?,
                host: None,
                routed: Some(dash(g(6)?).is_some()),
                user_agent: dash(g(5)?),
            }),
        ))
    }

    fn parse_json<'s>(&'s mut self, line: &'s str) -> Option<(IpAddr, Event<'s>)> {
        let parsed: Line<'s> = serde_json::from_str(line).ok()?;
        let ip = super::ip(
            parsed
                .ClientHost
                .as_deref()
                .or(parsed.ClientAddr.as_deref())?,
        )?;
        let status = parsed.DownstreamStatus.or(parsed.OriginStatus)?;
        let routed = parsed.RouterName.as_ref().is_some_and(|r| !r.0.is_empty());
        let [path, host, agent, method] = &mut self.buffers;
        Some((
            ip,
            Event::Http(Http {
                method: text(parsed.RequestMethod, method).unwrap_or(""),
                path: text(parsed.RequestPath, path).unwrap_or(""),
                status,
                host: text(parsed.RequestHost, host).and_then(dash),
                routed: Some(routed),
                user_agent: text(parsed.user_agent, agent).and_then(dash),
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ip, method, path, status, routed, agent, host
    type Fields = (
        String,
        String,
        String,
        u16,
        Option<bool>,
        Option<String>,
        Option<String>,
    );

    fn http(parser: &mut Traefik, line: &str) -> Fields {
        match parser.parse(line) {
            Some((ip, Event::Http(h))) => (
                ip.to_string(),
                h.method.to_owned(),
                h.path.to_owned(),
                h.status,
                h.routed,
                h.user_agent.map(str::to_owned),
                h.host.map(str::to_owned),
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn common_log_format() {
        let mut p = Traefik::default();
        let f = http(
            &mut p,
            r#"203.0.113.5 - - [19/Oct/2026:12:17:57 +0000] "GET /www/.git/config HTTP/1.1" 404 19 "-" "-" 161616 "-" "-" 0ms"#,
        );
        assert_eq!(
            (f.0.as_str(), f.1.as_str(), f.2.as_str(), f.3, f.4, f.5),
            (
                "203.0.113.5",
                "GET",
                "/www/.git/config",
                404,
                Some(false),
                None
            )
        );

        let f = http(
            &mut p,
            r#"198.51.100.4 - - [02/Nov/2026:16:07:32 +0000] "GET /api/v2/sync/maindata?rid=602 HTTP/1.1" 200 100 "-" "Mozilla/5.0 (X11)" 123719 "torrents@docker" "http://172.20.0.163:8080" 1ms"#,
        );
        assert_eq!(
            (f.2.as_str(), f.4, f.5.as_deref()),
            (
                "/api/v2/sync/maindata?rid=602",
                Some(true),
                Some("Mozilla/5.0 (X11)")
            )
        );

        // A request line without a protocol, as scanners send, and an aborted request.
        let f = http(
            &mut p,
            r#"2001:db8::7 - - [09/Nov/2026:02:07:04 +0000] "CFKQ /" 405 0 "-" "-" 1 "-" "-" 0ms"#,
        );
        assert_eq!(f.1, "CFKQ");
        let f = http(
            &mut p,
            r#"192.0.2.1 - - [14/Oct/2026:10:34:25 +0000] "GET /api/events HTTP/1.1" 0 0 "-" "-" 3 "app@docker" "http://172.18.0.3:8080" 6584ms"#,
        );
        assert_eq!(f.3, 0);

        assert!(
            p.parse("2026-11-10T15:42:51Z DBG github.com/traefik/... Service selected by WRR")
                .is_none()
        );
    }

    #[test]
    fn json_format() {
        let mut p = Traefik::default();
        let f = http(
            &mut p,
            r#"{"ClientHost":"192.0.2.44","RequestMethod":"POST","RequestPath":"/a?b=1&c=2","RequestHost":"example.com","DownstreamStatus":404,"RouterName":"blog@docker","request_User-Agent":"curl/8","Duration":1}"#,
        );
        assert_eq!(
            (f.0.as_str(), f.1.as_str(), f.2.as_str()),
            ("192.0.2.44", "POST", "/a?b=1&c=2")
        );
        assert_eq!(
            (f.4, f.5.as_deref(), f.6.as_deref()),
            (Some(true), Some("curl/8"), Some("example.com"))
        );

        let f = http(
            &mut p,
            r#"{"ClientAddr":"192.0.2.44:5555","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":404}"#,
        );
        assert_eq!(f.4, Some(false));
        assert!(p.parse(r#"{"level":"debug","msg":"x"}"#).is_none());
    }
}
