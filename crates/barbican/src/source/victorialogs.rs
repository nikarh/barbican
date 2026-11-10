//! A VictoriaLogs query followed live (`/select/logsql/tail`). After a reconnect the last minutes are asked for
//! again, and lines up to the last time already read are skipped.

use futures_util::StreamExt;
use serde::Deserialize;

use super::{Backoff, Feeder};
use crate::parse::Text;

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow, rename = "_time")]
    time: Option<Text<'a>>,
    #[serde(borrow, rename = "_msg")]
    msg: Option<Text<'a>>,
}

fn tail_url(base: &str, query: &str, offset: &str) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(base).map_err(|e| e.to_string())?;
    url.set_path(&format!(
        "{}/select/logsql/tail",
        url.path().trim_end_matches('/')
    ));
    url.query_pairs_mut()
        .append_pair("query", query)
        .append_pair("start_offset", offset);
    Ok(url)
}

pub async fn run(mut feeder: Feeder, base: String, query: String) {
    let mut backoff = Backoff::default();
    // The time of the last line read, in nanoseconds: what isn't newer was read already.
    let mut last: Option<i128> = feeder.saved_cursor().await.and_then(|c| c.parse().ok());
    loop {
        let offset = if last.is_some() { "15m" } else { "1h" };
        let url = match tail_url(&base, &query, offset) {
            Ok(u) => u,
            Err(e) => {
                feeder.failed(&e);
                return;
            }
        };
        let response = feeder.app().http.get(url).send().await;
        let response = match response {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                feeder.failed(&format!("HTTP {}", r.status()));
                backoff.wait().await;
                continue;
            }
            Err(e) => {
                feeder.failed(&e.to_string());
                backoff.wait().await;
                continue;
            }
        };
        feeder.connected();
        let mut stream = response.bytes_stream();
        let mut buffer: Vec<u8> = Vec::new();
        while let Some(Ok(chunk)) = stream.next().await {
            backoff.reset();
            buffer.extend_from_slice(&chunk);
            let mut start = 0;
            while let Some(end) = buffer
                .get(start..)
                .and_then(|b| b.iter().position(|c| *c == b'\n'))
            {
                let raw = buffer.get(start..start + end).unwrap_or(&[]);
                start += end + 1;
                let Ok(text) = std::str::from_utf8(raw) else {
                    continue;
                };
                let Ok(line) = serde_json::from_str::<Line<'_>>(text) else {
                    continue;
                };
                let (Some(time), Some(msg)) = (&line.time, &line.msg) else {
                    continue;
                };
                let nanos = barbican_common::time::rfc3339_nanos(time);
                if let (Some(n), Some(l)) = (nanos, last)
                    && n <= l
                {
                    continue;
                }
                let at = nanos.map_or_else(crate::app::now, |n| {
                    i64::try_from(n / 1_000_000_000).unwrap_or(0)
                });
                if !feeder.line(msg, at).await {
                    return;
                }
                if let Some(n) = nanos {
                    last = Some(n);
                    feeder.cursor(n.to_string()).await;
                }
            }
            buffer.drain(..start);
        }
        feeder.flush_cursor().await;
        feeder.failed("the tail ended");
        backoff.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let url = tail_url("http://127.0.0.1:9428", "container_name:sftpd", "1h").unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:9428/select/logsql/tail?query=container_name%3Asftpd&start_offset=1h"
        );
        let url = tail_url("https://logs.example.com/vl/", "a b", "15m").unwrap();
        assert_eq!(url.path(), "/vl/select/logsql/tail");
    }
}
