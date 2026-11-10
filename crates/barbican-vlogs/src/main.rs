//! `barbican-vlogs`: the history of a VictoriaLogs query as lines of `<RFC 3339 time> <message>`, oldest first, on
//! stdout: what `barbican import` and `barbican replay` read.
//!
//! The time range is cut into windows, fetched several at a time from `/select/logsql/query` and written in order.
//! Each window is streamed and parsed as it arrives and sorted here: VictoriaLogs' own sort has a memory limit that a
//! busy hour exceeds.

use std::borrow::Cow;
use std::io::Write;
use std::process::ExitCode;

use futures_util::StreamExt;
use serde::Deserialize;

const HELP: &str = "\
barbican-vlogs: a VictoriaLogs query's history as `<time> <message>` lines, oldest first, on stdout

Usage:
  barbican-vlogs [options] <LogsQL query>

Options:
  --url <url>          the VictoriaLogs [default: http://127.0.0.1:9428]
  --since <time>       from: an RFC 3339 time, a date (2026-02-12) or an age (30d, 12h) [default: 365d]
  --until <time>       to, the same way [default: now]
  --window <hours>     the time range of one request [default: 6]
  --parallel <n>       requests at a time [default: 4]

  barbican import traefik:<(barbican-vlogs --since 2026-02-12 'container_name:traefik')
";

/// Attempts per window before giving up.
const TRIES: u32 = 5;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "_time")]
    time: Cow<'a, str>,
    #[serde(borrow, rename = "_msg", default)]
    msg: Cow<'a, str>,
}

/// A window's lines: their text in one buffer, and each line's time and place in it.
#[derive(Default)]
struct Lines {
    text: String,
    index: Vec<(i128, usize, usize)>,
}

impl Lines {
    /// Adds a response row (a JSON object on one line); rows without a time are skipped.
    fn push(&mut self, raw: &[u8]) {
        let Ok(row) = serde_json::from_slice::<Row<'_>>(raw) else {
            return;
        };
        let Some(at) = barbican_common::time::rfc3339_nanos(&row.time) else {
            return;
        };
        let start = self.text.len();
        self.text.push_str(&row.time);
        self.text.push(' ');
        // One line each: newlines in a message become spaces.
        for part in row.msg.split(['\n', '\r']) {
            if self.text.len() > start + row.time.len() + 1 && !part.is_empty() {
                self.text.push(' ');
            }
            self.text.push_str(part);
        }
        self.text.push('\n');
        self.index.push((at, start, self.text.len()));
    }

    /// In time order: a window's sort runs in its own task, on any core.
    fn sort(&mut self) {
        self.index.sort_by_key(|(at, ..)| *at);
    }

    fn write(&self, out: &mut impl Write) -> std::io::Result<()> {
        for (_, start, end) in &self.index {
            if let Some(line) = self.text.get(*start..*end) {
                out.write_all(line.as_bytes())?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Options {
    endpoint: reqwest::Url,
    query: String,
    since: i64,
    until: i64,
    window: i64,
    parallel: usize,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `2026-02-12T10:00:00Z`, `2026-02-12`, or an age: `30d`, `12h`, `90m`.
fn time_arg(s: &str, now: i64) -> Result<i64, String> {
    if let Some(t) = barbican_common::time::rfc3339(s) {
        return Ok(t);
    }
    if let Some(t) = barbican_common::time::rfc3339(&format!("{s}T00:00:00Z")) {
        return Ok(t);
    }
    let (number, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = number
        .parse()
        .map_err(|_| format!("{s:?} isn't a time, a date or an age"))?;
    let secs = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        _ => return Err(format!("{s:?}: an age ends in d, h or m")),
    };
    Ok(now - n * secs)
}

fn endpoint(base: &str) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(base).map_err(|e| format!("{base}: {e}"))?;
    url.set_path(&format!(
        "{}/select/logsql/query",
        url.path().trim_end_matches('/')
    ));
    Ok(url)
}

fn options(mut args: pico_args::Arguments) -> Result<Options, String> {
    let now = now();
    let url: String = args
        .opt_value_from_str("--url")
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "http://127.0.0.1:9428".to_owned());
    let since: Option<String> = args
        .opt_value_from_str("--since")
        .map_err(|e| e.to_string())?;
    let until: Option<String> = args
        .opt_value_from_str("--until")
        .map_err(|e| e.to_string())?;
    let window: i64 = args
        .opt_value_from_str("--window")
        .map_err(|e| e.to_string())?
        .unwrap_or(6);
    let parallel: usize = args
        .opt_value_from_str("--parallel")
        .map_err(|e| e.to_string())?
        .unwrap_or(4);
    let rest = args.finish();
    let [query] = rest.as_slice() else {
        return Err("one LogsQL query".to_owned());
    };
    let since = time_arg(since.as_deref().unwrap_or("365d"), now)?;
    let until = until.as_deref().map_or(Ok(now), |u| time_arg(u, now))?;
    if window < 1 || parallel < 1 {
        return Err("--window and --parallel are at least 1".to_owned());
    }
    Ok(Options {
        endpoint: endpoint(&url)?,
        query: format!("{} | fields _time, _msg", query.to_string_lossy()),
        since,
        until,
        window: window * 3_600,
        parallel,
    })
}

fn main() -> ExitCode {
    let mut err = std::io::stderr();
    let args = pico_args::Arguments::from_env();
    if std::env::args().any(|a| a == "-h" || a == "--help") {
        let _ = err.write_all(HELP.as_bytes());
        return ExitCode::SUCCESS;
    }
    let options = match options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = writeln!(err, "barbican-vlogs: {e}\n\n{HELP}");
            return ExitCode::FAILURE;
        }
    };
    // Windows are parsed on all cores.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "barbican-vlogs: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(&options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(err, "barbican-vlogs: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(o: &Options) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .user_agent(concat!("barbican-vlogs/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let windows = (0..)
        .map(|i| o.since + i * o.window)
        .take_while(|start| *start < o.until)
        .map(|start| (start, (start + o.window).min(o.until)));
    let o = std::sync::Arc::new(o.clone());
    // Each window is a task of its own (so they are parsed in parallel), awaited in order.
    let mut fetched = futures_util::stream::iter(windows)
        .map(|(start, end)| {
            let (client, o) = (client.clone(), std::sync::Arc::clone(&o));
            tokio::spawn(async move { fetch(&client, &o, start, end).await })
        })
        .buffered(o.parallel);
    let mut out = std::io::BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
    while let Some(lines) = fetched.next().await {
        let lines = lines.map_err(|e| e.to_string())??;
        match lines.write(&mut out) {
            Ok(()) => {}
            // The reader is gone (an import that stopped, `| head`): nothing more is wanted.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
    }
    match out.flush() {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// One window, tried again a few times.
async fn fetch(
    client: &reqwest::Client,
    o: &Options,
    start: i64,
    end: i64,
) -> Result<Lines, String> {
    let mut tries = 0;
    loop {
        match fetch_once(client, o, start, end).await {
            Ok(lines) => return Ok(lines),
            Err(e) => {
                tries += 1;
                if tries >= TRIES {
                    return Err(format!("{start}..{end}: {e}"));
                }
                let _ = writeln!(
                    std::io::stderr(),
                    "barbican-vlogs: {start}..{end}: {e}; trying again"
                );
                tokio::time::sleep(std::time::Duration::from_secs(u64::from(tries) * 2)).await;
            }
        }
    }
}

async fn fetch_once(
    client: &reqwest::Client,
    o: &Options,
    start: i64,
    end: i64,
) -> Result<Lines, String> {
    // Both ends are inclusive: a line at exactly `end` belongs to the next window.
    let response = client
        .post(o.endpoint.clone())
        .form(&[
            ("query", o.query.as_str()),
            ("start", &start.to_string()),
            ("end", &format!("{}.999999999", end - 1)),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {}", body.trim()));
    }
    let mut lines = Lines::default();
    let mut stream = response.bytes_stream();
    let mut buffer: Vec<u8> = Vec::with_capacity(1 << 16);
    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk.map_err(|e| e.to_string())?);
        let mut start = 0;
        while let Some(len) = buffer
            .get(start..)
            .and_then(|b| b.iter().position(|c| *c == b'\n'))
        {
            if let Some(row) = buffer.get(start..start + len) {
                lines.push(row);
            }
            start += len + 1;
        }
        buffer.drain(..start);
    }
    if !buffer.is_empty() {
        lines.push(&buffer);
    }
    lines.sort();
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_become_sorted_lines() {
        let mut lines = Lines::default();
        lines.push(br#"{"_time":"2026-11-01T00:00:27Z","_msg":"second"}"#);
        lines.push(
            br#"{"_time":"2026-11-01T00:00:26.5Z","_msg":"Invalid user a\nfrom 192.0.2.1 port 1"}"#,
        );
        lines.push(br#"{"_msg":"no time"}"#);
        lines.push(b"not json");
        lines.push(br#"{"_time":"2026-11-01T00:00:26.25Z","_msg":"esc\u00e9 \"q\""}"#);
        let mut out = Vec::new();
        lines.sort();
        lines.write(&mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2026-11-01T00:00:26.25Z escé \"q\"\n\
             2026-11-01T00:00:26.5Z Invalid user a from 192.0.2.1 port 1\n\
             2026-11-01T00:00:27Z second\n"
        );
    }

    #[test]
    fn times() {
        let now = 1_800_000_000;
        assert_eq!(time_arg("2026-02-12", now), Ok(1_770_854_400));
        assert_eq!(time_arg("2026-02-12T01:00:00Z", now), Ok(1_770_858_000));
        assert_eq!(time_arg("30d", now), Ok(now - 30 * 86_400));
        assert_eq!(time_arg("12h", now), Ok(now - 12 * 3_600));
        assert!(time_arg("soon", now).is_err());
        assert!(time_arg("3w", now).is_err());
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            endpoint("http://127.0.0.1:9428").unwrap().as_str(),
            "http://127.0.0.1:9428/select/logsql/query"
        );
        assert_eq!(
            endpoint("https://logs.example.com/vl/").unwrap().as_str(),
            "https://logs.example.com/vl/select/logsql/query"
        );
    }
}
