//! The systemd journal, through `journalctl --follow --output=json`, for one unit or syslog identifier. The cursor
//! is the journal's own; without one (the first start) the last hour is read.

use std::process::Stdio;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use super::{Backoff, Feeder};
use crate::parse::Text;

#[derive(Deserialize)]
struct Entry<'a> {
    #[serde(borrow, rename = "MESSAGE")]
    message: Option<Text<'a>>,
    #[serde(borrow, rename = "__CURSOR")]
    cursor: Option<Text<'a>>,
    #[serde(borrow, rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<Text<'a>>,
}

/// The arguments of `journalctl`.
fn arguments(unit: Option<&str>, identifier: Option<&str>, cursor: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--follow".to_owned(),
        "--output=json".to_owned(),
        "--output-fields=MESSAGE".to_owned(),
        "--no-pager".to_owned(),
    ];
    if let Some(unit) = unit {
        args.push(format!("--unit={unit}"));
    }
    if let Some(identifier) = identifier {
        args.push(format!("--identifier={identifier}"));
    }
    match cursor {
        Some(cursor) => args.push(format!("--after-cursor={cursor}")),
        None => args.push("--since=-1h".to_owned()),
    }
    args
}

pub async fn run(mut feeder: Feeder, unit: Option<String>, identifier: Option<String>) {
    let mut backoff = Backoff::default();
    let mut cursor = feeder.saved_cursor().await;
    loop {
        let args = arguments(unit.as_deref(), identifier.as_deref(), cursor.as_deref());
        let child = Command::new("journalctl")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                feeder.failed(&format!("journalctl: {e}"));
                backoff.wait().await;
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            continue;
        };
        feeder.connected();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            backoff.reset();
            let Ok(entry) = serde_json::from_str::<Entry<'_>>(&line) else {
                // MESSAGE as an array of bytes (not UTF-8): skipped.
                continue;
            };
            let at = entry
                .realtime
                .as_deref()
                .and_then(|t| t.parse::<i64>().ok())
                .map_or_else(crate::app::now, |us| us / 1_000_000);
            if let Some(message) = &entry.message
                && !feeder.line(message, at).await
            {
                return;
            }
            if let Some(c) = entry.cursor {
                let c = c.0.into_owned();
                cursor = Some(c.clone());
                feeder.cursor(c).await;
            }
        }
        feeder.flush_cursor().await;
        let _ = child.kill().await;
        feeder.failed("journalctl stopped");
        backoff.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args() {
        let a = arguments(Some("sshd.service"), None, Some("s=abc"));
        assert!(a.contains(&"--unit=sshd.service".to_owned()));
        assert!(a.contains(&"--after-cursor=s=abc".to_owned()));
        let a = arguments(None, Some("sshd"), None);
        assert!(a.contains(&"--identifier=sshd".to_owned()));
        assert!(a.contains(&"--since=-1h".to_owned()));
    }

    #[test]
    fn entries() {
        let e: Entry<'_> = serde_json::from_str(
            r#"{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1794325371123456","MESSAGE":"Invalid user a from 192.0.2.1 port 1"}"#,
        )
        .unwrap();
        assert_eq!(
            e.message.as_deref(),
            Some("Invalid user a from 192.0.2.1 port 1")
        );
        assert_eq!(e.cursor.as_deref(), Some("s=1;i=2"));
        assert!(serde_json::from_str::<Entry<'_>>(r#"{"MESSAGE":[1,2,3]}"#).is_err());
    }
}
