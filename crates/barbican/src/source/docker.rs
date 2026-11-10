//! A container's log, through the Docker API on its unix socket (or a read-only proxy of it), with timestamps. The
//! cursor is the time of the last line read; a stopped, restarted or recreated container is found again by name.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;

use super::{Backoff, Feeder};

#[derive(Debug)]
struct Error(String);

impl<E: std::fmt::Display> From<E> for Error {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

type Body = hyper::body::Incoming;

async fn get(socket: &Path, path: &str) -> Result<hyper::Response<Body>, Error> {
    let stream = UnixStream::connect(socket).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::get(path)
        .header(hyper::header::HOST, "docker")
        .body(Empty::<Bytes>::new())?;
    Ok(sender.send_request(request).await?)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    id: String,
    config: InspectConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InspectConfig {
    #[serde(default)]
    tty: bool,
}

async fn inspect(socket: &Path, container: &str) -> Result<Inspect, Error> {
    let response = get(socket, &format!("/containers/{container}/json")).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        return Err(Error(format!(
            "{container}: HTTP {status} {}",
            String::from_utf8_lossy(&body).trim()
        )));
    }
    Ok(serde_json::from_slice(&body)?)
}

/// Splits Docker's multiplexed stream (8-byte headers: stream, 3 zero bytes, big-endian length) into payloads.
#[derive(Default)]
struct Demux {
    buffer: Vec<u8>,
}

impl Demux {
    /// Appends data, and gives the complete frames' payloads to `f`.
    fn push(&mut self, data: &[u8], mut each: impl FnMut(&[u8])) {
        self.buffer.extend_from_slice(data);
        let mut start = 0;
        while let Some(header) = self
            .buffer
            .get(start..start + 8)
            .and_then(|h| <[u8; 8]>::try_from(h).ok())
        {
            let [_, _, _, _, size @ ..] = header;
            let len = u32::from_be_bytes(size) as usize;
            let Some(payload) = self.buffer.get(start + 8..start + 8 + len) else {
                break;
            };
            each(payload);
            start += 8 + len;
        }
        self.buffer.drain(..start);
    }
}

/// `since` for the logs request: the saved cursor, or the last hour on the first start.
fn since(cursor: Option<&str>) -> String {
    match cursor {
        Some(c) => c.to_owned(),
        None => (crate::app::now() - 3_600).to_string(),
    }
}

/// The cursor of a line's RFC 3339 time: seconds and nanoseconds, as Docker's `since` takes it.
fn cursor_of(time: &str) -> Option<String> {
    let secs = crate::time::rfc3339(time)?;
    let nanos = time
        .split_once('.')
        .map(|(_, rest)| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .take(9)
                .collect::<String>()
        })
        .unwrap_or_default();
    Some(format!("{secs}.{nanos:0<9}"))
}

pub async fn run(mut feeder: Feeder, socket: PathBuf, container: String) {
    let mut backoff = Backoff::default();
    let mut cursor = feeder.saved_cursor().await;
    loop {
        match follow(&mut feeder, &socket, &container, &mut cursor, &mut backoff).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => feeder.failed(&e.0),
        }
        feeder.flush_cursor().await;
        backoff.wait().await;
    }
}

/// Follows the container's log until it ends. `Ok(true)` when the engine is gone.
async fn follow(
    feeder: &mut Feeder,
    socket: &Path,
    container: &str,
    cursor: &mut Option<String>,
    backoff: &mut Backoff,
) -> Result<bool, Error> {
    let info = inspect(socket, container).await?;
    let path = format!(
        "/containers/{}/logs?follow=1&stdout=1&stderr=1&timestamps=1&since={}",
        info.id,
        since(cursor.as_deref())
    );
    let response = get(socket, &path).await?;
    if !response.status().is_success() {
        return Err(Error(format!(
            "{container}: logs: HTTP {}",
            response.status()
        )));
    }
    feeder.connected();
    let mut body = response.into_body();
    let mut demux = Demux::default();
    // Received bytes not yet handled: complete lines are read from it in place, then dropped.
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let frame = match tokio::time::timeout(Duration::from_secs(3_600), body.frame()).await {
            // Nothing logged for an hour: reconnect, in case the container was replaced quietly.
            Err(_) => return Ok(false),
            Ok(None) => {
                feeder.failed("the container's log ended (stopped?)");
                return Ok(false);
            }
            Ok(Some(frame)) => frame?,
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        backoff.reset();
        if info.config.tty {
            pending.extend_from_slice(data);
        } else {
            demux.push(data, |payload| pending.extend_from_slice(payload));
        }
        let Some(end) = pending.iter().rposition(|b| *b == b'\n') else {
            continue;
        };
        for raw in pending.get(..end).unwrap_or(&[]).split(|b| *b == b'\n') {
            let Ok(line) = std::str::from_utf8(raw) else {
                continue;
            };
            let Some((time, message)) = line.split_once(' ') else {
                continue;
            };
            let Some(new_cursor) = cursor_of(time) else {
                continue;
            };
            // `since` is inclusive: the line the cursor points at comes again.
            if cursor
                .as_deref()
                .is_some_and(|c| c.len() == new_cursor.len() && c >= new_cursor.as_str())
            {
                continue;
            }
            let at = crate::time::rfc3339(time).unwrap_or_else(crate::app::now);
            if !feeder.line(message, at).await {
                return Ok(true);
            }
            *cursor = Some(new_cursor.clone());
            feeder.cursor(new_cursor).await;
        }
        pending.drain(..=end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![stream, 0, 0, 0];
        f.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn demultiplexes_split_frames() {
        let mut data = frame(1, b"first\nsec");
        data.extend(frame(2, b"ond\n"));
        let mut demux = Demux::default();
        let mut out = Vec::new();
        // Delivered in awkward pieces.
        for piece in data.chunks(5) {
            demux.push(piece, |p| out.extend_from_slice(p));
        }
        assert_eq!(out, b"first\nsecond\n");
        assert_eq!(demux.buffer, Vec::<u8>::new());
    }

    #[test]
    fn cursors() {
        assert_eq!(
            cursor_of("2026-11-10T15:42:51.995856621Z").as_deref(),
            Some("1794325371.995856621")
        );
        assert_eq!(
            cursor_of("2026-11-10T15:42:51.5Z").as_deref(),
            Some("1794325371.500000000")
        );
        assert_eq!(cursor_of("nope"), None);
        assert_eq!(since(Some("1794325371.5")), "1794325371.5");
    }
}
