//! The edge API: edge agents connect, say hello with one of the configured clients' tokens, and stay connected; the
//! agent pushes its changes and its list to them as they happen, and keeps what each reports about itself for the
//! UI. The protocol is `barbican_common::edge`'s. Only over TLS: edges pin the agent's certificate by its
//! fingerprint, so nobody between them can read the tokens or put words in the agent's mouth.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use barbican_common::edge::PROTOCOL_VERSION;
use barbican_common::edge::wire::{self, Frame, HEARTBEAT, SILENCE};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, sleep_until, timeout};

use crate::api::{EdgeReport, EdgeUpstream};
use crate::app::{App, now};

/// The certificate and key the edge API serves, and the certificate's fingerprint.
pub struct Identity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: String,
}

/// The SHA-256 of a certificate (DER): hex pairs joined by colons, as edges are configured with it.
#[must_use]
pub fn fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Where the certificate and key are: as configured, or next to the database.
fn paths(config: &crate::config::Config, edge: &crate::config::Edge) -> (PathBuf, PathBuf) {
    if let (Some(cert), Some(key)) = (&edge.cert, &edge.key) {
        return (cert.clone(), key.clone());
    }
    let dir = config
        .database
        .path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    (dir.join("edge-cert.pem"), dir.join("edge-key.pem"))
}

fn read(cert: &Path, key: &Path) -> Result<Identity, String> {
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let first = certs
        .first()
        .ok_or_else(|| format!("{}: no certificate", cert.display()))?;
    let fingerprint = fingerprint(first.as_ref());
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    Ok(Identity {
        certs,
        key,
        fingerprint,
    })
}

/// The edge API's certificate and key: read, or, when neither is configured and none was made yet, made now
/// (self-signed, valid for as long as anyone cares) and stored next to the database.
pub fn identity(
    config: &crate::config::Config,
    edge: &crate::config::Edge,
    create: bool,
) -> Result<Identity, String> {
    let (cert, key) = paths(config, edge);
    if cert.exists() || edge.cert.is_some() || !create {
        return read(&cert, &key);
    }
    let made = rcgen::generate_simple_self_signed(vec!["barbican".to_owned()])
        .map_err(|e| e.to_string())?;
    let write = |path: &Path, text: &str, mode: u32| {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    write(&key, &made.signing_key.serialize_pem(), 0o600)?;
    write(&cert, &made.cert.pem(), 0o644)?;
    tracing::info!(cert = %cert.display(), "Made a certificate for the edge API");
    read(&cert, &key)
}

struct Edge {
    app: Arc<App>,
    /// Token to client name.
    tokens: HashMap<String, String>,
    /// Numbers connections, so a connection that ends doesn't mark a newer one of the same edge disconnected.
    connections: AtomicU64,
    /// Each edge's newest connection.
    current: std::sync::Mutex<HashMap<String, u64>>,
    /// The list as last written, by version: written once for every edge that needs it.
    list: std::sync::Mutex<Option<(String, Arc<Vec<u8>>)>>,
}

/// Compares in constant time, so a token can't be guessed byte by byte from response times.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The largest hello: nothing bigger is read before the token is known.
const MAX_HELLO: usize = 64 * 1024;

impl Edge {
    fn client(&self, token: &str) -> Option<&str> {
        let mut found = None;
        for (t, name) in &self.tokens {
            if same(t.as_bytes(), token.as_bytes()) {
                found = Some(name.as_str());
            }
        }
        found
    }

    /// The list's frames, written when its version is new.
    fn list_frames(&self) -> (String, Arc<Vec<u8>>) {
        let lists = self.app.lists.read().map(|l| l.clone()).unwrap_or_default();
        let Ok(mut cached) = self.list.lock() else {
            let mut out = Vec::new();
            wire::encode_list(&mut out, &lists.version, &lists.nets);
            return (lists.version, Arc::new(out));
        };
        if let Some((version, frames)) = cached.as_ref()
            && *version == lists.version
        {
            return (version.clone(), Arc::clone(frames));
        }
        let mut out = Vec::new();
        wire::encode_list(&mut out, &lists.version, &lists.nets);
        let frames = Arc::new(out);
        *cached = Some((lists.version.clone(), Arc::clone(&frames)));
        (lists.version, frames)
    }
}

/// Reads one frame into `buf` (its type and payload).
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<(), String> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await.map_err(|e| e.to_string())?;
    let len = wire::frame_len(header).map_err(|e| e.to_string())?;
    if len > limit {
        return Err(format!("a frame of {len} bytes"));
    }
    buf.resize(len, 0);
    r.read_exact(buf).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn write<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), String> {
    timeout(SILENCE, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    .map_err(|_| "the edge stopped reading".to_owned())?
    .map_err(|e| e.to_string())
}

/// Turns a time of the edge's clock into this agent's.
fn local(t: Option<u64>, offset: i64) -> Option<i64> {
    t.and_then(|t| i64::try_from(t).ok())
        .map(|t| t.saturating_add(offset))
}

/// Where an edge is, as its hello said.
struct Start {
    client: String,
    epoch: String,
    seq: u64,
    list_version: String,
    lists: bool,
}

/// Pushes what the edge needs: what it missed, then every change as it happens, and the list when it changed.
async fn push<W: AsyncWrite + Unpin>(
    edge: &Edge,
    w: &mut W,
    start: Start,
    connection: u64,
) -> Result<(), String> {
    let app = &edge.app;
    let mut out = Vec::new();
    wire::Welcome {
        client: &start.client,
        version: crate::VERSION,
    }
    .encode(&mut out);
    let mut news = app.journal_seq.subscribe();
    news.borrow_and_update();
    let (mut epoch, mut seq, mut list_version) = (start.epoch, start.seq, start.list_version);
    let mut first = true;
    loop {
        let unix = u64::try_from(now()).unwrap_or(0);
        let changes = app
            .journal
            .lock()
            .map_err(|_| "the journal's lock is poisoned".to_owned())?
            .since(&epoch, seq, unix);
        let news_for_it = first
            || changes.full
            || changes.seq != seq
            || !(changes.block.is_empty()
                && changes.unblock.is_empty()
                && changes.allow.is_empty()
                && changes.unallow.is_empty());
        if news_for_it {
            wire::encode_changes(&mut out, &changes);
            epoch.clone_from(&changes.epoch);
            seq = changes.seq;
        }
        first = false;
        write(w, &out).await?;
        out.clear();
        if news_for_it {
            edge.update(&start.client, connection, |e| e.seq = seq);
        }
        if start.lists {
            let version = app
                .lists
                .read()
                .map(|l| l.version.clone())
                .unwrap_or_default();
            // An empty version: not computed yet since the agent started; the edge keeps what it has meanwhile.
            if !version.is_empty() && version != list_version {
                let (version, frames) = edge.list_frames();
                write(w, &frames).await?;
                list_version = version;
            }
        }
        let mut quiet = Instant::now() + HEARTBEAT;
        loop {
            tokio::select! {
                changed = news.changed() => {
                    changed.map_err(|_| "stopping".to_owned())?;
                    break;
                }
                () = sleep_until(quiet) => {
                    wire::encode_ping(&mut out);
                    write(w, &out).await?;
                    out.clear();
                    quiet = Instant::now() + HEARTBEAT;
                }
            }
        }
    }
}

/// Takes in a status report.
fn report(edge: &Edge, client: &str, connection: u64, status: &wire::Status<'_>) {
    let received = now();
    let offset = received.saturating_sub(i64::try_from(status.report.at).unwrap_or(0));
    let r = &status.report;
    let text = |s: &str| (!s.is_empty()).then(|| s.to_owned());
    let report = EdgeReport {
        received,
        uptime: r.uptime,
        rss: r.rss,
        applied: local(r.applied, offset),
        blocks: r.blocks,
        listed: r.listed,
        dropped_blocked: r.dropped.blocked.packets,
        dropped_blocked_bytes: r.dropped.blocked.bytes,
        dropped_listed: r.dropped.listed.packets,
        dropped_listed_bytes: r.dropped.listed.bytes,
        error: text(status.error),
        upstreams: status
            .upstreams
            .iter()
            .map(|u| EdgeUpstream {
                name: u.name.to_owned(),
                this: u.this,
                connected: u.connected,
                last_contact: local(u.last_contact, offset),
                error: text(u.error),
            })
            .collect(),
    };
    edge.update(client, connection, |e| {
        e.version = Some(status.version.to_owned());
        e.backend = Some(status.backend.to_owned());
        e.enforcing = Some(r.enforcing);
        e.report = Some(report);
    });
}

/// Serves one edge: its hello, then its reports while pushing what it needs, until either side goes quiet.
async fn connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    edge: Arc<Edge>,
    stream: S,
    peer: SocketAddr,
) {
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = Vec::new();
    let refuse = async |w: &mut tokio::io::WriteHalf<S>, reason: &str| {
        tracing::warn!(address = %peer.ip(), reason, "Refused an edge");
        let mut out = Vec::new();
        wire::encode_refuse(&mut out, reason);
        let _ = timeout(Duration::from_secs(5), async {
            let _ = w.write_all(&out).await;
            let _ = w.shutdown().await;
        })
        .await;
    };
    match timeout(
        Duration::from_secs(10),
        read_frame(&mut r, &mut buf, MAX_HELLO),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return refuse(&mut w, &format!("expected a hello: {e}")).await,
        Err(_) => return refuse(&mut w, "no hello within 10 s").await,
    }
    let hello = match wire::decode(&buf) {
        Ok(Frame::Hello(hello)) => hello,
        Err(wire::Error::Protocol(theirs)) => {
            let reason = format!(
                "the edge speaks protocol {theirs}, this agent {PROTOCOL_VERSION}: update the older one"
            );
            return refuse(&mut w, &reason).await;
        }
        Ok(_) => return refuse(&mut w, "expected a hello").await,
        Err(e) => return refuse(&mut w, &format!("a broken hello: {e}")).await,
    };
    let Some(client) = edge.client(hello.token).map(str::to_owned) else {
        return refuse(&mut w, "unknown token").await;
    };
    let connection = edge.connections.fetch_add(1, Ordering::Relaxed) + 1;
    if let Ok(mut current) = edge.current.lock() {
        current.insert(client.clone(), connection);
    }
    let start = Start {
        client: client.clone(),
        epoch: hello.epoch.to_owned(),
        seq: hello.seq,
        list_version: hello.list_version.to_owned(),
        lists: hello.lists,
    };
    tracing::info!(edge = %client, address = %peer.ip(), version = hello.version, "Edge connected");
    edge.update(&client, connection, |e| {
        e.connected = true;
        e.since = Some(now());
        e.address = Some(peer.ip().to_string());
        e.seq = hello.seq;
        e.version = Some(hello.version.to_owned());
        e.backend = Some(hello.backend.to_owned());
        e.enforcing = Some(hello.enforcing);
    });

    let mut pusher = {
        let edge = Arc::clone(&edge);
        tokio::spawn(async move { push(&edge, &mut w, start, connection).await })
    };
    let reason = loop {
        let read = tokio::select! {
            pushed = &mut pusher => break match pushed {
                Ok(Err(e)) => e,
                _ => "stopped".to_owned(),
            },
            read = timeout(SILENCE, read_frame(&mut r, &mut buf, wire::MAX_FRAME)) => read,
        };
        match read {
            Err(_) => break format!("silent for {} s", SILENCE.as_secs()),
            Ok(Err(e)) => break e,
            Ok(Ok(())) => {}
        }
        match wire::decode(&buf) {
            Ok(Frame::Ping) => {}
            Ok(Frame::Status(status)) => report(&edge, &client, connection, &status),
            Ok(_) => break "an unexpected frame".to_owned(),
            Err(e) => break format!("a broken frame: {e}"),
        }
    };
    pusher.abort();
    tracing::info!(edge = %client, address = %peer.ip(), reason, "Edge disconnected");
    edge.update(&client, connection, |e| {
        e.connected = false;
        e.since = Some(now());
    });
}

impl Edge {
    /// Changes an edge's status, unless a newer connection of the same edge took over.
    fn update(
        &self,
        client: &str,
        connection: u64,
        change: impl FnOnce(&mut crate::api::EdgeStatus),
    ) {
        let current = self
            .current
            .lock()
            .is_ok_and(|c| c.get(client) == Some(&connection));
        if !current {
            return;
        }
        self.app.edges.send_modify(|edges| {
            let e = edges.entry(client.to_owned()).or_default();
            client.clone_into(&mut e.name);
            change(e);
        });
    }
}

/// Serves the edge API until the process ends.
pub async fn serve(app: Arc<App>, config: &crate::config::Edge) -> Result<(), String> {
    let mut tokens = HashMap::new();
    for client in &config.clients {
        let token = client.token().map_err(|e| e.to_string())?;
        if token.len() < 16 {
            return Err(format!(
                "edge client {:?}: use a token of at least 16 characters",
                client.name
            ));
        }
        tokens.insert(token, client.name.clone());
    }
    let identity = identity(&app.config, config, true)?;
    tracing::info!(fingerprint = %identity.fingerprint, "Edge API certificate");
    let _ = app.edge_fingerprint.set(identity.fingerprint.clone());
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(identity.certs, identity.key)
    .map_err(|e| format!("the edge API's certificate: {e}"))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let edge = Arc::new(Edge {
        app,
        tokens,
        connections: AtomicU64::new(0),
        current: std::sync::Mutex::new(HashMap::new()),
        list: std::sync::Mutex::new(None),
    });
    let listener = crate::run::bind(config.listen, "Edge API (TLS)").await;
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let edge = Arc::clone(&edge);
        tokio::spawn(async move {
            let Ok(Ok(stream)) = timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
            else {
                return;
            };
            connection(edge, stream, peer).await;
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison() {
        assert!(same(b"abcdef", b"abcdef"));
        assert!(!same(b"abcdef", b"abcdeg"));
        assert!(!same(b"abc", b"abcd"));
    }
}
