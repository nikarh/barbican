//! The API edge agents follow (see `barbican_common::edge`): changes since a sequence number, long polled, and
//! the combined list. Only over TLS: edges pin the agent's certificate by its fingerprint, so nobody between them can
//! read the tokens or put words in the agent's mouth. Every request needs one of the configured clients' tokens.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use barbican_common::edge::{CHANGES_PATH, LIST_PATH, MAX_WAIT_SECS, render_list};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;

use crate::api::EdgeStatus;
use crate::app::{App, now};

/// The address an edge connects from.
#[derive(Debug, Clone, Copy)]
struct Peer(SocketAddr);

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
}

#[derive(Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    epoch: String,
    #[serde(default)]
    since: u64,
    #[serde(default)]
    wait: u64,
}

/// Compares in constant time, so a token can't be guessed byte by byte from response times.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Edge {
    fn client(&self, headers: &HeaderMap) -> Option<&str> {
        let token = headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?;
        let mut found = None;
        for (t, name) in &self.tokens {
            if same(t.as_bytes(), token.as_bytes()) {
                found = Some(name.as_str());
            }
        }
        found
    }
}

async fn changes(
    State(edge): State<Arc<Edge>>,
    Extension(Peer(peer)): Extension<Peer>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> Response {
    let Some(client) = edge.client(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let app = &edge.app;
    let mut seq = app.journal_seq.subscribe();
    let current = *seq.borrow_and_update();
    let epoch_matches = app.journal.lock().is_ok_and(|j| j.epoch() == query.epoch);
    // Nothing new for this edge: wait for news, or until the wait runs out.
    if epoch_matches && query.since == current && query.wait > 0 {
        let wait = Duration::from_secs(query.wait.min(MAX_WAIT_SECS));
        let _ = tokio::time::timeout(wait, seq.changed()).await;
    }
    let Ok(changes) = app
        .journal
        .lock()
        .map(|j| j.since(&query.epoch, query.since, u64::try_from(now()).unwrap_or(0)))
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Ok(mut edges) = app.edges.lock() {
        edges.insert(
            client.to_owned(),
            EdgeStatus {
                name: client.to_owned(),
                address: peer.ip().to_string(),
                last_poll: now(),
                seq: changes.seq,
                agent: headers
                    .get(header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            },
        );
    }
    axum::Json(changes).into_response()
}

async fn list(State(edge): State<Arc<Edge>>, headers: HeaderMap) -> Response {
    if edge.client(&headers).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let lists = edge.app.lists.read().map(|l| l.clone()).unwrap_or_default();
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_list(&lists.version, &lists.nets),
    )
        .into_response()
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
    let edge = Arc::new(Edge { app, tokens });
    let router = Router::new()
        .route(CHANGES_PATH, get(changes))
        .route(LIST_PATH, get(list))
        .with_state(edge);
    let listener = crate::run::bind(config.listen, "Edge API (TLS)").await;
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let acceptor = acceptor.clone();
        let service = router.clone().layer(Extension(Peer(peer)));
        tokio::spawn(async move {
            let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
            else {
                return;
            };
            let service = hyper_util::service::TowerToHyperService::new(service);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
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
