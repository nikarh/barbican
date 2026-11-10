//! The API edge agents follow (see `barbican_common::edge`): changes since a sequence number, long polled, and
//! the combined list. Every request needs one of the configured clients' tokens.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use barbican_common::edge::{CHANGES_PATH, LIST_PATH, MAX_WAIT_SECS, render_list};
use serde::Deserialize;

use crate::api::EdgeStatus;
use crate::app::{App, now};

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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let edge = Arc::new(Edge { app, tokens });
    let router = Router::new()
        .route(CHANGES_PATH, get(changes))
        .route(LIST_PATH, get(list))
        .with_state(edge);
    let listener = crate::run::bind(config.listen, "Edge API").await;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| e.to_string())
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
