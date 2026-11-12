//! The UI's WebSocket endpoint: parses request frames, runs the calls concurrently and streams the responses back.
//! See [`crate::api`] for the protocol, and [`crate::ui`] for what the methods do.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};
use tokio::task::{AbortHandle, JoinSet};

use crate::api::{
    Call, DEFLATE_MIN, DEFLATE_PROTOCOL, ErrorCode, Request, RpcError, ServerMessage,
};
use crate::app::App;

/// Requests in one frame, at most.
const MAX_BATCH: usize = 200;
const PING_INTERVAL: Duration = Duration::from_secs(30);

type Subscriptions = Arc<Mutex<HashMap<String, AbortHandle>>>;

pub async fn upgrade(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers) {
        tracing::warn!(origin = ?headers.get(header::ORIGIN), "Refused a WebSocket from another origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    upgrade
        .max_message_size(1024 * 1024)
        .protocols([DEFLATE_PROTOCOL])
        .on_upgrade(move |socket| serve(socket, app))
}

/// Browsers open WebSockets cross-site with the user's cookies, which a proxy in front may authenticate by: only
/// pages of this origin may connect.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) else {
        // Not a browser.
        return true;
    };
    let Some(origin_host) = origin.split_once("://").map(|(_, host)| host) else {
        return false;
    };
    [header::HOST.as_str(), "x-forwarded-host"]
        .iter()
        .filter_map(|name| headers.get(*name).and_then(|h| h.to_str().ok()))
        .flat_map(|h| h.split(','))
        .any(|host| host.trim().eq_ignore_ascii_case(origin_host))
}

/// A message as a frame: compressed in a binary frame when the client asked for that and it's large enough.
fn encode(message: &ServerMessage, deflate: bool) -> Result<Message, String> {
    let text = serde_json::to_string(message).map_err(|e| e.to_string())?;
    if !deflate || text.len() < DEFLATE_MIN {
        return Ok(Message::Text(Utf8Bytes::from(text)));
    }
    let mut encoder = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(text.len() / 4),
        flate2::Compression::default(),
    );
    std::io::Write::write_all(&mut encoder, text.as_bytes()).map_err(|e| e.to_string())?;
    let bytes = encoder.finish().map_err(|e| e.to_string())?;
    Ok(Message::Binary(bytes.into()))
}

pub async fn serve(socket: WebSocket, app: Arc<App>) {
    let deflate = socket
        .protocol()
        .is_some_and(|p| p.as_bytes() == DEFLATE_PROTOCOL.as_bytes());
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(256);

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.reset();
        loop {
            let message = tokio::select! {
                message = rx.recv() => match message {
                    Some(message) => match encode(&message, deflate) {
                        Ok(frame) => frame,
                        Err(e) => {
                            tracing::error!(error = %e, "Serializing a response failed");
                            continue;
                        }
                    },
                    None => break,
                },
                _ = ping.tick() => Message::Ping(axum::body::Bytes::new()),
            };
            if sink.send(message).await.is_err() {
                return;
            }
        }
        // Answers the browser's close (or closes): without it the browser sees an unclean close (1006), and the
        // proxies in between keep the connection until they notice.
        let _ = sink.close().await;
    });

    let subscriptions: Subscriptions = Arc::default();
    let mut calls = JoinSet::new();

    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => break,
            _ => continue,
        };
        for (id, call) in parse(&text) {
            let call = match call {
                Ok(call) => call,
                Err(error) => {
                    if tx.send(ServerMessage::Error { id, error }).await.is_err() {
                        break;
                    }
                    continue;
                }
            };
            let Some(id) = id else { continue };
            let app = Arc::clone(&app);
            let tx = tx.clone();
            let subscriptions = Arc::clone(&subscriptions);
            calls.spawn(async move {
                let message = match run(&app, &id, call, &tx, &subscriptions).await {
                    // Already answered.
                    Ok(None) => return,
                    Ok(Some(result)) => ServerMessage::Result { id, result },
                    Err(error) => ServerMessage::Error {
                        id: Some(id),
                        error,
                    },
                };
                let _ = tx.send(message).await;
            });
        }
        // Reap finished calls so the set doesn't grow over a long connection.
        while calls.try_join_next().is_some() {}
    }

    calls.abort_all();
    if let Ok(subscriptions) = subscriptions.lock() {
        for handle in subscriptions.values() {
            handle.abort();
        }
    }
    drop(tx);
    let _ = writer.await;
}

/// Splits a frame into its calls. An unparsable call yields an error, with the id when there is one.
fn parse(text: &str) -> Vec<(Option<String>, Result<Call, RpcError>)> {
    let bad = |message: String| RpcError {
        code: ErrorCode::BadRequest,
        message,
    };
    let values = match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(values)) => values,
        Ok(value @ Value::Object(_)) => vec![value],
        Ok(_) => {
            return vec![(
                None,
                Err(bad("expected a request or an array of them".into())),
            )];
        }
        Err(e) => return vec![(None, Err(bad(format!("invalid JSON: {e}"))))],
    };
    if values.len() > MAX_BATCH {
        return vec![(
            None,
            Err(bad(format!("at most {MAX_BATCH} requests per frame"))),
        )];
    }
    values
        .into_iter()
        .map(|value| {
            let id = value.get("id").and_then(Value::as_str).map(str::to_owned);
            match (&id, serde_json::from_value::<Request>(value)) {
                (Some(_), Ok(request)) => (Some(request.id), Ok(request.call)),
                (None, _) => (None, Err(bad("a request needs a string id".into()))),
                (Some(_), Err(e)) => (id, Err(bad(e.to_string()))),
            }
        })
        .collect()
}

async fn run(
    app: &Arc<App>,
    id: &str,
    call: Call,
    tx: &mpsc::Sender<ServerMessage>,
    subscriptions: &Subscriptions,
) -> Result<Option<Value>, RpcError> {
    match call {
        Call::LiveSubscribe => {
            subscribe_live(app, id, tx, subscriptions).await?;
            Ok(None)
        }
        Call::EdgesSubscribe => {
            subscribe_edges(app, id, tx, subscriptions).await?;
            Ok(None)
        }
        Call::Unsubscribe(p) => {
            let handle = subscriptions.lock().ok().and_then(|mut s| s.remove(&p.id));
            if let Some(handle) = handle {
                handle.abort();
            }
            Ok(Some(Value::Null))
        }
        call => crate::ui::call(app, call).await.map(Some),
    }
}

fn check_new(id: &str, subscriptions: &Subscriptions) -> Result<(), RpcError> {
    if subscriptions.lock().is_ok_and(|s| s.contains_key(id)) {
        return Err(RpcError {
            code: ErrorCode::BadRequest,
            message: "a subscription with this id exists".to_owned(),
        });
    }
    Ok(())
}

fn keep(id: &str, task: &tokio::task::JoinHandle<()>, subscriptions: &Subscriptions) {
    if let Ok(mut subscriptions) = subscriptions.lock() {
        subscriptions.insert(id.to_owned(), task.abort_handle());
    } else {
        task.abort();
    }
}

/// Answers the call, then pushes the edges as they are, and again whenever one of them changes.
async fn subscribe_edges(
    app: &Arc<App>,
    id: &str,
    tx: &mpsc::Sender<ServerMessage>,
    subscriptions: &Subscriptions,
) -> Result<(), RpcError> {
    check_new(id, subscriptions)?;
    let mut edges = app.edges.subscribe();
    let _ = tx
        .send(ServerMessage::Result {
            id: id.to_owned(),
            result: Value::Null,
        })
        .await;
    let tx = tx.clone();
    let task_id = id.to_owned();
    let task = tokio::spawn(async move {
        loop {
            let list: Vec<_> = edges.borrow_and_update().values().cloned().collect();
            let Ok(event) = serde_json::to_value(&list) else {
                return;
            };
            if tx
                .send(ServerMessage::Event {
                    id: task_id.clone(),
                    event,
                })
                .await
                .is_err()
                || edges.changed().await.is_err()
            {
                return;
            }
        }
    });
    keep(id, &task, subscriptions);
    Ok(())
}

/// Answers the call with the latest live items (oldest first), then pushes new ones as they come.
async fn subscribe_live(
    app: &Arc<App>,
    id: &str,
    tx: &mpsc::Sender<ServerMessage>,
    subscriptions: &Subscriptions,
) -> Result<(), RpcError> {
    check_new(id, subscriptions)?;
    let (recent, mut events) = app.live();
    let _ = tx
        .send(ServerMessage::Result {
            id: id.to_owned(),
            result: serde_json::to_value(&recent).unwrap_or(Value::Null),
        })
        .await;
    let tx = tx.clone();
    let task_id = id.to_owned();
    let task = tokio::spawn(async move {
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                // A slow client misses events; the UI refetches what it shows now and then anyway.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Ok(event) = serde_json::to_value(&event) else {
                continue;
            };
            if tx
                .send(ServerMessage::Event {
                    id: task_id.clone(),
                    event,
                })
                .await
                .is_err()
            {
                return;
            }
        }
    });
    keep(id, &task, subscriptions);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    axum::http::HeaderName::from_static(k),
                    HeaderValue::from_static(v),
                )
            })
            .collect()
    }

    #[test]
    fn origins() {
        assert!(origin_allowed(&headers(&[("host", "a.example")])));
        assert!(origin_allowed(&headers(&[
            ("host", "a.example"),
            ("origin", "https://a.example")
        ])));
        assert!(origin_allowed(&headers(&[
            ("host", "127.0.0.1:7381"),
            ("x-forwarded-host", "a.example"),
            ("origin", "https://a.example")
        ])));
        assert!(!origin_allowed(&headers(&[
            ("host", "a.example"),
            ("origin", "https://evil.example")
        ])));
    }

    #[test]
    fn parses_batches() {
        let parsed = parse(
            r#"[{"id":"1","method":"meta.get"},
                {"id":"2","method":"ips.list","params":{"filter":"banned","offset":100}},
                {"id":"3","method":"nope"},
                {"method":"meta.get"}]"#,
        );
        assert_eq!(parsed.len(), 4);
        assert!(matches!(parsed[0], (Some(_), Ok(Call::MetaGet))));
        let (_, Ok(Call::IpsList(p))) = &parsed[1] else {
            panic!("expected ips.list");
        };
        assert_eq!(p.offset, 100);
        assert!(matches!(&parsed[2], (Some(id), Err(_)) if id == "3"));
        assert!(matches!(parsed[3], (None, Err(_))));
        assert!(matches!(&parse("42")[..], [(None, Err(_))]));
    }

    #[test]
    fn compresses_large_messages_for_clients_that_ask() {
        let small = ServerMessage::Result {
            id: "1".into(),
            result: Value::Null,
        };
        let large = ServerMessage::Result {
            id: "2".into(),
            result: Value::String("x".repeat(DEFLATE_MIN)),
        };
        assert!(matches!(encode(&small, true), Ok(Message::Text(_))));
        assert!(matches!(encode(&large, false), Ok(Message::Text(_))));
        let Ok(Message::Binary(bytes)) = encode(&large, true) else {
            panic!("expected a binary frame");
        };
        let mut text = String::new();
        std::io::Read::read_to_string(&mut flate2::read::ZlibDecoder::new(&bytes[..]), &mut text)
            .unwrap();
        assert_eq!(text, serde_json::to_string(&large).unwrap());
        assert!(bytes.len() < text.len() / 4);
    }
}
