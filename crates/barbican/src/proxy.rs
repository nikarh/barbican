//! `barbican ui-proxy`: the UI for a container, in front of an agent whose UI listens on a unix socket
//! (`ui.socket`). It serves the UI's files itself and passes `/api` (the WebSocket included) to the socket, with the
//! request's own Host and Origin, so the agent's checks see what the browser sent.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

struct Proxy {
    socket: PathBuf,
}

async fn forward(State(proxy): State<Arc<Proxy>>, mut request: Request) -> Response {
    match pass(&proxy, &mut request).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, socket = %proxy.socket.display(), "The agent can't be reached");
            (StatusCode::BAD_GATEWAY, "the agent can't be reached").into_response()
        }
    }
}

async fn pass(proxy: &Proxy, request: &mut Request) -> Result<Response, String> {
    let stream = UnixStream::connect(&proxy.socket)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    // The browser's side of a WebSocket, once both sides have switched protocols.
    let upgrade = hyper::upgrade::on(&mut *request);
    let mut outgoing = hyper::Request::builder().method(request.method()).uri(
        request
            .uri()
            .path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str),
    );
    for (name, value) in request.headers() {
        outgoing = outgoing.header(name, value);
    }
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let outgoing = outgoing.body(body).map_err(|e| e.to_string())?;
    let mut response = sender
        .send_request(outgoing)
        .await
        .map_err(|e| e.to_string())?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let agent = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            if let (Ok(browser), Ok(agent)) = (upgrade.await, agent.await) {
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(browser),
                    &mut TokioIo::new(agent),
                )
                .await;
            }
        });
    }
    Ok(response.map(Body::new))
}

/// Serves the UI on `listen`, for the agent on `socket`.
pub async fn run(socket: PathBuf, listen: SocketAddr) -> Result<(), String> {
    let proxy = Arc::new(Proxy { socket });
    let router = Router::new()
        .route("/api/{*rest}", any(forward))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(crate::web::serve)
        .with_state(proxy);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("{listen}: {e}"))?;
    tracing::info!(%listen, "UI proxy listening");
    // As a container's PID 1 nothing stops it but its own handler: SIGTERM (docker stop) and SIGINT end it at once,
    // open WebSockets with it (the UI reconnects).
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    tokio::select! {
        served = axum::serve(listener, router) => served.map_err(|e| e.to_string()),
        _ = term.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// `barbican healthcheck`: a plain HTTP GET of `url`'s path at its address, healthy on a 200 (an image `FROM scratch`
/// has no curl).
pub fn healthcheck(address: SocketAddr, path: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(3))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    let request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.1 200")
}
