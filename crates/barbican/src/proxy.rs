//! `barbican ui-proxy`: the UI for a container, in front of an agent whose UI listens on a unix socket
//! (`ui.socket`). It serves the UI's files itself and passes `/api` (the WebSocket included) to the socket, with the
//! request's own Host and Origin, so the agent's checks see what the browser sent. `GET /api/proxy` it answers itself:
//! whether the agent answers on the socket and, if not, why (a [`ProxyStatus`]), which is also the body of its 502s.
//!
//! The UI is full control over the agent, so the proxy only answers requests an authenticating reverse proxy forwarded
//! ([`Gate`]): from one of its addresses (`--trusted-proxy`, required), and with `--user-header` only those naming the
//! user it authenticated (Authelia's forward auth sets `Remote-User`). It is meant to run in a container on a network
//! only that reverse proxy reaches; a debug build alone can run it without a trusted proxy, for development.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use barbican_common::net::Net;

use crate::api::{ProxyProblem, ProxyProblemKind, ProxyStatus};

/// How long `/api/proxy` waits for the agent's `/healthz`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

struct Proxy {
    socket: PathBuf,
    gate: Gate,
}

/// Which requests the proxy answers: only those from a trusted reverse proxy's addresses, and with a user header
/// configured only those that name a user. `/healthz` is always answered: the container's healthcheck asks it.
#[derive(Debug, Clone, Default)]
pub struct Gate {
    trusted: Vec<Net>,
    header: Option<HeaderName>,
}

impl Gate {
    /// Only requests from `trusted` addresses (at least one), carrying a non-empty `header` when one is given.
    pub fn new(trusted: Vec<Net>, header: Option<&str>) -> Result<Self, String> {
        if trusted.is_empty() {
            return Err(
                "--trusted-proxy is required: the addresses of the reverse proxy that authenticates users (whoever \
                 else reaches the UI would control the agent)"
                    .to_owned(),
            );
        }
        let header = header
            .map(|h| {
                HeaderName::try_from(h.trim()).map_err(|e| format!("--user-header {h:?}: {e}"))
            })
            .transpose()?;
        Ok(Self { trusted, header })
    }

    /// Every request, from anywhere: for development only, so only in debug builds.
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn insecure_for_development() -> Self {
        Self::default()
    }

    /// Whether a request for `path` from `peer` with `headers` may pass.
    fn admits(&self, path: &str, peer: IpAddr, headers: &HeaderMap) -> bool {
        if path == "/healthz" {
            return true;
        }
        // Only `insecure_for_development` (debug builds) has no trusted proxy.
        if self.trusted.is_empty() {
            return cfg!(debug_assertions);
        }
        // An IPv4 peer of a dual-stack socket arrives as ::ffff:a.b.c.d.
        let peer = match peer {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(peer, IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        self.trusted.iter().any(|n| n.contains_ip(peer))
            && self.header.as_ref().is_none_or(|header| {
                headers
                    .get(header)
                    .is_some_and(|v| !v.as_bytes().trim_ascii().is_empty())
            })
    }
}

/// Refuses what the [`Gate`] doesn't admit, before anything else sees it.
async fn admit(
    State(proxy): State<Arc<Proxy>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if proxy
        .gate
        .admits(request.uri().path(), peer.ip(), request.headers())
    {
        next.run(request).await
    } else {
        tracing::warn!(peer = %peer, path = request.uri().path(), "Refused a request not forwarded by a trusted proxy with a user");
        (StatusCode::FORBIDDEN, "forbidden\n").into_response()
    }
}

impl Proxy {
    fn status(&self, problem: Option<ProxyProblem>) -> ProxyStatus {
        ProxyStatus {
            socket: self.socket.display().to_string(),
            problem,
        }
    }
}

/// What a failed connect to the agent's socket means, and what to check.
fn classify(e: &io::Error, socket: &Path) -> ProxyProblem {
    let socket = socket.display();
    let (kind, hint) = match e.kind() {
        io::ErrorKind::NotFound => (
            ProxyProblemKind::NotFound,
            format!(
                "There is no socket at {socket}. Is the agent running, and is its ui.socket this path? In a \
                 container, is the socket's directory mounted (the directory, not the socket)?"
            ),
        ),
        io::ErrorKind::PermissionDenied => (
            ProxyProblemKind::PermissionDenied,
            format!(
                "The proxy may not use {socket}. Is the container in the socket's group (group_add with the gid of \
                 barbican-ui on the host: getent group barbican-ui), and is the agent's ui.socket_group that group?"
            ),
        ),
        io::ErrorKind::ConnectionRefused => (
            ProxyProblemKind::Refused,
            format!(
                "{socket} exists, but nothing accepts connections on it: the agent has stopped, or is starting. \
                 Check that it runs and what its log says."
            ),
        ),
        _ => (
            ProxyProblemKind::Other,
            format!("The proxy can't connect to {socket}. Is --socket the agent's ui.socket?"),
        ),
    };
    ProxyProblem {
        kind,
        error: e.to_string(),
        hint,
    }
}

fn no_answer(error: String) -> ProxyProblem {
    ProxyProblem {
        kind: ProxyProblemKind::NoAnswer,
        error,
        hint: "The agent accepted the connection but didn't answer. Check its log.".to_owned(),
    }
}

/// Sends `request` to the agent, over a connection of its own that also carries a protocol switch.
async fn send(
    socket: &Path,
    request: hyper::Request<Body>,
) -> Result<hyper::Response<Incoming>, ProxyProblem> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| classify(&e, socket))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| no_answer(e.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|e| no_answer(e.to_string()))
}

/// Whether the agent answers its `/healthz` on the socket.
async fn probe(socket: &Path) -> Option<ProxyProblem> {
    let mut request = hyper::Request::new(Body::empty());
    *request.uri_mut() = Uri::from_static("/healthz");
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));
    match tokio::time::timeout(PROBE_TIMEOUT, send(socket, request)).await {
        Err(_) => Some(no_answer(format!(
            "no answer within {} seconds",
            PROBE_TIMEOUT.as_secs()
        ))),
        Ok(Err(problem)) => Some(problem),
        Ok(Ok(response)) if response.status().is_success() => None,
        Ok(Ok(response)) => Some(no_answer(format!(
            "/healthz answered {}",
            response.status()
        ))),
    }
}

fn json(status: StatusCode, body: &ProxyStatus) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /api/proxy`: answered by the proxy itself, whether the agent is reachable or not.
async fn status(State(proxy): State<Arc<Proxy>>) -> Response {
    let problem = probe(&proxy.socket).await;
    json(StatusCode::OK, &proxy.status(problem))
}

async fn forward(State(proxy): State<Arc<Proxy>>, mut request: Request) -> Response {
    match pass(&proxy, &mut request).await {
        Ok(response) => response,
        Err(problem) => {
            tracing::warn!(
                error = %problem.error,
                kind = ?problem.kind,
                socket = %proxy.socket.display(),
                "The agent can't be reached"
            );
            json(StatusCode::BAD_GATEWAY, &proxy.status(Some(problem)))
        }
    }
}

async fn pass(proxy: &Proxy, request: &mut Request) -> Result<Response, ProxyProblem> {
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
    let outgoing = outgoing.body(body).map_err(|e| ProxyProblem {
        kind: ProxyProblemKind::Other,
        error: e.to_string(),
        hint: "The request can't be passed on.".to_owned(),
    })?;
    let mut response = send(&proxy.socket, outgoing).await?;
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
pub async fn run(socket: PathBuf, listen: SocketAddr, gate: Gate) -> Result<(), String> {
    #[cfg(debug_assertions)]
    if gate.trusted.is_empty() {
        tracing::warn!(
            "Development build without a trusted proxy: whoever reaches this proxy controls the agent"
        );
    }
    if !gate.trusted.is_empty() {
        tracing::info!(trusted = ?gate.trusted, header = ?gate.header, "Only requests forwarded by a trusted proxy are answered");
        if gate.header.is_none() {
            tracing::warn!(
                "No --user-header: any request from the trusted proxy's addresses passes, authenticated or not"
            );
        }
    }
    if !in_container() {
        tracing::warn!(
            "This doesn't look like a container: anything on this host that reaches the proxy's port controls the \
             agent. Run it in a container, on a network only the reverse proxy reaches"
        );
    }
    let proxy = Arc::new(Proxy { socket, gate });
    let router = Router::new()
        .route("/api/proxy", get(status))
        .route("/api/{*rest}", any(forward))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(crate::web::serve)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&proxy),
            admit,
        ))
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
        served = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()) => {
            served.map_err(|e| e.to_string())
        }
        _ = term.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// Whether this process runs in a container: as its PID 1, or where Docker or Podman leave their marks.
fn in_container() -> bool {
    std::process::id() == 1
        || Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_admits_only_a_trusted_proxy_with_a_user() {
        let any: IpAddr = "203.0.113.9".parse().unwrap();
        // Development builds only (tests are one).
        assert!(Gate::insecure_for_development().admits("/api/ws", any, &HeaderMap::new()));
        assert!(Gate::new(Vec::new(), Some("Remote-User")).is_err());
        assert!(Gate::new(Vec::new(), None).is_err());
        // A trusted proxy without a user header: its addresses only.
        let addresses = Gate::new(vec!["172.20.0.248/29".parse().unwrap()], None).unwrap();
        assert!(addresses.admits(
            "/api/ws",
            "172.20.0.249".parse().unwrap(),
            &HeaderMap::new()
        ));
        assert!(!addresses.admits("/api/ws", any, &HeaderMap::new()));

        let gate = Gate::new(
            vec!["172.20.0.248/29".parse().unwrap()],
            Some("Remote-User"),
        )
        .unwrap();
        let traefik: IpAddr = "172.20.0.249".parse().unwrap();
        let mut user = HeaderMap::new();
        user.insert("remote-user", HeaderValue::from_static("alice"));
        let mut blank = HeaderMap::new();
        blank.insert("remote-user", HeaderValue::from_static("  "));
        assert!(gate.admits("/api/ws", traefik, &user));
        assert!(gate.admits("/", traefik, &user));
        // Mapped IPv4 of a dual-stack socket.
        assert!(gate.admits("/api/proxy", "::ffff:172.20.0.249".parse().unwrap(), &user));
        assert!(!gate.admits("/api/ws", traefik, &HeaderMap::new()));
        assert!(!gate.admits("/api/ws", traefik, &blank));
        assert!(!gate.admits("/api/ws", any, &user));
        assert!(!gate.admits("/api/proxy", any, &user));
        // The container's healthcheck, from anywhere and without a user.
        assert!(gate.admits("/healthz", "127.0.0.1".parse().unwrap(), &HeaderMap::new()));

        assert!(Gate::new(vec!["10.0.0.0/8".parse().unwrap()], Some("bad header")).is_err());
    }

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("barbican-proxy-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn classifies_connect_errors() {
        let socket = Path::new("/run/barbican-ui/ui.sock");
        let cases = [
            (
                libc_errno::ENOENT,
                ProxyProblemKind::NotFound,
                "Is the agent running",
            ),
            (
                libc_errno::EACCES,
                ProxyProblemKind::PermissionDenied,
                "group_add",
            ),
            (
                libc_errno::ECONNREFUSED,
                ProxyProblemKind::Refused,
                "nothing accepts",
            ),
            (
                libc_errno::ENAMETOOLONG,
                ProxyProblemKind::Other,
                "--socket",
            ),
        ];
        for (errno, kind, hint) in cases {
            let problem = classify(&io::Error::from_raw_os_error(errno), socket);
            assert_eq!(problem.kind, kind, "errno {errno}");
            assert!(problem.hint.contains(hint), "{}", problem.hint);
            assert!(
                problem.hint.contains("/run/barbican-ui/ui.sock"),
                "{}",
                problem.hint
            );
            assert_eq!(
                problem.error,
                io::Error::from_raw_os_error(errno).to_string()
            );
        }
    }

    /// Linux's numbers: std has no constants for them.
    mod libc_errno {
        pub const ENOENT: i32 = 2;
        pub const EACCES: i32 = 13;
        pub const ENAMETOOLONG: i32 = 36;
        pub const ECONNREFUSED: i32 = 111;
    }

    #[tokio::test]
    async fn probes_a_missing_socket() {
        let socket = temp("missing").join("ui.sock");
        let problem = probe(&socket).await.unwrap();
        assert_eq!(problem.kind, ProxyProblemKind::NotFound);
    }

    #[tokio::test]
    async fn probes_a_stale_socket() {
        let dir = temp("stale");
        let socket = dir.join("ui.sock");
        // The file stays behind when the listener is gone, as after a crash.
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let problem = probe(&socket).await.unwrap();
        assert_eq!(problem.kind, ProxyProblemKind::Refused);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn probes_a_silent_socket() {
        let dir = temp("silent");
        let socket = dir.join("ui.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        // Accepts and hangs up without answering.
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let problem = probe(&socket).await.unwrap();
        assert_eq!(problem.kind, ProxyProblemKind::NoAnswer);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn probes_an_agent() {
        let dir = temp("agent");
        let socket = dir.join("ui.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let router: Router = Router::new().route("/healthz", get(|| async { "ok" }));
        tokio::spawn(async move { axum::serve(listener, router).await });
        assert_eq!(probe(&socket).await, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn status_json() {
        let proxy = Proxy {
            gate: Gate::default(),
            socket: "/run/barbican-ui/ui.sock".into(),
        };
        let problem = classify(
            &io::Error::from_raw_os_error(libc_errno::EACCES),
            &proxy.socket,
        );
        let json = serde_json::to_value(proxy.status(Some(problem))).unwrap();
        assert_eq!(json["socket"], "/run/barbican-ui/ui.sock");
        assert_eq!(json["problem"]["kind"], "permissionDenied");
        assert_eq!(
            serde_json::to_value(proxy.status(None)).unwrap()["problem"],
            serde_json::Value::Null
        );
    }
}
