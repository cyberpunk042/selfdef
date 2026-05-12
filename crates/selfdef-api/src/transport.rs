//! Server lifecycle: bind, serve, shut down.
//!
//! The API can run on a UNIX socket, a TCP port, or both. UNIX socket
//! traffic is trusted (filesystem permissions are the auth boundary);
//! TCP requires `Authorization: Bearer <token>` matching `token_file`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use thiserror::Error;
use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::{debug, error, info, warn};

use crate::ApiState;

/// API server configuration. Mirrors the `[api]` block in `selfdef.toml`.
/// Defaults are conservative: disabled. The daemon only spawns the API
/// task when `enabled` is true.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    /// UNIX socket path (e.g. `/run/selfdef.sock`). Empty/None to disable.
    pub unix_socket: Option<PathBuf>,
    /// TCP bind address (e.g. `127.0.0.1:8443` or `0.0.0.0:8443`). None to disable.
    pub tcp_addr: Option<SocketAddr>,
    /// Path to a file containing the bearer token (single line, whitespace-trimmed).
    /// Required when `tcp_addr` is set.
    pub token_file: Option<PathBuf>,
    /// File mode for the UNIX socket after bind (octal). `0o660` by default.
    pub unix_socket_mode: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unix_socket: None,
            tcp_addr: None,
            token_file: None,
            unix_socket_mode: 0o660,
        }
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("token file '{path}' is empty or unreadable")]
    EmptyToken { path: PathBuf },
    #[error("tcp transport requires a token_file in [api]")]
    MissingToken,
    #[error("no transport configured: set unix_socket or tcp_addr")]
    NoTransport,
}

/// API server. Holds the router and config; `run` blocks until shutdown.
pub struct ApiServer {
    router: Router,
    cfg: ApiConfig,
}

impl ApiServer {
    pub fn new(state: ApiState, cfg: ApiConfig) -> Self {
        Self {
            router: crate::router(state),
            cfg,
        }
    }

    /// Run the API. Returns Ok(()) on clean shutdown; Err for early-bind
    /// failures (invalid socket path, port already taken, missing token).
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        if !self.cfg.enabled {
            debug!("api disabled in config");
            return Ok(());
        }

        let unix = self.cfg.unix_socket.clone();
        let tcp = self.cfg.tcp_addr;

        if unix.is_none() && tcp.is_none() {
            return Err(ServerError::NoTransport);
        }

        // Per-transport router. The UNIX socket transport gets the plain
        // router (no auth middleware). The TCP transport wraps the same
        // router in a bearer-token layer.
        let unix_router = self.router.clone();
        let tcp_router = if let Some(addr) = tcp {
            let token = load_token(&self.cfg)?;
            info!(addr = %addr, "api: tcp transport enabled (bearer-token auth)");
            Some(
                self.router
                    .clone()
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::new(token),
                        bearer_auth,
                    )),
            )
        } else {
            None
        };

        let mut joins = Vec::new();

        if let Some(path) = unix {
            let sd = shutdown.clone();
            let r = unix_router;
            let mode = self.cfg.unix_socket_mode;
            joins.push(tokio::spawn(async move {
                if let Err(e) = serve_unix(path, r, sd, mode).await {
                    error!(error = %e, "api: unix socket serve failed");
                }
            }));
        }

        if let (Some(addr), Some(r)) = (tcp, tcp_router) {
            let sd = shutdown.clone();
            joins.push(tokio::spawn(async move {
                if let Err(e) = serve_tcp(addr, r, sd).await {
                    error!(error = %e, "api: tcp serve failed");
                }
            }));
        }

        for j in joins {
            let _ = j.await;
        }
        info!("api: all transports stopped");
        Ok(())
    }
}

// ---------------------------------------------------------------- helpers

fn load_token(cfg: &ApiConfig) -> Result<String, ServerError> {
    let path = cfg.token_file.clone().ok_or(ServerError::MissingToken)?;
    let raw = std::fs::read_to_string(&path)?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(ServerError::EmptyToken { path });
    }
    Ok(token)
}

async fn bearer_auth(
    state: axum::extract::State<Arc<String>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let expected = state.0.as_str();
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    match presented {
        // Constant-time-ish compare. We don't need cryptographic CT here
        // since the token is high-entropy and the API is local/LAN-scope,
        // but matching length first avoids any easy length oracle.
        Some(p) if p.len() == expected.len() && p.bytes().eq(expected.bytes()) => {
            next.run(request).await
        }
        _ => {
            let mut resp = Response::new(Body::from(r#"{"error":"unauthorized"}"#));
            *resp.status_mut() = StatusCode::UNAUTHORIZED;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="selfdef-api""#),
            );
            resp
        }
    }
}

async fn serve_unix(
    path: PathBuf,
    router: Router,
    shutdown: CancellationToken,
    mode: u32,
) -> std::io::Result<()> {
    // Remove any stale socket file from a previous crash. A live process
    // bound here will fail the bind right after and we'll error out.
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(path = %path.display(), error = %e, "could not remove stale socket; bind may fail");
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&path)?;
    set_unix_socket_mode(&path, mode);
    info!(path = %path.display(), mode = format!("{mode:o}"), "api: unix socket bound");

    // axum 0.7's `axum::serve` only accepts a TcpListener, so we drive the
    // UDS accept loop ourselves via hyper-util. The trade-off: more code
    // here, but no shim/proxy in front of selfdef.
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accept = listener.accept() => {
                let (socket, _peer) = match accept {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "api: unix accept failed");
                        continue;
                    }
                };
                let svc = router.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(socket);
                    let hyper_svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut svc = svc.clone();
                        async move { svc.call(req).await }
                    });
                    if let Err(e) = HyperBuilder::new(TokioExecutor::new())
                        .serve_connection(io, hyper_svc)
                        .await
                    {
                        debug!(error = %e, "api: unix connection ended");
                    }
                });
            }
        }
    }

    // Best-effort cleanup so the next start has a clean filesystem.
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[cfg(unix)]
fn set_unix_socket_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            warn!(path = %path.display(), error = %e, "could not chmod unix socket");
        }
    }
}

#[cfg(not(unix))]
fn set_unix_socket_mode(_path: &std::path::Path, _mode: u32) {}

async fn serve_tcp(
    addr: SocketAddr,
    router: Router,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "api: tcp socket bound");
    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;
    Ok(())
}
