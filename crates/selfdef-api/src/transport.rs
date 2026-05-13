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
    /// Path to a file containing the read-only bearer token.
    /// Required when `tcp_addr` is set. Grants GET access only — control
    /// verbs (rule reload, panic, action runs) reject this token.
    pub token_file: Option<PathBuf>,
    /// Optional path to a file containing the control bearer token.
    /// Grants the read-only API *and* the control endpoints. When
    /// unset, the TCP transport refuses every control verb so the
    /// daemon's "writes" surface only opens up by explicit configuration.
    pub control_token_file: Option<PathBuf>,
    /// File mode for the UNIX socket after bind (octal). `0o660` by default.
    pub unix_socket_mode: u32,
    /// Optional TLS configuration for the TCP transport. When set, the
    /// TCP listener wraps each accepted connection in `tokio_rustls`.
    /// When `tls.client_ca` is also set, client certificates are required
    /// and validated against that CA — i.e. mTLS.
    pub tls: Option<TlsConfig>,
}

/// Server-side TLS for the TCP transport. Bearer-token auth still
/// applies — TLS adds confidentiality / integrity / (optionally) client
/// authentication on top.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// PEM file containing the server certificate chain.
    pub cert_path: PathBuf,
    /// PEM file containing the matching private key.
    pub key_path: PathBuf,
    /// Optional PEM bundle of CA certificates used to validate client
    /// certificates. When set, the listener requires client
    /// authentication (mTLS); when None, the listener accepts anonymous
    /// clients (regular TLS).
    pub client_ca: Option<PathBuf>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unix_socket: None,
            tcp_addr: None,
            token_file: None,
            control_token_file: None,
            unix_socket_mode: 0o660,
            tls: None,
        }
    }
}

/// Capabilities a request has earned via authentication. Carried as a
/// request extension; handlers can inspect it for fine-grained checks
/// beyond the routing-level gate the auth layers already provide.
///
/// - `Full` — UNIX socket clients (trusted via fs permissions), TCP
///   clients with the control token, mTLS clients with a verified cert.
/// - `Read` — TCP clients with the read-only token. Control endpoints
///   reject these requests at the layer below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Read,
    Full,
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
    #[error("tls config error: {0}")]
    Tls(String),
}

/// Shared, hot-swappable token state for the TCP bearer-token
/// middleware. SDD-004 F-2026-023 follow-up: the daemon holds an
/// `Arc<RwLock<Option<LoadedTokens>>>` that the middleware reads
/// on every request; a `TokenReloader` (returned by
/// [`ApiServer::token_reloader`]) re-reads `token_file` /
/// `control_token_file` and atomically replaces the inner value
/// under the write lock. Used by the daemon's SIGUSR2 handler and
/// `selfdefctl api rotate-token`.
type SharedTokens = Arc<std::sync::RwLock<Option<LoadedTokens>>>;

/// Handle for rotating the API tokens at runtime. Returned by
/// [`ApiServer::token_reloader`]; the daemon's SIGUSR2 handler
/// invokes [`TokenReloader::reload`] to pick up an updated
/// `api.token_file` (or `api.control_token_file`) without
/// restarting the server.
#[derive(Clone)]
pub struct TokenReloader {
    cfg: ApiConfig,
    tokens: SharedTokens,
}

impl TokenReloader {
    /// Re-read the token files configured in `[api]` and swap them
    /// in atomically. Returns an error if the file is unreadable
    /// or empty; on error, the previously-loaded tokens stay in
    /// place (the daemon stays up; existing valid tokens keep
    /// working). The caller logs the error.
    pub fn reload(&self) -> Result<(), ServerError> {
        let new = load_tokens(&self.cfg)?;
        let mut guard = self.tokens.write().unwrap_or_else(|p| p.into_inner());
        *guard = Some(new);
        Ok(())
    }

    /// True once the server has loaded the initial tokens. Used
    /// by tests + daemon startup checks.
    pub fn is_loaded(&self) -> bool {
        let guard = self.tokens.read().unwrap_or_else(|p| p.into_inner());
        guard.is_some()
    }
}

/// API server. Holds the router and config; `run` blocks until shutdown.
pub struct ApiServer {
    router: Router,
    cfg: ApiConfig,
    tokens: SharedTokens,
}

impl ApiServer {
    pub fn new(state: ApiState, cfg: ApiConfig) -> Self {
        Self {
            router: crate::router(state),
            cfg,
            tokens: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Get a reloader for the running server. The daemon stashes
    /// this in its SIGUSR2 handler.
    pub fn token_reloader(&self) -> TokenReloader {
        TokenReloader {
            cfg: self.cfg.clone(),
            tokens: Arc::clone(&self.tokens),
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
        // router with every request marked Full-capability (filesystem
        // permissions are the auth boundary). The TCP transport wraps
        // the same router in a bearer-token layer that classifies the
        // request as Read or Full based on which token was presented.
        // A second layer wraps the control routes and rejects requests
        // that lack Full capability.
        let unix_router = with_capability(self.router.clone(), Capability::Full);
        let tcp_router = if let Some(addr) = tcp {
            let initial = load_tokens(&self.cfg)?;
            let has_control = initial.control.is_some();
            {
                let mut guard = self.tokens.write().unwrap_or_else(|p| p.into_inner());
                *guard = Some(initial);
            }
            info!(
                addr = %addr,
                control_token = has_control,
                "api: tcp transport enabled (bearer-token auth)"
            );
            Some(
                self.router
                    .clone()
                    // Outer layer (runs first) verifies the token and
                    // tags the request with a Capability extension.
                    // The middleware reads the shared tokens via the
                    // Arc<RwLock<>>; reload via TokenReloader swaps
                    // them atomically (SDD-004 F-2026-023 follow-up).
                    .layer(axum::middleware::from_fn_with_state(
                        Arc::clone(&self.tokens),
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
            let tls = self.cfg.tls.clone();
            joins.push(tokio::spawn(async move {
                if let Err(e) = serve_tcp(addr, r, sd, tls).await {
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

/// Tokens loaded from disk for the TCP transport. The `read` token is
/// mandatory; `control` is optional. When `control` is `None`, no
/// presented token can earn the [`Capability::Full`] grant.
struct LoadedTokens {
    read: String,
    control: Option<String>,
}

fn load_tokens(cfg: &ApiConfig) -> Result<LoadedTokens, ServerError> {
    let read = read_token(cfg.token_file.as_deref().ok_or(ServerError::MissingToken)?)?;
    let control = match cfg.control_token_file.as_deref() {
        Some(p) => Some(read_token(p)?),
        None => None,
    };
    Ok(LoadedTokens { read, control })
}

fn read_token(path: &std::path::Path) -> Result<String, ServerError> {
    let raw = std::fs::read_to_string(path)?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(ServerError::EmptyToken {
            path: path.to_path_buf(),
        });
    }
    Ok(token)
}

/// Constant-time-ish compare. The token is high-entropy and the API is
/// local/LAN-scope, so we don't need a cryptographic CT comparator, but
/// matching length first avoids the easy length oracle.
fn token_eq(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len() && presented.bytes().eq(expected.bytes())
}

async fn bearer_auth(
    state: axum::extract::State<SharedTokens>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    // SDD-004 F-2026-023 follow-up: read tokens through the shared
    // RwLock so SIGUSR2 rotation picks up the new values without
    // restarting the server. The lock is held only for the
    // duration of the byte-compare — microseconds.
    let cap = {
        let guard = state.read().unwrap_or_else(|p| p.into_inner());
        let Some(tokens) = guard.as_ref() else {
            // Tokens never loaded (shouldn't happen post-startup,
            // but a robust empty-state for tests + race windows).
            return unauthorized();
        };
        match (presented, tokens.control.as_deref()) {
            (Some(p), Some(c)) if token_eq(p, c) => Some(Capability::Full),
            (Some(p), _) if token_eq(p, tokens.read.as_str()) => Some(Capability::Read),
            _ => None,
        }
    };

    let Some(cap) = cap else {
        return unauthorized();
    };
    request.extensions_mut().insert(cap);
    next.run(request).await
}

/// Wrap a router so every request comes in pre-stamped with the given
/// capability. The UNIX-socket transport uses this to grant Full; tests
/// use it to skip the bearer-token auth path and exercise the routes
/// directly.
pub fn with_capability(router: Router, cap: Capability) -> Router {
    let layer = axum::middleware::from_fn(move |mut req: Request<Body>, next: Next| async move {
        req.extensions_mut().insert(cap);
        next.run(req).await
    });
    router.layer(layer)
}

fn unauthorized() -> Response {
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
    tls: Option<TlsConfig>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    let tls_state = match tls {
        Some(t) => Some(build_tls_acceptor(&t)?),
        None => None,
    };
    info!(
        addr = %addr,
        tls = tls_state.is_some(),
        mtls = matches!(&tls_state, Some((_, mtls)) if *mtls),
        "api: tcp socket bound"
    );

    if let Some((acceptor, _mtls)) = tls_state {
        // TLS-wrapped accept loop. Same shape as the UDS loop — drive
        // hyper directly because axum::serve doesn't take TLS streams.
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                accept = listener.accept() => {
                    let (sock, _peer) = match accept {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "api: tcp accept failed");
                            continue;
                        }
                    };
                    let svc = router.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(sock).await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!(error = %e, "api: tls handshake failed");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        let hyper_svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut svc = svc.clone();
                            async move { svc.call(req).await }
                        });
                        if let Err(e) = HyperBuilder::new(TokioExecutor::new())
                            .serve_connection(io, hyper_svc)
                            .await
                        {
                            debug!(error = %e, "api: tls connection ended");
                        }
                    });
                }
            }
        }
        Ok(())
    } else {
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await?;
        Ok(())
    }
}

/// Load certs, key, and (optionally) a client CA bundle. Returns a
/// configured [`TlsAcceptor`] and a flag indicating whether mTLS
/// (client-cert verification) is in effect.
fn build_tls_acceptor(cfg: &TlsConfig) -> Result<(tokio_rustls::TlsAcceptor, bool), ServerError> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| {
            // Install the ring-based provider as the process default if
            // no provider has been installed yet. selfdef has no other
            // rustls call sites today, so this is effectively a no-op
            // outside the API.
            let p = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let _ = rustls::crypto::CryptoProvider::install_default((*p).clone());
            p
        });

    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ServerError::Tls(format!("default protocols: {e}")))?;

    let server_cfg = match &cfg.client_ca {
        Some(ca_path) => {
            let roots = load_root_store(ca_path)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
                .build()
                .map_err(|e| ServerError::Tls(format!("client verifier: {e}")))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| ServerError::Tls(format!("single cert: {e}")))?
        }
        None => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(format!("single cert: {e}")))?,
    };

    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
    Ok((acceptor, cfg.client_ca.is_some()))
}

fn load_certs(
    path: &std::path::Path,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, ServerError> {
    use rustls_pki_types::pem::PemObject;
    // Use rustls-pki-types' built-in PEM iterator. The standalone
    // `rustls-pemfile` crate is archived as of 2025; its parsing has
    // been folded into pki-types.
    rustls_pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| ServerError::Tls(format!("open {}: {e}", path.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("parse certs {}: {e}", path.display())))
}

fn load_private_key(
    path: &std::path::Path,
) -> Result<rustls_pki_types::PrivateKeyDer<'static>, ServerError> {
    use rustls_pki_types::pem::PemObject;
    rustls_pki_types::PrivateKeyDer::from_pem_file(path)
        .map_err(|e| ServerError::Tls(format!("parse key {}: {e}", path.display())))
}

fn load_root_store(path: &std::path::Path) -> Result<rustls::RootCertStore, ServerError> {
    let certs = load_certs(path)?;
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|e| ServerError::Tls(format!("add root: {e}")))?;
    }
    Ok(roots)
}

#[cfg(test)]
mod token_reload_tests {
    //! SDD-004 F-2026-023 follow-up: TokenReloader covers
    //! atomic swap, error handling on bad files, and the
    //! "no tokens loaded" race window the middleware can hit
    //! before `run()` initialises them.
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn cfg_with_token_file(path: &std::path::Path) -> ApiConfig {
        ApiConfig {
            enabled: true,
            unix_socket: None,
            unix_socket_mode: 0o660,
            tcp_addr: Some("127.0.0.1:0".parse().unwrap()),
            token_file: Some(path.to_path_buf()),
            control_token_file: None,
            tls: None,
        }
    }

    fn make_token_file(token: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(token.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn reload_swaps_in_new_token() {
        let f = make_token_file("first-token");
        let cfg = cfg_with_token_file(f.path());
        let tokens: SharedTokens = Arc::new(std::sync::RwLock::new(None));
        let reloader = TokenReloader {
            cfg,
            tokens: Arc::clone(&tokens),
        };
        // First reload populates from disk.
        reloader.reload().expect("initial load");
        {
            let g = tokens.read().unwrap();
            assert_eq!(g.as_ref().unwrap().read, "first-token");
        }
        // Rewrite the file; next reload picks up the new value.
        std::fs::write(f.path(), "second-token").unwrap();
        reloader.reload().expect("second load");
        {
            let g = tokens.read().unwrap();
            assert_eq!(g.as_ref().unwrap().read, "second-token");
        }
    }

    #[test]
    fn reload_keeps_prior_tokens_on_empty_file() {
        let f = make_token_file("valid-token");
        let cfg = cfg_with_token_file(f.path());
        let tokens: SharedTokens = Arc::new(std::sync::RwLock::new(None));
        let reloader = TokenReloader {
            cfg,
            tokens: Arc::clone(&tokens),
        };
        reloader.reload().expect("initial load");

        // Truncate the file.
        std::fs::write(f.path(), "").unwrap();
        let err = reloader.reload().expect_err("empty token must fail");
        match err {
            ServerError::EmptyToken { .. } => {}
            other => panic!("expected EmptyToken, got: {other:?}"),
        }
        // The previously-loaded token must still be in place — the
        // daemon stays up; existing valid tokens keep working.
        let g = tokens.read().unwrap();
        assert_eq!(g.as_ref().unwrap().read, "valid-token");
    }

    #[test]
    fn reload_keeps_prior_tokens_on_io_error() {
        let f = make_token_file("valid-token");
        let cfg = cfg_with_token_file(f.path());
        let tokens: SharedTokens = Arc::new(std::sync::RwLock::new(None));
        let reloader = TokenReloader {
            cfg,
            tokens: Arc::clone(&tokens),
        };
        reloader.reload().expect("initial load");

        // Delete the file → next reload should fail without
        // disturbing the loaded tokens.
        drop(f); // drops NamedTempFile → unlinks the path
        let err = reloader.reload().expect_err("missing file must fail");
        assert!(matches!(err, ServerError::Io(_)), "got: {err:?}");
        let g = tokens.read().unwrap();
        assert_eq!(g.as_ref().unwrap().read, "valid-token");
    }

    #[test]
    fn is_loaded_reflects_internal_state() {
        let f = make_token_file("token");
        let cfg = cfg_with_token_file(f.path());
        let tokens: SharedTokens = Arc::new(std::sync::RwLock::new(None));
        let reloader = TokenReloader {
            cfg,
            tokens: Arc::clone(&tokens),
        };
        assert!(!reloader.is_loaded());
        reloader.reload().unwrap();
        assert!(reloader.is_loaded());
    }
}
