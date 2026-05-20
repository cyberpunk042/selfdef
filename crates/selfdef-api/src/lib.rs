//! Read-only HTTP API for selfdef.
//!
//! Used by the bundled PWA dashboard and by `selfdefctl` for the future
//! IPC channel that replaces direct SQLite reads. The API is intentionally
//! *read-only* in this milestone — control-plane verbs (rule reload,
//! panic, action runs) land in a later patch when the auth/audit story
//! is fleshed out.
//!
//! ## Endpoints
//!
//! - `GET /status` — version, schema, host_tag, event_count, uptime, build info.
//! - `GET /events?n=N` — last N events (newest first), as JSON array.
//! - `GET /findings?n=N` — last N detection findings.
//! - `GET /events/stream` — Server-Sent Events stream of live events from the bus.
//! - `GET /metrics` — Prometheus exposition (counters + gauges for
//!   events, findings, store size, uptime, build info).
//!
//! ## Transports
//!
//! - **UNIX socket** (default): bound to a configurable path; filesystem
//!   permissions (`0660 root:adm` recommended) gate access. No token check.
//! - **TCP** (opt-in): bound to a configurable `host:port`; requires
//!   `Authorization: Bearer <token>` on every request, where `<token>`
//!   matches the contents of `token_file`.
//!
//! Both transports can run simultaneously. When neither is configured,
//! the API task no-ops at startup.
//!
//! ## Why not push events out instead of pulling
//!
//! The SSE stream subscribes to a fresh `Subscriber` on the bus and writes
//! a JSON line per event. Clients that disconnect free their subscription
//! immediately; lagged subscribers see a comment line and recover.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

mod control;
mod friction_audit;
mod guardian;
mod handlers;
mod perimeter;
pub mod metrics;
mod state;
mod transport;

pub use metrics::{Metrics, run_ingest as run_metrics_ingest};
pub use state::{ApiState, ControlHandles, SseCaps};
pub use transport::{
    ApiConfig, ApiServer, Capability, ServerError, TlsConfig, TokenFingerprint, TokenReloader,
    with_capability,
};

/// **Test-only**: wraps the router in a layer granting every
/// request `Capability::Full`. F-2027-014: gated behind the
/// `test-helpers` Cargo feature so it disappears from release
/// builds — calling it from production code would silently bypass
/// the bearer-token check on TCP transports. The daemon itself
/// uses [`transport::with_capability`] directly on the UNIX socket
/// path (filesystem-permission gated); only integration tests
/// need a blanket grant.
#[cfg(feature = "test-helpers")]
pub fn with_full_capability(router: Router) -> Router {
    with_capability(router, Capability::Full)
}

/// **Test-only**: wrap the router so every request lands with
/// both `Capability::Full` *and* a specific `TokenFingerprint`
/// in extensions — exactly the post-bearer-auth state the
/// production `bearer_auth` middleware leaves on the request.
/// SDD-007 / F-2028-037: lets the per-token-cap integration
/// tests choose which "token" each in-process call appears to
/// be from, without setting up real bearer-auth.
#[cfg(feature = "test-helpers")]
pub fn with_full_capability_for_fingerprint(router: Router, fp: TokenFingerprint) -> Router {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::middleware::Next;
    let layer = axum::middleware::from_fn(move |mut req: Request<Body>, next: Next| async move {
        req.extensions_mut().insert(Capability::Full);
        req.extensions_mut().insert(fp);
        next.run(req).await
    });
    router.layer(layer)
}

/// **Test-only**: integration tests need the SSE subscriber cap
/// to drive the cap-exhaustion case deterministically. F-2027-061
/// owns the constant; this re-export is gated behind `test-helpers`
/// so production code still treats it as an internal tuning knob.
#[cfg(feature = "test-helpers")]
pub const MAX_SSE_SUBSCRIBERS: usize = handlers::MAX_SSE_SUBSCRIBERS;

/// **Test-only**: re-export of SDD-007's per-token cap so
/// integration tests can saturate it deterministically.
#[cfg(feature = "test-helpers")]
pub const MAX_SSE_SUBSCRIBERS_PER_TOKEN: usize = handlers::MAX_SSE_SUBSCRIBERS_PER_TOKEN;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Build the API router. Exposed so integration tests can call routes
/// directly via `tower::ServiceExt::oneshot` without spinning up a socket.
///
/// The returned router has *no* auth middleware applied — when serving
/// it through `ApiServer`, the UNIX socket transport adds a Full-cap
/// middleware and the TCP transport adds the bearer-token verifier.
/// Integration tests that want to exercise control endpoints can apply
/// [`with_full_capability`] to grant the test request the Full grant.
pub fn router(state: ApiState) -> Router {
    Router::new()
        // ---- read endpoints ----
        .route("/status", get(handlers::status))
        .route("/events", get(handlers::events))
        .route("/findings", get(handlers::findings))
        .route("/events/stream", get(handlers::events_stream))
        .route("/metrics", get(handlers::metrics))
        // SDD-027 / MS046: friction-audit operator surface (read-only).
        // Mutation endpoints (POST /v1/friction-audit/overrides/:gate)
        // require Ring 0 authority + MS003 multi-sig and are deferred.
        .route("/v1/friction-audit", get(friction_audit::show))
        .route("/v1/friction-audit/history", get(friction_audit::history))
        // SDD-028 / MS047: perimeter (sovereign-kernel-fence) operator surface
        // (read-only). Mutation flows through `selfdefctl perimeter extend/revoke`.
        .route("/v1/perimeter", get(perimeter::show))
        .route("/v1/perimeter/history", get(perimeter::history))
        // SDD-029 / MS044: Guardian Daemon (sain-01 §10 guardian-core)
        // operator surface (read-only). Mutation flows through
        // `selfdefctl guardian` (replay / rollback).
        .route("/v1/guardian", get(guardian::show))
        .route("/v1/guardian/history", get(guardian::history))
        // SDD-008 D-4 HTTP ack — open auth: the token in the URL
        // IS the auth (UUIDv7, ~122 bits of post-timestamp entropy;
        // rides out-of-band over the operator-trusted channels).
        .route("/notify/ack/:token", get(handlers::notify_ack))
        // ---- control endpoints ----
        // Each control verb checks for the relevant handle in ApiState
        // and returns 503 Service Unavailable when missing — so the
        // routes are always *present* (callers can rely on the route
        // table) but only useful when the daemon has wired the handles
        // in. Tests can construct an ApiState without them.
        .route("/actions", get(control::actions_list))
        .route("/actions/:name/run", post(control::actions_run))
        .route("/rules/reload", post(control::rules_reload))
        .route("/panic", post(control::panic_fire))
        // CORS: permissive by default since both transports already gate
        // access (UNIX socket via fs perms, TCP via bearer token). Operators
        // running the API on an exposed port should narrow this via a
        // reverse proxy.
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
