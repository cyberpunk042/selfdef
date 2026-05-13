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
mod handlers;
pub mod metrics;
mod state;
mod transport;

pub use metrics::{Metrics, run_ingest as run_metrics_ingest};
pub use state::{ApiState, ControlHandles};
pub use transport::{
    ApiConfig, ApiServer, Capability, ServerError, TlsConfig, TokenReloader, with_capability,
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
