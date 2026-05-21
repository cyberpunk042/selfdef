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

mod alerts;
mod control;
mod cpu;
mod friction_audit;
mod gpu;
mod hardware;
mod health;
mod network;
mod raid;
mod storage;
mod guardian;
mod handlers;
mod modules;
mod perimeter;
mod scheduler;
pub mod watchdog_metrics;
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
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Build the API router. Exposed so integration tests can call routes
/// directly via `tower::ServiceExt::oneshot` without spinning up a socket.
///
/// The returned router has *no* auth middleware applied — when serving
/// it through `ApiServer`, the UNIX socket transport adds a Full-cap
/// middleware and the TCP transport adds the bearer-token verifier.
/// Integration tests that want to exercise control endpoints can apply
/// [`with_full_capability`] to grant the test request the Full grant.
/// Default filesystem location of the bundled PWA dashboard assets when
/// installed by the Debian package. Override via the optional
/// `SELFDEF_DASHBOARD_DIR` env var.
pub const DEFAULT_DASHBOARD_DIR: &str = "/usr/share/selfdef/dashboard";

/// MS043 F05093 — minimal local web fallback. Returns the dashboard
/// directory the API should serve under `/dashboard/*`. Honors the env
/// var override (used during local dev when running from a checkout)
/// and returns None when the directory doesn't exist (the route is
/// then simply not mounted; `/v1/*` endpoints still work).
#[must_use]
pub fn dashboard_dir() -> Option<std::path::PathBuf> {
    let p = std::env::var("SELFDEF_DASHBOARD_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_DASHBOARD_DIR));
    if p.is_dir() { Some(p) } else { None }
}

pub fn router(state: ApiState) -> Router {
    let mut router = Router::new();
    // MS043 F05093 / F05096 — mount the bundled PWA dashboard under
    // `/dashboard/*` when its asset directory is present. Operators
    // running the API on a TCP transport then have the same surface
    // the dashboard PWA shows, served from selfdefd itself with no
    // external web server. Skipped (silently) when the asset dir is
    // missing — e.g. cargo-deb didn't install it OR the operator
    // overrode SELFDEF_DASHBOARD_DIR to a path that doesn't exist.
    if let Some(dir) = dashboard_dir() {
        router = router.nest_service("/dashboard", ServeDir::new(dir));
    }
    router
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
        // SDD-031 / MS048: Goldilocks Scheduler operator surface
        // (read-only). Mutation flows through `selfdefctl scheduler force`
        // (Ring 0 + MS003 multi-sig).
        .route("/v1/scheduler", get(scheduler::show))
        .route("/v1/scheduler/history", get(scheduler::history))
        .route("/v1/scheduler/backpressure", get(scheduler::backpressure))
        .route("/v1/scheduler/weights", get(scheduler::weights))
        .route("/v1/scheduler/explain/:request_id", get(scheduler::explain))
        // MS006 / SDD-009 Q-G: operator-facing module-list surface.
        // Read-only — module activation goes through the CLI's
        // operator-confirmed `selfdefctl modules apply` flow.
        .route("/v1/modules", get(modules::list))
        // MS011 Z-13 / SD-R83 — modules diff (installed / available /
        // orphaned partition). Registered BEFORE the :name catch-all
        // so the literal segment `diff` doesn't get captured as a
        // slug name.
        .route("/v1/modules/diff", get(modules::diff))
        .route("/v1/modules/:name", get(modules::show))
        // MS027: server-side classification of the 9 four-watchdog
        // alert series. PWA dashboard + `selfdefctl alerts` both
        // consume this typed JSON shape — single source of truth.
        .route("/v1/alerts", get(alerts::list))
        // MS010 / SDD-018: hardware-aware-modules HTTP surface. The
        // probe is cached per-process (OnceLock) — hardware doesn't
        // hot-swap at runtime. /v1/hardware = full snapshot;
        // /capabilities = derived flags (AVX-512, GPU presence, …);
        // /sain01 = match-verdict against the SAIN-01 reference rig.
        .route("/v1/hardware", get(hardware::snapshot))
        .route("/v1/hardware/capabilities", get(hardware::capabilities))
        .route("/v1/hardware/sain01", get(hardware::sain01))
        // MS011 Z-7 / SDD-026 — network state surface. Probes the 5
        // operator-relevant components (internet, dns, cloudflared,
        // tailscale, traefik) on each request.
        .route("/v1/network", get(network::show))
        // MS011 Z-10 / SDD-026 — storage state: per-mount disk usage
        // (df parsed + state-classified) + selfdef-managed log dirs
        // (recursive byte/file counts).
        .route("/v1/storage", get(storage::show))
        // MS011 Z-9 / SDD-026 — software RAID state read from
        // /proc/mdstat. selfdef NEVER manipulates the array.
        .route("/v1/raid", get(raid::show))
        // MS011 Z-5 / SDD-026 — per-GPU watt deviance against the
        // operator-authored /etc/selfdef/gpu-policy.toml.
        .route("/v1/gpu", get(gpu::show))
        // MS011 Z-4 / SDD-026 — CPU mode classification (read-only;
        // SET surface will land when the IPC privilege boundary
        // supports privileged /sys writes).
        .route("/v1/cpu", get(cpu::show))
        // MS011 Z-6 / SDD-026 — composite autohealth aggregate
        // across the read surfaces. Single endpoint for "is the box
        // OK?". Aggregates alerts/network/storage/raid/gpu/cpu.
        .route("/v1/health", get(health::show))
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
