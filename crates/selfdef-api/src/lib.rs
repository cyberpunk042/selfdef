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
mod audit_chains;
mod authority;
mod capability_tokens;
mod mcp;
mod nats;
mod oracle_triage;
mod policy;
mod commit_authority;
mod communication_boundary;
mod control;
mod cpu;
mod dashboard_prefs;
mod filesystem_boundary;
mod flex_profile;
mod friction_audit;
mod gpu;
mod hardware;
mod health;
mod inference_backends;
mod network;
mod network_boundary;
mod raid;
mod repl;
mod sandbox_tiers;
mod storage;
mod tool_authority;
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
        // MS011 Z-13 / SD-R86 — modules install-options (deps-only
        // classification; hardware-gate enrichment deferred).
        .route("/v1/modules/install-options", get(modules::install_options))
        // MS011 Z-13 / SD-R87 — modules install-plan (topological
        // sort over the READY set via Kahn's algorithm). Operators
        // get a deterministic order in which to apply pending modules.
        .route("/v1/modules/install-plan", get(modules::install_plan))
        // MS006/MS016..MS031 — per-module install/check.sh invocation.
        // Registered as a SPECIFIC subpath under :name so the show
        // handler still handles the bare `/v1/modules/:name`.
        .route("/v1/modules/:name/check", get(modules::check))
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
        // MS009 — composite audit-chain replay across the 3 chained
        // watchdogs (perimeter / guardian / scheduler). Surfaces per-
        // chain ok/error + events_verified count.
        .route("/v1/audit-chains", get(audit_chains::show))
        // MS041 / SDD-043 D-3 — commit-authority schema discovery.
        // Static doctrine + classifier rules; agents/tools can learn
        // the durable-change contract without reading the Rust source.
        .route("/v1/commit-authority", get(commit_authority::show))
        // MS042 / SDD-050 D-2 — tool-authority schema discovery.
        // Static 11-crate pipeline contract for the 8 ToolId × 7
        // ExecutionMode × 6 Profile authorization matrix.
        .route("/v1/tool-authority", get(tool_authority::show))
        // MS035 / SDD-044 D-2 — capability-tokens schema discovery.
        // Token shape + 5-verdict CheckVerdict ladder + 5-companion
        // crate ecosystem + caller contract.
        .route("/v1/capability-tokens", get(capability_tokens::show))
        // MS037 / SDD-045 D-2 — filesystem-boundary discovery.
        // 3 exchange dirs + 6-step pipeline + 5-field patch schema +
        // 6 predicates + 2 doctrines.
        .route("/v1/filesystem-boundary", get(filesystem_boundary::show))
        // MS038 / SDD-046 D-2 — network-boundary discovery. 5-
        // profile NetworkProfile ladder with bit values + cross-
        // cycle bindings to MS032 + MS039.
        .route("/v1/network-boundary", get(network_boundary::show))
        // MS032 / SDD-047 D-2 — sandbox-tiers discovery. 5-tier
        // capability ladder + 4 PromotionGate variants + 5
        // companion crates.
        .route("/v1/sandbox-tiers", get(sandbox_tiers::show))
        // MS034 / SDD-048 D-2 — communication-boundary discovery.
        // 4 transports + 8 message types + 2 doctrines +
        // proposal→commit mapping.
        .route("/v1/communication-boundary", get(communication_boundary::show))
        // MS039 + MS040 / SDD-049 D-2 — authority discovery. 7-level
        // ladder + 5 trust rings + 6 profile envelopes + 4
        // TransitionGate variants + 5 authority crates.
        .route("/v1/authority", get(authority::show))
        // MS033 / SDD-051 D-2 — policy-cluster discovery. 8 functional
        // clusters organizing the 36-crate selfdef-policy-* ecosystem.
        .route("/v1/policy", get(policy::show))
        // MS015 / SDD-053 D-2 — NATS bridge schema discovery. Two-way
        // pump subject schema + modes + echo defense + cross-host
        // invariants.
        .route("/v1/nats", get(nats::show))
        // MS011 Z-11 / SDD-026 + SD-R84 — MCP-interop foundation
        // discovery. Transports + framings + curation policy +
        // pointer to the CLI catalog source.
        .route("/v1/mcp", get(mcp::show))
        // MS011 Z-3 / SDD-026 + `selfdef-flex-profile` — flex-profile
        // state schema + (when DEFAULT_STATE_PATH exists) the live
        // state read.
        .route("/v1/flex-profile", get(flex_profile::show))
        // MS011 Z-3 mutation surfaces — apply a Delta or revert the
        // most-recent one. Persists to DEFAULT_STATE_PATH (override
        // via SELFDEF_FLEX_PROFILE_PATH env). Operator-gating via
        // SDD-043 commit-authority + SDD-044 capability-tokens is
        // the next caller-integration arc per SDD-055.
        .route("/v1/flex-profile/apply", post(flex_profile::apply))
        .route("/v1/flex-profile/revert", post(flex_profile::revert))
        // MS043 UX — operator dashboard preferences persisted daemon-
        // side so view choices survive browser/host switches. GET
        // returns the current TOML (missing file → blank-valid body),
        // PUT validates enums + atomically writes. localStorage on
        // the PWA side is just a cache; the daemon is source of truth.
        .route("/v1/dashboard-prefs", get(dashboard_prefs::show).put(dashboard_prefs::put))
        // MS011 Z-2 / SDD-026 — inference-backend probe surface.
        // Probes for the 4 canonical backends (llama.cpp / vllm /
        // bitnet.cpp / unsloth) + reports installed state + version.
        .route("/v1/inference-backends", get(inference_backends::show))
        // MS011 Z-12 / SDD-026 + SD-R85 — multi-tier REPL discovery.
        // 3 tiers (Programming / Proto-Programming / Proto-Proto-
        // Programming) with Tier 1's 11+ Python callables enumerated.
        .route("/v1/repl", get(repl::show))
        // SDD-016 — oracle-triage channel doctrine + wire format +
        // tier-routing. Operators verify the daemon's notifier
        // configuration without parsing the source crate.
        .route("/v1/oracle-triage", get(oracle_triage::show))
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
