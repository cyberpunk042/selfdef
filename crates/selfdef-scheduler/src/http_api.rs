//! `selfdef-scheduler::http_api` — M01165: REST endpoints for the
//! scheduler operator surface.
//!
//! Catalog grounding: MS048 module `M01165 selfdef-scheduler-http-
//! api-endpoints` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`. Exposes the same
//! data the M01163 TUI panel + M01164 CLI subcommand render, but as
//! a typed JSON HTTP surface that sovereign-os mirror-publishers
//! (M01166) and the cockpit's web panel can consume.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — peace-machine clause
//! "disciplined enough to explain itself" + Core Law clause
//! "Tools prove" (every endpoint returns timestamped, structured data
//! the operator can correlate against other observability streams).
//!
//! ## Localhost-only by design
//!
//! Per the operator's host-network-boundary discipline (preserved in
//! the M01174 systemd unit `PrivateNetwork=true`), the scheduler does
//! NOT bind a public socket on its own. M01165 ships the Router; the
//! BIND is the caller's responsibility (selfdef-api crate mounts it
//! at `/api/scheduler/*`).
//!
//! ## Endpoints
//!
//! All endpoints return JSON. All endpoints are read-only.
//!
//! ```text
//! GET  /status                 → DriverReading (current snapshot from
//!                                 textfile OR audit-tail per query param)
//! GET  /status/compact         → CompactStatus (single-line summary)
//! GET  /audit/stats            → ChainStats (event count, last sha256,
//!                                 first+last timestamp)
//! POST /replay/counterfactual  → ReplayStats (request body specifies
//!                                 alternate BackpressureThresholds)
//! ```
//!
//! ## Query parameters
//!
//! `?source=textfile` (default) or `?source=audit` — selects whether
//! `/status` and `/status/compact` read from the Prometheus textfile
//! or the M01170 audit-log tail.
//!
//! `?path=<P>` — overrides the source path (must be within the
//! caller-supplied [`HttpApiState::allowed_paths`] allowlist to
//! prevent arbitrary-file-read; if empty, any path is permitted —
//! useful for tests, NOT for production).
//!
//! ## What this module provides
//!
//! 1. `HttpApiState` — shared state (source path defaults + allowlist).
//! 2. `router(state)` → `axum::Router` — the assembled scheduler
//!    routes. Caller mounts at any prefix (`/scheduler`, `/api/scheduler`,
//!    etc.) via `Router::nest`.
//! 3. Typed response shapes — all serializable for sovereign-os
//!    mirror-publisher consumption.
//!
//! ## Non-goals
//!
//! - Not a writer. All endpoints are read-only.
//! - Not a binder. selfdef-api owns the actual socket.
//! - Not a streaming endpoint. Polling is operator-preference; SSE
//!   live-tail is a future slot (M01165-stream or similar).
//!
//! Standing rule: We do not minimize anything.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::backpressure_driver::{DriverReading, SubstrateHealth};
use crate::decision_audit::{verify_chain, ChainStats, DriverAuditEntry};
use crate::driver_replay::{replay_audit_log, ReplayStats};
use crate::tui_panel::{parse_textfile_into_reading, render_panel_compact};
use crate::BackpressureThresholds;

// ============================================================================
// HttpApiState
// ============================================================================

/// Shared state for the scheduler HTTP router.
#[derive(Clone, Debug)]
pub struct HttpApiState {
    /// Default textfile path when `?path=` query is absent.
    pub default_textfile_path: PathBuf,
    /// Default audit-log path when `?path=` query is absent.
    pub default_audit_path: PathBuf,
    /// Allowlist of source paths the operator permits. Empty = no
    /// restriction (useful for tests). In production, set this to
    /// `vec![default_textfile_path.clone(), default_audit_path.clone()]`
    /// at minimum to prevent arbitrary-file-read.
    pub allowed_paths: Arc<Vec<PathBuf>>,
}

impl HttpApiState {
    /// Construct a state with the canonical defaults + path
    /// allowlist locked to those defaults. Operators expanding the
    /// allowlist (rare) must construct manually.
    #[must_use]
    pub fn with_defaults(textfile: PathBuf, audit: PathBuf) -> Self {
        let allowed = vec![textfile.clone(), audit.clone()];
        Self {
            default_textfile_path: textfile,
            default_audit_path: audit,
            allowed_paths: Arc::new(allowed),
        }
    }

    fn path_for(&self, source: SourceKind, override_path: Option<PathBuf>) -> Result<PathBuf, ApiError> {
        let candidate = match override_path {
            Some(p) => p,
            None => match source {
                SourceKind::Textfile => self.default_textfile_path.clone(),
                SourceKind::Audit => self.default_audit_path.clone(),
            },
        };
        // Allowlist enforcement: if non-empty, require candidate ∈ allowlist.
        if !self.allowed_paths.is_empty() && !self.allowed_paths.iter().any(|p| p == &candidate) {
            return Err(ApiError::Forbidden(format!(
                "path {} not in allowlist",
                candidate.display()
            )));
        }
        Ok(candidate)
    }
}

// ============================================================================
// Query parameters
// ============================================================================

/// Source toggle (textfile vs audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// Read from the live Prometheus textfile.
    #[default]
    Textfile,
    /// Read from the M01170 audit log tail.
    Audit,
}

/// Query parameters for `/status` + `/status/compact` + `/audit/stats`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StatusQuery {
    /// Source toggle. Default: `textfile`.
    #[serde(default)]
    pub source: SourceKind,
    /// Path override (must be in allowlist).
    pub path: Option<PathBuf>,
}

// ============================================================================
// Response shapes
// ============================================================================

/// Single-line summary for `/status/compact`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactStatus {
    /// One-line string suitable for status-bar embedding.
    pub line: String,
    /// Per-source healthy/degraded counts for programmatic consumers.
    pub substrate_health: SubstrateHealth,
}

/// Request body for `/replay/counterfactual`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayRequest {
    /// Alternate thresholds to replay against. All 6 required (no
    /// partial overrides; operator supplies the full alternate
    /// configuration explicitly).
    pub thresholds: BackpressureThresholds,
    /// Audit-log path to replay against (must be in allowlist).
    /// When absent, the default audit path is used.
    pub audit_path: Option<PathBuf>,
}

// ============================================================================
// Errors
// ============================================================================

/// Error type returned as JSON `{ "error": <kind>, "detail": <msg> }`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Path not on the allowlist.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Source IO error (file missing, permission denied, etc.).
    #[error("io: {0}")]
    Io(String),
    /// Source malformed (textfile / audit / replay).
    #[error("parse: {0}")]
    Parse(String),
    /// Audit chain integrity break.
    #[error("chain_break: {0}")]
    ChainBreak(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Io(_) => (StatusCode::NOT_FOUND, "io"),
            Self::Parse(_) => (StatusCode::UNPROCESSABLE_ENTITY, "parse"),
            Self::ChainBreak(_) => (StatusCode::UNPROCESSABLE_ENTITY, "chain_break"),
        };
        let body = Json(serde_json::json!({
            "error": kind,
            "detail": self.to_string(),
        }));
        (status, body).into_response()
    }
}

// ============================================================================
// router
// ============================================================================

/// Build the scheduler HTTP router. Caller mounts at the prefix of
/// their choice via `Router::nest("/scheduler", router(state))`.
pub fn router(state: HttpApiState) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/status/compact", get(get_status_compact))
        .route("/audit/stats", get(get_audit_stats))
        .route("/replay/counterfactual", post(post_replay_counterfactual))
        .with_state(state)
}

// ============================================================================
// Handlers
// ============================================================================

async fn get_status(
    State(state): State<HttpApiState>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<DriverReading>, ApiError> {
    let path = state.path_for(q.source, q.path)?;
    let reading = match q.source {
        SourceKind::Textfile => read_textfile_reading(&path).await?,
        SourceKind::Audit => read_audit_tail_reading(&path).await?,
    };
    Ok(Json(reading))
}

async fn get_status_compact(
    State(state): State<HttpApiState>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<CompactStatus>, ApiError> {
    let path = state.path_for(q.source, q.path)?;
    let reading = match q.source {
        SourceKind::Textfile => read_textfile_reading(&path).await?,
        SourceKind::Audit => read_audit_tail_reading(&path).await?,
    };
    let line = render_panel_compact(&reading);
    let substrate_health = reading.substrate_health.clone();
    Ok(Json(CompactStatus {
        line,
        substrate_health,
    }))
}

async fn get_audit_stats(
    State(state): State<HttpApiState>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<ChainStats>, ApiError> {
    let path = match q.path {
        Some(p) => state.path_for(SourceKind::Audit, Some(p))?,
        None => state.default_audit_path.clone(),
    };
    // Call synchronous verify_chain via spawn_blocking — it reads
    // the whole file + SHA-256s each line.
    let stats = tokio::task::spawn_blocking(move || verify_chain(&path))
        .await
        .map_err(|e| ApiError::Io(format!("audit-stats join: {e}")))?
        .map_err(audit_error)?;
    Ok(Json(stats))
}

async fn post_replay_counterfactual(
    State(state): State<HttpApiState>,
    Json(req): Json<ReplayRequest>,
) -> Result<Json<ReplayStats>, ApiError> {
    let path = match req.audit_path {
        Some(p) => state.path_for(SourceKind::Audit, Some(p))?,
        None => state.default_audit_path.clone(),
    };
    let thresholds = req.thresholds;
    let stats = tokio::task::spawn_blocking(move || replay_audit_log(&path, &thresholds))
        .await
        .map_err(|e| ApiError::Io(format!("replay join: {e}")))?
        .map_err(audit_error)?;
    Ok(Json(stats))
}

// ============================================================================
// Source-reading helpers
// ============================================================================

async fn read_textfile_reading(path: &PathBuf) -> Result<DriverReading, ApiError> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::Io(format!("textfile {} read: {e}", path.display())))?;
    parse_textfile_into_reading(&text).map_err(ApiError::Parse)
}

async fn read_audit_tail_reading(path: &PathBuf) -> Result<DriverReading, ApiError> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::Io(format!("audit {} read: {e}", path.display())))?;
    let last_line = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .next_back()
        .ok_or_else(|| ApiError::Parse(format!("audit log {} is empty", path.display())))?;
    let entry: DriverAuditEntry = serde_json::from_str(last_line).map_err(|e| {
        ApiError::Parse(format!(
            "parsing last audit entry of {}: {e}",
            path.display()
        ))
    })?;
    Ok(entry.reading)
}

fn audit_error(e: crate::decision_audit::DriverAuditError) -> ApiError {
    use crate::decision_audit::DriverAuditError as E;
    match e {
        E::Io { source, .. } => ApiError::Io(source.to_string()),
        E::Serde(s) => ApiError::Parse(s),
        E::ChainBreak { line, detail } => ApiError::ChainBreak(format!("line {line}: {detail}")),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backpressure_driver::SubstrateHealth;
    use crate::decision_audit::emit_driver_reading;
    use crate::prometheus_exporter::render_prometheus;
    use crate::{BackpressureState, ResourceMeasurements};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::fs;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn sample_reading() -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 1_700_000_000_000_000,
            measurements: ResourceMeasurements {
                blackwell_vram_util: 0.85,
                gpu3090_util: 0.30,
                cpu_psi: 0.15,
                mem_psi: 0.10,
                io_psi: 0.05,
                human_gate_queue_depth: 2,
            },
            state: BackpressureState {
                blackwell_vram_high: false,
                gpu3090_busy: false,
                cpu_pressure: false,
                ram_pressure: false,
                io_pressure: false,
                human_gate_queue_high: false,
            },
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    /// Build a (state, router, textfile_path, audit_path) tuple
    /// against a temp dir + fixture files.
    fn build_fixture_app(tmp: &tempfile::TempDir) -> (Router, PathBuf, PathBuf) {
        let textfile = tmp.path().join("scheduler.prom");
        let audit = tmp.path().join("scheduler.driver.audit.jsonl");
        fs::write(&textfile, render_prometheus(&sample_reading())).unwrap();
        emit_driver_reading(&audit, &sample_reading(), None).unwrap();
        let state = HttpApiState::with_defaults(textfile.clone(), audit.clone());
        let app = router(state);
        (app, textfile, audit)
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ---------------- /status --------------------------------------

    #[tokio::test]
    async fn status_from_textfile_returns_driver_reading() {
        let tmp = tempdir().unwrap();
        let (app, _t, _a) = build_fixture_app(&tmp);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status?source=textfile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert!((v["measurements"]["cpu_psi"].as_f64().unwrap() - 0.15).abs() < 1e-4);
    }

    #[tokio::test]
    async fn status_from_audit_returns_driver_reading() {
        let tmp = tempdir().unwrap();
        let (app, _t, _a) = build_fixture_app(&tmp);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status?source=audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert!((v["measurements"]["cpu_psi"].as_f64().unwrap() - 0.15).abs() < 1e-4);
    }

    #[tokio::test]
    async fn status_default_source_is_textfile() {
        let tmp = tempdir().unwrap();
        let (app, _t, _a) = build_fixture_app(&tmp);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_with_path_override_outside_allowlist_forbidden() {
        let tmp = tempdir().unwrap();
        let (app, _t, _a) = build_fixture_app(&tmp);
        // Allowlist is locked to the two default paths; override to
        // a different path → 403.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status?source=textfile&path=/etc/passwd")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let v = body_json(resp).await;
        assert_eq!(v["error"], "forbidden");
    }

    #[tokio::test]
    async fn status_missing_textfile_returns_404() {
        let tmp = tempdir().unwrap();
        let textfile = tmp.path().join("scheduler.prom");
        let audit = tmp.path().join("audit.jsonl");
        // Don't actually create the textfile.
        let state = HttpApiState::with_defaults(textfile, audit);
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status?source=textfile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---------------- /status/compact ------------------------------

    #[tokio::test]
    async fn status_compact_returns_line_and_substrate_health() {
        let tmp = tempdir().unwrap();
        let (app, _t, _a) = build_fixture_app(&tmp);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status/compact")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        let line = v["line"].as_str().unwrap();
        assert!(line.starts_with("MS048:"));
        assert!(line.contains("cpu=15.0%"));
        // substrate_health serializes Healthy → "Healthy"
        let psi = v["substrate_health"]["psi_status"].as_str();
        assert_eq!(psi, Some("Healthy"));
    }

    // ---------------- /audit/stats ---------------------------------

    #[tokio::test]
    async fn audit_stats_returns_chain_stats() {
        let tmp = tempdir().unwrap();
        let (app, _t, audit) = build_fixture_app(&tmp);
        // Add 2 more entries.
        emit_driver_reading(&audit, &sample_reading(), None).unwrap();
        emit_driver_reading(&audit, &sample_reading(), None).unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/audit/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["event_count"], 3);
        assert!(v["last_sha256"].is_string());
    }

    // ---------------- /replay/counterfactual -----------------------

    #[tokio::test]
    async fn replay_counterfactual_returns_replay_stats() {
        let tmp = tempdir().unwrap();
        let (app, _t, audit) = build_fixture_app(&tmp);
        // Add a high-vram reading so the counterfactual fires.
        let mut high = sample_reading();
        high.measurements.blackwell_vram_util = 0.88;
        emit_driver_reading(&audit, &high, None).unwrap();

        let body = serde_json::json!({
            "thresholds": {
                "blackwell_vram_high": 0.80,
                "gpu3090_busy": 0.80,
                "cpu_pressure": 0.50,
                "ram_pressure": 0.30,
                "io_pressure": 0.40,
                "human_gate_queue_high": 5
            }
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/replay/counterfactual")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["entries_replayed"], 2);
        // 0.88 > 0.80 alt threshold → counterfactual fires.
        assert!(v["blackwell_vram_high"]["only_counterfactual_fired"].as_u64().unwrap() >= 1);
    }

    // ---------------- HttpApiState::path_for guards ---------------

    #[test]
    fn allowlist_blocks_arbitrary_path() {
        let allowed = vec![PathBuf::from("/var/log/selfdef/x.jsonl")];
        let state = HttpApiState {
            default_textfile_path: PathBuf::from("/textfile"),
            default_audit_path: PathBuf::from("/audit"),
            allowed_paths: Arc::new(allowed),
        };
        let err = state
            .path_for(SourceKind::Audit, Some(PathBuf::from("/etc/passwd")))
            .unwrap_err();
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[test]
    fn empty_allowlist_permits_any_path() {
        let state = HttpApiState {
            default_textfile_path: PathBuf::from("/textfile"),
            default_audit_path: PathBuf::from("/audit"),
            allowed_paths: Arc::new(vec![]),
        };
        let p = state
            .path_for(SourceKind::Textfile, Some(PathBuf::from("/etc/passwd")))
            .unwrap();
        assert_eq!(p, PathBuf::from("/etc/passwd"));
    }
}
