//! HTTP handlers for the Goldilocks Scheduler (MS048 / SDD-031)
//! operator surface.
//!
//! Mounts at:
//! - GET /v1/scheduler                  — current state + last 16 decisions
//! - GET /v1/scheduler/history?limit=N  — decision history
//! - GET /v1/scheduler/backpressure     — backpressure state snapshot
//! - GET /v1/scheduler/weights?profile=P— 7-axis weight matrix
//! - GET /v1/scheduler/explain/:request-id — single-decision detail
//!
//! Read-only. Mutation flows through `selfdefctl scheduler force`
//! (Ring 0 + MS003 multi-sig).
//!
//! Cross-references:
//! - SDD-031 Deliverable 4
//! - MS048 R11431-R11436 (HTTP API surface)
//! - selfdef-api/src/{friction_audit,perimeter,guardian}.rs sister modules

use std::path::Path;

use axum::Json;
use axum::extract::{Path as AxumPath, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use selfdef_scheduler::{
    AxisWeights, DEFAULT_AUDIT_LOG_PATH, DEFAULT_RING_DIR, Decision, Profile, SchedulerError,
    audit_chain_check, now_ms, read_ring_buffer,
};

/// Response body for `GET /v1/scheduler`.
#[derive(Debug, Serialize)]
pub(crate) struct SchedulerBody {
    /// Aggregate state: "ok" / "backpressure" / "unknown".
    pub aggregate: &'static str,
    /// Wall-clock when the response was assembled (epoch ms).
    pub now_ms: u64,
    /// OCSF audit chain event count (None on chain integrity error).
    pub audit_chain_events: Option<usize>,
    /// Last 16 decisions (newest-first).
    pub decisions: Vec<Decision>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HistoryBody {
    pub decisions: Vec<Decision>,
}

/// Backpressure state response. Derived from the most-recent decision
/// in the ring buffer; when ring is empty, reports clean state.
#[derive(Debug, Serialize)]
pub(crate) struct BackpressureBody {
    /// True when ANY of the 6 surfaces is under pressure.
    pub any_pressure: bool,
    /// How many surfaces are under pressure.
    pub pressure_count: u8,
    /// Per-surface flags.
    pub blackwell_vram_high: bool,
    pub gpu3090_busy: bool,
    pub cpu_pressure: bool,
    pub ram_pressure: bool,
    pub io_pressure: bool,
    pub human_gate_queue_high: bool,
    /// ts_ms of the decision the snapshot is derived from (0 when empty).
    pub source_decision_ts_ms: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WeightsQuery {
    /// Profile name (lowercase). When omitted, returns all 6.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WeightsEntry {
    pub profile: Profile,
    pub weights: AxisWeights,
    pub sum: f32,
}

fn parse_profile(s: &str) -> Option<Profile> {
    match s.to_ascii_lowercase().as_str() {
        "fast" => Some(Profile::Fast),
        "careful" => Some(Profile::Careful),
        "private" => Some(Profile::Private),
        "autonomous" => Some(Profile::Autonomous),
        "experimental" => Some(Profile::Experimental),
        "production" => Some(Profile::Production),
        _ => None,
    }
}

/// `GET /v1/scheduler` — current state + last 16 decisions.
pub(crate) async fn show() -> Result<Json<SchedulerBody>, ApiError> {
    let now = now_ms();
    let decisions = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring read: {e}")))?;
    let last_16: Vec<Decision> = decisions.into_iter().take(16).collect();
    let audit_chain_events = audit_chain_check(Path::new(DEFAULT_AUDIT_LOG_PATH)).ok();
    let aggregate = aggregate(&last_16);
    Ok(Json(SchedulerBody {
        aggregate,
        now_ms: now,
        audit_chain_events,
        decisions: last_16,
    }))
}

/// `GET /v1/scheduler/history?limit=N` — decisions newest-first.
pub(crate) async fn history(Query(q): Query<HistoryQuery>) -> Result<Json<HistoryBody>, ApiError> {
    let limit = q.limit.unwrap_or(32).min(256) as usize;
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring read: {e}")))?;
    let decisions: Vec<Decision> = all.into_iter().take(limit).collect();
    Ok(Json(HistoryBody { decisions }))
}

/// `GET /v1/scheduler/backpressure` — backpressure state snapshot.
pub(crate) async fn backpressure() -> Result<Json<BackpressureBody>, ApiError> {
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring read: {e}")))?;
    let body = match all.first() {
        None => BackpressureBody {
            any_pressure: false,
            pressure_count: 0,
            blackwell_vram_high: false,
            gpu3090_busy: false,
            cpu_pressure: false,
            ram_pressure: false,
            io_pressure: false,
            human_gate_queue_high: false,
            source_decision_ts_ms: 0,
        },
        Some(d) => {
            let b = d.backpressure;
            BackpressureBody {
                any_pressure: b.any_pressure(),
                pressure_count: b.pressure_count(),
                blackwell_vram_high: b.blackwell_vram_high,
                gpu3090_busy: b.gpu3090_busy,
                cpu_pressure: b.cpu_pressure,
                ram_pressure: b.ram_pressure,
                io_pressure: b.io_pressure,
                human_gate_queue_high: b.human_gate_queue_high,
                source_decision_ts_ms: d.ts_ms,
            }
        }
    };
    Ok(Json(body))
}

/// `GET /v1/scheduler/weights?profile=P` — 7-axis weight matrix readout.
pub(crate) async fn weights(
    Query(q): Query<WeightsQuery>,
) -> Result<Json<Vec<WeightsEntry>>, ApiError> {
    let profiles: Vec<Profile> = match q.profile.as_deref() {
        Some(p) => match parse_profile(p) {
            Some(prof) => vec![prof],
            None => {
                return Err(ApiError::BadRequest(format!(
                    "unknown profile {p:?}: expected fast/careful/private/autonomous/experimental/production"
                )));
            }
        },
        None => Profile::all().to_vec(),
    };
    let entries: Vec<WeightsEntry> = profiles
        .into_iter()
        .map(|p| {
            let w = AxisWeights::for_profile(p);
            let sum = w.sum();
            WeightsEntry {
                profile: p,
                weights: w,
                sum,
            }
        })
        .collect();
    Ok(Json(entries))
}

/// `GET /v1/scheduler/explain/:request-id` — single-decision detail.
pub(crate) async fn explain(
    AxumPath(request_id): AxumPath<String>,
) -> Result<Json<Decision>, ApiError> {
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring read: {e}")))?;
    let found = all.into_iter().find(|d| d.request_id == request_id);
    match found {
        None => Err(ApiError::NotFound(format!(
            "request_id={request_id:?} not found"
        ))),
        Some(d) => Ok(Json(d)),
    }
}

/// Aggregate rule:
/// - "backpressure" if any decision in window has any surface under pressure
/// - "unknown" when ring buffer is empty
/// - "ok" otherwise
fn aggregate(decisions: &[Decision]) -> &'static str {
    if decisions.is_empty() {
        return "unknown";
    }
    if decisions.iter().any(|d| d.backpressure.any_pressure()) {
        return "backpressure";
    }
    "ok"
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("internal: {0}")]
    Internal(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

impl From<SchedulerError> for ApiError {
    fn from(e: SchedulerError) -> Self {
        Self::Internal(format!("scheduler: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_scheduler::{AxisSignals, BackpressureState, Route, evaluate_objective};

    fn sample_decision(ts_ms: u64, with_pressure: bool) -> Decision {
        let signals = AxisSignals {
            latency: 0.9,
            cost: 0.8,
            risk: 0.7,
            energy: 0.6,
            human_attention: 0.5,
            hardware_pressure: 0.8,
        };
        let scores = evaluate_objective(signals, Profile::Careful);
        let backpressure = if with_pressure {
            BackpressureState {
                blackwell_vram_high: true,
                gpu3090_busy: false,
                cpu_pressure: false,
                ram_pressure: false,
                io_pressure: false,
                human_gate_queue_high: false,
            }
        } else {
            BackpressureState::clean()
        };
        Decision::new(
            format!("req-{ts_ms}"),
            Profile::Careful,
            Route::Blackwell,
            scores,
            backpressure,
            ts_ms,
            "host-A",
            "kid-policy-1",
            "test",
        )
    }

    #[test]
    fn aggregate_unknown_on_empty() {
        assert_eq!(aggregate(&[]), "unknown");
    }

    #[test]
    fn aggregate_ok_when_clean() {
        let d = sample_decision(1, false);
        assert_eq!(aggregate(&[d]), "ok");
    }

    #[test]
    fn aggregate_backpressure_when_any_pressure() {
        let d = sample_decision(1, true);
        assert_eq!(aggregate(&[d]), "backpressure");
    }

    #[test]
    fn parse_profile_six_known_names() {
        assert_eq!(parse_profile("fast"), Some(Profile::Fast));
        assert_eq!(parse_profile("CAREFUL"), Some(Profile::Careful));
        assert_eq!(parse_profile("Private"), Some(Profile::Private));
        assert_eq!(parse_profile("autonomous"), Some(Profile::Autonomous));
        assert_eq!(parse_profile("experimental"), Some(Profile::Experimental));
        assert_eq!(parse_profile("production"), Some(Profile::Production));
    }

    #[test]
    fn parse_profile_rejects_unknown() {
        assert_eq!(parse_profile("bogus"), None);
        assert_eq!(parse_profile(""), None);
    }
}
