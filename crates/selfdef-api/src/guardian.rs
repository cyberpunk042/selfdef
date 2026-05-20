//! HTTP handlers for the Guardian Daemon (sain-01 §10 guardian-core)
//! operator surface.
//!
//! Mounts at `/v1/guardian` and `/v1/guardian/history`.
//! Read-only. Mutation (replay / rollback) flows through
//! `selfdefctl guardian` rather than HTTP.
//!
//! Cross-references:
//! - SDD-029 Deliverable 8 (HTTP API endpoints)
//! - MS044 R10486-R10510 (HTTP API + cockpit panel binding)
//! - selfdef-api/src/{friction_audit,perimeter}.rs — sister modules,
//!   same shape (third leg of the three-watchdog trio)

use std::path::Path;

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use selfdef_guardian::{
    audit_chain_check, now_ms, read_ring_buffer, GuardianError, Verdict, DEFAULT_OCSF_PATH,
    DEFAULT_RING_DIR, DEFAULT_SOCKET_PATH,
};

/// Response body for `GET /v1/guardian`.
#[derive(Debug, Serialize)]
pub(crate) struct GuardianBody {
    /// Aggregate state: "ok" / "degraded" / "alert" / "unknown".
    pub aggregate: &'static str,
    /// Wall-clock when this response was assembled (epoch ms).
    pub now_ms: u64,
    /// Tetragon socket presence (proxy for whether Guardian can ingest).
    pub tetragon_socket_present: bool,
    /// OCSF audit chain event count (None on chain integrity error).
    pub audit_chain_events: Option<usize>,
    /// Last 16 verdicts (newest-first).
    pub verdicts: Vec<Verdict>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryQuery {
    /// How many verdicts to return (newest-first). Default 32, max 256.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Response body for `GET /v1/guardian/history`.
#[derive(Debug, Serialize)]
pub(crate) struct HistoryBody {
    /// All verdicts, newest-first, capped at `limit` (default 32,
    /// hard-max 256).
    pub verdicts: Vec<Verdict>,
}

/// `GET /v1/guardian` — daemon state + last 16 events + chain status.
pub(crate) async fn show() -> Result<Json<GuardianBody>, ApiError> {
    let now = now_ms();
    let verdicts = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let socket_present = Path::new(DEFAULT_SOCKET_PATH).exists();
    let audit_chain_events = audit_chain_check(Path::new(DEFAULT_OCSF_PATH)).ok();
    let last_16: Vec<Verdict> = verdicts.into_iter().take(16).collect();
    let aggregate = aggregate(&last_16, socket_present);
    Ok(Json(GuardianBody {
        aggregate,
        now_ms: now,
        tetragon_socket_present: socket_present,
        audit_chain_events,
        verdicts: last_16,
    }))
}

/// `GET /v1/guardian/history?limit=N` — verdicts newest-first.
pub(crate) async fn history(
    Query(q): Query<HistoryQuery>,
) -> Result<Json<HistoryBody>, ApiError> {
    let limit = q.limit.unwrap_or(32).min(256) as usize;
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let verdicts: Vec<Verdict> = all.into_iter().take(limit).collect();
    Ok(Json(HistoryBody { verdicts }))
}

/// Aggregate state rule:
/// - "alert"    — any verdict with a failed step in the window
/// - "degraded" — Tetragon socket missing (Guardian can't ingest)
/// - "unknown"  — zero verdicts AND socket present
/// - "ok"       — verdicts present, all clean, socket present
fn aggregate(verdicts: &[Verdict], socket_present: bool) -> &'static str {
    if verdicts.iter().any(|v| !v.all_steps_ok()) {
        return "alert";
    }
    if !socket_present {
        return "degraded";
    }
    if verdicts.is_empty() {
        return "unknown";
    }
    "ok"
}

/// API-level error type.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

impl From<GuardianError> for ApiError {
    fn from(e: GuardianError) -> Self {
        Self::Internal(format!("guardian: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_guardian::{Action, ResponseStep, StepOutcome, StepResult};

    fn three_step_ok() -> Vec<StepResult> {
        vec![
            StepResult { step: ResponseStep::Sigkill, outcome: StepOutcome::Ok },
            StepResult { step: ResponseStep::AuditAppend, outcome: StepOutcome::Ok },
            StepResult { step: ResponseStep::ConsoleAlert, outcome: StepOutcome::Ok },
        ]
    }

    fn sample(all_ok: bool) -> Verdict {
        let steps = if all_ok {
            three_step_ok()
        } else {
            let mut s = three_step_ok();
            s[0].outcome = StepOutcome::Failed("stub".into());
            s
        };
        Verdict::new(
            "evt-1",
            Action::Sigkill,
            42,
            "/",
            "",
            "/usr/bin/curl",
            steps,
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    #[test]
    fn aggregate_unknown_on_empty_with_socket() {
        assert_eq!(aggregate(&[], true), "unknown");
    }

    #[test]
    fn aggregate_degraded_when_socket_missing() {
        assert_eq!(aggregate(&[], false), "degraded");
    }

    #[test]
    fn aggregate_ok_when_clean() {
        assert_eq!(aggregate(&[sample(true)], true), "ok");
    }

    #[test]
    fn aggregate_alert_when_any_failed_step() {
        assert_eq!(aggregate(&[sample(false)], true), "alert");
    }

    #[test]
    fn aggregate_alert_overrides_degraded() {
        assert_eq!(aggregate(&[sample(false)], false), "alert");
    }
}
