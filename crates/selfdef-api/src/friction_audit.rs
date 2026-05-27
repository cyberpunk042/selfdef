//! HTTP handlers for the friction-audit gate operator surface.
//!
//! Mounts at `/v1/friction-audit` and `/v1/friction-audit/history`.
//! Read-only. Mutation endpoints (operator-signed override
//! create / revoke) require Ring 0 authority + MS003 multi-sig and
//! are tracked for a later round.
//!
//! Cross-references:
//! - SDD-027 Deliverable 5 (selfdefctl CLI) + Deliverable 4 (runtime crate)
//! - MS046 R10913-R10920 (operator surface), R11136-R11142 (cockpit panel)
//! - selfdef-cli/src/friction_audit.rs — sister module, same shape

use std::path::Path;

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use selfdef_friction_audit::{
    DEFAULT_OVERRIDE_DIR, DEFAULT_RING_DIR, DEFAULT_TRUST_ROOTS_DIR, FrictionAuditError, Gate,
    OverrideManifest, OverrideStore, Verdict, now_ms, read_ring_buffer,
};

/// Response body for `GET /v1/friction-audit`.
#[derive(Debug, Serialize)]
pub(crate) struct FrictionAuditBody {
    /// Aggregate health: "ok" / "fail" / "override" / "unknown".
    pub aggregate: &'static str,
    /// Wall-clock when this response was assembled (epoch ms).
    pub now_ms: u64,
    /// Latest verdict per gate (newest-per-gate from the ring buffer).
    pub verdicts: Vec<Verdict>,
    /// Currently-active operator override manifests.
    pub overrides: Vec<OverrideManifest>,
    /// Per-gate active override summary (for quick UI consumption).
    pub overridden_gates: Vec<Gate>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryQuery {
    /// How many verdicts to return (newest-first). Default 32, max 256.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Response body for `GET /v1/friction-audit/history`.
#[derive(Debug, Serialize)]
pub(crate) struct HistoryBody {
    /// All verdicts, newest-first, capped at `limit` (default 32,
    /// hard-max 256).
    pub verdicts: Vec<Verdict>,
}

/// `GET /v1/friction-audit` — latest per-gate verdict + active overrides.
pub(crate) async fn show() -> Result<Json<FrictionAuditBody>, ApiError> {
    let now = now_ms();
    let verdicts = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let (store, _report) = OverrideStore::load_dir(
        Path::new(DEFAULT_OVERRIDE_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now,
    )
    .map_err(|e| ApiError::Internal(format!("override store load: {e}")))?;

    // Reduce to one verdict per gate (newest-first ordering already
    // produced by read_ring_buffer).
    let mut latest_per_gate: std::collections::BTreeMap<String, Verdict> =
        std::collections::BTreeMap::new();
    for v in verdicts {
        let key = format!("{:?}", v.gate);
        latest_per_gate.entry(key).or_insert(v);
    }
    let mut verdicts: Vec<Verdict> = latest_per_gate.into_values().collect();
    verdicts.sort_by_key(|v| format!("{:?}", v.gate));

    let overridden_gates = store.active_gates(now);
    let overrides: Vec<OverrideManifest> = overridden_gates
        .iter()
        .filter_map(|g| store.get(*g, now).cloned())
        .collect();
    let aggregate = aggregate(&verdicts, &overridden_gates);
    Ok(Json(FrictionAuditBody {
        aggregate,
        now_ms: now,
        verdicts,
        overrides,
        overridden_gates,
    }))
}

/// `GET /v1/friction-audit/history?limit=N` — all verdicts newest-first.
pub(crate) async fn history(Query(q): Query<HistoryQuery>) -> Result<Json<HistoryBody>, ApiError> {
    let limit = q.limit.unwrap_or(32).min(256) as usize;
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let verdicts: Vec<Verdict> = all.into_iter().take(limit).collect();
    Ok(Json(HistoryBody { verdicts }))
}

/// Aggregate health rule:
/// - "fail" if any gate is in Fail status (no override honoring)
/// - "override" if any gate is overridden but no failures
/// - "unknown" if zero verdicts recorded
/// - "ok" otherwise
fn aggregate(verdicts: &[Verdict], overridden_gates: &[Gate]) -> &'static str {
    if verdicts.is_empty() {
        return "unknown";
    }
    if verdicts.iter().any(Verdict::is_failing) {
        return "fail";
    }
    if !overridden_gates.is_empty() {
        return "override";
    }
    "ok"
}

/// API-level error type. Maps to HTTP responses.
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

// Required to make the inner FrictionAuditError convertible — but
// callers map manually above so the Display surface is friendlier.
impl From<FrictionAuditError> for ApiError {
    fn from(e: FrictionAuditError) -> Self {
        Self::Internal(format!("friction-audit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_unknown_on_empty() {
        let a = aggregate(&[], &[]);
        assert_eq!(a, "unknown");
    }

    #[test]
    fn aggregate_ok_when_all_pass() {
        let v = vec![Verdict {
            schema_version: selfdef_friction_audit_mirror::SCHEMA_VERSION.to_string(),
            gate: Gate::Pcie,
            status: selfdef_friction_audit_mirror::Status::Pass,
            ts_ms: 1,
            hostname: "h".into(),
            signer_kid_policy: "k".into(),
            signer_kid_extension: None,
        }];
        assert_eq!(aggregate(&v, &[]), "ok");
    }

    #[test]
    fn aggregate_fail_when_any_failing() {
        let v = vec![
            Verdict {
                schema_version: selfdef_friction_audit_mirror::SCHEMA_VERSION.to_string(),
                gate: Gate::Pcie,
                status: selfdef_friction_audit_mirror::Status::Pass,
                ts_ms: 1,
                hostname: "h".into(),
                signer_kid_policy: "k".into(),
                signer_kid_extension: None,
            },
            Verdict {
                schema_version: selfdef_friction_audit_mirror::SCHEMA_VERSION.to_string(),
                gate: Gate::Zfs,
                status: selfdef_friction_audit_mirror::Status::Fail(2),
                ts_ms: 2,
                hostname: "h".into(),
                signer_kid_policy: "k".into(),
                signer_kid_extension: None,
            },
        ];
        assert_eq!(aggregate(&v, &[]), "fail");
    }

    #[test]
    fn aggregate_override_when_overridden_no_fail() {
        let v = vec![Verdict {
            schema_version: selfdef_friction_audit_mirror::SCHEMA_VERSION.to_string(),
            gate: Gate::Pcie,
            status: selfdef_friction_audit_mirror::Status::Pass,
            ts_ms: 1,
            hostname: "h".into(),
            signer_kid_policy: "k".into(),
            signer_kid_extension: None,
        }];
        let overrides = vec![Gate::Memory];
        assert_eq!(aggregate(&v, &overrides), "override");
    }
}
