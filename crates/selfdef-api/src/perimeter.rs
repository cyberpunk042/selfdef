//! HTTP handlers for the perimeter (Tetragon sovereign-kernel-fence)
//! operator surface.
//!
//! Mounts at `/v1/perimeter` and `/v1/perimeter/history`.
//! Read-only. Mutation endpoints (operator-signed extension
//! create / revoke) require Ring 0 authority + MS003 multi-sig and
//! flow through `selfdefctl perimeter extend/revoke` rather than HTTP.
//!
//! Cross-references:
//! - SDD-028 Deliverable 8 (HTTP API endpoints)
//! - MS047 R11088-R11109 (OCSF + ZFS log bridge)
//! - selfdef-cli/src/perimeter.rs MS047 surface — sister module
//! - selfdef-api/src/friction_audit.rs — twin module, same shape

use std::path::Path;

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use selfdef_perimeter::{
    DEFAULT_ALLOWLIST, DEFAULT_EXTENSION_DIR, DEFAULT_OCSF_PATH, DEFAULT_POLICY_PATH,
    DEFAULT_RING_DIR, DEFAULT_TRUST_ROOTS_DIR, ExtensionManifest, ExtensionStore, Outcome,
    PerimeterError, Verdict, audit_chain_check, now_ms, read_ring_buffer,
};

/// Response body for `GET /v1/perimeter`.
#[derive(Debug, Serialize)]
pub(crate) struct PerimeterBody {
    /// Aggregate state: "ok" / "alert" / "extended" / "unknown".
    pub aggregate: &'static str,
    /// Wall-clock when this response was assembled (epoch ms).
    pub now_ms: u64,
    /// Active TracingPolicy summary.
    pub policy: PolicySummary,
    /// Verbatim sain-01 §6 default allowlist (immutable).
    pub default_allowlist: &'static [&'static str],
    /// Currently-loaded extension manifests (non-expired).
    pub active_extensions: Vec<ExtensionManifest>,
    /// Allowlist-extension binary paths currently honored.
    pub extension_paths: Vec<String>,
    /// Last 16 verdicts (newest-first).
    pub verdicts: Vec<Verdict>,
    /// OCSF audit chain event count (None on chain integrity error).
    pub audit_chain_events: Option<usize>,
}

/// Active policy summary.
#[derive(Debug, Serialize)]
pub(crate) struct PolicySummary {
    /// Filesystem path of the active TracingPolicy.
    pub path: String,
    /// Whether the policy file is present on disk.
    pub present: bool,
    /// metadata.name of the policy (constant — sain-01 §6 verbatim).
    pub name: &'static str,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HistoryQuery {
    /// How many verdicts to return (newest-first). Default 32, max 256.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Response body for `GET /v1/perimeter/history`.
#[derive(Debug, Serialize)]
pub(crate) struct HistoryBody {
    /// All verdicts, newest-first, capped at `limit` (default 32,
    /// hard-max 256).
    pub verdicts: Vec<Verdict>,
}

/// `GET /v1/perimeter` — active policy summary + last 16 verdicts + extensions.
pub(crate) async fn show() -> Result<Json<PerimeterBody>, ApiError> {
    let now = now_ms();
    let verdicts = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let (store, _report) = ExtensionStore::load_dir(
        Path::new(DEFAULT_EXTENSION_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now,
    )
    .map_err(|e| ApiError::Internal(format!("extension store load: {e}")))?;

    let active_extensions: Vec<ExtensionManifest> =
        store.active(now).into_iter().cloned().collect();
    let extension_paths = store.active_paths(now);
    let policy_present = Path::new(DEFAULT_POLICY_PATH).exists();
    let audit_chain_events = audit_chain_check(Path::new(DEFAULT_OCSF_PATH)).ok();
    let last_16: Vec<Verdict> = verdicts.into_iter().take(16).collect();
    let aggregate = aggregate(&last_16, &active_extensions);

    Ok(Json(PerimeterBody {
        aggregate,
        now_ms: now,
        policy: PolicySummary {
            path: DEFAULT_POLICY_PATH.to_string(),
            present: policy_present,
            name: "sovereign-kernel-fence",
        },
        default_allowlist: DEFAULT_ALLOWLIST,
        active_extensions,
        extension_paths,
        verdicts: last_16,
        audit_chain_events,
    }))
}

/// `GET /v1/perimeter/history?limit=N` — verdicts newest-first.
pub(crate) async fn history(Query(q): Query<HistoryQuery>) -> Result<Json<HistoryBody>, ApiError> {
    let limit = q.limit.unwrap_or(32).min(256) as usize;
    let all = read_ring_buffer(Path::new(DEFAULT_RING_DIR))
        .map_err(|e| ApiError::Internal(format!("ring buffer read: {e}")))?;
    let verdicts: Vec<Verdict> = all.into_iter().take(limit).collect();
    Ok(Json(HistoryBody { verdicts }))
}

/// Aggregate state rule:
/// - "alert"    — at least one Sigkill verdict in the recent window
/// - "extended" — no Sigkills but at least one active extension
/// - "unknown"  — zero verdicts AND no extensions
/// - "ok"       — verdicts present, none Sigkill, no extensions
fn aggregate(verdicts: &[Verdict], extensions: &[ExtensionManifest]) -> &'static str {
    let has_sigkill = verdicts
        .iter()
        .any(|v| matches!(v.outcome, Outcome::Sigkill));
    if has_sigkill {
        return "alert";
    }
    if !extensions.is_empty() {
        return "extended";
    }
    if verdicts.is_empty() {
        return "unknown";
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

impl From<PerimeterError> for ApiError {
    fn from(e: PerimeterError) -> Self {
        Self::Internal(format!("perimeter: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verdict(outcome: Outcome) -> Verdict {
        Verdict::new(
            outcome,
            "/usr/bin/curl",
            42,
            41,
            "/system.slice/sshd.service",
            "",
            "curl",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    fn sample_extension() -> ExtensionManifest {
        ExtensionManifest {
            schema_version: selfdef_perimeter::SCHEMA_VERSION.to_string(),
            extension_id: "x".into(),
            binary_paths: vec!["/usr/local/bin/foo".into()],
            reason: "r".into(),
            issued_at_ms: 1,
            expires_at_ms: 1_700_000_000_000_000,
            signer_kid: "a".into(),
            auditor_kid: "b".into(),
            incident_url: None,
        }
    }

    #[test]
    fn aggregate_unknown_on_empty() {
        assert_eq!(aggregate(&[], &[]), "unknown");
    }

    #[test]
    fn aggregate_alert_when_any_sigkill() {
        let v = vec![sample_verdict(Outcome::Sigkill)];
        assert_eq!(aggregate(&v, &[]), "alert");
    }

    #[test]
    fn aggregate_alert_overrides_extensions() {
        let v = vec![sample_verdict(Outcome::Sigkill)];
        let e = vec![sample_extension()];
        assert_eq!(aggregate(&v, &e), "alert");
    }

    #[test]
    fn aggregate_extended_when_extensions_no_sigkill() {
        let v = vec![sample_verdict(Outcome::Allowlisted)];
        let e = vec![sample_extension()];
        assert_eq!(aggregate(&v, &e), "extended");
    }

    #[test]
    fn aggregate_extended_when_extensions_no_verdicts() {
        let e = vec![sample_extension()];
        assert_eq!(aggregate(&[], &e), "extended");
    }

    #[test]
    fn aggregate_ok_when_clean() {
        let v = vec![sample_verdict(Outcome::Allowlisted)];
        assert_eq!(aggregate(&v, &[]), "ok");
    }
}
