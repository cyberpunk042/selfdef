//! D-18 trust-scores *live registry* read + operator-override surface.
//!
//! Companion to the existing `trust_scores` schema-discovery module at
//! `GET /v1/trust-scores`. This module exposes the daemon-resident
//! registry:
//!
//! - `GET  /v1/trust-scores/snapshot`         — current snapshot
//! - `POST /v1/trust-scores/admit`            — admit a new tool (signed)
//! - `POST /v1/trust-scores/operator-delta`   — operator-signed manual
//!   delta (override of canonical magnitude)
//!
//! Daemon-side `record_delta` calls (the canonical per-DeltaReason
//! magnitude) happen inside the daemon's scoring loop — not exposed
//! over HTTP, since they originate from the daemon's own observations,
//! not operator input.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_trust_score_registry::{
    OperatorDeltaRequest, RegistryError, TrustScoreMirrorSnapshot, TrustScoreRegistry,
};
use serde::Deserialize;
use time::OffsetDateTime;

fn state_path() -> PathBuf {
    std::env::var("SELFDEF_TRUST_SCORES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_trust_score_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<TrustScoreRegistry, (StatusCode, String)> {
    TrustScoreRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &TrustScoreRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Unsigned
        | RegistryError::EmptyField(_)
        | RegistryError::InitialScoreOutOfRange(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        RegistryError::Malformed { .. }
        | RegistryError::Io { .. }
        | RegistryError::TimeFormat(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `POST /v1/trust-scores/admit` body.
#[derive(Debug, Deserialize)]
pub(crate) struct AdmitRequest {
    /// Tool name to admit.
    pub tool: String,
    /// MS003 declarer fingerprint.
    pub declarer: String,
    /// Starting score (0..=1000).
    pub initial_score: u16,
    /// MS003 signature over the canonical-JSON admit request.
    pub signature: String,
}

/// `GET /v1/trust-scores/snapshot`.
pub(crate) async fn snapshot() -> Result<Json<TrustScoreMirrorSnapshot>, (StatusCode, String)> {
    let reg = load(&state_path())?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/trust-scores/admit`.
pub(crate) async fn admit(
    _cap: crate::control::RequireControl,
    Json(req): Json<AdmitRequest>,
) -> Result<Json<TrustScoreMirrorSnapshot>, (StatusCode, String)> {
    if req.signature.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "admit request unsigned".to_string(),
        ));
    }
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let _ = reg
        .admit(&req.tool, &req.declarer, req.initial_score, now)
        .map_err(map_err)?;
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/trust-scores/operator-delta`.
pub(crate) async fn operator_delta(
    _cap: crate::control::RequireControl,
    Json(req): Json<OperatorDeltaRequest>,
) -> Result<Json<TrustScoreMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.apply_operator_delta(&req, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no trust-score entry for tool {}", req.tool),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_trust_score_registry::DeltaReason;

    #[test]
    fn admit_then_operator_delta() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-scores.json");
        let now = OffsetDateTime::now_utc();
        let mut reg = TrustScoreRegistry::load(&path).unwrap();
        reg.admit("rg", "operator-fp", 750, now).unwrap();
        save(&reg, &path).unwrap();
        let req = OperatorDeltaRequest {
            tool: "rg".into(),
            actor: "operator-fp".into(),
            reason: DeltaReason::OperatorAdjustment,
            delta: -100,
            trace_id: "incident-1".into(),
            signature: "ms003-sig".into(),
        };
        let mut reg2 = TrustScoreRegistry::load(&path).unwrap();
        assert!(reg2.apply_operator_delta(&req, now).unwrap());
        save(&reg2, &path).unwrap();
        assert_eq!(
            TrustScoreRegistry::load(&path).unwrap().score_of("rg"),
            Some(650)
        );
    }

    #[test]
    fn unsigned_operator_delta_maps_to_400() {
        let mut reg = TrustScoreRegistry::new();
        reg.admit("rg", "op", 500, OffsetDateTime::now_utc())
            .unwrap();
        let bad = OperatorDeltaRequest {
            tool: "rg".into(),
            actor: "operator-fp".into(),
            reason: DeltaReason::OperatorAdjustment,
            delta: -100,
            trace_id: String::new(),
            signature: String::new(),
        };
        let err = reg
            .apply_operator_delta(&bad, OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
