//! D-14 capability-tokens *live registry* mutation + read surface.
//!
//! Sister to the existing `capability_tokens` module (which serves the
//! static MS035/SDD-044 schema discovery at `GET /v1/capability-tokens`).
//! That endpoint stays as the schema/doctrine surface; this module
//! exposes the daemon-resident *live* registry:
//!
//! - `GET  /v1/capability-tokens/snapshot` — current snapshot
//! - `POST /v1/capability-tokens/issue`    — operator-signed issuance
//! - `POST /v1/capability-tokens/revoke`   — revoke by token id
//!
//! Mutations persist to the resident store
//! (`selfdef-capability-registry::DEFAULT_STATE_PATH`, override via
//! `SELFDEF_CAPABILITY_TOKENS_PATH`) — the exact store the daemon's
//! mirror-export loop republishes READ-ONLY for the sovereign-os D-14
//! dashboard. Same router + precedent as the grants + flex-profile
//! mutation surfaces (SDD-055 commit-authority gating tracked there).

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_capability_registry::{
    CapabilityEntry, CapabilityMirrorSnapshot, CapabilityRegistry, CapabilityRequest, RegistryError,
};
use serde::Deserialize;
use time::OffsetDateTime;

fn state_path() -> PathBuf {
    std::env::var("SELFDEF_CAPABILITY_TOKENS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_capability_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<CapabilityRegistry, (StatusCode, String)> {
    CapabilityRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &CapabilityRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Validation refusals → 400 (caller-fixable), storage/format → 500.
fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Unsigned
        | RegistryError::EmptyField(_)
        | RegistryError::EmptyTools
        | RegistryError::UnknownTool(_, _)
        | RegistryError::InvalidSandboxTier(_)
        | RegistryError::TtlAboveCeiling(_, _)
        | RegistryError::TtlZero
        | RegistryError::WordBuild(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        RegistryError::Malformed { .. }
        | RegistryError::Io { .. }
        | RegistryError::TimeFormat(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeRequest {
    /// Capability-token id to revoke.
    pub token_id: String,
}

/// `GET /v1/capability-tokens/snapshot` — current resident snapshot.
pub(crate) async fn snapshot() -> Result<Json<CapabilityMirrorSnapshot>, (StatusCode, String)> {
    let reg = load(&state_path())?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/capability-tokens/issue` — body is the operator-signed
/// [`CapabilityRequest`]. The daemon mints `token_id`/`trace_id` + stamps
/// now. Returns the issued (Pending) capability entry.
pub(crate) async fn issue(
    _cap: crate::control::RequireControl,
    Json(req): Json<CapabilityRequest>,
) -> Result<Json<CapabilityEntry>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let nanos = now.unix_timestamp_nanos();
    let token_id = format!("tok-{nanos:x}");
    let trace_id = format!("tr-{nanos:x}");
    let id = reg
        .issue(&req, &token_id, &trace_id, now)
        .map_err(map_err)?;
    save(&reg, &path)?;
    let entry = reg
        .tokens()
        .iter()
        .find(|t| t.token_id == id)
        .cloned()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "issued capability token missing from registry".to_string(),
        ))?;
    Ok(Json(entry))
}

/// `POST /v1/capability-tokens/revoke` — revoke by id (404 if unknown).
pub(crate) async fn revoke(
    _cap: crate::control::RequireControl,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<CapabilityMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.revoke(&req.token_id, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no capability token with id {}", req.token_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_capability_registry::{AuthorityLevel, TokenState, TrustRing};

    fn req() -> CapabilityRequest {
        CapabilityRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            allowed_tools: vec!["tests".into(), "builds".into()],
            trust_ring: TrustRing::Ring2,
            authority_level: AuthorityLevel::L4Execute,
            sandbox_tier: "A".into(),
            parent_token_id: String::new(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn issue_persist_revoke_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability-tokens.json");
        let now = OffsetDateTime::now_utc();
        let mut reg = CapabilityRegistry::load(&path).unwrap();
        let id = reg.issue(&req(), "tok-x", "tr-x", now).unwrap();
        save(&reg, &path).unwrap();
        let reloaded = CapabilityRegistry::load(&path).unwrap();
        assert_eq!(reloaded.tokens().len(), 1);
        assert_eq!(reloaded.tokens()[0].state, TokenState::Pending);
        let mut reg2 = CapabilityRegistry::load(&path).unwrap();
        assert!(reg2.revoke(&id, now).unwrap());
        save(&reg2, &path).unwrap();
        assert_eq!(
            CapabilityRegistry::load(&path).unwrap().tokens()[0].state,
            TokenState::Revoked
        );
    }

    #[test]
    fn unknown_tool_maps_to_400() {
        let mut bad = req();
        bad.allowed_tools = vec!["godmode".into()];
        let mut reg = CapabilityRegistry::new();
        let err = reg
            .issue(&bad, "x", "t", OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
