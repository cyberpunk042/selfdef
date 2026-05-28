//! D-15 sandboxes *live registry* mutation + read surface.
//!
//! Sister to the existing `sandbox_tiers` module (which serves the
//! static MS032/MS036/SDD-047 tier-discovery doctrine at
//! `GET /v1/sandbox-tiers`). That endpoint stays as the doctrine
//! surface; this module exposes the daemon-resident *live* registry:
//!
//! - `GET  /v1/sandboxes/snapshot` — current snapshot
//! - `POST /v1/sandboxes/allocate` — operator-signed allocation
//! - `POST /v1/sandboxes/release`  — release by allocation id
//!
//! Mutations persist via `selfdef-sandbox-registry` to the resident
//! store (`DEFAULT_STATE_PATH`, override via `SELFDEF_SANDBOXES_PATH`)
//! — the exact store the daemon's mirror-export loop republishes
//! READ-ONLY for the sovereign-os D-15 dashboard.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_sandbox_registry::{
    AllocationEntry, AllocationRequest, RegistryError, SandboxMirrorSnapshot, SandboxRegistry,
};
use serde::Deserialize;
use time::OffsetDateTime;

fn state_path() -> PathBuf {
    std::env::var("SELFDEF_SANDBOXES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_sandbox_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<SandboxRegistry, (StatusCode, String)> {
    SandboxRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &SandboxRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Validation refusals → 400 (caller-fixable), storage/format → 500.
fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Unsigned
        | RegistryError::EmptyField(_)
        | RegistryError::Ms032OutOfRange(_, _, _, _)
        | RegistryError::TtlAboveCeiling(_, _)
        | RegistryError::TtlZero => (StatusCode::BAD_REQUEST, e.to_string()),
        RegistryError::Malformed { .. }
        | RegistryError::Io { .. }
        | RegistryError::TimeFormat(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReleaseRequest {
    /// Allocation id to release.
    pub allocation_id: String,
}

/// `GET /v1/sandboxes/snapshot` — current resident snapshot.
pub(crate) async fn snapshot() -> Result<Json<SandboxMirrorSnapshot>, (StatusCode, String)> {
    let reg = load(&state_path())?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/sandboxes/allocate` — body is the operator-signed
/// [`AllocationRequest`]. Daemon mints `allocation_id`/`trace_id` +
/// stamps now. Returns the issued (Pending) allocation entry.
pub(crate) async fn allocate(
    Json(req): Json<AllocationRequest>,
) -> Result<Json<AllocationEntry>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let nanos = now.unix_timestamp_nanos();
    let allocation_id = format!("alloc-{nanos:x}");
    let trace_id = format!("tr-{nanos:x}");
    let id = reg
        .allocate(&req, &allocation_id, &trace_id, now)
        .map_err(map_err)?;
    save(&reg, &path)?;
    let entry = reg
        .allocations()
        .iter()
        .find(|a| a.allocation_id == id)
        .cloned()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "issued allocation missing from registry".to_string(),
        ))?;
    Ok(Json(entry))
}

/// `POST /v1/sandboxes/release` — release by id (404 if unknown).
pub(crate) async fn release(
    Json(req): Json<ReleaseRequest>,
) -> Result<Json<SandboxMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.release(&req.allocation_id, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no allocation with id {}", req.allocation_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_sandbox_registry::{
        AllocationState, IsolationPrimitive, SandboxTier, ms032_range_for,
    };

    fn req() -> AllocationRequest {
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        AllocationRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            tier: SandboxTier::TierA,
            ms032_tier: lo,
            isolation: IsolationPrimitive::HostSeccomp,
            tool: "rg".into(),
            capability_token_id: "tok-1".into(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn allocate_persist_release_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandboxes.json");
        let now = OffsetDateTime::now_utc();
        let mut reg = SandboxRegistry::load(&path).unwrap();
        let id = reg.allocate(&req(), "alloc-x", "tr-x", now).unwrap();
        save(&reg, &path).unwrap();
        let reloaded = SandboxRegistry::load(&path).unwrap();
        assert_eq!(reloaded.allocations().len(), 1);
        assert_eq!(reloaded.allocations()[0].state, AllocationState::Pending);
        let mut reg2 = SandboxRegistry::load(&path).unwrap();
        assert!(reg2.release(&id, now).unwrap());
        save(&reg2, &path).unwrap();
        assert_eq!(
            SandboxRegistry::load(&path).unwrap().allocations()[0].state,
            AllocationState::Released
        );
    }

    #[test]
    fn ms032_out_of_range_maps_to_400() {
        let mut bad = req();
        bad.ms032_tier = 99;
        let mut reg = SandboxRegistry::new();
        let err = reg
            .allocate(&bad, "x", "t", OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
