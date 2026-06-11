//! D-13 grants mutation + read surface.
//!
//! `GET /v1/grants` returns the current daemon-resident grant snapshot;
//! `POST /v1/grants/issue` issues a signed grant; `POST /v1/grants/revoke`
//! revokes one. Mutations persist the registry to the resident store
//! (`selfdef-grant-registry::DEFAULT_STATE_PATH`, override via
//! `SELFDEF_GRANTS_PATH`) — the exact store the daemon's mirror-export
//! loop republishes READ-ONLY for the sovereign-os D-13 dashboard.
//!
//! This is the permission-correct write path: operators reach it through
//! the (root) daemon API rather than writing `/var/lib/selfdef` directly.
//! Mirrors the MS011 Z-3 flex-profile mutation precedent (same router,
//! no separate control-token gate yet — that cross-cutting commit-
//! authority arc is SDD-055, tracked there for all mutation surfaces).

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_grant_registry::{
    GrantEntry, GrantRegistry, GrantRequest, GrantsMirrorSnapshot, RegistryError,
};
use serde::Deserialize;
use time::OffsetDateTime;

/// Resident grant store path. Honors `SELFDEF_GRANTS_PATH` (kept in sync
/// with the daemon's mirror-export reader), else the crate default.
fn state_path() -> PathBuf {
    std::env::var("SELFDEF_GRANTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_grant_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<GrantRegistry, (StatusCode, String)> {
    GrantRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &GrantRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Validation refusals (unsigned / empty-field / TTL) are the caller's
/// fault → 400; storage/format problems are the daemon's → 500.
fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Issue(inner) => (StatusCode::BAD_REQUEST, inner.to_string()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// `POST /v1/grants/revoke` body.
#[derive(Debug, Deserialize)]
pub(crate) struct RevokeRequest {
    /// Grant id to revoke.
    pub grant_id: String,
}

/// `GET /v1/grants` — current resident grant snapshot (the same wire
/// type the mirror publishes). Absent store → empty-but-valid snapshot.
///
/// Applies presentation-time TTL expiry (in-memory, not persisted — the
/// durable store is selfdefctl's) so this surface never reports a past-TTL
/// grant as `Active`, matching the sovereign-os mirror's already-established
/// hygiene (`mirror_export_loop::publish_grants`). Without this the two grant
/// read surfaces disagreed on an expired grant's state.
pub(crate) async fn show() -> Result<Json<GrantsMirrorSnapshot>, (StatusCode, String)> {
    let mut reg = load(&state_path())?;
    let _ = reg.expire_due(OffsetDateTime::now_utc());
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/grants/issue` — body is the operator-signed [`GrantRequest`].
/// The daemon mints the `grant_id` + `trace_id` (callers never supply
/// them) and stamps `now`. Returns the issued (Pending) grant.
pub(crate) async fn issue(
    _cap: crate::control::RequireControl,
    Json(req): Json<GrantRequest>,
) -> Result<Json<GrantEntry>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let nanos = now.unix_timestamp_nanos();
    let grant_id = format!("gr-{nanos:x}");
    let trace_id = format!("tr-{nanos:x}");
    let id = reg
        .issue(&req, &grant_id, &trace_id, now)
        .map_err(map_err)?;
    save(&reg, &path)?;
    let entry = reg
        .grants()
        .iter()
        .find(|g| g.grant_id == id)
        .cloned()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "issued grant missing from registry".to_string(),
        ))?;
    Ok(Json(entry))
}

/// `POST /v1/grants/revoke` — revoke a grant by id. 404 when unknown.
/// Returns the updated snapshot.
pub(crate) async fn revoke(
    _cap: crate::control::RequireControl,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<GrantsMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.revoke(&req.grant_id, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no grant with id {}", req.grant_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_grant_registry::{GrantKind, GrantState};

    fn req(kind: GrantKind) -> GrantRequest {
        GrantRequest {
            kind,
            scope: "/workspace/**".into(),
            reason: "ship feature".into(),
            profile: "careful".into(),
            actor: "operator-fp".into(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    /// Issue → persist → revoke cycle through the registry, driving the
    /// same code path the handlers use (sans the axum Json wrapper).
    #[test]
    fn issue_persist_revoke_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let now = OffsetDateTime::now_utc();

        let mut reg = GrantRegistry::load(&path).unwrap();
        let id = reg
            .issue(&req(GrantKind::Filesystem), "gr-x", "tr-x", now)
            .unwrap();
        save(&reg, &path).unwrap();

        let reloaded = GrantRegistry::load(&path).unwrap();
        assert_eq!(reloaded.grants().len(), 1);
        assert_eq!(reloaded.grants()[0].state, GrantState::Pending);

        let mut reg2 = GrantRegistry::load(&path).unwrap();
        assert!(reg2.revoke(&id, now).unwrap());
        save(&reg2, &path).unwrap();
        assert_eq!(
            GrantRegistry::load(&path).unwrap().grants()[0].state,
            GrantState::Revoked
        );
    }

    /// The `show` handler applies presentation-time expiry: a grant whose TTL
    /// has elapsed must read as `Expired`, not `Active`, matching the mirror.
    /// Drives the same load → expire_due → snapshot path the handler uses.
    #[test]
    fn show_path_expires_past_ttl_grants_for_presentation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let issued = OffsetDateTime::now_utc();

        let mut reg = GrantRegistry::load(&path).unwrap();
        // 1s TTL.
        let mut r = req(GrantKind::Filesystem);
        r.ttl_seconds = 1;
        let id = reg.issue(&r, "gr-ttl", "tr-ttl", issued).unwrap();
        reg.activate(&id, issued).unwrap();
        save(&reg, &path).unwrap();

        // The durable store still holds it Active (selfdefctl owns durable
        // expiry); but the show path applies presentation-time expiry.
        let mut shown = GrantRegistry::load(&path).unwrap();
        assert_eq!(shown.grants()[0].state, GrantState::Active, "stored Active");
        let later = issued + time::Duration::seconds(5);
        let _ = shown.expire_due(later);
        assert_eq!(
            shown.snapshot().grants[0].state,
            GrantState::Expired,
            "show must present a past-TTL grant as Expired"
        );
    }

    #[test]
    fn unsigned_request_maps_to_400() {
        let mut bad = req(GrantKind::Network);
        bad.signature = String::new();
        let mut reg = GrantRegistry::new();
        let err = reg
            .issue(&bad, "g", "t", OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}
