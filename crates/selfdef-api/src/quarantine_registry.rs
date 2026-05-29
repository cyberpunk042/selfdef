//! D-17 quarantine *live registry* read + operator-override surface.
//!
//! Companion to the existing `quarantine` schema-discovery module
//! (which serves the static doctrine at `GET /v1/quarantine`). This
//! module exposes the daemon-resident registry:
//!
//! - `GET  /v1/quarantine/snapshot` — current snapshot
//! - `POST /v1/quarantine/release`  — operator-signed release
//! - `POST /v1/quarantine/forfeit`  — operator-signed forfeit
//!
//! Quarantine entries are daemon-populated by the MS042 detection loop
//! (not by an operator allocate/issue verb); the only operator
//! mutations are the post-block release or forfeit overrides.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_quarantine_registry::{
    OverrideRequest, QuarantineMirrorSnapshot, QuarantineRegistry, RegistryError,
};
use time::OffsetDateTime;

fn state_path() -> PathBuf {
    std::env::var("SELFDEF_QUARANTINE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_quarantine_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<QuarantineRegistry, (StatusCode, String)> {
    QuarantineRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &QuarantineRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Unsigned | RegistryError::EmptyField(_) | RegistryError::EmptyMismatches => {
            (StatusCode::BAD_REQUEST, e.to_string())
        }
        RegistryError::Malformed { .. }
        | RegistryError::Io { .. }
        | RegistryError::TimeFormat(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `GET /v1/quarantine/snapshot`.
pub(crate) async fn snapshot() -> Result<Json<QuarantineMirrorSnapshot>, (StatusCode, String)> {
    let reg = load(&state_path())?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/quarantine/release` — body is the operator-signed
/// [`OverrideRequest`].
pub(crate) async fn release(
    Json(req): Json<OverrideRequest>,
) -> Result<Json<QuarantineMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.release(&req, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no quarantine entry with id {}", req.quarantine_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/quarantine/forfeit` — body is the operator-signed
/// [`OverrideRequest`].
pub(crate) async fn forfeit(
    Json(req): Json<OverrideRequest>,
) -> Result<Json<QuarantineMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.forfeit(&req, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no quarantine entry with id {}", req.quarantine_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_quarantine_registry::{
        BlockReport, MismatchDetail, MismatchField, MismatchSeverity, QuarantineState,
    };

    #[test]
    fn unsigned_override_maps_to_400() {
        let req = OverrideRequest {
            quarantine_id: "q-1".into(),
            actor: "operator-fp".into(),
            signature: String::new(),
        };
        let mut reg = QuarantineRegistry::new();
        let err = reg
            .release(&req, OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn release_persist_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quarantine.json");
        let now = OffsetDateTime::now_utc();
        let mut reg = QuarantineRegistry::load(&path).unwrap();
        let report = BlockReport {
            tool: "rg".into(),
            declarer: "operator-fp".into(),
            capability_token_id: "tok-1".into(),
            mismatches: vec![MismatchDetail {
                field: MismatchField::ReadPaths,
                declared: "/safe".into(),
                observed: "/etc/passwd".into(),
                first_observed_at: "2027-01-15T07:59:00Z".into(),
                severity: MismatchSeverity::Critical,
            }],
        };
        reg.record_block(&report, "q-1", "t1", now).unwrap();
        save(&reg, &path).unwrap();
        let req = OverrideRequest {
            quarantine_id: "q-1".into(),
            actor: "operator-fp".into(),
            signature: "ms003-sig".into(),
        };
        let mut reg2 = QuarantineRegistry::load(&path).unwrap();
        assert!(reg2.release(&req, now).unwrap());
        save(&reg2, &path).unwrap();
        let back = QuarantineRegistry::load(&path).unwrap();
        assert_eq!(back.entries()[0].state, QuarantineState::Released);
    }
}
