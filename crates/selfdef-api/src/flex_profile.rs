//! `GET /v1/flex-profile` — MS011 Z-3 / `selfdef-flex-profile`
//! schema discovery + (when DEFAULT_STATE_PATH exists) the live
//! state read.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use selfdef_flex_profile::{DEFAULT_STATE_PATH, Delta, FlexProfile, FlexProfileError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(crate) struct FlexProfileResponse {
    /// Static schema documentation.
    pub schema: FlexProfileSchema,
    /// Live state — `Some` when DEFAULT_STATE_PATH exists + parses;
    /// `None` when the operator hasn't persisted any flex-profile yet.
    pub state: Option<FlexProfile>,
    /// Resolved path the daemon read from.
    pub state_path: String,
    /// True iff the state file exists on disk.
    pub state_present: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct FlexProfileSchema {
    pub delta_fields: &'static [&'static str],
    pub delta_op_variants: &'static [&'static str],
    pub revert_record_fields: &'static [&'static str],
    pub refusal_rules: &'static [&'static str],
    pub default_state_path: &'static str,
    pub doctrine_phrase: &'static str,
}

const DELTA_FIELDS: &[&str] = &[
    "id              monotonic, 1-indexed",
    "actor           MS003 fingerprint of the applying party",
    "reason          human-readable (non-empty per R09657)",
    "applied_at_ms   Unix millis at apply time",
    "operation       DeltaOp enum (4 variants)",
];

const DELTA_OP_VARIANTS: &[&str] = &[
    "AttachModel  {slug}",
    "DetachModel  {slug}",
    "AttachLora   {base_model, lora}",
    "DetachLora   {base_model, lora}",
];

const REVERT_RECORD_FIELDS: &[&str] = &[
    "original         the Delta that was reverted",
    "actor            MS003 fingerprint of the reverting party",
    "reverted_at_ms   Unix millis at revert time",
    "reason           operator-readable reason for the revert",
];

const REFUSAL_RULES: &[&str] = &[
    "SchemaMismatch         — schema_version drift",
    "NothingToRevert        — revert called with empty delta stack",
    "MandatoryFieldMissing  — actor or reason empty",
];

const DOCTRINE_PHRASE: &str = "live delta over baseline YAMLs with full revert history";

fn read_state(path: &Path) -> Option<FlexProfile> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<FlexProfile>(&text).ok()
}

pub(crate) async fn show() -> Json<FlexProfileResponse> {
    let path_str = std::env::var("SELFDEF_FLEX_PROFILE_PATH")
        .unwrap_or_else(|_| DEFAULT_STATE_PATH.to_string());
    let path = std::path::PathBuf::from(&path_str);
    let state_present = path.exists();
    let state = if state_present {
        read_state(&path)
    } else {
        None
    };
    Json(FlexProfileResponse {
        schema: FlexProfileSchema {
            delta_fields: DELTA_FIELDS,
            delta_op_variants: DELTA_OP_VARIANTS,
            revert_record_fields: REVERT_RECORD_FIELDS,
            refusal_rules: REFUSAL_RULES,
            default_state_path: DEFAULT_STATE_PATH,
            doctrine_phrase: DOCTRINE_PHRASE,
        },
        state,
        state_path: path_str,
        state_present,
    })
}

/// MS011 Z-3 mutation — `POST /v1/flex-profile/apply` body.
#[derive(Debug, Deserialize)]
pub(crate) struct ApplyRequest {
    /// Baseline name to use if the state file doesn't exist yet.
    /// Required-on-first-apply; ignored on subsequent applies.
    #[serde(default)]
    pub baseline: Option<String>,
    /// The Delta to apply.
    pub delta: Delta,
}

/// MS011 Z-3 mutation — `POST /v1/flex-profile/revert` body.
#[derive(Debug, Deserialize)]
pub(crate) struct RevertRequest {
    /// MS003 fingerprint of the reverting party (required).
    pub actor: String,
    /// Operator-readable reason (required).
    pub reason: String,
    /// Unix millis at revert time. Optional — caller may omit to
    /// let the daemon stamp `SystemTime::now()`.
    #[serde(default)]
    pub now_ms: Option<u64>,
}

fn current_state_path() -> PathBuf {
    std::env::var("SELFDEF_FLEX_PROFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STATE_PATH))
}

/// Read-or-create. When the state file doesn't exist + the caller
/// supplied `baseline`, returns a fresh empty profile. When the
/// file doesn't exist + no baseline, returns Err.
fn read_or_create(
    path: &Path,
    baseline_for_new: Option<&str>,
) -> Result<FlexProfile, (StatusCode, String)> {
    if let Ok(text) = std::fs::read_to_string(path) {
        serde_json::from_str::<FlexProfile>(&text).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("malformed flex-profile.json at {}: {e}", path.display()),
            )
        })
    } else {
        match baseline_for_new {
            Some(b) => Ok(FlexProfile::new(b)),
            None => Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "no flex-profile at {} and no `baseline` field in request body \
                    (required on first apply)",
                    path.display()
                ),
            )),
        }
    }
}

/// Atomic write — write to a sibling temp file, then rename.
fn atomic_write(path: &Path, body: &str) -> Result<(), (StatusCode, String)> {
    let tmp = path.with_extension("json.tmp");
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("create_dir_all {}: {e}", parent.display()),
                )
            })?;
        }
    }
    std::fs::write(&tmp, body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write {}: {e}", tmp.display()),
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rename {} → {}: {e}", tmp.display(), path.display()),
        )
    })?;
    Ok(())
}

fn map_flex_error(e: FlexProfileError) -> (StatusCode, String) {
    match e {
        FlexProfileError::SchemaMismatch => {
            (StatusCode::CONFLICT, "schema version mismatch".to_string())
        }
        FlexProfileError::NothingToRevert => (
            StatusCode::CONFLICT,
            "no delta on the stack to revert".to_string(),
        ),
        FlexProfileError::MandatoryFieldMissing(f) => (
            StatusCode::BAD_REQUEST,
            format!("mandatory field missing: {f}"),
        ),
    }
}

/// `POST /v1/flex-profile/apply` — apply a Delta to the persisted
/// state. Creates the state file if absent (caller must supply
/// `baseline`).
pub(crate) async fn apply(
    Json(req): Json<ApplyRequest>,
) -> Result<Json<FlexProfile>, (StatusCode, String)> {
    let path = current_state_path();
    let mut profile = read_or_create(&path, req.baseline.as_deref())?;
    profile.apply(req.delta).map_err(map_flex_error)?;
    let body = serde_json::to_string_pretty(&profile)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?;
    atomic_write(&path, &body)?;
    Ok(Json(profile))
}

/// `POST /v1/flex-profile/revert` — pop the most-recent delta off
/// the stack + record the revert in history.
pub(crate) async fn revert(
    Json(req): Json<RevertRequest>,
) -> Result<Json<FlexProfile>, (StatusCode, String)> {
    let path = current_state_path();
    let mut profile = read_or_create(&path, None)?;
    let now_ms = req.now_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    profile
        .revert(&req.actor, &req.reason, now_ms)
        .map_err(map_flex_error)?;
    let body = serde_json::to_string_pretty(&profile)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?;
    atomic_write(&path, &body)?;
    Ok(Json(profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts() {
        assert_eq!(DELTA_FIELDS.len(), 5);
        assert_eq!(DELTA_OP_VARIANTS.len(), 4);
        assert_eq!(REVERT_RECORD_FIELDS.len(), 4);
        assert_eq!(REFUSAL_RULES.len(), 3);
        assert!(DEFAULT_STATE_PATH.ends_with("flex-profile.json"));
    }
}
