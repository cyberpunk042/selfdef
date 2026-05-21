//! `GET /v1/flex-profile` — MS011 Z-3 / `selfdef-flex-profile`
//! schema discovery + (when DEFAULT_STATE_PATH exists) the live
//! state read.

use std::path::Path;

use axum::Json;
use selfdef_flex_profile::{FlexProfile, DEFAULT_STATE_PATH};
use serde::Serialize;

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

const DOCTRINE_PHRASE: &str =
    "live delta over baseline YAMLs with full revert history";

fn read_state(path: &Path) -> Option<FlexProfile> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<FlexProfile>(&text).ok()
}

pub(crate) async fn show() -> Json<FlexProfileResponse> {
    let path_str = std::env::var("SELFDEF_FLEX_PROFILE_PATH")
        .unwrap_or_else(|_| DEFAULT_STATE_PATH.to_string());
    let path = std::path::PathBuf::from(&path_str);
    let state_present = path.exists();
    let state = if state_present { read_state(&path) } else { None };
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
