//! # `selfdef-ux-checklist`
//!
//! Per-module UX-checklist mirroring **sovereign-os R457
//! ux-design-audit** (E11.M10). Cross-repo binding ID:
//! `SD-R-UX-CHECKLIST-1`.
//!
//! Per operator §1g (sovereign-os mandate verbatim):
//!
//! > "everything will also need to go through a thorough UX Design
//! >  stage in order to be of quality"
//!
//! Every selfdef module ships a `ux-checklist.toml` declaring its
//! standing on each of the 6 operator-named UX-quality dimensions.
//! The sovereign-os `ux-design-audit` instrument can fold these into
//! its cross-repo coverage matrix in a future round.
//!
//! ## 6 UX dimensions (mirror of sovereign-os R457 DIMENSIONS)
//!
//! ```text
//! action-budget    operator reaches goal in N (default 3) actions
//! discoverable     surface enumerable from a single entry point
//! recoverable      destructive ops preview-before-apply (triple-gate)
//! next-step        verbs surface "next_action" / "next:" / "Run:" hints
//! operator-named   §1g/§1h verbatim discipline (anti-fabrication)
//! readable-30s     help text dense enough to read in 30s
//! ```
//!
//! ## Wire format
//!
//! ```toml
//! schema_version = 1
//!
//! [module]
//! id    = "agent-guard"
//! label = "Agent Guard"
//!
//! [[dimensions]]
//! id     = "action-budget"
//! state  = "pass"
//!
//! [[dimensions]]
//! id     = "discoverable"
//! state  = "pass"
//!
//! [[dimensions]]
//! id     = "recoverable"
//! state  = "n-a"
//! reason = "read-only module, no destructive ops"
//!
//! [[dimensions]]
//! id     = "next-step"
//! state  = "fail"
//!
//! [[dimensions]]
//! id     = "operator-named"
//! state  = "pass"
//!
//! [[dimensions]]
//! id     = "readable-30s"
//! state  = "pass"
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// 6 operator-named UX dimensions in sovereign-os R457 verbatim
/// order. Drift = cross-repo contract break.
pub const UX_DIMENSIONS: [&str; 6] = [
    "action-budget",
    "discoverable",
    "recoverable",
    "next-step",
    "operator-named",
    "readable-30s",
];

/// Per-dimension checklist state. Wire format kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DimensionState {
    /// Dimension passes the audit.
    Pass,
    /// Dimension fails — the operator's standard is not met.
    Fail,
    /// Not applicable to this module (e.g., recoverable on a
    /// read-only module). `reason` field MUST be set.
    NA,
}

/// One dimension entry inside the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DimensionEntry {
    /// One of [`UX_DIMENSIONS`].
    pub id: String,
    /// Audit state.
    pub state: DimensionState,
    /// Operator-named rationale. REQUIRED when `state == NA` or `Fail`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `[module]` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleHeader {
    /// selfdef module id.
    pub id: String,
    /// Human-readable label.
    pub label: String,
}

/// One module's UX checklist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxChecklist {
    /// Schema version.
    pub schema_version: u32,
    /// Module identity.
    pub module: ModuleHeader,
    /// Per-dimension entries.
    pub dimensions: Vec<DimensionEntry>,
}

/// Errors during load / validation.
#[derive(Debug, Error)]
pub enum UxChecklistError {
    /// IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML decode failure.
    #[error("toml decode: {0}")]
    Toml(#[from] toml::de::Error),
    /// Validation rule violated.
    #[error("validation: {0}")]
    Validation(String),
}

/// Load + validate from a TOML string.
pub fn from_toml_str(s: &str) -> Result<UxChecklist, UxChecklistError> {
    let m: UxChecklist = toml::from_str(s)?;
    validate(&m)?;
    Ok(m)
}

/// Load + validate from a filesystem path.
pub fn from_toml_path<P: AsRef<Path>>(p: P) -> Result<UxChecklist, UxChecklistError> {
    let s = std::fs::read_to_string(p)?;
    from_toml_str(&s)
}

/// Validate the checklist:
/// - schema_version == 1
/// - module.id + module.label non-empty
/// - dimensions[] non-empty
/// - each dim id ∈ UX_DIMENSIONS
/// - no duplicate dim ids
/// - state == NA or Fail requires non-empty reason
pub fn validate(c: &UxChecklist) -> Result<(), UxChecklistError> {
    if c.schema_version != SCHEMA_VERSION {
        return Err(UxChecklistError::Validation(format!(
            "schema_version {} not supported",
            c.schema_version
        )));
    }
    if c.module.id.is_empty() {
        return Err(UxChecklistError::Validation(
            "module.id must be non-empty".into(),
        ));
    }
    if c.module.label.is_empty() {
        return Err(UxChecklistError::Validation(
            "module.label must be non-empty".into(),
        ));
    }
    if c.dimensions.is_empty() {
        return Err(UxChecklistError::Validation(
            "dimensions[] must have at least one entry".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for d in &c.dimensions {
        if !UX_DIMENSIONS.contains(&d.id.as_str()) {
            return Err(UxChecklistError::Validation(format!(
                "dimension id={:?} not in UX_DIMENSIONS {:?}",
                d.id, UX_DIMENSIONS
            )));
        }
        if !seen.insert(d.id.clone()) {
            return Err(UxChecklistError::Validation(format!(
                "duplicate dimension id={:?}",
                d.id
            )));
        }
        if matches!(d.state, DimensionState::NA | DimensionState::Fail)
            && d.reason.as_deref().unwrap_or("").is_empty()
        {
            return Err(UxChecklistError::Validation(format!(
                "dimension id={:?} state={:?} requires a 'reason' \
                 field (operator-discoverable rationale)",
                d.id, d.state
            )));
        }
    }
    Ok(())
}

/// Count of dimensions with `state == Pass`. Cross-repo UX-audit
/// gap detection reads this; 6 = full pass, 0 = no dimension met.
#[must_use]
pub fn pass_count(c: &UxChecklist) -> usize {
    c.dimensions
        .iter()
        .filter(|d| d.state == DimensionState::Pass)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
schema_version = 1

[module]
id    = "agent-guard"
label = "Agent Guard"

[[dimensions]]
id    = "action-budget"
state = "pass"

[[dimensions]]
id    = "discoverable"
state = "pass"

[[dimensions]]
id     = "recoverable"
state  = "n-a"
reason = "read-only module"

[[dimensions]]
id     = "next-step"
state  = "fail"
reason = "missing next_action hints"

[[dimensions]]
id    = "operator-named"
state = "pass"

[[dimensions]]
id    = "readable-30s"
state = "pass"
"#;

    #[test]
    fn ux_dimensions_match_sovereign_os_r457_verbatim_order() {
        // R457 DIMENSIONS verbatim order (operator §1g standard):
        assert_eq!(
            UX_DIMENSIONS,
            [
                "action-budget",
                "discoverable",
                "recoverable",
                "next-step",
                "operator-named",
                "readable-30s",
            ]
        );
    }

    #[test]
    fn dimension_count_is_six() {
        assert_eq!(UX_DIMENSIONS.len(), 6);
    }

    #[test]
    fn parses_well_formed_checklist() {
        let c = from_toml_str(GOOD).unwrap();
        assert_eq!(c.module.id, "agent-guard");
        assert_eq!(c.dimensions.len(), 6);
        assert_eq!(pass_count(&c), 4);
    }

    #[test]
    fn rejects_unknown_dimension_id() {
        let bad = GOOD.replace(r#"id    = "action-budget""#, r#"id    = "vibes-check""#);
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("UX_DIMENSIONS"));
    }

    #[test]
    fn rejects_unknown_state() {
        let bad = GOOD.replace(r#"state = "pass""#, r#"state = "magnificent""#);
        let err = from_toml_str(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("toml") || msg.contains("variant"), "got {msg}");
    }

    #[test]
    fn rejects_fail_without_reason() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[dimensions]]
id    = "action-budget"
state = "fail"
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("reason"));
    }

    #[test]
    fn rejects_na_without_reason() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[dimensions]]
id    = "recoverable"
state = "n-a"
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("reason"));
    }

    #[test]
    fn rejects_duplicate_dimension() {
        let dup = format!("{GOOD}\n[[dimensions]]\nid = \"action-budget\"\nstate = \"pass\"\n");
        let err = from_toml_str(&dup).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn rejects_empty_module_id() {
        let bad = GOOD.replace(r#"id    = "agent-guard""#, r#"id    = """#);
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("module.id"));
    }

    #[test]
    fn rejects_future_schema_version() {
        let bad = GOOD.replace("schema_version = 1", "schema_version = 99");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("schema_version"));
    }

    #[test]
    fn pass_count_only_counts_pass() {
        let c = from_toml_str(GOOD).unwrap();
        assert_eq!(pass_count(&c), 4); // 4 pass + 1 n-a + 1 fail
    }

    #[test]
    fn round_trips_via_serde() {
        let c = from_toml_str(GOOD).unwrap();
        let s = toml::to_string(&c).unwrap();
        let c2 = from_toml_str(&s).unwrap();
        assert_eq!(c, c2);
    }
}
