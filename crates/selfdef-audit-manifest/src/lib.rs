//! # `selfdef-audit-manifest`
//!
//! Per-module anti-minimization audit manifest. Cross-repo binding to
//! **sovereign-os R456 anti-minimization-audit** (E11.M11).
//! Cross-repo binding ID: `SD-R-AUDIT-1`.
//!
//! Per operator §1g STANDING RULE (sovereign-os mandate verbatim):
//!
//! > "If you think something is really already done, ask yourself if
//! >  you covered all angles and levels and layers and even if then
//! >  improve it. Do not minimize or settle for less."
//! >
//! > "We do not minimize anything."
//!
//! **Intended model** (not yet realized — see status note below): each
//! selfdef module ships an `audit-manifest.toml` declaring its standing on
//! each of the 8 operator-named minimization patterns, and the sovereign-os
//! anti-minimization audit folds these into its cross-repo coverage matrix.
//!
//! **Current status:** this crate is the parser + wire-format + validation
//! for that manifest. No module ships an `audit-manifest.toml` yet and no
//! generator emits them, so the per-module manifests and the cross-repo
//! fold-in are the open follow-up — not a present invariant. Stating it as
//! already-shipped would itself be the minimization the §1g rule forbids.
//!
//! ## 8 minimization patterns (mirror of sovereign-os R456 PATTERNS)
//!
//! ```text
//! todo-no-anchor       TODO/FIXME without R-number or SDD anchor
//! empty-stub           Python pass-only function body
//! skipped-no-followup  "skipped"/"deferred"/"stub" without ticket ref
//! surface-gap          Module below R453 surface-map threshold
//! doc-gap              Module below R454 doc-coverage threshold
//! mandate-todo         Mandate E11.Mx or E10.Mx row still TODO
//! minimize-phrase      Code/comment contains operator-named violation
//! partial-status       Mandate row status 'partial' or 'in-flight'
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
//! [[findings]]
//! pattern = "todo-no-anchor"
//! count   = 0
//!
//! [[findings]]
//! pattern = "empty-stub"
//! count   = 0
//!
//! [[findings]]
//! pattern = "minimize-phrase"
//! count   = 2
//! note    = "two intentional uses in operator-named context"
//! ```
//!
//! Each finding records the COUNT for that pattern (0 = no
//! minimization detected) + an optional `note` (REQUIRED when
//! count > 0 — every non-zero finding must have operator-discoverable
//! rationale, mirroring R456's no-self-exclusion-without-reason
//! discipline).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// 8 operator-named minimization patterns in sovereign-os R456
/// verbatim order. Drift = cross-repo contract break.
pub const PATTERN_IDS: [&str; 8] = [
    "todo-no-anchor",
    "empty-stub",
    "skipped-no-followup",
    "surface-gap",
    "doc-gap",
    "mandate-todo",
    "minimize-phrase",
    "partial-status",
];

/// One finding entry inside the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEntry {
    /// One of [`PATTERN_IDS`].
    pub pattern: String,
    /// Count of detected occurrences (0 = clean).
    pub count: u32,
    /// Operator-named rationale. REQUIRED when `count > 0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The `[module]` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleHeader {
    /// selfdef module id.
    pub id: String,
    /// Human-readable label.
    pub label: String,
}

/// One module's audit manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditManifest {
    /// Schema version.
    pub schema_version: u32,
    /// Module identity.
    pub module: ModuleHeader,
    /// Per-pattern findings.
    pub findings: Vec<FindingEntry>,
}

/// Errors during load / validation.
#[derive(Debug, Error)]
pub enum AuditManifestError {
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
pub fn from_toml_str(s: &str) -> Result<AuditManifest, AuditManifestError> {
    let m: AuditManifest = toml::from_str(s)?;
    validate(&m)?;
    Ok(m)
}

/// Load + validate from a filesystem path.
pub fn from_toml_path<P: AsRef<Path>>(p: P) -> Result<AuditManifest, AuditManifestError> {
    let s = std::fs::read_to_string(p)?;
    from_toml_str(&s)
}

/// Validate:
/// - schema_version == 1
/// - module.id + module.label non-empty
/// - findings[] non-empty
/// - each pattern ∈ PATTERN_IDS
/// - no duplicate patterns
/// - count > 0 requires non-empty note
pub fn validate(m: &AuditManifest) -> Result<(), AuditManifestError> {
    if m.schema_version != SCHEMA_VERSION {
        return Err(AuditManifestError::Validation(format!(
            "schema_version {} not supported",
            m.schema_version
        )));
    }
    if m.module.id.is_empty() {
        return Err(AuditManifestError::Validation(
            "module.id must be non-empty".into(),
        ));
    }
    if m.module.label.is_empty() {
        return Err(AuditManifestError::Validation(
            "module.label must be non-empty".into(),
        ));
    }
    if m.findings.is_empty() {
        return Err(AuditManifestError::Validation(
            "findings[] must have at least one entry".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for f in &m.findings {
        if !PATTERN_IDS.contains(&f.pattern.as_str()) {
            return Err(AuditManifestError::Validation(format!(
                "pattern {:?} not in PATTERN_IDS {:?}",
                f.pattern, PATTERN_IDS
            )));
        }
        if !seen.insert(f.pattern.clone()) {
            return Err(AuditManifestError::Validation(format!(
                "duplicate pattern {:?}",
                f.pattern
            )));
        }
        if f.count > 0 && f.note.as_deref().unwrap_or("").is_empty() {
            return Err(AuditManifestError::Validation(format!(
                "pattern {:?} count={} requires a non-empty 'note' \
                 (operator-discoverable rationale per operator §1g \
                 'do not minimize or settle for less')",
                f.pattern, f.count
            )));
        }
    }
    Ok(())
}

/// Sum of all finding counts. 0 = the module is clean against ALL 8
/// minimization patterns. Cross-repo aggregation reads this.
#[must_use]
pub fn total_findings(m: &AuditManifest) -> u32 {
    m.findings.iter().map(|f| f.count).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
schema_version = 1

[module]
id    = "agent-guard"
label = "Agent Guard"

[[findings]]
pattern = "todo-no-anchor"
count   = 0

[[findings]]
pattern = "empty-stub"
count   = 0

[[findings]]
pattern = "minimize-phrase"
count   = 2
note    = "two intentional uses in operator-named context"
"#;

    #[test]
    fn pattern_ids_match_sovereign_os_r456_verbatim_order() {
        assert_eq!(
            PATTERN_IDS,
            [
                "todo-no-anchor",
                "empty-stub",
                "skipped-no-followup",
                "surface-gap",
                "doc-gap",
                "mandate-todo",
                "minimize-phrase",
                "partial-status",
            ]
        );
    }

    #[test]
    fn parses_well_formed() {
        let m = from_toml_str(GOOD).unwrap();
        assert_eq!(m.module.id, "agent-guard");
        assert_eq!(m.findings.len(), 3);
        assert_eq!(total_findings(&m), 2);
    }

    #[test]
    fn rejects_count_positive_without_note() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[findings]]
pattern = "todo-no-anchor"
count   = 5
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("note"));
    }

    #[test]
    fn rejects_unknown_pattern() {
        let bad = GOOD.replace(
            r#"pattern = "todo-no-anchor""#,
            r#"pattern = "unknown-pattern""#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("PATTERN_IDS"));
    }

    #[test]
    fn rejects_duplicate_pattern() {
        let bad = format!("{GOOD}\n[[findings]]\npattern = \"todo-no-anchor\"\ncount = 0\n");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn count_zero_no_note_required() {
        let ok = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[findings]]
pattern = "todo-no-anchor"
count   = 0
"#;
        from_toml_str(ok).unwrap();
    }

    #[test]
    fn total_findings_aggregates() {
        let m = from_toml_str(GOOD).unwrap();
        assert_eq!(total_findings(&m), 2);
    }

    #[test]
    fn round_trips_via_serde() {
        let m = from_toml_str(GOOD).unwrap();
        let s = toml::to_string(&m).unwrap();
        let m2 = from_toml_str(&s).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn rejects_future_schema_version() {
        let bad = GOOD.replace("schema_version = 1", "schema_version = 99");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("schema_version"));
    }

    #[test]
    fn rejects_empty_findings() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
"#;
        let err = from_toml_str(bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing") || msg.contains("at least one"));
    }
}
