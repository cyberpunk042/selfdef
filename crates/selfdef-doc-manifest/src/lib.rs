//! # `selfdef-doc-manifest`
//!
//! Per-module doc-coverage manifest. Cross-repo binding to
//! **sovereign-os R454 doc-coverage** (E11.M1). Cross-repo binding
//! ID: `SD-R-DOC-MANIFEST-1`.
//!
//! Per operator §1g VERBATIM (sovereign-os mandate):
//!
//! > "very clear and well defined documentation through and through
//! >  which follow the high standards"
//!
//! Every selfdef module ships a `doc-manifest.toml` declaring which
//! of the 6 operator-named documentation surfaces it ships docs in.
//! The sovereign-os `doc-coverage` instrument can fold these into
//! its cross-repo coverage matrix.
//!
//! Note that the **sovereign-os side is auto-discovery** (grep-driven
//! against the actual filesystem). The selfdef side adds an
//! **explicit declaration** because Rust workspaces have less
//! reliable filesystem conventions than the sovereign-os repo
//! (e.g., per-crate docs/, per-module documentation under modules/,
//! rustdoc embedded in source).
//!
//! ## 6 doc surfaces (mirror of sovereign-os R454 DOC_KINDS)
//!
//! ```text
//! readme            top-level README.md or crate README
//! sdd               dedicated chapter under docs/sdd/
//! helptext          selfdefctl CLI help section
//! metric-inventory  Prometheus metric registry / dashboard README
//! mandate-row       sovereign-os mandate or selfdef backlog row
//! man-page          stub under docs/man/ or packaging
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
//! [[docs]]
//! kind  = "readme"
//! state = "shipped"
//! path  = "crates/selfdef-collector-tetragon/README.md"
//!
//! [[docs]]
//! kind  = "sdd"
//! state = "shipped"
//! path  = "docs/sdd/004-security-threat-model.md"
//!
//! [[docs]]
//! kind   = "metric-inventory"
//! state  = "waived"
//! reason = "metrics shipped via daemon /metrics endpoint; no inventory file"
//!
//! [[docs]]
//! kind  = "man-page"
//! state = "planned"
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// 6 operator-named doc kinds in sovereign-os R454 verbatim order.
/// Drift = cross-repo contract break.
pub const DOC_KINDS: [&str; 6] = [
    "readme",
    "sdd",
    "helptext",
    "metric-inventory",
    "mandate-row",
    "man-page",
];

/// Per-doc shipping state. Kebab-case wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocState {
    /// Doc ships today.
    Shipped,
    /// Doc intentionally absent. `reason` field MUST be set.
    Waived,
    /// TODO with intent to ship.
    Planned,
}

/// One doc entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocEntry {
    /// One of [`DOC_KINDS`].
    pub kind: String,
    /// Shipping state.
    pub state: DocState,
    /// Optional repo-relative path to the doc artifact (REQUIRED
    /// when `state == Shipped`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Operator-named rationale. REQUIRED when `state == Waived`.
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

/// One module's doc manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocManifest {
    /// Schema version.
    pub schema_version: u32,
    /// Module identity.
    pub module: ModuleHeader,
    /// Per-doc entries.
    pub docs: Vec<DocEntry>,
}

/// Errors during load / validation.
#[derive(Debug, Error)]
pub enum DocManifestError {
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
pub fn from_toml_str(s: &str) -> Result<DocManifest, DocManifestError> {
    let m: DocManifest = toml::from_str(s)?;
    validate(&m)?;
    Ok(m)
}

/// Load + validate from a filesystem path.
pub fn from_toml_path<P: AsRef<Path>>(p: P) -> Result<DocManifest, DocManifestError> {
    let s = std::fs::read_to_string(p)?;
    from_toml_str(&s)
}

/// Validate:
/// - schema_version == 1
/// - module.id + module.label non-empty
/// - docs[] non-empty
/// - each kind ∈ DOC_KINDS
/// - no duplicate doc kinds
/// - Shipped requires non-empty path
/// - Waived requires non-empty reason
pub fn validate(m: &DocManifest) -> Result<(), DocManifestError> {
    if m.schema_version != SCHEMA_VERSION {
        return Err(DocManifestError::Validation(format!(
            "schema_version {} not supported",
            m.schema_version
        )));
    }
    if m.module.id.is_empty() {
        return Err(DocManifestError::Validation(
            "module.id must be non-empty".into(),
        ));
    }
    if m.module.label.is_empty() {
        return Err(DocManifestError::Validation(
            "module.label must be non-empty".into(),
        ));
    }
    if m.docs.is_empty() {
        return Err(DocManifestError::Validation(
            "docs[] must have at least one entry".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for d in &m.docs {
        if !DOC_KINDS.contains(&d.kind.as_str()) {
            return Err(DocManifestError::Validation(format!(
                "doc kind {:?} not in DOC_KINDS {:?}",
                d.kind, DOC_KINDS
            )));
        }
        if !seen.insert(d.kind.clone()) {
            return Err(DocManifestError::Validation(format!(
                "duplicate doc kind {:?}",
                d.kind
            )));
        }
        match d.state {
            DocState::Shipped => {
                if d.path.as_deref().unwrap_or("").is_empty() {
                    return Err(DocManifestError::Validation(format!(
                        "kind {:?} state=shipped requires a non-empty \
                         'path' field (operator-discoverable doc-location)",
                        d.kind
                    )));
                }
            }
            DocState::Waived => {
                if d.reason.as_deref().unwrap_or("").is_empty() {
                    return Err(DocManifestError::Validation(format!(
                        "kind {:?} state=waived requires a non-empty \
                         'reason' field",
                        d.kind
                    )));
                }
            }
            DocState::Planned => {}
        }
    }
    Ok(())
}

/// Count of docs with `state == Shipped`. 0..=6.
#[must_use]
pub fn shipped_count(m: &DocManifest) -> usize {
    m.docs
        .iter()
        .filter(|d| d.state == DocState::Shipped)
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

[[docs]]
kind  = "readme"
state = "shipped"
path  = "README.md"

[[docs]]
kind  = "sdd"
state = "shipped"
path  = "docs/sdd/004-security-threat-model.md"

[[docs]]
kind  = "helptext"
state = "shipped"
path  = "crates/selfdef-cli/src/main.rs"

[[docs]]
kind   = "metric-inventory"
state  = "waived"
reason = "metrics shipped via daemon /metrics endpoint"

[[docs]]
kind  = "mandate-row"
state = "shipped"
path  = "docs/operator/2026-05-18-e11-cross-repo-backlog.md"

[[docs]]
kind  = "man-page"
state = "planned"
"#;

    #[test]
    fn doc_kinds_match_sovereign_os_r454_verbatim_order() {
        assert_eq!(
            DOC_KINDS,
            [
                "readme",
                "sdd",
                "helptext",
                "metric-inventory",
                "mandate-row",
                "man-page",
            ]
        );
    }

    #[test]
    fn doc_kinds_count_is_six() {
        assert_eq!(DOC_KINDS.len(), 6);
    }

    #[test]
    fn parses_well_formed() {
        let m = from_toml_str(GOOD).unwrap();
        assert_eq!(m.docs.len(), 6);
        assert_eq!(shipped_count(&m), 4);
    }

    #[test]
    fn rejects_unknown_doc_kind() {
        let bad = GOOD.replace(r#"kind  = "readme""#, r#"kind  = "podcast""#);
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("DOC_KINDS"));
    }

    #[test]
    fn rejects_shipped_without_path() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[docs]]
kind  = "readme"
state = "shipped"
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("path"));
    }

    #[test]
    fn rejects_waived_without_reason() {
        let bad = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[docs]]
kind  = "readme"
state = "waived"
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("reason"));
    }

    #[test]
    fn planned_no_extras_required() {
        let ok = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[docs]]
kind  = "man-page"
state = "planned"
"#;
        from_toml_str(ok).unwrap();
    }

    #[test]
    fn rejects_duplicate_kind() {
        let dup =
            format!("{GOOD}\n[[docs]]\nkind = \"readme\"\nstate = \"shipped\"\npath = \"X\"\n");
        let err = from_toml_str(&dup).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn rejects_empty_docs() {
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

    #[test]
    fn rejects_future_schema_version() {
        let bad = GOOD.replace("schema_version = 1", "schema_version = 99");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("schema_version"));
    }

    #[test]
    fn rejects_unknown_state() {
        let bad = GOOD.replace(r#"state = "shipped""#, r#"state = "maybe""#);
        let err = from_toml_str(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("toml") || msg.contains("variant"), "got {msg}");
    }

    #[test]
    fn shipped_count_excludes_other_states() {
        let m = from_toml_str(GOOD).unwrap();
        // 4 shipped + 1 waived + 1 planned
        assert_eq!(shipped_count(&m), 4);
    }

    #[test]
    fn round_trips_via_serde() {
        let m = from_toml_str(GOOD).unwrap();
        let s = toml::to_string(&m).unwrap();
        let m2 = from_toml_str(&s).unwrap();
        assert_eq!(m, m2);
    }
}
