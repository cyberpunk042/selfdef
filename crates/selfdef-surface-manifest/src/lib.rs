//! # `selfdef-surface-manifest`
//!
//! Per-module surface manifest. Cross-repo binding to **sovereign-os
//! R453 (E11.M3 multi-surface delivery contract)**. Every selfdef
//! module declares which of the 8 operator-named §1g surfaces it
//! ships; the sovereign-os `surface-map` instrument can fold these
//! into its cross-repo coverage matrix.
//!
//! Cross-repo binding ID: `SD-R-MULTI-SURFACE-AUDIT-1`.
//!
//! ## Operator-discoverable contract
//!
//! Per operator §1g (sovereign-os mandate verbatim):
//!
//! > "Everything is not just core, not just cli, not just TUI, not
//! >  just API, not just tool and MCP but also Dashboards and Web
//! >  Apps and Services"
//!
//! ## File location
//!
//! Default path: `/etc/selfdef/surfaces/<module>.toml`.
//! Env-override: `SELFDEF_SURFACE_MANIFEST_DIR` (cross-repo
//! consumed by sovereign-os `surface-map` discovery in the future).
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
//! # The §1g 8-surface taxonomy. Each entry: surface id + state
//! # (shipped / waived / planned).
//! [[surfaces]]
//! id     = "core"
//! state  = "shipped"
//!
//! [[surfaces]]
//! id     = "cli"
//! state  = "shipped"
//!
//! [[surfaces]]
//! id     = "dashboard"
//! state  = "shipped"
//!
//! [[surfaces]]
//! id     = "tui"
//! state  = "waived"
//! reason = "not applicable — daemon, no interactive surface"
//!
//! [[surfaces]]
//! id     = "api"
//! state  = "planned"
//! ```
//!
//! `shipped` = module ships this surface today. `waived` = surface
//! intentionally absent with operator-named rationale (operator-
//! discoverable opt-out, mirrors sovereign-os surface-map waiver
//! pattern). `planned` = TODO with intent to ship.
//!
//! ## Cross-repo binding integrity
//!
//! [`SURFACE_TAXONOMY`] mirrors sovereign-os R453 `SURFACES`
//! verbatim ordering. Drift = test failure in both repos.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Schema version. Bump only on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

/// The 8 §1g operator-named surfaces in verbatim order ("not just
/// core, not just cli, not just TUI, not just API, not just tool and
/// MCP but also Dashboards and Web Apps and Services"). Drift between
/// this constant and the sovereign-os R453 `SURFACES` table is a
/// contract violation.
pub const SURFACE_TAXONOMY: [&str; 8] = [
    "core",
    "cli",
    "tui",
    "api",
    "mcp",
    "dashboard",
    "webapp",
    "service",
];

/// Per-surface shipping state. Wire format is the kebab-case form
/// (`shipped` / `waived` / `planned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceState {
    /// Module ships this surface today.
    Shipped,
    /// Surface intentionally absent. `reason` field MUST be set.
    Waived,
    /// TODO with intent to ship.
    Planned,
}

/// One surface entry inside a manifest's `[[surfaces]]` array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceEntry {
    /// One of [`SURFACE_TAXONOMY`].
    pub id: String,
    /// Shipping state.
    pub state: SurfaceState,
    /// Operator-named rationale. REQUIRED when `state == Waived`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `[module]` header section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleHeader {
    /// selfdef module id (e.g., `"agent-guard"`).
    pub id: String,
    /// Human-readable label.
    pub label: String,
}

/// One module's surface manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceManifest {
    /// Schema version this file was authored against.
    pub schema_version: u32,
    /// Module identity header.
    pub module: ModuleHeader,
    /// Per-surface entries (one per cell — operator-discoverable).
    pub surfaces: Vec<SurfaceEntry>,
}

/// Errors produced while loading / validating a manifest.
#[derive(Debug, Error)]
pub enum SurfaceManifestError {
    /// IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML decode failure (includes serde-level rejection of unknown
    /// surface-state variants).
    #[error("toml decode: {0}")]
    Toml(#[from] toml::de::Error),
    /// Validation rule violated.
    #[error("validation: {0}")]
    Validation(String),
}

/// Load + validate a manifest from a TOML string.
pub fn from_toml_str(s: &str) -> Result<SurfaceManifest, SurfaceManifestError> {
    let m: SurfaceManifest = toml::from_str(s)?;
    validate(&m)?;
    Ok(m)
}

/// Load + validate from a filesystem path.
pub fn from_toml_path<P: AsRef<Path>>(p: P) -> Result<SurfaceManifest, SurfaceManifestError> {
    let s = std::fs::read_to_string(p)?;
    from_toml_str(&s)
}

/// Enforce the operator-discoverable constraints on a manifest.
///
/// Rules:
/// - `schema_version == 1`.
/// - `module.id` and `module.label` non-empty.
/// - At least one `[[surfaces]]` entry.
/// - Each surface `id` ∈ [`SURFACE_TAXONOMY`].
/// - No duplicate surface ids.
/// - Every `Waived` entry MUST have a non-empty `reason`.
pub fn validate(m: &SurfaceManifest) -> Result<(), SurfaceManifestError> {
    if m.schema_version != SCHEMA_VERSION {
        return Err(SurfaceManifestError::Validation(format!(
            "schema_version {} not supported (this crate speaks {})",
            m.schema_version, SCHEMA_VERSION
        )));
    }
    if m.module.id.is_empty() {
        return Err(SurfaceManifestError::Validation(
            "module.id must be non-empty".into(),
        ));
    }
    if m.module.label.is_empty() {
        return Err(SurfaceManifestError::Validation(
            "module.label must be non-empty".into(),
        ));
    }
    if m.surfaces.is_empty() {
        return Err(SurfaceManifestError::Validation(
            "at least one [[surfaces]] entry required".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for s in &m.surfaces {
        if !SURFACE_TAXONOMY.contains(&s.id.as_str()) {
            return Err(SurfaceManifestError::Validation(format!(
                "surface id={:?} not in §1g taxonomy {:?}",
                s.id, SURFACE_TAXONOMY
            )));
        }
        if !seen.insert(s.id.clone()) {
            return Err(SurfaceManifestError::Validation(format!(
                "duplicate surface id={:?}",
                s.id
            )));
        }
        if s.state == SurfaceState::Waived && s.reason.as_deref().unwrap_or("").is_empty() {
            return Err(SurfaceManifestError::Validation(format!(
                "surface id={:?} state=waived requires a 'reason' field \
                 (operator-discoverable opt-out rationale)",
                s.id
            )));
        }
    }
    Ok(())
}

/// Return the count of surfaces with `state == Shipped`. Cross-repo
/// surface-map gap-detection reads this to know how many of the 8
/// §1g surfaces a module actually delivers.
#[must_use]
pub fn shipped_count(m: &SurfaceManifest) -> usize {
    m.surfaces
        .iter()
        .filter(|s| s.state == SurfaceState::Shipped)
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

[[surfaces]]
id    = "core"
state = "shipped"

[[surfaces]]
id    = "cli"
state = "shipped"

[[surfaces]]
id    = "dashboard"
state = "shipped"

[[surfaces]]
id     = "tui"
state  = "waived"
reason = "daemon — no interactive surface"

[[surfaces]]
id    = "api"
state = "planned"
"#;

    #[test]
    fn surface_taxonomy_matches_sovereign_os_r453_verbatim_order() {
        // §1g verbatim: 'not just core, not just cli, not just TUI,
        // not just API, not just tool and MCP but also Dashboards and
        // Web Apps and Services'. Drift = surface-map cross-repo break.
        assert_eq!(
            SURFACE_TAXONOMY,
            [
                "core",
                "cli",
                "tui",
                "api",
                "mcp",
                "dashboard",
                "webapp",
                "service"
            ]
        );
    }

    #[test]
    fn surface_taxonomy_has_eight_entries() {
        assert_eq!(SURFACE_TAXONOMY.len(), 8);
    }

    #[test]
    fn parses_well_formed_manifest() {
        let m = from_toml_str(GOOD).expect("good manifest");
        assert_eq!(m.module.id, "agent-guard");
        assert_eq!(m.surfaces.len(), 5);
        assert_eq!(shipped_count(&m), 3);
    }

    #[test]
    fn rejects_unknown_surface_state() {
        let bad = GOOD.replace(r#"state = "shipped""#, r#"state = "maybe""#);
        let err = from_toml_str(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("toml") || msg.contains("variant"), "got {msg}");
    }

    #[test]
    fn rejects_unknown_surface_id() {
        let bad = GOOD.replace(r#"id    = "core""#, r#"id    = "telepathy""#);
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("taxonomy"));
    }

    #[test]
    fn rejects_duplicate_surface_id() {
        let bad = format!("{GOOD}\n[[surfaces]]\nid = \"core\"\nstate = \"shipped\"\n");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn rejects_waived_without_reason() {
        let bad = r#"
schema_version = 1

[module]
id    = "x"
label = "X"

[[surfaces]]
id    = "core"
state = "waived"
"#;
        let err = from_toml_str(bad).unwrap_err();
        assert!(format!("{err}").contains("reason"));
    }

    #[test]
    fn rejects_empty_surfaces_array() {
        let bad = r#"
schema_version = 1

[module]
id    = "x"
label = "X"
"#;
        let err = from_toml_str(bad).unwrap_err();
        // Either serde missing-field OR validation "at least one"
        let msg = format!("{err}");
        assert!(
            msg.contains("missing") || msg.contains("at least one"),
            "got {msg}"
        );
    }

    #[test]
    fn rejects_empty_module_fields() {
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
    fn shipped_count_excludes_waived_and_planned() {
        let m = from_toml_str(GOOD).unwrap();
        // 3 shipped (core, cli, dashboard); 1 waived (tui); 1 planned (api)
        assert_eq!(shipped_count(&m), 3);
    }

    #[test]
    fn round_trips_via_serde() {
        let m = from_toml_str(GOOD).unwrap();
        let s = toml::to_string(&m).unwrap();
        let m2 = from_toml_str(&s).unwrap();
        assert_eq!(m, m2);
    }
}
