//! # `selfdef-dashboard-manifest`
//!
//! Per-module dashboard manifest. Cross-repo binding to **sovereign-os
//! E11.M2** (reverse-proxy aggregator, R452). Every selfdef module that
//! exposes a dashboard ships a `dashboard-manifest.toml` at the module's
//! conventional config path; the sovereign-os `master-dashboard`
//! aggregator reads the union to build reverse-proxy routes under a
//! single super-dashboard port.
//!
//! Cross-repo binding ID: `SD-R-DASHBOARD-MANIFEST-1`.
//!
//! ## Operator-discoverable contract
//!
//! ```toml
//! # /etc/selfdef/dashboards/<module>.toml
//! schema_version = 1
//!
//! [dashboard]
//! module        = "agent-guard"        # selfdef module id
//! port          = 8090                  # listen port (loopback)
//! healthz_path  = "/healthz"            # liveness probe path
//! subpath       = "/agent-guard/"       # aggregator mount point
//! label         = "Agent Guard"         # human-readable label
//! auth_tier     = "basic"               # sovereign-os E11.M7 tier
//!                                       # (no-auth/basic/advanced/
//!                                       #  social/enterprise/network-level)
//!
//! # Optional: declare which §1g surfaces this dashboard exposes
//! # (cross-repo binding to sovereign-os E11.M3, R453).
//! surfaces      = ["dashboard", "api"]
//! ```
//!
//! ## What this crate provides
//!
//! - The `DashboardManifest` data type (serde-derived).
//! - `from_toml_str` / `from_toml_path` loaders.
//! - `validate` — enforces the operator-discoverable constraints
//!   (port range, auth_tier enum, subpath leading-slash, etc.).
//! - `AUTH_TIERS` constant — mirrors sovereign-os R450 6-tier ladder
//!   in operator-§1g verbatim order (drift between repos = lint
//!   failure on both sides).
//!
//! Per operator §1g (sovereign-os mandate verbatim):
//!
//! > "a mode of access from no auth at all by default to basic auth
//! >  to advanced auth to social auth to enterprise auth and network
//! >  level access and etc."

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// 6-tier auth ladder. Mirrors sovereign-os R450 (E11.M7) operator
/// §1g verbatim ordering (LOW → HIGH). Drift between this constant
/// and the sovereign-os `AUTH_TIERS` table is a contract violation.
pub const AUTH_TIERS: [&str; 6] = [
    "no-auth",
    "basic",
    "advanced",
    "social",
    "enterprise",
    "network-level",
];

/// 8-surface taxonomy. Mirrors sovereign-os R453 (E11.M3) operator
/// §1g verbatim ordering ("not just core, not just cli, not just TUI,
/// not just API, not just tool and MCP but also Dashboards and Web
/// Apps and Services").
pub const SURFACES: [&str; 8] = [
    "core",
    "cli",
    "tui",
    "api",
    "mcp",
    "dashboard",
    "webapp",
    "service",
];

/// Current manifest schema version. Bump only on breaking changes;
/// readers MUST refuse unknown future versions and warn about
/// missing field defaults.
pub const SCHEMA_VERSION: u32 = 1;

/// One module's dashboard manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardManifest {
    /// Schema version this file was authored against.
    pub schema_version: u32,
    /// The dashboard descriptor (single `[dashboard]` section).
    pub dashboard: DashboardSpec,
}

/// Dashboard descriptor (one per manifest file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardSpec {
    /// selfdef module id (e.g., `"agent-guard"`).
    pub module: String,
    /// Listen port (TCP). MUST be in 1024..=65535 (unprivileged range).
    pub port: u16,
    /// Liveness probe path (begins with `/`).
    pub healthz_path: String,
    /// Aggregator mount-point path (begins AND ends with `/`).
    pub subpath: String,
    /// Human-readable label for `sovereign-osctl master-dashboard list`.
    pub label: String,
    /// One of the [`AUTH_TIERS`] strings.
    pub auth_tier: String,
    /// Optional list of §1g surfaces this dashboard exposes
    /// (subset of [`SURFACES`]).
    #[serde(default)]
    pub surfaces: Vec<String>,
}

/// Errors produced while loading / validating a manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// IO failure while reading the file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// TOML deserialization failure.
    #[error("toml decode: {0}")]
    Toml(#[from] toml::de::Error),
    /// Validation rule violated.
    #[error("validation: {0}")]
    Validation(String),
}

/// Load + validate a manifest from a TOML string.
pub fn from_toml_str(s: &str) -> Result<DashboardManifest, ManifestError> {
    let m: DashboardManifest = toml::from_str(s)?;
    validate(&m)?;
    Ok(m)
}

/// Load + validate a manifest from a filesystem path.
pub fn from_toml_path<P: AsRef<Path>>(p: P)
    -> Result<DashboardManifest, ManifestError>
{
    let s = std::fs::read_to_string(p)?;
    from_toml_str(&s)
}

/// Enforce the operator-discoverable constraints on a manifest.
///
/// Returns `Err(ManifestError::Validation)` on the first failure.
pub fn validate(m: &DashboardManifest) -> Result<(), ManifestError> {
    if m.schema_version != SCHEMA_VERSION {
        return Err(ManifestError::Validation(format!(
            "schema_version {} not supported (this crate speaks {})",
            m.schema_version, SCHEMA_VERSION
        )));
    }
    let d = &m.dashboard;
    if d.module.is_empty() {
        return Err(ManifestError::Validation(
            "dashboard.module must be non-empty".into(),
        ));
    }
    if d.port < 1024 {
        return Err(ManifestError::Validation(format!(
            "dashboard.port={} must be ≥1024 (unprivileged)",
            d.port
        )));
    }
    if !d.healthz_path.starts_with('/') {
        return Err(ManifestError::Validation(format!(
            "dashboard.healthz_path={:?} must start with '/'",
            d.healthz_path
        )));
    }
    if !d.subpath.starts_with('/') || !d.subpath.ends_with('/') {
        return Err(ManifestError::Validation(format!(
            "dashboard.subpath={:?} must start AND end with '/'",
            d.subpath
        )));
    }
    if d.label.is_empty() {
        return Err(ManifestError::Validation(
            "dashboard.label must be non-empty".into(),
        ));
    }
    if !AUTH_TIERS.contains(&d.auth_tier.as_str()) {
        return Err(ManifestError::Validation(format!(
            "dashboard.auth_tier={:?} not one of {:?} \
             (sovereign-os R450 ladder)",
            d.auth_tier, AUTH_TIERS
        )));
    }
    for s in &d.surfaces {
        if !SURFACES.contains(&s.as_str()) {
            return Err(ManifestError::Validation(format!(
                "dashboard.surfaces[]={:?} not one of {:?} \
                 (sovereign-os R453 taxonomy)",
                s, SURFACES
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_MANIFEST: &str = r#"
schema_version = 1

[dashboard]
module        = "agent-guard"
port          = 8090
healthz_path  = "/healthz"
subpath       = "/agent-guard/"
label         = "Agent Guard"
auth_tier     = "basic"
surfaces      = ["dashboard", "api"]
"#;

    #[test]
    fn auth_tiers_matches_sovereign_os_r450_verbatim_order() {
        // §1g verbatim: "no auth at all by default to basic auth to
        // advanced auth to social auth to enterprise auth and network
        // level access". Drift here = silent contract break.
        assert_eq!(
            AUTH_TIERS,
            [
                "no-auth", "basic", "advanced", "social",
                "enterprise", "network-level"
            ]
        );
    }

    #[test]
    fn surfaces_matches_sovereign_os_r453_verbatim_order() {
        // §1g verbatim: "not just core, not just cli, not just TUI,
        // not just API, not just tool and MCP but also Dashboards and
        // Web Apps and Services".
        assert_eq!(
            SURFACES,
            [
                "core", "cli", "tui", "api", "mcp",
                "dashboard", "webapp", "service"
            ]
        );
    }

    #[test]
    fn parses_a_well_formed_manifest() {
        let m = from_toml_str(GOOD_MANIFEST).expect("good manifest");
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.dashboard.module, "agent-guard");
        assert_eq!(m.dashboard.port, 8090);
        assert_eq!(m.dashboard.auth_tier, "basic");
        assert_eq!(m.dashboard.surfaces, vec!["dashboard", "api"]);
    }

    #[test]
    fn rejects_unknown_auth_tier() {
        let bad = GOOD_MANIFEST.replace(
            r#"auth_tier     = "basic""#,
            r#"auth_tier     = "wide-open""#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("auth_tier"), "got {msg}");
        assert!(msg.contains("wide-open"), "got {msg}");
    }

    #[test]
    fn rejects_unknown_surface() {
        let bad = GOOD_MANIFEST.replace(
            r#"surfaces      = ["dashboard", "api"]"#,
            r#"surfaces      = ["dashboard", "telepathy"]"#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("surfaces"), "got {msg}");
    }

    #[test]
    fn rejects_privileged_port() {
        let bad = GOOD_MANIFEST.replace("port          = 8090",
                                        "port          = 80");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("port"));
    }

    #[test]
    fn rejects_unterminated_subpath() {
        let bad = GOOD_MANIFEST.replace(
            r#"subpath       = "/agent-guard/""#,
            r#"subpath       = "/agent-guard""#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("subpath"));
    }

    #[test]
    fn rejects_relative_healthz() {
        let bad = GOOD_MANIFEST.replace(
            r#"healthz_path  = "/healthz""#,
            r#"healthz_path  = "healthz""#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("healthz_path"));
    }

    #[test]
    fn rejects_empty_module() {
        let bad = GOOD_MANIFEST.replace(
            r#"module        = "agent-guard""#,
            r#"module        = """#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("module"));
    }

    #[test]
    fn rejects_empty_label() {
        let bad = GOOD_MANIFEST.replace(
            r#"label         = "Agent Guard""#,
            r#"label         = """#,
        );
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("label"));
    }

    #[test]
    fn rejects_future_schema_version() {
        let bad = GOOD_MANIFEST.replace("schema_version = 1",
                                        "schema_version = 99");
        let err = from_toml_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("schema_version"));
    }

    #[test]
    fn round_trips_via_serde() {
        let m = from_toml_str(GOOD_MANIFEST).unwrap();
        let s = toml::to_string(&m).unwrap();
        let m2 = from_toml_str(&s).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn surfaces_field_is_optional() {
        let without = r#"
schema_version = 1

[dashboard]
module        = "minimal"
port          = 8100
healthz_path  = "/h"
subpath       = "/minimal/"
label         = "Minimal"
auth_tier     = "no-auth"
"#;
        let m = from_toml_str(without).unwrap();
        assert!(m.dashboard.surfaces.is_empty());
    }
}
