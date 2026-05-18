//! Integration tests for `selfdef-dashboard-manifest`. Cross-repo
//! binding: sovereign-os R452 (master-dashboard aggregator) reads
//! these manifests at runtime; the contract is enforced here.

use selfdef_dashboard_manifest::{
    AUTH_TIERS, DashboardManifest, DashboardSpec, SCHEMA_VERSION, SURFACES, from_toml_path,
    from_toml_str, validate,
};
use std::io::Write;
use tempfile::NamedTempFile;

const FULL: &str = r#"
schema_version = 1

[dashboard]
module        = "agent-guard"
port          = 8090
healthz_path  = "/healthz"
subpath       = "/agent-guard/"
label         = "Agent Guard"
auth_tier     = "advanced"
surfaces      = ["dashboard", "api", "service"]
"#;

#[test]
fn loads_from_filesystem_path() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{FULL}").unwrap();
    let m = from_toml_path(f.path()).unwrap();
    assert_eq!(m.dashboard.module, "agent-guard");
    assert_eq!(m.dashboard.surfaces.len(), 3);
}

#[test]
fn schema_version_constant_matches_supported() {
    assert_eq!(SCHEMA_VERSION, 1);
    let m = from_toml_str(FULL).unwrap();
    assert_eq!(m.schema_version, SCHEMA_VERSION);
}

#[test]
fn programmatic_construction_passes_validation() {
    let m = DashboardManifest {
        schema_version: 1,
        dashboard: DashboardSpec {
            module: "polarproxy".into(),
            port: 8443,
            healthz_path: "/healthz".into(),
            subpath: "/polarproxy/".into(),
            label: "PolarProxy".into(),
            auth_tier: "social".into(),
            surfaces: vec!["dashboard".into(), "api".into()],
        },
    };
    validate(&m).expect("manifest validates");
}

#[test]
fn auth_tiers_constant_has_six_entries() {
    assert_eq!(AUTH_TIERS.len(), 6, "R450 contract: 6-tier ladder");
}

#[test]
fn surfaces_constant_has_eight_entries() {
    assert_eq!(SURFACES.len(), 8, "R453 contract: 8-surface taxonomy");
}

#[test]
fn ioerror_when_path_does_not_exist() {
    let err = from_toml_path("/nonexistent/path/no.toml").unwrap_err();
    assert!(format!("{err}").contains("io"));
}

#[test]
fn validate_passes_when_surfaces_subset_of_eight() {
    let mut m = from_toml_str(FULL).unwrap();
    m.dashboard.surfaces = SURFACES.iter().map(|s| (*s).into()).collect();
    validate(&m).expect("all 8 surfaces allowed");
}

#[test]
fn validate_rejects_when_subpath_missing_leading_slash() {
    let mut m = from_toml_str(FULL).unwrap();
    m.dashboard.subpath = "agent-guard/".into();
    assert!(validate(&m).is_err());
}
