//! Integration tests for `selfdef-ux-checklist`. Cross-repo sentinel:
//! UX_DIMENSIONS order drift from sovereign-os R457 fails both repos.

use selfdef_ux_checklist::{
    DimensionEntry, DimensionState, ModuleHeader, SCHEMA_VERSION, UX_DIMENSIONS, UxChecklist,
    from_toml_path, from_toml_str, pass_count, validate,
};
use std::io::Write;
use tempfile::NamedTempFile;

const FULL: &str = r#"
schema_version = 1

[module]
id    = "polarproxy"
label = "PolarProxy"

[[dimensions]]
id    = "action-budget"
state = "pass"

[[dimensions]]
id    = "discoverable"
state = "pass"

[[dimensions]]
id     = "recoverable"
state  = "n-a"
reason = "MITM proxy; no destructive verbs"

[[dimensions]]
id    = "next-step"
state = "pass"

[[dimensions]]
id    = "operator-named"
state = "pass"

[[dimensions]]
id     = "readable-30s"
state  = "fail"
reason = "help text exceeds 30s comfortable read"
"#;

#[test]
fn loads_from_filesystem() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{FULL}").unwrap();
    let c = from_toml_path(f.path()).unwrap();
    assert_eq!(c.module.id, "polarproxy");
    assert_eq!(c.dimensions.len(), 6);
    assert_eq!(pass_count(&c), 4);
}

#[test]
fn schema_version_constant_matches() {
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn ux_dimensions_has_six() {
    assert_eq!(UX_DIMENSIONS.len(), 6);
}

#[test]
fn each_dimension_in_taxonomy_can_be_used() {
    for &id in &UX_DIMENSIONS {
        let toml = format!(
            r#"schema_version = 1
[module]
id    = "m"
label = "M"
[[dimensions]]
id    = "{id}"
state = "pass"
"#
        );
        from_toml_str(&toml).unwrap_or_else(|e| {
            panic!("dimension {id:?} should parse: {e}");
        });
    }
}

#[test]
fn programmatic_construction_passes() {
    let c = UxChecklist {
        schema_version: 1,
        module: ModuleHeader {
            id: "agent-guard".into(),
            label: "Agent Guard".into(),
        },
        dimensions: vec![DimensionEntry {
            id: "action-budget".into(),
            state: DimensionState::Pass,
            reason: None,
        }],
    };
    validate(&c).unwrap();
    assert_eq!(pass_count(&c), 1);
}

#[test]
fn programmatic_fail_without_reason_rejected() {
    let c = UxChecklist {
        schema_version: 1,
        module: ModuleHeader {
            id: "x".into(),
            label: "X".into(),
        },
        dimensions: vec![DimensionEntry {
            id: "action-budget".into(),
            state: DimensionState::Fail,
            reason: None,
        }],
    };
    assert!(validate(&c).is_err());
}

#[test]
fn ioerror_when_path_missing() {
    let err = from_toml_path("/nonexistent/path.toml").unwrap_err();
    assert!(format!("{err}").contains("io"));
}

#[test]
fn pass_count_zero_when_all_fail() {
    let c = UxChecklist {
        schema_version: 1,
        module: ModuleHeader {
            id: "x".into(),
            label: "X".into(),
        },
        dimensions: UX_DIMENSIONS
            .iter()
            .map(|id| DimensionEntry {
                id: (*id).into(),
                state: DimensionState::Fail,
                reason: Some("test".into()),
            })
            .collect(),
    };
    validate(&c).unwrap();
    assert_eq!(pass_count(&c), 0);
}
