//! Integration tests for `selfdef-audit-manifest`. Cross-repo sentinel:
//! PATTERN_IDS order drift from sovereign-os R456 fails both repos.

use selfdef_audit_manifest::{
    AuditManifest, FindingEntry, ModuleHeader, PATTERN_IDS, SCHEMA_VERSION, from_toml_path,
    from_toml_str, total_findings, validate,
};
use std::io::Write;
use tempfile::NamedTempFile;

const FULL: &str = r#"
schema_version = 1

[module]
id    = "polarproxy"
label = "PolarProxy"

[[findings]]
pattern = "todo-no-anchor"
count   = 1
note    = "TODO: switch to async writer when tokio-uring stabilizes"

[[findings]]
pattern = "empty-stub"
count   = 0

[[findings]]
pattern = "doc-gap"
count   = 0
"#;

#[test]
fn loads_from_filesystem() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{FULL}").unwrap();
    let m = from_toml_path(f.path()).unwrap();
    assert_eq!(m.module.id, "polarproxy");
    assert_eq!(total_findings(&m), 1);
}

#[test]
fn schema_version_constant_matches() {
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn pattern_ids_count_is_eight() {
    assert_eq!(PATTERN_IDS.len(), 8);
}

#[test]
fn each_pattern_in_taxonomy_can_be_used() {
    for &p in &PATTERN_IDS {
        let toml = format!(
            r#"schema_version = 1
[module]
id    = "m"
label = "M"
[[findings]]
pattern = "{p}"
count   = 0
"#
        );
        from_toml_str(&toml).unwrap_or_else(|e| {
            panic!("pattern {p:?} should parse: {e}");
        });
    }
}

#[test]
fn programmatic_construction_passes() {
    let m = AuditManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "agent-guard".into(),
            label: "Agent Guard".into(),
        },
        findings: vec![FindingEntry {
            pattern: "todo-no-anchor".into(),
            count: 0,
            note: None,
        }],
    };
    validate(&m).unwrap();
    assert_eq!(total_findings(&m), 0);
}

#[test]
fn programmatic_count_without_note_rejected() {
    let m = AuditManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "x".into(),
            label: "X".into(),
        },
        findings: vec![FindingEntry {
            pattern: "todo-no-anchor".into(),
            count: 3,
            note: None,
        }],
    };
    assert!(validate(&m).is_err());
}

#[test]
fn ioerror_when_path_missing() {
    let err = from_toml_path("/nonexistent/path.toml").unwrap_err();
    assert!(format!("{err}").contains("io"));
}

#[test]
fn total_findings_zero_when_all_count_zero() {
    let m = AuditManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "clean".into(),
            label: "Clean".into(),
        },
        findings: PATTERN_IDS
            .iter()
            .map(|p| FindingEntry {
                pattern: (*p).into(),
                count: 0,
                note: None,
            })
            .collect(),
    };
    validate(&m).unwrap();
    assert_eq!(total_findings(&m), 0);
}
