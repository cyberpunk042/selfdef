//! Integration tests for `selfdef-doc-manifest`. Cross-repo sentinel:
//! DOC_KINDS order drift from sovereign-os R454 fails BOTH repos.

use selfdef_doc_manifest::{
    DOC_KINDS, DocEntry, DocManifest, DocState, ModuleHeader, SCHEMA_VERSION, from_toml_path,
    from_toml_str, shipped_count, validate,
};
use std::io::Write;
use tempfile::NamedTempFile;

const FULL: &str = r#"
schema_version = 1

[module]
id    = "polarproxy"
label = "PolarProxy"

[[docs]]
kind  = "readme"
state = "shipped"
path  = "modules/polarproxy/README.md"

[[docs]]
kind   = "sdd"
state  = "waived"
reason = "operator-named: MITM-proxy doesn't warrant its own SDD chapter"

[[docs]]
kind  = "helptext"
state = "shipped"
path  = "crates/selfdef-cli/src/main.rs"

[[docs]]
kind  = "metric-inventory"
state = "planned"

[[docs]]
kind  = "mandate-row"
state = "shipped"
path  = "docs/operator/2026-05-18-e11-cross-repo-backlog.md"

[[docs]]
kind   = "man-page"
state  = "waived"
reason = "no daemon binary; CLI verb only"
"#;

#[test]
fn loads_from_filesystem() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{FULL}").unwrap();
    let m = from_toml_path(f.path()).unwrap();
    assert_eq!(m.module.id, "polarproxy");
    assert_eq!(m.docs.len(), 6);
    assert_eq!(shipped_count(&m), 3);
}

#[test]
fn schema_version_constant_matches() {
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn doc_kinds_has_six_entries() {
    assert_eq!(DOC_KINDS.len(), 6);
}

#[test]
fn each_kind_in_taxonomy_can_be_used_when_planned() {
    // Planned state needs nothing — exercise every kind in turn.
    for &k in &DOC_KINDS {
        let toml = format!(
            r#"schema_version = 1
[module]
id    = "x"
label = "X"
[[docs]]
kind  = "{k}"
state = "planned"
"#
        );
        from_toml_str(&toml).unwrap_or_else(|e| {
            panic!("kind {k:?} should parse: {e}");
        });
    }
}

#[test]
fn programmatic_construction_passes() {
    let m = DocManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "agent-guard".into(),
            label: "Agent Guard".into(),
        },
        docs: vec![DocEntry {
            kind: "readme".into(),
            state: DocState::Shipped,
            path: Some("README.md".into()),
            reason: None,
        }],
    };
    validate(&m).unwrap();
    assert_eq!(shipped_count(&m), 1);
}

#[test]
fn programmatic_shipped_without_path_rejected() {
    let m = DocManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "x".into(),
            label: "X".into(),
        },
        docs: vec![DocEntry {
            kind: "readme".into(),
            state: DocState::Shipped,
            path: None,
            reason: None,
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
fn shipped_count_zero_when_all_waived_or_planned() {
    let toml = r#"
schema_version = 1
[module]
id    = "x"
label = "X"
[[docs]]
kind   = "readme"
state  = "waived"
reason = "test"
[[docs]]
kind  = "sdd"
state = "planned"
"#;
    let m = from_toml_str(toml).unwrap();
    assert_eq!(shipped_count(&m), 0);
}
