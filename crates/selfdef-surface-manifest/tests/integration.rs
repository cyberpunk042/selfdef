//! Integration tests for `selfdef-surface-manifest`. Cross-repo
//! binding sentinel: drift between SURFACE_TAXONOMY and the
//! sovereign-os R453 SURFACES table fails tests in both repos.

use selfdef_surface_manifest::{
    ModuleHeader, SCHEMA_VERSION, SURFACE_TAXONOMY, SurfaceEntry, SurfaceManifest, SurfaceState,
    from_toml_path, from_toml_str, shipped_count, validate,
};
use std::io::Write;
use tempfile::NamedTempFile;

const FULL: &str = r#"
schema_version = 1

[module]
id    = "polarproxy"
label = "PolarProxy"

[[surfaces]]
id    = "core"
state = "shipped"

[[surfaces]]
id    = "cli"
state = "shipped"

[[surfaces]]
id    = "service"
state = "shipped"

[[surfaces]]
id     = "dashboard"
state  = "waived"
reason = "MITM proxy; no operator-facing dashboard by design"

[[surfaces]]
id    = "api"
state = "planned"
"#;

#[test]
fn loads_from_filesystem_path() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{FULL}").unwrap();
    let m = from_toml_path(f.path()).unwrap();
    assert_eq!(m.module.id, "polarproxy");
    assert_eq!(m.surfaces.len(), 5);
}

#[test]
fn shipped_count_matches_expectations() {
    let m = from_toml_str(FULL).unwrap();
    assert_eq!(shipped_count(&m), 3);
}

#[test]
fn schema_version_constant_matches() {
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn programmatic_construction_passes() {
    let m = SurfaceManifest {
        schema_version: 1,
        module: ModuleHeader {
            id: "agent-guard".into(),
            label: "Agent Guard".into(),
        },
        surfaces: vec![
            SurfaceEntry {
                id: "core".into(),
                state: SurfaceState::Shipped,
                reason: None,
            },
            SurfaceEntry {
                id: "tui".into(),
                state: SurfaceState::Waived,
                reason: Some("daemon — no interactive surface".into()),
            },
        ],
    };
    validate(&m).unwrap();
    assert_eq!(shipped_count(&m), 1);
}

#[test]
fn ioerror_when_path_missing() {
    let err = from_toml_path("/nonexistent/no.toml").unwrap_err();
    assert!(format!("{err}").contains("io"));
}

#[test]
fn surface_taxonomy_has_exactly_eight() {
    assert_eq!(SURFACE_TAXONOMY.len(), 8);
}

#[test]
fn each_surface_in_taxonomy_can_be_used() {
    for &id in &SURFACE_TAXONOMY {
        let toml = format!(
            r#"schema_version = 1
[module]
id    = "x"
label = "X"
[[surfaces]]
id    = "{id}"
state = "shipped"
"#
        );
        from_toml_str(&toml).unwrap_or_else(|e| {
            panic!("surface {id:?} should parse: {e}");
        });
    }
}

#[test]
fn all_three_states_round_trip() {
    let cases = [
        (SurfaceState::Shipped, "shipped"),
        (SurfaceState::Waived, "waived"),
        (SurfaceState::Planned, "planned"),
    ];
    for (state, wire) in cases {
        let reason_line = if state == SurfaceState::Waived {
            "reason = \"test\"\n"
        } else {
            ""
        };
        let toml = format!(
            r#"schema_version = 1
[module]
id    = "x"
label = "X"
[[surfaces]]
id    = "core"
state = "{wire}"
{reason_line}"#
        );
        let m = from_toml_str(&toml).unwrap_or_else(|e| {
            panic!("state {wire:?} should parse: {e}");
        });
        assert_eq!(m.surfaces[0].state, state);
    }
}
