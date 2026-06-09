//! The canonical operator config example MUST load through the real
//! `Config::load` path.
//!
//! `config/selfdef.toml.example` is what operators copy to
//! `/etc/selfdef/selfdef.toml`. A TOML syntax error or a wrong-typed
//! value in the example (e.g. `interval_seconds = "five"`) would make
//! every operator who starts from it hit a daemon-startup config error —
//! and nothing tested that the example itself is loadable. This locks it:
//! the example must parse + deserialize into `Config` via the same
//! figment pipeline the daemon uses.
//!
//! (Note: serde ignores unknown keys, so this catches syntax + type
//! errors, not silently-typo'd keys. Spot-checking representative values
//! below proves the matching sections are actually read.)

use std::path::PathBuf;

use selfdef_config::Config;

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/selfdef.toml.example")
}

#[test]
fn canonical_example_loads_through_real_loader() {
    let path = example_path();
    assert!(
        path.exists(),
        "example config missing at {}",
        path.display()
    );
    let cfg = Config::load(Some(&path))
        .unwrap_or_else(|e| panic!("selfdef.toml.example failed to load: {e}"));

    // Spot-check representative values across sections so a section that
    // silently stopped parsing (wrong header, etc.) is caught.
    assert_eq!(cfg.store.hot_retention_days, 30, "store section");
    assert_eq!(
        cfg.hardware_probe.interval_seconds, 300,
        "hardware_probe section read"
    );
    assert_eq!(cfg.hardware_probe.thermal_critical_celsius, 95);
}

/// Discoverability: every top-level `[section]` the Config struct produces
/// MUST be documented in selfdef.toml.example. serde-default fields parse
/// fine when ABSENT from the example, so a new section added to Config can
/// silently ship undiscoverable (the `[deployment]` section — incl. the
/// node_exporter `hardware_metrics_path` + cross-repo cockpit
/// `selfdef_mirror_dir` knobs — was missing from the example for exactly
/// this reason). Lock the reverse direction: serialize Config::default()
/// and assert every top-level table appears in the example.
#[test]
fn every_top_level_config_section_is_documented_in_example() {
    let default_toml =
        toml::to_string(&Config::default()).expect("Config::default serializes to TOML");
    let default: toml::Value = toml::from_str(&default_toml).expect("serialized default re-parses");
    let example_str = std::fs::read_to_string(example_path()).expect("read example");
    let example: toml::Value = toml::from_str(&example_str).expect("example parses as TOML");

    let default_tbl = default.as_table().expect("default is a table");
    let example_tbl = example.as_table().expect("example is a table");

    let undocumented: Vec<&String> = default_tbl
        .iter()
        .filter(|(k, v)| v.is_table() && !example_tbl.contains_key(*k))
        .map(|(k, _)| k)
        .collect();

    assert!(
        undocumented.is_empty(),
        "Config has top-level section(s) {undocumented:?} that are NOT \
         documented in config/selfdef.toml.example — operators can't \
         discover them (serde-default makes them parse when absent). Add a \
         commented [section] block with the default values."
    );
}

/// Structural placement: operator-critical fields must live under the
/// CORRECT `[section]` in the example. serde-default + values that happen
/// to equal the code defaults make a misplaced key invisible to both the
/// loader test (it parses) and the value spot-check (default == documented
/// value) — exactly how the responder action-script fields (lockdown_script
/// / revoke_session_script / forensics_dir / velociraptor_binary /
/// velociraptor_args) silently sat under `[api.tls]` instead of
/// `[responder]`, so an operator customizing them had their value parsed
/// into the wrong table and ignored (the responder used the code default).
/// Pin each operator-critical field to its owning section so a future edit
/// (or a section header inserted above it) that displaces it fails loudly.
#[test]
fn operator_critical_fields_are_under_the_correct_section() {
    let example_str = std::fs::read_to_string(example_path()).expect("read example");
    let example: toml::Value = toml::from_str(&example_str).expect("example parses as TOML");
    let tbl = example.as_table().expect("example is a table");

    // (section path, field) pairs that MUST be present at that exact path.
    let expectations: &[(&[&str], &str)] = &[
        (&["responder"], "lockdown_script"),
        (&["responder"], "revoke_session_script"),
        (&["responder"], "forensics_dir"),
        (&["responder"], "velociraptor_binary"),
        (&["responder"], "velociraptor_args"),
        (&["responder"], "snapshot_dir"),
        (&["responder"], "allowed_actions"),
    ];

    let mut misplaced = Vec::new();
    for (section_path, field) in expectations {
        let mut node = example.clone();
        let mut ok = true;
        for seg in *section_path {
            match node.as_table().and_then(|t| t.get(*seg)) {
                Some(v) => node = v.clone(),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        let present = ok
            && node
                .as_table()
                .map(|t| t.contains_key(*field))
                .unwrap_or(false);
        if !present {
            // Find where it actually landed, for a useful message.
            let found_in: Vec<&String> = tbl
                .iter()
                .filter(|(_, v)| {
                    v.as_table()
                        .map(|t| t.contains_key(*field))
                        .unwrap_or(false)
                })
                .map(|(k, _)| k)
                .collect();
            misplaced.push(format!(
                "[{}].{field} missing (found instead under: {found_in:?})",
                section_path.join(".")
            ));
        }
    }

    assert!(
        misplaced.is_empty(),
        "operator-critical config field(s) are under the WRONG section in \
         config/selfdef.toml.example (an operator customizing them gets a \
         silent no-op — the daemon reads the field from its real section and \
         falls back to the code default):\n  {}",
        misplaced.join("\n  ")
    );
}
