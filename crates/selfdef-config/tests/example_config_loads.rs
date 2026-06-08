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
    let default_toml = toml::to_string(&Config::default())
        .expect("Config::default serializes to TOML");
    let default: toml::Value =
        toml::from_str(&default_toml).expect("serialized default re-parses");
    let example_str =
        std::fs::read_to_string(example_path()).expect("read example");
    let example: toml::Value =
        toml::from_str(&example_str).expect("example parses as TOML");

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
