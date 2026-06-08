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
