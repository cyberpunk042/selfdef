//! `selfdefd --validate` pre-flight — binary contract test (SDD-002).
//!
//! The flag must load + validate a NAMED config and exit without starting
//! the daemon: exit 0 + `OK:` for a valid file, exit 1 + `INVALID:` for a
//! bad value or a missing file. Spawns the real built binary via the
//! cargo-provided `CARGO_BIN_EXE_selfdefd` path — no daemon side-effects
//! run because `--validate` returns before any listener/probe.

use std::io::Write;
use std::process::Command;

use tempfile::NamedTempFile;

fn selfdefd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_selfdefd"))
}

#[test]
fn validate_accepts_a_valid_config() {
    // An empty TOML file is a valid config: it parses and every field
    // falls back to its (valid) default, so validate() passes.
    let f = NamedTempFile::new().unwrap();
    let out = selfdefd()
        .arg("--config")
        .arg(f.path())
        .arg("--validate")
        .output()
        .expect("spawn selfdefd");
    assert!(out.status.success(), "expected exit 0, got {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK:"), "stdout was: {stdout}");
}

#[test]
fn validate_rejects_an_invalid_value() {
    // An out-of-vocabulary collector read_from is rejected by the semantic
    // fail-fast rule — the flag must surface that, not silently pass.
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "[collectors.auditd]\nenabled = true\nread_from = \"begining\"").unwrap();
    let out = selfdefd()
        .arg("--config")
        .arg(f.path())
        .arg("--validate")
        .output()
        .expect("spawn selfdefd");
    assert_eq!(out.status.code(), Some(1), "expected exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("INVALID:"), "stderr was: {stderr}");
    assert!(stderr.contains("read_from"), "stderr was: {stderr}");
}

#[test]
fn validate_rejects_a_missing_file() {
    // A NAMED file that does not exist is a failure for a pre-flight, even
    // though the daemon's normal boot would fall back to defaults.
    let out = selfdefd()
        .arg("--config")
        .arg("/nonexistent/selfdef-does-not-exist.toml")
        .arg("--validate")
        .output()
        .expect("spawn selfdefd");
    assert_eq!(out.status.code(), Some(1), "expected exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("config file not found"), "stderr was: {stderr}");
}
