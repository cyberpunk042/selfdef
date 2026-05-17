//! SD-R76 (SDD-024 X-5) — `selfdefctl modules apply --reprobe-hardware`
//! safety knob. Forces a fresh hardware probe before the
//! `[requires_hardware]` gate evaluates, surfacing a visible stderr
//! "[SD-R76] forcing fresh hardware probe" line so operators get
//! end-to-end confirmation that the reprobe happened.
//!
//! The selfdef-hardware probe() call is already fresh per-invocation
//! in cycle 5; the flag is wired so a future round that introduces
//! daemon-emitted capability caching can short-circuit reading the
//! cache when the flag is set, without changing the operator CLI.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Stage a minimal one-module registry with no [requires_hardware]
/// block — apply on a CI runner without a real selfdef config still
/// completes cleanly and lets us observe the SD-R76 stderr banner.
fn stage_no_gate_module(dir: &std::path::Path) {
    let slug = "no-gate-module";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "no-gate-module"
version     = "0.1.0"
summary     = "no-gate demo for SD-R76 reprobe stderr smoke test"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
"#,
    )
    .unwrap();
    let apply = sub.join("install/apply.sh");
    std::fs::write(
        &apply,
        "#!/usr/bin/env bash\nprintf '{\"module\":\"no-gate-module\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&apply).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&apply, perms).unwrap();
    }
    // check.sh + uninstall.sh skeletons (not exercised here but
    // make the module strictly conformant per SD-R23).
    for s in ["check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\nprintf '{\"module\":\"no-gate-module\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

/// Stage a module WITH a [requires_hardware] block so apply will
/// invoke the gate path even on a CI runner that doesn't satisfy it.
/// Gate evaluates against probe() output; we don't need the gate to
/// PASS — we just need it to RUN so the SD-R76 stderr line fires.
fn stage_gated_module(dir: &std::path::Path) {
    let slug = "gated-module";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "gated-module"
version     = "0.1.0"
summary     = "gated demo for SD-R76 reprobe gate path"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[requires_hardware]
host_features_required = "absolutely-no-such-flag"
[install]
kind = "script"
"#,
    )
    .unwrap();
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\nprintf '{\"module\":\"gated-module\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

fn write_host_config(dir: &std::path::Path, slugs: &[&str]) -> PathBuf {
    let host_config = dir.join("modules.toml");
    let body: String = slugs.iter().map(|s| format!("[modules.{s}]\n")).collect();
    std::fs::write(&host_config, body).unwrap();
    host_config
}

#[test]
fn sdr76_apply_with_reprobe_emits_visible_stderr_banner() {
    let dir = tempfile::tempdir().unwrap();
    stage_gated_module(dir.path());
    let host_config = write_host_config(dir.path(), &["gated-module"]);

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "apply",
            "--dir",
            dir.path().to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--reprobe-hardware",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SD-R76") && stderr.contains("forcing fresh hardware probe"),
        "expected SD-R76 reprobe banner on stderr, got: {stderr}"
    );
}

#[test]
fn sdr76_apply_without_reprobe_does_not_emit_banner() {
    let dir = tempfile::tempdir().unwrap();
    stage_gated_module(dir.path());
    let host_config = write_host_config(dir.path(), &["gated-module"]);

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "apply",
            "--dir",
            dir.path().to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("SD-R76"),
        "expected NO SD-R76 banner without --reprobe-hardware, got: {stderr}"
    );
}

#[test]
fn sdr76_apply_help_documents_reprobe_flag() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "apply", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--reprobe-hardware"),
        "help must document --reprobe-hardware flag: {stdout}"
    );
    assert!(
        stdout.contains("SD-R76") || stdout.contains("FRESH hardware probe"),
        "help must explain what --reprobe-hardware does: {stdout}"
    );
}

#[test]
fn sdr76_no_gate_module_apply_skips_gate_entirely() {
    // When no module in the catalog has [requires_hardware], the
    // gate path isn't invoked AT ALL — --reprobe-hardware should
    // STILL log the banner (operator asked, we confirm we tried),
    // OR it should be quiet. Current implementation: the banner
    // fires only when the gate code path runs (any active module
    // has [requires_hardware]). Pin that contract.
    let dir = tempfile::tempdir().unwrap();
    stage_no_gate_module(dir.path());
    let host_config = write_host_config(dir.path(), &["no-gate-module"]);

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "apply",
            "--dir",
            dir.path().to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--reprobe-hardware",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // No gate ran → no SD-R76 banner. Operator-visible behavior is
    // pinned at the contract level so future caching work doesn't
    // change it silently.
    assert!(
        !stderr.contains("SD-R76"),
        "expected NO SD-R76 banner when no gated module is active: {stderr}"
    );
}
