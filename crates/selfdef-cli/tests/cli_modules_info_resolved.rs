//! SD-R80 (SDD-025 Y-4) — `selfdefctl modules info <slug> --resolved`
//! renderer. Pure operator-facing surface composing SD-R77 OR
//! predicates with SD-R79 evaluate_resolved branch-index lookup.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Module with two any_of branches: first trivially-empty (passes),
/// second demands an impossible flag (fails). On any host the gate
/// resolves via any_of[0].
fn stage_resolved_demo(dir: &std::path::Path) {
    let slug = "resolved-demo";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "resolved-demo"
version     = "0.1.0"
summary     = "SD-R80 — exercises --resolved renderer over any_of OR-paths"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"

[requires_hardware]
memory_gib_min = 1   # root predicate

[[requires_hardware.any_of]]
# Empty branch — always passes; any_of[0] matches.

[[requires_hardware.any_of]]
host_features_required = "no-such-flag"

[install]
kind = "script"
"#,
    )
    .unwrap();
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\nprintf '{\"module\":\"resolved-demo\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
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

fn stage_hardware_agnostic(dir: &std::path::Path) {
    let slug = "no-hw-demo";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "no-hw-demo"
version     = "0.1.0"
summary     = "SD-R80 — exercises --resolved on hardware-agnostic module"
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
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(&p, "#!/usr/bin/env bash\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

fn stage_root_only(dir: &std::path::Path) {
    let slug = "root-only-demo";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "root-only-demo"
version     = "0.1.0"
summary     = "SD-R80 — root-only gate"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[requires_hardware]
memory_gib_min = 1
[install]
kind = "script"
"#,
    )
    .unwrap();
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(&p, "#!/usr/bin/env bash\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

#[test]
fn sdr80_info_resolved_shows_anyof_branch_match() {
    let dir = tempfile::tempdir().unwrap();
    stage_resolved_demo(dir.path());

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "info",
            "resolved-demo",
            "--dir",
            dir.path().to_str().unwrap(),
            "--resolved",
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("resolved_requirements (SD-R80)"),
        "expected SD-R80 section: {stdout}"
    );
    assert!(
        stdout.contains("root predicates (AND-composed)"),
        "expected root-predicates block: {stdout}"
    );
    assert!(
        stdout.contains("memory_gib_min = 1"),
        "expected root predicate line: {stdout}"
    );
    assert!(
        stdout.contains("any_of: 2 OR-branch(es) declared"),
        "expected any_of count line: {stdout}"
    );
    assert!(
        stdout.contains("resolves on this host via any_of[0]"),
        "expected branch index match: {stdout}"
    );
}

#[test]
fn sdr80_info_resolved_handles_hardware_agnostic_module() {
    let dir = tempfile::tempdir().unwrap();
    stage_hardware_agnostic(dir.path());

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "info",
            "no-hw-demo",
            "--dir",
            dir.path().to_str().unwrap(),
            "--resolved",
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no [requires_hardware] block"),
        "expected agnostic banner: {stdout}"
    );
    assert!(
        stdout.contains("hardware-agnostic"),
        "expected agnostic banner: {stdout}"
    );
}

#[test]
fn sdr80_info_resolved_handles_root_only_module() {
    let dir = tempfile::tempdir().unwrap();
    stage_root_only(dir.path());

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "info",
            "root-only-demo",
            "--dir",
            dir.path().to_str().unwrap(),
            "--resolved",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("root predicates"),
        "expected root-predicates block: {stdout}"
    );
    assert!(
        stdout.contains("any_of: (none declared)"),
        "expected explicit 'none declared' marker: {stdout}"
    );
}

#[test]
fn sdr80_info_help_documents_resolved_flag() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "info", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--resolved"),
        "help must document --resolved flag: {stdout}"
    );
    assert!(
        stdout.contains("SD-R80") || stdout.contains("RESOLVED requirement"),
        "help must explain --resolved: {stdout}"
    );
}
