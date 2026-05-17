//! SD-R75 (SDD-024 X-6) — `selfdefctl modules list --category C
//! --phase P` filter flags. Operator-facing UX parallel to the R213
//! sovereign-os `models query` taxonomy filter.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Registry layout: `<dir>/<slug>/module.toml` per SD-R23.
fn write_module(dir: &std::path::Path, slug: &str, body: &str) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(sub.join("module.toml"), body).unwrap();
    // apply.sh exists so the loader doesn't trip on missing files
    // (the test path doesn't exercise apply).
    std::fs::write(
        sub.join("install/apply.sh"),
        "#!/usr/bin/env bash\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = sub.join("install/apply.sh");
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
}

fn stage_three_modules(dir: &std::path::Path) {
    // Phase enum values are pre / main / post per
    // crates/selfdef-cli/src/modules.rs::Phase.
    write_module(
        dir,
        "harden-thing",
        r#"
name        = "harden-thing"
version     = "0.1.0"
summary     = "hardening demo"
category    = "hardening"
depends_on  = []
provides    = []
consumes    = []
phase       = "post"
[install]
kind = "script"
"#,
    );
    write_module(
        dir,
        "inference-thing",
        r#"
name        = "inference-thing"
version     = "0.1.0"
summary     = "inference demo"
category    = "inference"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
"#,
    );
    write_module(
        dir,
        "network-thing",
        r#"
name        = "network-thing"
version     = "0.1.0"
summary     = "network demo"
category    = "network"
depends_on  = []
provides    = []
consumes    = []
phase       = "pre"
[install]
kind = "script"
"#,
    );
}

#[test]
fn sdr75_modules_list_filters_by_category() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "list",
            "--dir",
            dir.path().to_str().unwrap(),
            "--category",
            "hardening",
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
        stdout.contains("harden-thing"),
        "missing harden-thing: {stdout}"
    );
    assert!(
        !stdout.contains("inference-thing"),
        "leaked inference: {stdout}"
    );
    assert!(
        !stdout.contains("network-thing"),
        "leaked network: {stdout}"
    );
}

#[test]
fn sdr75_modules_list_filters_by_phase() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "list",
            "--dir",
            dir.path().to_str().unwrap(),
            "--phase",
            "pre",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("network-thing"),
        "missing network-thing: {stdout}"
    );
    assert!(
        !stdout.contains("harden-thing"),
        "leaked post-phase: {stdout}"
    );
}

#[test]
fn sdr75_modules_list_filters_compose_with_and_semantics() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    // hardening + pre → matches nothing in the fixture (hardening
    // module is post-phase, pre-phase module is network category).
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "list",
            "--dir",
            dir.path().to_str().unwrap(),
            "--category",
            "hardening",
            "--phase",
            "pre",
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no modules match"),
        "expected zero-match marker: {stdout}"
    );
}

#[test]
fn sdr75_modules_list_table_includes_phase_column() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "list", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // R75 added phase as a top-level column.
    assert!(
        stdout.contains("phase"),
        "expected `phase` column in header: {stdout}"
    );
    assert!(
        stdout.contains("main"),
        "expected `main` phase row: {stdout}"
    );
    assert!(
        stdout.contains("post"),
        "expected `post` phase row: {stdout}"
    );
}

#[test]
fn sdr75_modules_list_json_carries_filter_block_and_filters() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "list",
            "--json",
            "--dir",
            dir.path().to_str().unwrap(),
            "--category",
            "inference",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["filter"]["category"], "inference");
    assert!(v["filter"]["phase"].is_null());
    assert_eq!(v["total"], 1);
    assert_eq!(v["modules"][0]["name"], "inference-thing");
}

#[test]
fn sdr75_modules_list_no_filter_returns_all() {
    let dir = tempfile::tempdir().unwrap();
    stage_three_modules(dir.path());
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "list", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for slug in ["harden-thing", "inference-thing", "network-thing"] {
        assert!(
            stdout.contains(slug),
            "missing {slug}: stdout={stdout} stderr={stderr}"
        );
    }
}
