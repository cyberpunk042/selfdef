//! SD-R93 (SDD-026 Z-13 execution) — `selfdefctl modules apply-plan`.
//! End-to-end installer: walks the SD-R87 install-plan, invokes
//! `apply --only <slug>` per step, reports per-step outcome.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_module(dir: &std::path::Path, slug: &str, depends_on: &[&str]) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    let deps_line = if depends_on.is_empty() {
        String::from("depends_on  = []")
    } else {
        let q: Vec<String> = depends_on.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on  = [{}]", q.join(","))
    };
    std::fs::write(
        sub.join("module.toml"),
        format!(
            r#"
name        = "{slug}"
version     = "0.0.1"
summary     = "plan demo {slug}"
category    = "detection"
{deps_line}
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
"#
        ),
    )
    .unwrap();
    let apply = sub.join("install/apply.sh");
    std::fs::write(&apply, "#!/usr/bin/env bash\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&apply).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&apply, perms).unwrap();
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(args)
        .output()
        .expect("spawn selfdefctl");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn sdr93_apply_plan_dry_run_emits_step_per_module_with_command() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "alpha", &[]);
    write_module(&catalog, "beta", &["alpha"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run(&[
        "modules",
        "apply-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R93");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["plan_steps"], 2);
    assert_eq!(v["applied_count"], 0);
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let slugs: Vec<&str> = results
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["alpha", "beta"]);
    for r in results {
        assert_eq!(r["outcome"], "dry-run");
        let cmd = r["command"].as_str().unwrap();
        assert!(cmd.starts_with("selfdefctl modules apply --only "), "{cmd}");
    }
}

#[test]
fn sdr93_apply_plan_cycle_detection_returns_rc1() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "x", &["y"]);
    write_module(&catalog, "y", &["x"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run(&[
        "modules",
        "apply-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "cycle-detected");
}

#[test]
fn sdr93_apply_plan_empty_when_nothing_ready() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "only-one", &[]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.only-one]\n").unwrap();

    let (rc, stdout, _) = run(&[
        "modules",
        "apply-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["plan_steps"], 0);
    assert_eq!(v["results"].as_array().unwrap().len(), 0);
}

#[test]
fn sdr93_apply_plan_category_filter_passes_through_to_plan_generation() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    // Use the write_module helper for category=detection, and an
    // inline write for telemetry.
    write_module(&catalog, "det-1", &[]);
    let sub = catalog.join("tel-1");
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "tel-1"
version     = "0.0.1"
summary     = "telemetry"
category    = "telemetry"
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
    std::fs::write(&apply, "#!/usr/bin/env bash\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&apply).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&apply, perms).unwrap();
    }
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run(&[
        "modules",
        "apply-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--category",
        "detection",
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let slugs: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["det-1"]);
}

#[test]
fn sdr93_apply_plan_human_render_marks_steps() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "alpha", &[]);
    write_module(&catalog, "beta", &["alpha"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run(&[
        "modules",
        "apply-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("SD-R93 selfdefctl modules apply-plan"));
    assert!(stdout.contains("DRY-RUN"), "{stdout}");
    assert!(stdout.contains("1. alpha"), "{stdout}");
    assert!(stdout.contains("2. beta"), "{stdout}");
}

#[test]
fn sdr93_apply_plan_help_documents_flags() {
    let (_, stdout, _) = run(&["modules", "apply-plan", "--help"]);
    assert!(stdout.contains("--apply"), "{stdout}");
    assert!(stdout.contains("--continue-on-failure"), "{stdout}");
    assert!(stdout.contains("--category"), "{stdout}");
}
