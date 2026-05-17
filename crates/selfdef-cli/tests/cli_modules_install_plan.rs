//! SD-R87 (SDD-026 Z-13 closure) — `selfdefctl modules install-plan`.
//! Topologically-ordered install sequence over the SD-R86 READY set
//! with dep-cycle detection.

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

fn run_plan(args: &[&str]) -> (i32, String, String) {
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
fn sdr87_install_plan_topological_order_simple_chain() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    // C depends on B, B depends on A → install order A, B, C.
    write_module(&catalog, "alpha-base", &[]);
    write_module(&catalog, "beta-mid", &["alpha-base"]);
    write_module(&catalog, "gamma-top", &["beta-mid"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0, "stdout: {stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R87");
    assert_eq!(v["cycle_present"], false);
    let steps: Vec<&str> = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["slug"].as_str().unwrap())
        .collect();
    assert_eq!(steps, vec!["alpha-base", "beta-mid", "gamma-top"]);
    // Each step carries an apply command.
    for s in v["steps"].as_array().unwrap() {
        let cmd = s["command"].as_str().unwrap();
        assert!(cmd.starts_with("selfdefctl modules apply --only "), "{cmd}");
    }
}

#[test]
fn sdr87_install_plan_skipped_section_lists_not_ready_modules() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    // ready: alpha. blocked-by-missing-deps: needs-external (depends on slug
    // not in catalog and not in host).
    write_module(&catalog, "alpha", &[]);
    write_module(&catalog, "needs-external", &["never-existed"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let step_slugs: Vec<&str> = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["slug"].as_str().unwrap())
        .collect();
    assert_eq!(step_slugs, vec!["alpha"]);
    let skipped: Vec<&str> = v["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["slug"].as_str().unwrap())
        .collect();
    assert_eq!(skipped, vec!["needs-external"]);
    assert_eq!(v["skipped"][0]["recommendation"], "blocked-by-missing-deps");
}

#[test]
fn sdr87_install_plan_dep_cycle_detected_rc1() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    // Genuine cycle in the AVAILABLE-and-hardware-passing set: a→b→a.
    // Plan-readiness considers these mutually satisfiable (both will
    // be installed by this plan), so both land in the dep graph; Kahn
    // detects the cycle and refuses the plan.
    write_module(&catalog, "node-a", &["node-b"]);
    write_module(&catalog, "node-b", &["node-a"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 1, "stdout: {stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["cycle_present"], true);
    let nodes: Vec<&str> = v["cycle_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(nodes.contains(&"node-a"));
    assert!(nodes.contains(&"node-b"));
}

#[test]
fn sdr87_install_plan_dep_on_missing_slug_lands_in_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    // present depends on a slug NOT in the catalog AND NOT installed.
    write_module(&catalog, "present", &["never-existed"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["steps"].as_array().unwrap().len(), 0);
    let skipped_slugs: Vec<&str> = v["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["slug"].as_str().unwrap())
        .collect();
    assert_eq!(skipped_slugs, vec!["present"]);
    assert_eq!(v["skipped"][0]["recommendation"], "blocked-by-missing-deps");
}

#[test]
fn sdr87_install_plan_filter_by_category() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "det-1", &[]);
    write_module(&catalog, "det-2", &["det-1"]);
    // tel-1 in a different category — change category by writing differently.
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

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
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
    let slugs: Vec<&str> = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["det-1", "det-2"]);
    assert_eq!(v["filter"]["category"], "detection");
}

#[test]
fn sdr87_install_plan_empty_when_everything_installed() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "only-one", &[]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.only-one]\n").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("(no READY modules to install)"), "{stdout}");
}

#[test]
fn sdr87_install_plan_human_render_shows_numbered_commands() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "alpha", &[]);
    write_module(&catalog, "beta", &["alpha"]);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let (rc, stdout, _) = run_plan(&[
        "modules",
        "install-plan",
        "--dir",
        catalog.to_str().unwrap(),
        "--host-config",
        host_config.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("SD-R87 selfdefctl modules install-plan"));
    assert!(stdout.contains("PLAN (2 step(s)"), "{stdout}");
    assert!(
        stdout.contains("selfdefctl modules apply --only alpha"),
        "{stdout}"
    );
    assert!(
        stdout.contains("selfdefctl modules apply --only beta"),
        "{stdout}"
    );
}
