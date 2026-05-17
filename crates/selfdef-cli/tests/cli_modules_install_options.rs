//! SD-R86 (SDD-026 Z-13) — `selfdefctl modules install-options`.
//! Surface uninstalled-but-available catalog modules with operator-
//! actionable recommendations (ready / blocked-by-hardware /
//! blocked-by-missing-deps / needs-review).

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_module(
    dir: &std::path::Path,
    slug: &str,
    category: &str,
    summary: &str,
    depends_on: &[&str],
    requires_hardware: Option<&str>,
) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    let deps_line = if depends_on.is_empty() {
        String::from("depends_on  = []")
    } else {
        let q: Vec<String> = depends_on.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on  = [{}]", q.join(","))
    };
    let hw_block = requires_hardware.unwrap_or("");
    std::fs::write(
        sub.join("module.toml"),
        format!(
            r#"
name        = "{slug}"
version     = "0.0.1"
summary     = "{summary}"
category    = "{category}"
{deps_line}
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
{hw_block}
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

#[test]
fn sdr86_install_options_lists_only_uninstalled_with_ready_recommendation() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "already-installed",
        "detection",
        "skip",
        &[],
        None,
    );
    write_module(&catalog, "ready-A", "detection", "ready alpha", &[], None);
    write_module(&catalog, "ready-B", "telemetry", "ready beta", &[], None);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.already-installed]\n").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "install-options",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R86");
    assert_eq!(v["sdd_vector"], "SDD-026 Z-13");
    assert_eq!(v["counts"]["total"], 2);
    assert_eq!(v["counts"]["ready"], 2);
    assert_eq!(v["counts"]["blocked_by_hardware"], 0);
    assert_eq!(v["counts"]["blocked_by_missing_deps"], 0);

    let slugs: Vec<&str> = v["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert!(slugs.contains(&"ready-A"));
    assert!(slugs.contains(&"ready-B"));
    assert!(!slugs.contains(&"already-installed"));

    for opt in v["options"].as_array().unwrap() {
        assert_eq!(opt["recommendation"], "ready");
        assert_eq!(opt["hardware_gate"]["verdict"], "ungated");
    }
}

#[test]
fn sdr86_install_options_blocked_by_missing_deps() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "needs-base",
        "detection",
        "depends",
        &["base-mod"],
        None,
    );
    write_module(&catalog, "base-mod", "telemetry", "base", &[], None);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "install-options",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let by_slug: std::collections::BTreeMap<&str, &serde_json::Value> = v["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o["slug"].as_str().unwrap(), o))
        .collect();
    assert_eq!(
        by_slug["needs-base"]["recommendation"],
        "blocked-by-missing-deps"
    );
    let deps = by_slug["needs-base"]["depends_on"].as_array().unwrap();
    assert_eq!(deps[0]["slug"], "base-mod");
    assert_eq!(deps[0]["installed"], false);
    assert_eq!(by_slug["base-mod"]["recommendation"], "ready");
    assert_eq!(v["counts"]["ready"], 1);
    assert_eq!(v["counts"]["blocked_by_missing_deps"], 1);
}

#[test]
fn sdr86_install_options_filter_by_category() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "alpha", "detection", "a", &[], None);
    write_module(&catalog, "beta", "telemetry", "b", &[], None);
    write_module(&catalog, "gamma", "detection", "c", &[], None);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "install-options",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--category",
            "detection",
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let slugs: Vec<&str> = v["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["alpha", "gamma"]);
    assert_eq!(v["filter"]["category"], "detection");
}

#[test]
fn sdr86_install_options_only_ready_filter() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "ready", "detection", "r", &[], None);
    write_module(&catalog, "blocked", "detection", "b", &["missing"], None);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "install-options",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
            "--only-ready",
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let slugs: Vec<&str> = v["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["ready"]);
    // Counts reflect the FULL set, not the filtered render.
    assert_eq!(v["counts"]["ready"], 1);
    assert_eq!(v["counts"]["blocked_by_missing_deps"], 1);
}

#[test]
fn sdr86_install_options_human_render_lists_recommendation_glyph() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "alpha", "detection", "alpha summary", &[], None);
    write_module(&catalog, "needs-x", "detection", "needs", &["nope"], None);
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "install-options",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SD-R86 selfdefctl modules install-options"));
    assert!(stdout.contains("✓ alpha"), "{stdout}");
    assert!(stdout.contains("ready=1"), "{stdout}");
    assert!(stdout.contains("blocked-by-deps=1"), "{stdout}");
    assert!(stdout.contains("missing deps: nope"), "{stdout}");
    assert!(stdout.contains("alpha summary"), "{stdout}");
}

#[test]
fn sdr86_install_options_help_documents_verb() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "install-options", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--category"), "{stdout}");
    assert!(stdout.contains("--only-ready"), "{stdout}");
    assert!(stdout.contains("--json"), "{stdout}");
}
