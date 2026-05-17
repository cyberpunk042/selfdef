//! SD-R83 (SDD-026 Z-13 partial) — `selfdefctl modules diff`.
//! Partition catalog × host-config join into installed / available /
//! orphaned buckets. Operator-facing discovery surface (the CLI
//! counterpart to the future Z-1 dashboard's "Browse available" tab).

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_module(dir: &std::path::Path, slug: &str) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        format!(
            r#"
name        = "{slug}"
version     = "0.0.1"
summary     = "diff demo"
category    = "detection"
depends_on  = []
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

#[test]
fn sdr83_modules_diff_partitions_installed_available_orphaned() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "in-both-A");
    write_module(&catalog, "in-both-B");
    write_module(&catalog, "catalog-only");
    let host_config = dir.path().join("modules.toml");
    std::fs::write(
        &host_config,
        "[modules.in-both-A]\n[modules.in-both-B]\n[modules.host-only-orphan]\n",
    )
    .unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "diff",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Header references SD-R83
    assert!(
        stdout.contains("SD-R83 selfdefctl modules diff"),
        "{stdout}"
    );
    // INSTALLED block — both in-both modules
    assert!(stdout.contains("installed (2)"), "{stdout}");
    assert!(stdout.contains("✓ in-both-A"), "{stdout}");
    assert!(stdout.contains("✓ in-both-B"), "{stdout}");
    // AVAILABLE — catalog-only
    assert!(stdout.contains("available (1)"), "{stdout}");
    assert!(stdout.contains("+ catalog-only"), "{stdout}");
    // ORPHANED — host-only-orphan
    assert!(stdout.contains("orphaned (1)"), "{stdout}");
    assert!(stdout.contains("? host-only-orphan"), "{stdout}");
    // Operator-actionable hint when orphans present
    assert!(
        stdout.contains("restore the missing manifest"),
        "expected actionable orphan hint: {stdout}"
    );
}

#[test]
fn sdr83_modules_diff_empty_state_when_all_installed_and_none_orphaned() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "single");
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.single]\n").unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "diff",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("installed (1)"), "{stdout}");
    assert!(stdout.contains("✓ single"), "{stdout}");
    assert!(stdout.contains("available (0)"), "{stdout}");
    assert!(
        stdout.contains("every catalog module is activated"),
        "{stdout}"
    );
    assert!(stdout.contains("orphaned (0)"), "{stdout}");
}

#[test]
fn sdr83_modules_diff_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "shared");
    write_module(&catalog, "available-one");
    let host_config = dir.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.shared]\n[modules.orphan]\n").unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "diff",
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
    assert_eq!(v["schema_version"], "1.0.0");
    let installed: Vec<&str> = v["installed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    let available: Vec<&str> = v["available"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    let orphaned: Vec<&str> = v["orphaned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(installed, vec!["shared"]);
    assert_eq!(available, vec!["available-one"]);
    assert_eq!(orphaned, vec!["orphan"]);
    assert_eq!(v["counts"]["installed"], 1);
    assert_eq!(v["counts"]["available"], 1);
    assert_eq!(v["counts"]["orphaned"], 1);
}

#[test]
fn sdr83_modules_diff_handles_instance_suffix_in_host_keys() {
    // host_config can carry `slug#instance` for instanced modules
    // (per SD-R23). The diff must collapse the instance suffix back
    // to the base slug when joining against the catalog.
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(&catalog, "tunnel");
    let host_config = dir.path().join("modules.toml");
    // TOML dotted-key under the [modules] table — needs the
    // instance suffix quoted because `#` would otherwise be a comment.
    std::fs::write(
        &host_config,
        "[modules.\"tunnel#wg0\"]\n[modules.\"tunnel#wg1\"]\n",
    )
    .unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "diff",
            "--dir",
            catalog.to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Both wg0 + wg1 collapse to base slug `tunnel` → installed
    assert!(stdout.contains("installed (1)"), "{stdout}");
    assert!(stdout.contains("✓ tunnel"), "{stdout}");
    assert!(stdout.contains("orphaned (0)"), "{stdout}");
}

#[test]
fn sdr83_modules_diff_help_documents_verb() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["modules", "diff", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--host-config"), "{stdout}");
    assert!(stdout.contains("--dir"), "{stdout}");
    assert!(stdout.contains("--json"), "{stdout}");
    assert!(
        stdout.contains("SD-R83") || stdout.contains("orphaned"),
        "help must explain diff semantics: {stdout}"
    );
}
