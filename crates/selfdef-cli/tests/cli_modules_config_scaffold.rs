//! SD-R88 (SDD-026 Z-13 follow-up) — `selfdefctl modules config-scaffold`.
//! Emit a copy-pasteable `[modules."<slug>"]` block + matching
//! `[daemon.*]` keys from the module manifest, so the operator can
//! `configure them` (operator-verbatim quote from the 2026-05-17
//! dashboard expansion).

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_module(dir: &std::path::Path, slug: &str, body: &str) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(sub.join("module.toml"), body).unwrap();
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
fn sdr88_config_scaffold_basic_module_emits_modules_block() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "alpha",
        r#"
name        = "alpha"
version     = "0.0.1"
summary     = "no daemon requires"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
"#,
    );
    let (rc, stdout, _) = run(&[
        "modules",
        "config-scaffold",
        "alpha",
        "--dir",
        catalog.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("SD-R88 selfdefctl modules config-scaffold"));
    assert!(stdout.contains("[modules.\"alpha\"]"), "{stdout}");
    assert!(
        stdout.contains("selfdefctl modules apply --only alpha"),
        "{stdout}"
    );
}

#[test]
fn sdr88_config_scaffold_renders_daemon_requires_block() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "with-daemon",
        r#"
name        = "with-daemon"
version     = "0.1.0"
summary     = "needs daemon config"
category    = "telemetry"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
[daemon_requires]
"collectors.tetragon.enabled" = true
"collectors.eventstream.paths" = ["/var/log/a", "/var/log/b"]
"router.batch_size" = 64
"#,
    );
    let (rc, stdout, _) = run(&[
        "modules",
        "config-scaffold",
        "with-daemon",
        "--dir",
        catalog.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R88");
    assert_eq!(v["slug"], "with-daemon");
    assert_eq!(v["has_daemon_requires"], true);
    let daemon_toml = v["daemon_toml"].as_str().unwrap();
    assert!(
        daemon_toml.contains("[collectors.tetragon]"),
        "{daemon_toml}"
    );
    assert!(daemon_toml.contains("enabled = true"), "{daemon_toml}");
    assert!(
        daemon_toml.contains("[collectors.eventstream]"),
        "{daemon_toml}"
    );
    assert!(
        daemon_toml.contains("paths = [\"/var/log/a\", \"/var/log/b\"]"),
        "{daemon_toml}"
    );
    assert!(daemon_toml.contains("[router]"), "{daemon_toml}");
    assert!(daemon_toml.contains("batch_size = 64"), "{daemon_toml}");
}

#[test]
fn sdr88_config_scaffold_instanced_module_requires_instance_flag() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "tunnel",
        r#"
name        = "tunnel"
version     = "0.0.1"
summary     = "wg tunnel"
category    = "network"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
instanced   = true
[install]
kind = "script"
"#,
    );

    // Without --instance: rc=2.
    let (rc, _stdout, stderr) = run(&[
        "modules",
        "config-scaffold",
        "tunnel",
        "--dir",
        catalog.to_str().unwrap(),
    ]);
    assert_eq!(rc, 2);
    assert!(stderr.contains("instanced"), "{stderr}");

    // With --instance wg0: rc=0 + the host key carries the suffix.
    let (rc, stdout, _) = run(&[
        "modules",
        "config-scaffold",
        "tunnel",
        "--dir",
        catalog.to_str().unwrap(),
        "--instance",
        "wg0",
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["host_key"], "tunnel#wg0");
    let modules_toml = v["modules_toml"].as_str().unwrap();
    assert!(
        modules_toml.contains("[modules.\"tunnel#wg0\"]"),
        "{modules_toml}"
    );
}

#[test]
fn sdr88_config_scaffold_depends_on_surfaces_as_comment() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "needs-base",
        r#"
name        = "needs-base"
version     = "0.0.1"
summary     = "has deps + provides"
category    = "detection"
depends_on  = ["base-mod", "telemetry-mod"]
provides    = ["enriched-events"]
consumes    = []
phase       = "main"
[install]
kind = "script"
"#,
    );
    let (rc, stdout, _) = run(&[
        "modules",
        "config-scaffold",
        "needs-base",
        "--dir",
        catalog.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("depends_on: base-mod, telemetry-mod"),
        "{stdout}"
    );
    assert!(stdout.contains("provides: enriched-events"), "{stdout}");
}

#[test]
fn sdr88_config_scaffold_unknown_slug_rc2() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    write_module(
        &catalog,
        "alpha",
        r#"
name        = "alpha"
version     = "0.0.1"
summary     = ""
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"
[install]
kind = "script"
"#,
    );
    let (rc, _stdout, stderr) = run(&[
        "modules",
        "config-scaffold",
        "nope",
        "--dir",
        catalog.to_str().unwrap(),
    ]);
    assert_eq!(rc, 2);
    assert!(stderr.contains("unknown module slug"), "{stderr}");
    assert!(stderr.contains("first 10 known"), "{stderr}");
}
