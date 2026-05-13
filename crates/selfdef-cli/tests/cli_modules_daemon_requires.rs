//! Integration tests for SDD-002 `[daemon_requires]` (closes
//! F-2026-004 / -018 / -020). Hermetic: each test builds a tiny
//! catalog with a manifest carrying `[daemon_requires]`, plus a
//! host config that activates it, plus a stub daemon
//! `selfdef.toml` that either satisfies the requirement or
//! doesn't, then runs `selfdefctl modules apply --dry-run` and
//! asserts the outcome.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_executable(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Stages a one-module catalog whose manifest carries
/// `[daemon_requires]` plus a host config activating it.
struct Fixture {
    _root: tempfile::TempDir,
    catalog: std::path::PathBuf,
    host_config: std::path::PathBuf,
    module_config: std::path::PathBuf,
    daemon_config: std::path::PathBuf,
}

fn build_fixture(daemon_config_body: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    let modroot = catalog.join("widget");
    std::fs::create_dir_all(&modroot).unwrap();

    let manifest = r#"
name = "widget"
version = "0.0.0"
summary = "test"
category = "test"

[install]
kind = "script"
apply = "install/apply.sh"

[daemon_requires]
"collectors.widget.enabled" = true
"collectors.widget.input_path" = "${widget_log_path}"
"#;
    std::fs::write(modroot.join("module.toml"), manifest).unwrap();

    let apply_body = "#!/usr/bin/env bash\necho '{\"module\":\"widget\",\"status\":\"ok\",\"message\":\"applied\"}'\n";
    write_executable(&modroot.join("install/apply.sh"), apply_body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.widget]\n").unwrap();

    let module_config = root.path().join("widget.toml");
    std::fs::write(
        &module_config,
        "widget_log_path = \"/var/log/widget/events.json\"\n",
    )
    .unwrap();

    let daemon_config = root.path().join("selfdef.toml");
    std::fs::write(&daemon_config, daemon_config_body).unwrap();

    // selfdefctl's resolver picks the per-module config via
    // `--host-config` + the conventional default path; for this
    // hermetic test we point the module's host entry at the
    // module_config explicitly:
    std::fs::write(
        &host_config,
        format!(
            "[modules.widget]\nconfig = \"{}\"\n",
            module_config.display(),
        ),
    )
    .unwrap();

    let root_path = root.path().to_path_buf();
    let _ = root_path;
    Fixture {
        _root: root,
        catalog,
        host_config,
        module_config,
        daemon_config,
    }
}

fn run_apply(fx: &Fixture, extra_args: &[&str]) -> std::process::Output {
    let daemon_cfg = fx.daemon_config.to_str().unwrap().to_string();
    let mut args = vec![
        "--config".to_string(),
        daemon_cfg,
        "modules".to_string(),
        "apply".to_string(),
        "--host-config".to_string(),
        fx.host_config.to_str().unwrap().to_string(),
        "--dir".to_string(),
        fx.catalog.to_str().unwrap().to_string(),
        "--dry-run".to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));
    Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn apply_refuses_when_daemon_requires_missing() {
    // Empty daemon config — every requirement is unmet.
    let fx = build_fixture("");
    let out = run_apply(&fx, &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 on unmet requires"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not satisfy every active module's [daemon_requires]"),
        "stderr: {stderr}",
    );
    assert!(
        stderr.contains("collectors.widget.enabled = true"),
        "stderr should include the missing key + value:\n{stderr}",
    );
    assert!(
        stderr.contains("collectors.widget.input_path = \"/var/log/widget/events.json\""),
        "stderr should include the expanded substitution:\n{stderr}",
    );
    let _ = &fx.module_config;
}

#[test]
fn apply_succeeds_when_daemon_requires_satisfied() {
    let fx = build_fixture(
        "[collectors.widget]\nenabled = true\ninput_path = \"/var/log/widget/events.json\"\n",
    );
    let out = run_apply(&fx, &[]);
    assert!(
        out.status.success(),
        "expected success when requires satisfied; stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
}

#[test]
fn apply_bypasses_check_with_ignore_flag() {
    let fx = build_fixture(""); // empty daemon config
    let out = run_apply(&fx, &["--ignore-daemon-requires"]);
    assert!(
        out.status.success(),
        "expected success with --ignore-daemon-requires; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn show_requires_prints_expanded_snippet() {
    let fx = build_fixture("");
    let out = Command::new(binary())
        .args([
            "--config",
            fx.daemon_config.to_str().unwrap(),
            "modules",
            "show-requires",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
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
        stdout.contains("# ── widget ──"),
        "show-requires should print a per-module header:\n{stdout}",
    );
    assert!(
        stdout.contains("collectors.widget.enabled = true"),
        "stdout: {stdout}",
    );
    assert!(
        stdout.contains("collectors.widget.input_path = \"/var/log/widget/events.json\""),
        "substitution should be expanded in show-requires output:\n{stdout}",
    );
}
