//! Dry-run smoke tests for the `tetragon` module.
//!
//! Hermetic: each test builds a scratch tempdir holding fake
//! tetragon + systemctl binaries on PATH, a host config, and a
//! writable target tree. Then it runs apply.sh / check.sh /
//! uninstall.sh in dry-run mode.
//!
//! The apply path is the interesting one — it renders Tetragon's
//! main config from the lib helper. We assert the render is
//! byte-stable across two consecutive applies (so a no-op re-apply
//! reports "already at desired state" and never restarts the
//! service).

use std::path::PathBuf;
use std::process::{Command, Output};

// F-2027-049 / -050 / -051: workspace_root / module_dir /
// write_executable / prepended_path / last_stdout_line all live
// in `tests/common/mod.rs`. The `mod common;` declaration below
// (was previously late in the file for the dry-run-noop test
// only) is now re-used across the whole test module.
mod common;
use common::{last_stdout_line, prepended_path, write_executable};

fn module_dir() -> PathBuf {
    common::module_dir("tetragon")
}

/// Stub bin dir with `tetragon` (no-op) and `systemctl` (accepts
/// every verb). Suitable for dry-run apply where we never actually
/// expect the binary to be invoked.
fn stub_bin_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_executable(
        &dir.path().join("tetragon"),
        "#!/usr/bin/env bash\nexit 0\n",
    );
    write_executable(
        &dir.path().join("systemctl"),
        "#!/usr/bin/env bash\nexit 0\n",
    );
    dir
}

struct Fixture {
    _root: tempfile::TempDir,
    _bins: tempfile::TempDir,
    config_path: PathBuf,
    config_render_path: PathBuf,
    policy_dir: PathBuf,
    event_log: PathBuf,
    bins: PathBuf,
    /// F-2027-024: per-test override of the shared module-lib's
    /// install-manifest path so parallel tests don't trample
    /// `/var/lib/selfdef/installed/tetragon.manifest`.
    manifest_path: PathBuf,
}

fn fixture() -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();

    let event_log = root.join("tetragon-events.json");
    let policy_dir = root.join("tetragon.tp.d");
    let config_render_path = root.join("tetragon.yaml");

    let host_cfg = root.join("tetragon.toml");
    std::fs::write(
        &host_cfg,
        format!(
            "profile = \"default\"\n\
             event_log_path  = \"{}\"\n\
             policy_dir      = \"{}\"\n\
             metrics_address = \"127.0.0.1:2112\"\n\
             config_path     = \"{}\"\n\
             service_unit    = \"tetragon-test.service\"\n",
            event_log.display(),
            policy_dir.display(),
            config_render_path.display(),
        ),
    )
    .unwrap();

    let bins_holder = stub_bin_dir();
    let bins = bins_holder.path().to_path_buf();

    let manifest_path = root.join("installed.manifest");

    Fixture {
        _root: root_holder,
        _bins: bins_holder,
        config_path: host_cfg,
        config_render_path,
        policy_dir,
        event_log,
        bins,
        manifest_path,
    }
}

fn run_dry_apply(fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn apply.sh")
}

fn run_live_apply(fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn apply.sh")
}

#[test]
fn dry_run_apply_succeeds_and_emits_status() {
    let fx = fixture();
    let out = run_dry_apply(&fx);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"module\":\"tetragon\"") && line.contains("\"status\":\"ok\""),
        "got: {line}",
    );
    // Dry-run must not have actually created anything.
    assert!(!fx.config_render_path.exists());
    assert!(!fx.policy_dir.exists());
}

#[test]
fn live_apply_renders_byte_stable_config_and_reapply_is_noop() {
    let fx = fixture();
    let first = run_live_apply(&fx);
    assert!(first.status.success(), "first apply failed");
    assert!(
        fx.config_render_path.exists(),
        "expected config to be rendered",
    );
    assert!(fx.policy_dir.is_dir(), "policy dir was not created");
    assert!(
        fx.event_log.parent().unwrap().is_dir(),
        "event log dir was not created",
    );

    let rendered_first = std::fs::read(&fx.config_render_path).unwrap();
    // Touch nothing; reapply.
    let second = run_live_apply(&fx);
    assert!(second.status.success(), "reapply failed");
    let rendered_second = std::fs::read(&fx.config_render_path).unwrap();
    assert_eq!(
        rendered_first, rendered_second,
        "config render is not byte-stable",
    );
    let line = last_stdout_line(&second);
    assert!(
        line.contains("already at desired state"),
        "expected no-op re-apply, got: {line}",
    );
}

#[test]
fn rendered_config_contains_operator_values() {
    let fx = fixture();
    run_live_apply(&fx);
    let rendered = std::fs::read_to_string(&fx.config_render_path).unwrap();
    assert!(
        rendered.contains(&format!("export-filename: \"{}\"", fx.event_log.display())),
        "render missing event_log_path:\n{rendered}",
    );
    assert!(
        rendered.contains(&format!(
            "tracing-policy-dir: \"{}\"",
            fx.policy_dir.display()
        )),
        "render missing policy_dir:\n{rendered}",
    );
    assert!(
        rendered.contains("metrics-server: \"127.0.0.1:2112\""),
        "render missing metrics_address:\n{rendered}",
    );
}

#[test]
fn check_fails_before_apply() {
    let fx = fixture();
    let out = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn check.sh");
    assert!(!out.status.success(), "check must fail before apply");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("config not found"),
        "got: {line}",
    );
}

#[test]
fn check_succeeds_after_apply() {
    let fx = fixture();
    run_live_apply(&fx);
    let out = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn check.sh");
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "check should pass: {line}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(line.contains("substrate healthy"), "got: {line}");
}

#[test]
fn uninstall_removes_config_and_empty_policy_dir() {
    let fx = fixture();
    run_live_apply(&fx);
    assert!(fx.config_render_path.exists());
    assert!(fx.policy_dir.is_dir());

    let out = Command::new("bash")
        .arg(module_dir().join("install/uninstall.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success(), "uninstall failed");
    assert!(
        !fx.config_render_path.exists(),
        "config still present after uninstall",
    );
    assert!(
        !fx.policy_dir.exists(),
        "empty policy dir should have been removed",
    );
}

#[test]
fn uninstall_preserves_policy_dir_when_non_empty() {
    let fx = fixture();
    run_live_apply(&fx);
    // Pretend a peer module dropped a policy file in there.
    std::fs::write(fx.policy_dir.join("foreign.yaml"), "x: 1\n").unwrap();

    let out = Command::new("bash")
        .arg(module_dir().join("install/uninstall.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success(), "uninstall failed");
    assert!(
        fx.policy_dir.is_dir(),
        "policy dir must be preserved when non-empty",
    );
    assert!(
        fx.policy_dir.join("foreign.yaml").exists(),
        "foreign policy must not be removed",
    );
}

/// SDD-005 D-2a / Test-1: dry-run must be a no-op on disk.
/// tetragon's apply normally renders the main config + creates
/// the policy directory; dry-run must skip the writes.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let fx = fixture();
    // Snapshot the scratch root that holds the config, policy_dir,
    // and config_render_path. The apply writes into these paths
    // in live mode.
    let scope = fx
        .config_path
        .parent()
        .expect("config_path has parent")
        .to_path_buf();
    let before = common::snapshot_tree(&scope);
    let out = run_dry_apply(&fx);
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(&scope);
    common::assert_tree_unchanged(&before, &after);
    assert!(
        !fx.config_render_path.exists(),
        "dry-run must not write the tetragon.yaml",
    );
}
