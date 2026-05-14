//! Smoke-tests for the `bridge-l2` module's install scripts.
//!
//! Runs `apply.sh` in `SELFDEF_DRY_RUN=1` mode against a synthetic
//! config and verifies the structured-status contract from
//! `docs/src/modules.md`. We can't actually create a bridge in CI, but
//! every state-changing call goes through `run "<desc>" -- <cmd...>`
//! which the dry-run path short-circuits — so the entire decision
//! tree is exercised.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// F-2027-049 / -050 / -051: helpers live in common/mod.rs.
mod common;
use common::{last_stdout_line, prepended_path};

fn module_dir() -> PathBuf {
    common::module_dir("bridge-l2")
}

fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write");
    f
}

/// Build a directory that supplies stub `ip` and `nft` binaries so the
/// script's `command -v` preflight passes on test hosts that don't have
/// iproute2/nftables installed. In `SELFDEF_DRY_RUN=1` mode the stubs
/// are never actually executed — the script only checks they exist.
fn stub_path_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in &["ip", "nft"] {
        let path = dir.path().join(name);
        std::fs::write(&path, "#!/usr/bin/env bash\nexit 0\n").expect("write stub");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod stub");
    }
    dir
}

fn run_apply(cfg_path: &std::path::Path, path_dir: &Path) -> std::process::Output {
    let module = module_dir();
    Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_BRIDGE_L2_CONFIG", cfg_path)
        .env("SELFDEF_BRIDGE_L2_TEMPLATES", module.join("templates"))
        .env("PATH", prepended_path(path_dir))
        .output()
        .expect("spawn apply.sh")
}

#[test]
fn apply_succeeds_in_dry_run_with_valid_config() {
    let cfg = write_config(
        r#"
bridge_name      = "br0"
members          = ["eth0", "eth1"]
management_iface = ""
forward_policy   = "accept"
persist          = "boot-script"
"#,
    );
    let stubs = stub_path_dir();
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"module\":\"bridge-l2\"") && line.contains("\"status\":\"ok\""),
        "unexpected status line: {line}"
    );
}

#[test]
fn apply_fails_when_members_is_empty() {
    let cfg = write_config(
        r#"
bridge_name    = "br0"
members        = []
forward_policy = "accept"
"#,
    );
    let stubs = stub_path_dir();
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should have failed");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("members list is empty"),
        "unexpected status line: {line}"
    );
}

#[test]
fn apply_fails_on_invalid_forward_policy() {
    let cfg = write_config(
        r#"
bridge_name    = "br0"
members        = ["eth0"]
forward_policy = "banana"
"#,
    );
    let stubs = stub_path_dir();
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(
        line.contains("forward_policy must be accept|drop"),
        "got: {line}"
    );
}

#[test]
fn check_fails_when_bridge_not_present() {
    // Use a bridge name that almost certainly does not exist on the
    // runner. `check.sh` does *not* honour dry-run — it inspects real
    // host state, and should report missing-bridge cleanly.
    let cfg = write_config(
        r#"
bridge_name = "selfdef_test_nope_99"
members     = ["eth0"]
"#,
    );
    let stubs = stub_path_dir();
    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/check.sh"))
        .env("SELFDEF_BRIDGE_L2_CONFIG", cfg.path())
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn check.sh");
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should have exited non-zero");
    assert!(
        line.contains("\"status\":\"failed\""),
        "unexpected status: {line}"
    );
}

/// SDD-005 D-2a / Test-1: dry-run must be a no-op on disk.
/// bridge-l2's apply hard-codes its nftables output path at
/// `/etc/nftables.d/selfdef-bridge.conf`, so we can't fully
/// assert system-wide; but the test scope (the tempdir holding
/// the config) must stay byte-stable across a dry-run apply —
/// catching regressions that write diagnostic files alongside
/// the config or to the script's working directory.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg_path = scratch.path().join("bridge-l2.toml");
    std::fs::write(
        &cfg_path,
        r#"
bridge_name      = "br0"
members          = ["eth0", "eth1"]
management_iface = ""
forward_policy   = "accept"
persist          = "boot-script"
"#,
    )
    .unwrap();

    let before = common::snapshot_tree(scratch.path());
    let out = run_apply(&cfg_path, stubs.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(scratch.path());
    common::assert_tree_unchanged(&before, &after);
}
