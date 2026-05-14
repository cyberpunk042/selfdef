//! Smoke-tests for the vpn-bridge `tailscale` profile.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// F-2027-049 / -050 / -051: helpers live in common/mod.rs.
mod common;
use common::{last_stdout_line, prepended_path};

fn module_dir() -> PathBuf {
    common::module_dir("vpn-bridge")
}

fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write");
    f
}

fn write_stub(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write stub");
    let mut perms = std::fs::metadata(&p).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).expect("chmod");
}

fn stub_path_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_stub(dir.path(), "tailscale", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(
        dir.path(),
        "systemctl",
        "#!/usr/bin/env bash\ncase \"$1\" in is-active|is-enabled) exit 3 ;; *) exit 0 ;; esac\n",
    );
    dir
}

fn run_apply(cfg: &Path, path_dir: &Path) -> std::process::Output {
    let module = module_dir();
    Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg)
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("PATH", prepended_path(path_dir))
        .output()
        .expect("spawn apply.sh")
}

#[test]
fn tailscale_apply_succeeds_in_dry_run() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let key_path = scratch.path().join("auth.key");
    std::fs::write(&key_path, "tskey-test\n").unwrap();

    let cfg = write_config(&format!(
        r#"
profile          = "tailscale"
auth_key_path    = "{}"
control_url      = ""
hostname         = ""
advertise_routes = ""
accept_routes    = "false"
tags             = ""
"#,
        key_path.display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"module\":\"vpn-bridge\"") && line.contains("\"status\":\"ok\""),
        "got: {line}"
    );
}

#[test]
fn tailscale_apply_fails_without_auth_key_path() {
    let stubs = stub_path_dir();
    let cfg = write_config("profile = \"tailscale\"\nauth_key_path = \"\"\n");
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("auth_key_path is required"),
        "got: {line}"
    );
}

#[test]
fn tailscale_apply_fails_when_key_missing() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config(&format!(
        "profile = \"tailscale\"\nauth_key_path = \"{}/missing\"\n",
        scratch.path().display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "got: {line}");
    assert!(line.contains("auth_key_path not readable"), "got: {line}");
}

#[test]
fn tailscale_apply_rejects_bad_control_url() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let key_path = scratch.path().join("auth.key");
    std::fs::write(&key_path, "tskey-test\n").unwrap();

    let cfg = write_config(&format!(
        "profile = \"tailscale\"\nauth_key_path = \"{}\"\ncontrol_url = \"javascript:alert(1)\"\n",
        key_path.display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "got: {line}");
    assert!(line.contains("control_url must be http"), "got: {line}");
}

#[test]
fn tailscale_apply_accepts_headscale_url() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let key_path = scratch.path().join("auth.key");
    std::fs::write(&key_path, "tskey-test\n").unwrap();

    let cfg = write_config(&format!(
        r#"
profile          = "tailscale"
auth_key_path    = "{}"
control_url      = "https://headscale.example.com"
hostname         = "lab-host"
advertise_routes = "192.168.50.0/24"
accept_routes    = "true"
tags             = "tag:home,tag:lab"
"#,
        key_path.display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(line.contains("\"status\":\"ok\""), "got: {line}");
}

/// F-2027-048: SDD-005 D-2a / Test-1 — dry-run must be a no-op on
/// disk. tailscale's apply shells out to `tailscale up …` plus
/// `systemctl enable --now tailscaled`; dry-run must skip both.
/// The fixture scope catches any rogue write to the operator's
/// scratch dir (e.g. a stray temp file leak from the renderer).
#[test]
fn tailscale_dry_run_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let key_path = scratch.path().join("auth.key");
    std::fs::write(&key_path, "tskey-test\n").unwrap();

    let cfg_path = scratch.path().join("vpn-bridge.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "profile = \"tailscale\"\nauth_key_path = \"{}\"\n",
            key_path.display(),
        ),
    )
    .unwrap();

    let before = common::snapshot_tree(scratch.path());
    let out = run_apply(&cfg_path, stubs.path());
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(scratch.path());
    common::assert_tree_unchanged(&before, &after);
}
