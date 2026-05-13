//! Smoke-tests for the `vpn-bridge` module's install scripts.
//!
//! Same shape as the other module tests: stub the binaries the
//! preflight checks for, run with SELFDEF_DRY_RUN=1, assert on the
//! final structured-status JSON line.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn module_dir() -> PathBuf {
    workspace_root().join("modules/vpn-bridge")
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

/// Default stubs: every required binary succeeds; systemctl reports
/// service inactive/disabled so the apply path exercises start +
/// enable. `ip` is also stubbed because check.sh uses it.
fn stub_path_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_stub(dir.path(), "wg", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(dir.path(), "wg-quick", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(dir.path(), "ip", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(dir.path(), "nft", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(
        dir.path(),
        "systemctl",
        "#!/usr/bin/env bash\ncase \"$1\" in is-active|is-enabled) exit 3 ;; *) exit 0 ;; esac\n",
    );
    dir
}

fn prepended_path(extra: &Path) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut out = std::ffi::OsString::from(extra);
    out.push(":");
    out.push(&existing);
    out
}

fn make_wg_conf(dir: &Path, iface: &str) {
    std::fs::write(dir.join(format!("{iface}.conf")), "# placeholder\n").expect("wg.conf");
}

fn run_apply(cfg: &Path, path_dir: &Path, wg_dir: &Path, nft_dest: &Path) -> std::process::Output {
    let module = module_dir();
    Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg)
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("SELFDEF_VPN_BRIDGE_NFT_PATH", nft_dest)
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", wg_dir)
        .env("PATH", prepended_path(path_dir))
        .output()
        .expect("spawn apply.sh")
}

fn last_stdout_line(out: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().last().unwrap_or("").trim().to_string()
}

#[test]
fn endpoint_apply_succeeds_in_dry_run() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    make_wg_conf(&wg_dir, "wg0");

    let cfg = write_config(
        r#"
profile        = "relay-via-server"
role           = "endpoint"
interface      = "wg0"
listen_port    = 51820
forward_to_lan = ""
"#,
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &wg_dir,
        &scratch.path().join("nft.conf"),
    );
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

mod common;

/// SDD-005 D-2a / Test-1: dry-run must be a no-op. The
/// endpoint apply above asserts the live-positive path
/// succeeds; this negative asserts the dry-run path mutates
/// nothing on disk. Pre-SDD-005, a regression making dry-run
/// write the nft.conf file (or the wg-quick unit, etc.) would
/// have passed silently — the existing test only checked the
/// status JSON.
#[test]
fn endpoint_dry_run_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    make_wg_conf(&wg_dir, "wg0");

    let cfg_body = r#"
profile        = "relay-via-server"
role           = "relay"
interface      = "wg0"
listen_port    = 51820
forward_to_lan = "br0"
"#;
    common::write_file(&scratch.path().join("vpn-bridge.toml"), cfg_body);
    let cfg = scratch.path().join("vpn-bridge.toml");
    let nft_dest = scratch.path().join("nft.conf");

    let before = common::snapshot_tree(scratch.path());
    let out = run_apply(&cfg, stubs.path(), &wg_dir, &nft_dest);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = common::snapshot_tree(scratch.path());
    common::assert_tree_unchanged(&before, &after);
}

#[test]
fn relay_apply_with_forward_to_lan_succeeds() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    make_wg_conf(&wg_dir, "wg0");

    let cfg = write_config(
        r#"
profile        = "relay-via-server"
role           = "relay"
interface      = "wg0"
listen_port    = 51820
forward_to_lan = "br0"
"#,
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &wg_dir,
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(out.status.success());
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("applied"),
        "got: {line}"
    );
}

#[test]
fn apply_fails_without_wg_quick_config() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    // wg_dir exists but no wg0.conf inside.
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();

    let cfg = write_config(
        "profile = \"relay-via-server\"\nrole = \"endpoint\"\ninterface = \"wg0\"\nforward_to_lan = \"\"\n",
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &wg_dir,
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("wg-quick config missing"),
        "got: {line}"
    );
}

#[test]
fn apply_rejects_invalid_role() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    make_wg_conf(&wg_dir, "wg0");

    let cfg = write_config(
        "profile = \"relay-via-server\"\nrole = \"banana\"\ninterface = \"wg0\"\nforward_to_lan = \"\"\n",
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &wg_dir,
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(line.contains("role must be endpoint|relay"), "got: {line}");
}

#[test]
fn apply_rejects_unsafe_interface_name() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();

    // The script should reject this before checking for the .conf file.
    let cfg = write_config(
        "profile = \"relay-via-server\"\nrole = \"endpoint\"\ninterface = \"wg0; rm -rf /\"\nforward_to_lan = \"\"\n",
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &wg_dir,
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(line.contains("unsafe characters"), "got: {line}");
}

#[test]
fn check_reports_missing_wg_config() {
    let stubs = stub_path_dir();
    let cfg = write_config("interface = \"wg0\"\nforward_to_lan = \"\"\n");
    let scratch = tempfile::tempdir().expect("scratch");
    // wg_dir is empty — check.sh should flag the missing .conf.
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    let module = module_dir();

    let out = Command::new("bash")
        .arg(module.join("install/check.sh"))
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", &wg_dir)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn check.sh");
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "got: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("wg-quick config missing"),
        "got: {line}"
    );
}
