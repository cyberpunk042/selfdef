//! Smoke-tests for the `polarproxy` module's install scripts.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn module_dir() -> PathBuf {
    workspace_root().join("modules/polarproxy")
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

/// Default stubs: PolarProxy + nft both succeed; systemctl reports
/// service inactive/disabled so apply exercises the start/enable
/// branches. `install` exits 0 (the script uses /usr/bin/install).
fn stub_path_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_stub(dir.path(), "PolarProxy", "#!/usr/bin/env bash\nexit 0\n");
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

fn run_apply(
    cfg: &Path,
    path_dir: &Path,
    unit_dest: &Path,
    nft_dest: &Path,
) -> std::process::Output {
    let module = module_dir();
    Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_POLARPROXY_CONFIG", cfg)
        .env("SELFDEF_POLARPROXY_TEMPLATES", module.join("templates"))
        .env("SELFDEF_POLARPROXY_UNIT_PATH", unit_dest)
        .env("SELFDEF_POLARPROXY_NFT_PATH", nft_dest)
        .env("PATH", prepended_path(path_dir))
        .output()
        .expect("spawn apply.sh")
}

fn last_stdout_line(out: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().last().unwrap_or("").trim().to_string()
}

#[test]
fn host_tls_mitm_apply_succeeds_in_dry_run() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config(
        r#"
profile           = "host-tls-mitm"
listen_port       = 10443
pcap_over_ip_port = 4430
cert_http_port    = 10080
log_dir           = "/var/log/polarproxy"
ca_pfx_path       = "/etc/polarproxy/ca.pfx"
ca_pfx_password   = ""
"#,
    );
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &scratch.path().join("polarproxy.service"),
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"module\":\"polarproxy\"") && line.contains("\"status\":\"ok\""),
        "got: {line}"
    );
}

#[test]
fn bridge_tap_apply_fails_without_bridge_table() {
    // nft stub returns non-zero for `list table` (table absent),
    // succeeds for everything else.
    let dir = tempfile::tempdir().expect("tempdir");
    write_stub(dir.path(), "PolarProxy", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(
        dir.path(),
        "systemctl",
        "#!/usr/bin/env bash\ncase \"$1\" in is-active|is-enabled) exit 3 ;; *) exit 0 ;; esac\n",
    );
    write_stub(
        dir.path(),
        "nft",
        "#!/usr/bin/env bash\nif [[ \"$1\" == \"list\" && \"$2\" == \"table\" ]]; then exit 1; fi\nexit 0\n",
    );

    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config(
        r#"
profile     = "bridge-tap"
listen_port = 10443
bridge_name = "br0"
"#,
    );
    let out = run_apply(
        cfg.path(),
        dir.path(),
        &scratch.path().join("polarproxy.service"),
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should have failed: {line}");
    assert!(
        line.contains("\"status\":\"failed\"")
            && line.contains("bridge-tap profile requires bridge-l2"),
        "got: {line}"
    );
}

#[test]
fn apply_rejects_invalid_profile() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config("profile = \"banana\"\nlisten_port = 10443\n");
    let out = run_apply(
        cfg.path(),
        stubs.path(),
        &scratch.path().join("polarproxy.service"),
        &scratch.path().join("nft.conf"),
    );
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(
        line.contains("profile must be host-tls-mitm|bridge-tap"),
        "got: {line}"
    );
}

#[test]
fn apply_fails_when_polarproxy_binary_missing() {
    // PATH dir without a PolarProxy stub.
    let dir = tempfile::tempdir().expect("tempdir");
    write_stub(dir.path(), "nft", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(dir.path(), "systemctl", "#!/usr/bin/env bash\nexit 0\n");
    // Build an isolated PATH that ONLY contains our stub dir, so even
    // /usr/bin/PolarProxy (which obviously doesn't exist in a sandbox)
    // can't satisfy command -v.
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config("profile = \"host-tls-mitm\"\nlisten_port = 10443\n");

    let module = module_dir();
    // Use an absolute bash path so launching the test doesn't need PATH,
    // then point the script's PATH at our stub dir only — PolarProxy is
    // not in it, so `command -v PolarProxy` fails inside the script.
    let bash = std::env::var("BASH").unwrap_or_else(|_| "/usr/bin/bash".to_string());
    let bash_path = if std::path::Path::new(&bash).exists() {
        bash
    } else {
        "/bin/bash".to_string()
    };
    let out = Command::new(&bash_path)
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_POLARPROXY_CONFIG", cfg.path())
        .env("SELFDEF_POLARPROXY_TEMPLATES", module.join("templates"))
        .env(
            "SELFDEF_POLARPROXY_UNIT_PATH",
            scratch.path().join("polarproxy.service"),
        )
        .env(
            "SELFDEF_POLARPROXY_NFT_PATH",
            scratch.path().join("nft.conf"),
        )
        .env("PATH", dir.path().as_os_str())
        .output()
        .expect("spawn apply.sh");
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(
        line.contains("PolarProxy") && line.contains("missing"),
        "got: {line}"
    );
}

#[test]
fn check_reports_inactive_service() {
    let stubs = stub_path_dir();
    let cfg = write_config("profile = \"host-tls-mitm\"\n");
    let scratch = tempfile::tempdir().expect("scratch");
    // No unit file at the override path → check.sh complains about it
    // plus the inactive service.
    let unit_path = scratch.path().join("nope.service");
    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/check.sh"))
        .env("SELFDEF_POLARPROXY_CONFIG", cfg.path())
        .env("SELFDEF_POLARPROXY_UNIT_PATH", &unit_path)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn check.sh");
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "got: {line}");
    assert!(line.contains("\"status\":\"failed\""), "got: {line}");
    assert!(
        line.contains("systemd unit missing"),
        "expected unit-missing error: {line}"
    );
}

mod common;

/// SDD-005 D-2a / Test-1: dry-run must be a no-op on disk.
/// polarproxy's apply writes the systemd unit + nft rules in
/// host-tls-mitm mode; dry-run must skip the writes.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config(
        r#"
profile           = "host-tls-mitm"
listen_port       = 10443
pcap_over_ip_port = 4430
cert_http_port    = 10080
log_dir           = "/var/log/polarproxy"
ca_pfx_path       = "/etc/polarproxy/ca.pfx"
ca_pfx_password   = ""
"#,
    );
    let unit_dest = scratch.path().join("polarproxy.service");
    let nft_dest = scratch.path().join("polarproxy-nat.conf");

    let before = common::snapshot_tree(scratch.path());
    let out = run_apply(cfg.path(), stubs.path(), &unit_dest, &nft_dest);
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(scratch.path());
    common::assert_tree_unchanged(&before, &after);
    assert!(
        !unit_dest.exists() && !nft_dest.exists(),
        "dry-run must not write the unit or nft files",
    );
}
