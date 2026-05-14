//! Smoke-tests for the vpn-bridge `cloudflare-tunnel` profile.

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
    write_stub(dir.path(), "cloudflared", "#!/usr/bin/env bash\nexit 0\n");
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
fn cloudflare_token_mode_apply_succeeds() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let token_path = scratch.path().join("token");
    std::fs::write(&token_path, "ey...token...\n").unwrap();

    let cfg = write_config(&format!(
        "profile = \"cloudflare-tunnel\"\ntunnel_token_path = \"{}\"\n",
        token_path.display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("token mode"),
        "got: {line}"
    );
}

#[test]
fn cloudflare_apply_fails_without_either_mode() {
    let stubs = stub_path_dir();
    let cfg = write_config("profile = \"cloudflare-tunnel\"\ntunnel_token_path = \"\"\n");
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("either tunnel_token_path OR"),
        "got: {line}"
    );
}

#[test]
fn cloudflare_apply_fails_when_token_file_missing() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg = write_config(&format!(
        "profile = \"cloudflare-tunnel\"\ntunnel_token_path = \"{}/missing\"\n",
        scratch.path().display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(
        line.contains("tunnel_token_path not readable"),
        "got: {line}"
    );
}

#[test]
fn cloudflare_config_file_mode_apply_succeeds() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let creds = scratch.path().join("creds.json");
    let conf = scratch.path().join("config.yml");
    std::fs::write(&creds, "{}").unwrap();
    std::fs::write(&conf, "tunnel: abc\n").unwrap();

    let cfg = write_config(&format!(
        r#"
profile          = "cloudflare-tunnel"
tunnel_id        = "0123abcd-ef45-6789-abcd-ef0123456789"
credentials_path = "{}"
config_path      = "{}"
"#,
        creds.display(),
        conf.display(),
    ));
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("config-file mode"),
        "got: {line}"
    );
}

/// F-2027-048: SDD-005 D-2a / Test-1 — dry-run must be a no-op on
/// disk. cloudflare-tunnel's apply touches systemd (`tunnel install
/// --service`) and writes credentials.json; dry-run must skip both.
#[test]
fn cloudflare_dry_run_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let token_path = scratch.path().join("token");
    std::fs::write(&token_path, "ey...token...\n").unwrap();

    let cfg_path = scratch.path().join("vpn-bridge.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "profile = \"cloudflare-tunnel\"\ntunnel_token_path = \"{}\"\n",
            token_path.display(),
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
