//! SDD-003 integration tests for `vpn-bridge` multi-instance
//! honesty (closes F-2026-005). These tests exercise the profile
//! shell scripts directly (with stubbed binaries on PATH) and
//! assert two things:
//!
//!   1. `relay-via-server` parameterises its iface, nft table, and
//!      systemd unit by `$SELFDEF_INSTANCE_ID` — when set, the
//!      apply touches `selfdef-<inst>` not `selfdef0`/`wg0`.
//!
//!   2. The singleton profiles (`tailscale`, `cloudflare-tunnel`)
//!      refuse to run when `SELFDEF_INSTANCE_ID` is set, with a
//!      clear error message pointing at the resolver bypass.

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

/// Stubs every binary the relay-via-server preflight needs.
/// systemctl is-active / is-enabled return non-zero so the apply
/// path exercises start + enable.
fn relay_stub_path() -> tempfile::TempDir {
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

#[test]
fn relay_apply_with_instance_id_uses_per_instance_iface() {
    // SDD-003 D-3 + D-4: when SELFDEF_INSTANCE_ID is set, the
    // relay-via-server profile defaults `iface` to
    // `selfdef-<inst>` and looks for `selfdef-<inst>.conf` in
    // $WG_DIR. The wg-quick service it would touch is
    // `wg-quick@selfdef-<inst>.service`.
    let stubs = relay_stub_path();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    // Stage the per-instance wg.conf — the per-instance default
    // iface is `selfdef-publish`.
    std::fs::write(wg_dir.join("selfdef-publish.conf"), "# placeholder\n").unwrap();

    // No `interface = ` in the config → script must derive the
    // default from $SELFDEF_INSTANCE_ID.
    let cfg = write_config(
        "profile        = \"relay-via-server\"\nrole           = \"endpoint\"\nforward_to_lan = \"\"\n",
    );

    let module = module_dir();
    let nft_dest = scratch.path().join("nft.conf");
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_INSTANCE_ID", "publish")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("SELFDEF_VPN_BRIDGE_NFT_PATH", &nft_dest)
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", &wg_dir)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"ok\""),
        "expected ok status; line: {line}\nstderr: {stderr}",
    );
    // The dry-run trace (on stderr — vpn-bridge logs to stderr)
    // logs "enable wg-quick@selfdef-publish.service" and "start
    // wg-quick@selfdef-publish.service". Assert that the
    // per-instance iface name appears.
    assert!(
        stderr.contains("wg-quick@selfdef-publish.service"),
        "expected per-instance service name; stderr: {stderr}",
    );
    assert!(
        !stderr.contains("wg-quick@wg0.service"),
        "should not touch wg0.service when instance is set; stderr: {stderr}",
    );
}

#[test]
fn relay_apply_without_instance_id_keeps_legacy_wg0_defaults() {
    // Single-instance shape: SELFDEF_INSTANCE_ID is unset, so
    // the default interface remains `wg0` and the default nft
    // table is `selfdef_vpn_bridge`. This locks in backwards
    // compatibility for pre-SDD-003 deployments.
    let stubs = relay_stub_path();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    std::fs::write(wg_dir.join("wg0.conf"), "# placeholder\n").unwrap();

    let cfg = write_config(
        "profile        = \"relay-via-server\"\nrole           = \"endpoint\"\nforward_to_lan = \"\"\n",
    );

    let module = module_dir();
    let nft_dest = scratch.path().join("nft.conf");
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("SELFDEF_VPN_BRIDGE_NFT_PATH", &nft_dest)
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", &wg_dir)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    assert!(
        stderr.contains("wg-quick@wg0.service"),
        "expected legacy wg0 service; stderr: {stderr}",
    );
}

#[test]
fn tailscale_apply_refuses_when_instance_id_is_set() {
    // Defence-in-depth: the resolver should normally refuse
    // `vpn-bridge#<inst>` for the tailscale profile, but if
    // anything ever bypasses the resolver, profile_apply must
    // die before touching any host state.
    let stubs = tempfile::tempdir().expect("tempdir");
    write_stub(stubs.path(), "tailscale", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(stubs.path(), "systemctl", "#!/usr/bin/env bash\nexit 0\n");

    let cfg = write_config(
        "profile       = \"tailscale\"\nauth_key_path = \"/dev/null\"\ncontrol_url   = \"\"\n",
    );

    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_INSTANCE_ID", "extra")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    assert!(
        !out.status.success(),
        "apply should fail; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("singleton-only"),
        "expected singleton refusal; got: {line}",
    );
}

#[test]
fn cloudflare_apply_refuses_when_instance_id_is_set() {
    // Same defence-in-depth check for cloudflare-tunnel.
    let stubs = tempfile::tempdir().expect("tempdir");
    write_stub(stubs.path(), "cloudflared", "#!/usr/bin/env bash\nexit 0\n");
    write_stub(stubs.path(), "systemctl", "#!/usr/bin/env bash\nexit 0\n");

    let scratch = tempfile::tempdir().expect("scratch");
    let token_path = scratch.path().join("token");
    std::fs::write(&token_path, "abc\n").unwrap();

    let cfg = write_config(&format!(
        "profile           = \"cloudflare-tunnel\"\ntunnel_token_path = \"{}\"\n",
        token_path.display(),
    ));

    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_INSTANCE_ID", "extra")
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    assert!(
        !out.status.success(),
        "apply should fail; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("singleton-only"),
        "expected singleton refusal; got: {line}",
    );
}

#[test]
fn cli_resolver_refuses_singleton_profile_with_instance_suffix() {
    // End-to-end CLI test: stage the real vpn-bridge catalog, put
    // a `vpn-bridge#extra` host-config block whose per-instance
    // config selects the tailscale profile, run
    // `selfdefctl modules apply --dry-run`, and assert a non-zero
    // exit with the SDD-003 refusal message — without invoking
    // any apply.sh.
    let bin = env!("CARGO_BIN_EXE_selfdefctl");
    let scratch = tempfile::tempdir().expect("scratch");

    let inst_cfg = scratch.path().join("vpn-bridge.extra.toml");
    std::fs::write(&inst_cfg, "profile = \"tailscale\"\n").unwrap();

    let host_cfg = scratch.path().join("modules.toml");
    std::fs::write(
        &host_cfg,
        format!(
            "[modules.\"vpn-bridge#extra\"]\nconfig = \"{}\"\n",
            inst_cfg.display(),
        ),
    )
    .unwrap();

    let daemon_cfg = scratch.path().join("selfdef.toml");
    std::fs::write(&daemon_cfg, "").unwrap();

    let out = Command::new(bin)
        .args([
            "--config",
            daemon_cfg.to_str().unwrap(),
            "modules",
            "apply",
            "--host-config",
            host_cfg.to_str().unwrap(),
            "--dir",
            common::workspace_root().join("modules").to_str().unwrap(),
            "--ignore-daemon-requires", // SDD-002 — keep this test focused on SDD-003.
            "--dry-run",
        ])
        .output()
        .expect("spawn selfdefctl");

    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("profile `tailscale` does not support"),
        "expected SDD-003 refusal; stderr: {stderr}",
    );
}

#[test]
fn relay_apply_refuses_when_instance_id_exceeds_seven_chars() {
    // SDD-003 Q-C / D-005: the WireGuard interface name 'selfdef-${INST}'
    // must fit Linux's 15-char IFNAMSIZ. 'selfdef-' is 8 chars, so INST
    // caps at 7. An 8-char id ('toolong1' below) overflows; apply must
    // refuse cleanly with an explicit operator-facing error rather than
    // letting 'ip link add' silently truncate or fail downstream.
    let stubs = relay_stub_path();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();

    let cfg = write_config(
        "profile        = \"relay-via-server\"\nrole           = \"endpoint\"\nforward_to_lan = \"\"\n",
    );

    let module = module_dir();
    let nft_dest = scratch.path().join("nft.conf");
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_INSTANCE_ID", "toolong1") // 8 chars — one over
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("SELFDEF_VPN_BRIDGE_NFT_PATH", &nft_dest)
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", &wg_dir)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "apply should fail when instance id > 7 chars; stdout: {stdout}\nstderr: {stderr}",
    );
    // die() emits a JSON {"status":"failed","message":...} to stdout via
    // packaging/lib/module-lib.sh::emit_status; the message field carries
    // the explicit error.
    assert!(
        stdout.contains("SELFDEF_INSTANCE_ID too long"),
        "expected explicit length-error message; stdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("IFNAMSIZ"),
        "error should reference the Linux limit by name; stdout: {stdout}",
    );
}

#[test]
fn relay_apply_accepts_seven_char_instance_id() {
    // Boundary case: 7 chars is the documented max — must succeed.
    let stubs = relay_stub_path();
    let scratch = tempfile::tempdir().expect("scratch");
    let wg_dir = scratch.path().join("wireguard");
    std::fs::create_dir_all(&wg_dir).unwrap();
    // Per-instance wg.conf for the 7-char id.
    std::fs::write(wg_dir.join("selfdef-edgex999.conf"), "# placeholder\n").ok(); // 8-char filename for the 7-char id
    std::fs::write(wg_dir.join("selfdef-edgex77.conf"), "# placeholder\n").unwrap();

    let cfg = write_config(
        "profile        = \"relay-via-server\"\nrole           = \"endpoint\"\nforward_to_lan = \"\"\n",
    );

    let module = module_dir();
    let nft_dest = scratch.path().join("nft.conf");
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_INSTANCE_ID", "edgex77") // exactly 7 chars
        .env("SELFDEF_VPN_BRIDGE_CONFIG", cfg.path())
        .env("SELFDEF_VPN_BRIDGE_TEMPLATES", module.join("templates"))
        .env("SELFDEF_VPN_BRIDGE_NFT_PATH", &nft_dest)
        .env("SELFDEF_VPN_BRIDGE_WG_DIR", &wg_dir)
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "apply should succeed for exactly 7-char instance id; stdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&out.stdout),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"ok\""),
        "expected ok status; line: {line}\nstderr: {stderr}",
    );
}
