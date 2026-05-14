//! Smoke-tests for the `suricata` module's install scripts.
//!
//! Same shape as `module_bridge_l2.rs`: stub the binaries the
//! preflight checks for, run in `SELFDEF_DRY_RUN=1` mode, assert the
//! structured-status JSON contract.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// F-2027-049 / -050 / -051: helpers live in common/mod.rs.
mod common;
use common::{last_stdout_line, prepended_path};

fn module_dir() -> PathBuf {
    common::module_dir("suricata")
}

fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(body.as_bytes()).expect("write");
    f
}

/// Path dir with stub binaries that `apply.sh` / `check.sh` look up.
/// `systemctl` is stubbed to always report inactive/disabled so the
/// scripts take the "needs change" branch in apply, and the
/// "service not active" branch in check.
fn stub_path_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let stubs: &[(&str, &str)] = &[
        ("suricata", "#!/usr/bin/env bash\nexit 0\n"),
        ("nft", "#!/usr/bin/env bash\nexit 0\n"),
        // is-active / is-enabled exit non-zero when the service isn't
        // active/enabled. We always return non-zero so the apply path
        // exercises the start/enable branches.
        (
            "systemctl",
            "#!/usr/bin/env bash\ncase \"$1\" in is-active|is-enabled) exit 3 ;; *) exit 0 ;; esac\n",
        ),
    ];
    for (name, body) in stubs {
        let path = dir.path().join(name);
        std::fs::write(&path, body).expect("write stub");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod stub");
    }
    dir
}

fn run_apply(cfg: &Path, path_dir: &Path) -> std::process::Output {
    let module = module_dir();
    Command::new("bash")
        .arg(module.join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_SURICATA_CONFIG", cfg)
        .env("SELFDEF_SURICATA_TEMPLATES", module.join("templates"))
        .env("PATH", prepended_path(path_dir))
        .output()
        .expect("spawn apply.sh")
}

#[test]
fn nfqueue_apply_fails_without_bridge_table() {
    // Stub nft exits 0, so `nft list table inet selfdef_bridge` "succeeds"
    // and the script proceeds. But the stub also makes the "rule already
    // present" check (which greps the output) return no match, so the
    // script tries to install. With our stub `nft -f <file>` succeeds.
    // The whole pipeline should end with status "ok" in dry-run.
    //
    // To get the bridge-table-missing branch, override the nft stub.
    let dir = tempfile::tempdir().expect("tempdir");
    for name in &["suricata", "systemctl"] {
        let p = dir.path().join(name);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\ncase \"$1\" in is-active|is-enabled) exit 3 ;; *) exit 0 ;; esac\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    // nft stub that fails `list table` (table absent), succeeds for everything else.
    let nft = dir.path().join("nft");
    std::fs::write(
        &nft,
        "#!/usr/bin/env bash\nif [[ \"$1\" == \"list\" && \"$2\" == \"table\" ]]; then exit 1; fi\nexit 0\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&nft).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&nft, perms).unwrap();

    let cfg = write_config("mode = \"nfqueue\"\nqueue_num = 0\n");
    let out = run_apply(cfg.path(), dir.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should have failed: {line}");
    assert!(
        line.contains("\"status\":\"failed\"")
            && line.contains("bridge-l2 nftables table not loaded"),
        "got: {line}"
    );
}

#[test]
fn nfqueue_apply_succeeds_in_dry_run() {
    let stubs = stub_path_dir();
    let cfg = write_config("mode = \"nfqueue\"\nqueue_num = 0\n");
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"module\":\"suricata\"") && line.contains("\"status\":\"ok\""),
        "got: {line}"
    );
}

#[test]
fn af_packet_apply_succeeds_without_bridge_table() {
    // AF_PACKET mode should not touch nftables at all (except to clean
    // up a stale NFQUEUE rule, which doesn't exist in this scenario).
    let stubs = stub_path_dir();
    let cfg = write_config("mode = \"af-packet\"\nqueue_num = 0\n");
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(out.status.success());
    assert!(line.contains("\"status\":\"ok\""), "got: {line}");
}

#[test]
fn apply_rejects_invalid_mode() {
    let stubs = stub_path_dir();
    let cfg = write_config("mode = \"banana\"\n");
    let out = run_apply(cfg.path(), stubs.path());
    let line = last_stdout_line(&out);
    assert!(!out.status.success());
    assert!(
        line.contains("mode must be nfqueue|af-packet"),
        "got: {line}"
    );
}

#[test]
fn check_reports_inactive_service() {
    let stubs = stub_path_dir();
    let cfg = write_config("mode = \"nfqueue\"\n");
    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/check.sh"))
        .env("SELFDEF_SURICATA_CONFIG", cfg.path())
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn check.sh");
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "got: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("suricata.service not active"),
        "got: {line}"
    );
}

/// SDD-005 D-2a / Test-1: dry-run must be a no-op on disk.
/// suricata's apply writes the systemd unit + ruleset in
/// nfqueue mode; dry-run must skip the writes.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let stubs = stub_path_dir();
    let scratch = tempfile::tempdir().expect("scratch");
    let cfg_path = scratch.path().join("suricata.toml");
    std::fs::write(&cfg_path, "mode = \"nfqueue\"\nqueue_num = 0\n").unwrap();

    let before = common::snapshot_tree(scratch.path());
    let out = Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_SURICATA_CONFIG", &cfg_path)
        .env("SELFDEF_SURICATA_TEMPLATES", module_dir().join("templates"))
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = common::snapshot_tree(scratch.path());
    common::assert_tree_unchanged(&before, &after);
}

/// F-2027-046: SDD-005 D-1 live-positive coverage. Previously the
/// suricata module-script tests all ran under `SELFDEF_DRY_RUN=1`,
/// so the live branch — which actually invokes `nft -f` to load
/// the NFQUEUE rule and `systemctl enable`/`start` to bring the
/// service up — had zero regression protection. This test runs
/// apply.sh *without* dry-run against recording stubs and asserts
/// every side-effecting command landed exactly as the script
/// describes its work in its emitted log.
///
/// The stubs append their argv into a per-test log file so the
/// test asserts on the call sequence; no real systemd / nft state
/// is touched.
#[test]
fn live_apply_invokes_nft_load_and_systemctl_start() {
    let scratch = tempfile::tempdir().expect("scratch");
    let calls_log = scratch.path().join("calls.log");

    let stubs = tempfile::tempdir().expect("stubs");

    // `suricata` stub: preflight `command -v` only.
    std::fs::write(
        stubs.path().join("suricata"),
        "#!/usr/bin/env bash\nexit 0\n",
    )
    .unwrap();

    // `nft` stub:
    //   * `list table inet selfdef_bridge` → exit 0 (table present).
    //   * `list chain ... forward_hook`    → exit 0 with output that
    //     does NOT mention `selfdef-suricata`, so `have_nfqueue_rule`
    //     returns false and the script enters the install branch.
    //   * `-f <file>` (and anything else)  → exit 0; we record argv.
    std::fs::write(
        stubs.path().join("nft"),
        format!(
            r#"#!/usr/bin/env bash
echo "nft $*" >> "{log}"
if [[ "$1" == "list" && "$2" == "table" ]]; then exit 0; fi
if [[ "$1" == "-a" && "$2" == "list" && "$3" == "chain" ]]; then
    # Empty chain dump — no selfdef-suricata jump present.
    echo "table inet selfdef_bridge {{ chain forward_hook {{ type filter hook forward priority 0; }} }}"
    exit 0
fi
exit 0
"#,
            log = calls_log.display(),
        ),
    )
    .unwrap();

    // `systemctl` stub:
    //   * `is-enabled suricata.service` → exit 3 (NOT enabled → trigger enable).
    //   * `is-active  suricata.service` → exit 3 (NOT active  → trigger start).
    //   * `enable` / `start`            → exit 0; we record argv.
    std::fs::write(
        stubs.path().join("systemctl"),
        format!(
            r#"#!/usr/bin/env bash
echo "systemctl $*" >> "{log}"
case "$1" in
    is-active|is-enabled) exit 3 ;;
    *) exit 0 ;;
esac
"#,
            log = calls_log.display(),
        ),
    )
    .unwrap();

    for name in &["suricata", "nft", "systemctl"] {
        let p = stubs.path().join(name);
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }

    let cfg = write_config("mode = \"nfqueue\"\nqueue_num = 7\n");
    let module = module_dir();
    let out = Command::new("bash")
        .arg(module.join("install/apply.sh"))
        // NOTE: SELFDEF_DRY_RUN deliberately *not* set → live branch.
        .env("SELFDEF_SURICATA_CONFIG", cfg.path())
        .env("SELFDEF_SURICATA_TEMPLATES", module.join("templates"))
        .env("PATH", prepended_path(stubs.path()))
        .output()
        .expect("spawn apply.sh");
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "live apply must succeed; stderr: {}\nlast stdout line: {line}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("\"module\":\"suricata\""),
        "got: {line}",
    );

    let calls = std::fs::read_to_string(&calls_log).expect("calls log");

    // The NFQUEUE jump must have been installed via `nft -f <rendered>`.
    assert!(
        calls.lines().any(|l| l.starts_with("nft -f ")),
        "expected `nft -f <file>` call; calls:\n{calls}",
    );
    // The service must have been both enabled and started.
    assert!(
        calls.contains("systemctl enable suricata.service"),
        "expected systemctl enable; calls:\n{calls}",
    );
    assert!(
        calls.contains("systemctl start suricata.service"),
        "expected systemctl start; calls:\n{calls}",
    );

    // The script's `log` helper writes to stderr; the "load
    // NFQUEUE jump" description landing there is our proof that
    // apply.sh entered the install branch (not the
    // "already-present" early-exit).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("load NFQUEUE jump"),
        "apply log should describe the NFQUEUE install; stderr: {stderr}",
    );
}
