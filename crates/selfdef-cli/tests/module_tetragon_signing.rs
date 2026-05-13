//! SDD-004 F-2026-024 follow-up integration tests for the
//! tetragon module's policy-signing enforcement.
//!
//! Tests build a hermetic fixture with:
//!   - the tetragon module's apply.sh / check.sh
//!   - a stubbed selfdefctl binary on PATH that mimics
//!     `selfdefctl keys verify` exit codes (so we don't have to
//!     actually generate minisign keypairs at every test —
//!     the verifier path is covered end-to-end by
//!     selfdef-signing's own unit suite + the correlator's
//!     signed_rules.rs integration suite)
//!   - a hermetic policy_dir with operator-controlled file
//!     contents per test
//!
//! Each test runs apply.sh (or check.sh) and asserts the right
//! outcome for the right combination of:
//!   • `require_signed_policies` = true | false
//!   • presence of `.minisig` sidecars
//!   • simulated `selfdefctl keys verify` exit code

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn module_dir() -> PathBuf {
    workspace_root().join("modules/tetragon")
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

fn prepended_path(extra: &Path) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut out = std::ffi::OsString::from(extra);
    out.push(":");
    out.push(&existing);
    out
}

/// Stub `selfdefctl` mimicking the two `keys` verbs the tetragon
/// module shells out to:
///   • `keys verify <target>` — exits 0 iff `${target}.minisig`
///     exists, 1 otherwise.
///   • `keys verify-dir <dir>` (F-2027-006) — walks the immediate
///     `*.yml`/`*.yaml` in `<dir>`, exits 0 iff every file has a
///     sibling `.minisig`, non-zero (count of failures) otherwise.
///
/// Mirrors the real CLI's exit-code contract without pulling
/// minisign into the test fixture; verifier path is covered
/// end-to-end by selfdef-signing's own unit suite + the
/// correlator's signed_rules.rs integration suite.
fn stub_selfdefctl() -> &'static str {
    r#"#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        keys)
            shift
            case "$1" in
                verify)
                    shift
                    target="$1"
                    [[ -f "${target}.minisig" ]] && exit 0 || exit 1
                    ;;
                verify-dir)
                    shift
                    dir="$1"
                    [[ -d "$dir" ]] || exit 2
                    failed=0
                    shopt -s nullglob
                    for p in "$dir"/*.yml "$dir"/*.yaml; do
                        if [[ -f "${p}.minisig" ]]; then
                            echo "ok:   $p"
                        else
                            echo "fail: $p: missing sidecar"
                            failed=$((failed + 1))
                        fi
                    done
                    [[ "$failed" -eq 0 ]] && exit 0 || exit 1
                    ;;
            esac
            ;;
    esac
    shift
done
exit 0
"#
}

struct Fixture {
    _root: tempfile::TempDir,
    _bins: tempfile::TempDir,
    config_path: PathBuf,
    policy_dir: PathBuf,
    bins: PathBuf,
}

fn fixture(require_signed: bool) -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();

    let event_log = root.join("tetragon-events.json");
    let policy_dir = root.join("tetragon.tp.d");
    std::fs::create_dir_all(&policy_dir).unwrap();
    let config_render_path = root.join("tetragon.yaml");

    let host_cfg = root.join("tetragon.toml");
    std::fs::write(
        &host_cfg,
        format!(
            "profile = \"default\"\n\
             event_log_path          = \"{}\"\n\
             policy_dir              = \"{}\"\n\
             metrics_address         = \"127.0.0.1:2112\"\n\
             config_path             = \"{}\"\n\
             service_unit            = \"tetragon-test.service\"\n\
             require_signed_policies = {}\n",
            event_log.display(),
            policy_dir.display(),
            config_render_path.display(),
            require_signed,
        ),
    )
    .unwrap();

    let bins_holder = tempfile::tempdir().unwrap();
    let bins = bins_holder.path().to_path_buf();
    write_executable(&bins.join("tetragon"), "#!/usr/bin/env bash\nexit 0\n");
    write_executable(&bins.join("systemctl"), "#!/usr/bin/env bash\nexit 0\n");
    write_executable(&bins.join("selfdefctl"), stub_selfdefctl());

    Fixture {
        _root: root_holder,
        _bins: bins_holder,
        config_path: host_cfg,
        policy_dir,
        bins,
    }
}

fn run_apply(fx: &Fixture, dry_run: bool) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", if dry_run { "1" } else { "0" })
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .output()
        .expect("spawn apply.sh")
}

fn run_check(fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_TETRAGON_CONFIG", &fx.config_path)
        .env("PATH", prepended_path(&fx.bins))
        .output()
        .expect("spawn check.sh")
}

fn last_stdout_line(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn write_policy_with_sig(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n").unwrap();
    let mut sig = p.as_os_str().to_owned();
    sig.push(".minisig");
    std::fs::write(PathBuf::from(sig), b"untrusted comment: stub\n").unwrap();
    p
}

fn write_policy_without_sig(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n").unwrap();
    p
}

#[test]
fn apply_passes_when_signing_disabled_and_unsigned_policies_present() {
    let fx = fixture(/*require_signed*/ false);
    write_policy_without_sig(&fx.policy_dir, "unsigned.yml");
    let out = run_apply(&fx, /*dry_run*/ true);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        last_stdout_line(&out).contains("\"status\":\"ok\""),
        "got: {}",
        last_stdout_line(&out),
    );
}

#[test]
fn apply_passes_when_signing_enabled_and_all_policies_signed() {
    let fx = fixture(/*require_signed*/ true);
    write_policy_with_sig(&fx.policy_dir, "ok.yml");
    write_policy_with_sig(&fx.policy_dir, "two.yaml");
    let out = run_apply(&fx, /*dry_run*/ false);
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"ok\""),
        "expected ok, got: {line}",
    );
}

#[test]
fn apply_refuses_when_signing_enabled_and_a_policy_is_unsigned() {
    let fx = fixture(/*require_signed*/ true);
    write_policy_with_sig(&fx.policy_dir, "ok.yml");
    write_policy_without_sig(&fx.policy_dir, "bad.yml");
    let out = run_apply(&fx, /*dry_run*/ false);
    assert!(
        !out.status.success(),
        "apply must refuse; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"")
            && line.contains("signature verification")
            && line.contains("tetragon"),
        "got: {line}",
    );
    // F-2027-023: the die message embeds the first failing
    // file's path so operators don't have to scroll back
    // through the verifier's per-file listing.
    assert!(
        (line.contains("first failure:") && line.contains("bad.yml"))
            || line.contains("policy file(s)"),
        "expected first-failure pointer or legacy aggregate message; got: {line}",
    );
}

#[test]
fn apply_in_dry_run_does_not_call_selfdefctl_keys_verify() {
    // Dry-run prints what it would verify but doesn't fail on
    // unsigned policies — the live apply.sh path is what enforces.
    let fx = fixture(/*require_signed*/ true);
    write_policy_without_sig(&fx.policy_dir, "unsigned.yml");
    let out = run_apply(&fx, /*dry_run*/ true);
    assert!(
        out.status.success(),
        "dry-run should succeed even with unsigned policies; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("DRY-RUN: would verify"),
        "expected DRY-RUN log line; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn check_passes_when_signing_disabled_with_unsigned_policies() {
    let fx = fixture(/*require_signed*/ false);
    write_policy_without_sig(&fx.policy_dir, "unsigned.yml");
    // check.sh needs the config file and event-log dirs to
    // exist; pre-create them so the check focuses on signing.
    std::fs::write(
        fx.config_path.parent().unwrap().join("tetragon.yaml"),
        "stub\n",
    )
    .unwrap();
    std::fs::File::create(
        fx.config_path
            .parent()
            .unwrap()
            .join("tetragon-events.json"),
    )
    .unwrap();
    let out = run_check(&fx);
    // check.sh either reports ok (signing disabled = unsigned ok)
    // or fails on systemctl (we stub systemctl is-active to
    // succeed via exit 0, so the success path is the expected
    // outcome).
    let line = last_stdout_line(&out);
    assert!(
        line.contains("tetragon substrate healthy"),
        "got: {line}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn check_fails_when_signing_enabled_and_unsigned_policy_present() {
    let fx = fixture(/*require_signed*/ true);
    write_policy_with_sig(&fx.policy_dir, "ok.yml");
    write_policy_without_sig(&fx.policy_dir, "unsigned.yml");
    std::fs::write(
        fx.config_path.parent().unwrap().join("tetragon.yaml"),
        "stub\n",
    )
    .unwrap();
    std::fs::File::create(
        fx.config_path
            .parent()
            .unwrap()
            .join("tetragon-events.json"),
    )
    .unwrap();
    let out = run_check(&fx);
    assert!(!out.status.success(), "check must fail on unsigned policy");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("signature verification"),
        "got: {line}",
    );
}
