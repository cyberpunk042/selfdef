//! Integration tests for `selfdefctl doctor`. Each test stages
//! a hermetic `selfdef.toml` with one cross-cutting feature
//! turned on, plus the on-disk state that feature checks, and
//! asserts the doctor's per-category status reflects reality.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("selfdef.toml");
    std::fs::write(&p, body).unwrap();
    p
}

fn write_token_file(dir: &Path, body: &str, mode: u32) -> PathBuf {
    let p = dir.join("api.token");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

fn run_doctor(cfg_path: &Path, json: bool) -> std::process::Output {
    let mut args = vec!["--config", cfg_path.to_str().unwrap(), "doctor"];
    if json {
        args.push("--json");
    }
    Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn doctor_with_no_optin_features_is_all_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");
    let out = run_doctor(&cfg, false);
    assert!(
        out.status.success(),
        "no opt-in features should be 0 fails; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The report has 4 categories: signing/api/eventstream/rbac.
    // With every feature off, each is "skip".
    assert!(stdout.contains("## signing"), "stdout: {stdout}");
    assert!(stdout.contains("## api"), "stdout: {stdout}");
    assert!(stdout.contains("## eventstream"), "stdout: {stdout}");
    assert!(stdout.contains("## rbac"), "stdout: {stdout}");
    assert!(stdout.contains("[skip]"), "stdout: {stdout}");
    assert!(
        stdout.contains("0 fail"),
        "summary should report 0 failures; stdout: {stdout}",
    );
}

#[test]
fn doctor_flags_api_token_with_world_readable_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let token = write_token_file(tmp.path(), "abcdef123", 0o644);
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[api]\nenabled = true\ntoken_file = \"{}\"\n",
            token.display(),
        ),
    );
    let out = run_doctor(&cfg, false);
    assert!(
        !out.status.success(),
        "non-0600 token file must fail the check; stdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[FAIL] token file:") && stdout.contains("mode 644"),
        "expected FAIL on token mode; stdout: {stdout}",
    );
}

#[test]
fn doctor_passes_api_token_at_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let token = write_token_file(tmp.path(), "abcdef123", 0o600);
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[api]\nenabled = true\ntoken_file = \"{}\"\n",
            token.display(),
        ),
    );
    let out = run_doctor(&cfg, false);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[  ok] token file:") && stdout.contains("mode 0600"),
        "stdout: {stdout}",
    );
}

#[test]
fn doctor_flags_signing_when_enabled_without_key_path() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "[security]\nrequire_signed_rules = true\n");
    let out = run_doctor(&cfg, false);
    assert!(!out.status.success(), "missing key path must fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[FAIL] public key:")
            && stdout.contains("signing_public_key_file is unset"),
        "stdout: {stdout}",
    );
}

#[test]
fn doctor_flags_eventstream_world_writable() {
    let tmp = tempfile::tempdir().unwrap();
    let stream = tmp.path().join("ssh.jsonl");
    std::fs::write(&stream, "").unwrap();
    let mut perms = std::fs::metadata(&stream).unwrap().permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(&stream, perms).unwrap();
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[collectors.eventstream]\nenabled = true\nintegrity_check = true\npaths = [\"{}\"]\n",
            stream.display(),
        ),
    );
    let out = run_doctor(&cfg, false);
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[FAIL]") && stdout.contains("world-writable"),
        "stdout: {stdout}",
    );
}

#[test]
fn doctor_json_emits_one_object_per_check() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");
    let out = run_doctor(&cfg, true);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut categories: std::collections::BTreeSet<String> = Default::default();
    for line in stdout.lines() {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("non-JSON line: {line}\n{e}"));
        let cat = v["category"].as_str().unwrap().to_string();
        let status = v["status"].as_str().unwrap();
        assert!(
            ["ok", "warn", "FAIL", "skip"].contains(&status),
            "unknown status {status}",
        );
        categories.insert(cat);
    }
    // We expect at least signing, api, eventstream, rbac.
    for must in ["signing", "api", "eventstream", "rbac"] {
        assert!(categories.contains(must), "missing category {must}");
    }
}

/// Helper: run doctor with the
/// `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` env override pointed at
/// a tempdir-staged config. Lets us exercise the rbac code
/// path without writing to /etc/selfdef/modules/.
fn run_doctor_with_agent_guard(cfg_path: &Path, agent_guard_path: &Path) -> std::process::Output {
    Command::new(binary())
        .args(["--config", cfg_path.to_str().unwrap(), "doctor"])
        .env(
            "SELFDEF_DOCTOR_AGENT_GUARD_CONFIG",
            agent_guard_path.to_str().unwrap(),
        )
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn doctor_rbac_pod_label_scope_is_skip_not_warn() {
    // F-2027-008: pre-fix, doctor emitted `warn:` for pod-label
    // scope even when nothing was actually wrong — just that
    // the operator hadn't run rbac-check yet. The fix flips
    // the emission to `skip:` with "posture not verified" so
    // the doctor's summary line doesn't suggest failure.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");
    let agent_guard = tmp.path().join("agent-guard.toml");
    std::fs::write(
        &agent_guard,
        "scope = \"pod-label\"\npod_label_key = \"selfdef.io/agent\"\npod_label_value = \"true\"\n",
    )
    .unwrap();

    let out = run_doctor_with_agent_guard(&cfg, &agent_guard);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The rbac section should be skip (the new behaviour),
    // not warn (the pre-fix behaviour).
    assert!(
        stdout.contains("[skip] agent-guard scope:") && stdout.contains("posture not verified"),
        "expected skip + 'posture not verified'; stdout: {stdout}",
    );
    assert!(
        !stdout.contains("[warn] agent-guard scope:"),
        "rbac category must NOT emit warn for pod-label; stdout: {stdout}",
    );
    // Crucially: the summary line should report 0 warn.
    assert!(
        stdout.contains("0 warn"),
        "doctor summary must report 0 warn; stdout: {stdout}",
    );
}

#[test]
fn doctor_rbac_container_scope_is_skip_with_not_gating_note() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");
    let agent_guard = tmp.path().join("agent-guard.toml");
    std::fs::write(&agent_guard, "scope = \"container\"\n").unwrap();

    let out = run_doctor_with_agent_guard(&cfg, &agent_guard);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[skip] agent-guard scope:") && stdout.contains("RBAC posture not gating"),
        "stdout: {stdout}",
    );
}

/// The cross-cutting `selfdefctl doctor` MUST surface the same 4
/// cli-mirror checks the standalone `selfdefctl cli-mirror doctor`
/// emits, so an operator who runs `doctor` for a daily health pulse
/// sees D-CLI chain state without needing to know the dedicated
/// verb exists. Drift between the two surfaces (e.g. someone adds a
/// 5th check to the standalone verb and forgets the roll-up) fails
/// this test.
#[test]
fn doctor_rolls_up_cli_mirror_chain_checks() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");
    let out = run_doctor(&cfg, false);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The m060 category must appear at all.
    assert!(
        stdout.contains("## m060"),
        "doctor must show m060 category; stdout: {stdout}"
    );
    // Each cli-mirror check must surface under m060 with the
    // canonical "cli-mirror · <check-name>" label.
    for name in [
        "cli-mirror · schema-version",
        "cli-mirror · resident-store",
        "cli-mirror · systemd-unit",
        "cli-mirror · published-mirror",
    ] {
        assert!(
            stdout.contains(name),
            "doctor must roll up the standalone cli-mirror doctor's '{name}' check; \
             stdout: {stdout}",
        );
    }
    // Schema-version is the wire-invariant check — always Ok.
    assert!(
        stdout.contains("[  ok] cli-mirror · schema-version"),
        "schema-version invariant must classify Ok; stdout: {stdout}",
    );
}

/// Quieting contract: when the operator hasn't opted into M060 (no
/// `[deployment].selfdef_mirror_dir` knob set), the cli-mirror checks
/// downgrade Warn→Skip in the roll-up. A fresh-install `doctor` MUST
/// NOT surface "M060 is broken" warnings for a chain the operator
/// never asked for. The standalone `cli-mirror doctor` verb still
/// shows the operator-actionable WARNs (operator explicitly invoked
/// it).
#[test]
fn doctor_quiets_cli_mirror_warns_when_m060_opted_out() {
    let tmp = tempfile::tempdir().unwrap();
    // No [deployment].selfdef_mirror_dir → operator not on M060.
    let cfg = write_config(tmp.path(), "");
    let out = run_doctor(&cfg, false);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // resident-store + systemd-unit + published-mirror are warn-level
    // in the dedicated verb on a fresh host; here they MUST be skip.
    for name in [
        "cli-mirror · resident-store",
        "cli-mirror · systemd-unit",
        "cli-mirror · published-mirror",
    ] {
        let line = stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("no {name} line; stdout:\n{stdout}"));
        assert!(
            line.contains("[skip]"),
            "without [deployment].selfdef_mirror_dir set, {name} MUST be skip \
             (operator hasn't onboarded M060). line: {line}",
        );
    }
    // Detail must still carry the fix text so curious operators get
    // the onboarding prompt even when skipped.
    let resident = stdout
        .lines()
        .find(|l| l.contains("cli-mirror · resident-store"))
        .expect("resident-store line");
    assert!(
        resident.contains("· fix:"),
        "skip row must still carry the `· fix:` segment for discoverability; line: {resident}",
    );
}

/// Inverse contract: when the operator HAS opted into M060
/// (`[deployment].selfdef_mirror_dir` set in selfdef.toml), the
/// cli-mirror warns surface as actual warns — the operator wants to
/// know their opted-in chain is misconfigured.
#[test]
fn doctor_surfaces_cli_mirror_warns_when_m060_opted_in() {
    let tmp = tempfile::tempdir().unwrap();
    let mirror_dir = tmp.path().join("mirror-dir");
    std::fs::create_dir_all(&mirror_dir).unwrap();
    // Opt the operator in by setting the knob.
    let cfg = write_config(
        tmp.path(),
        &format!(
            "[deployment]\nselfdef_mirror_dir = \"{}\"\n",
            mirror_dir.display()
        ),
    );
    let out = run_doctor(&cfg, false);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // resident-store still absent (no /var/lib/selfdef/cli-mirror.json
    // in this test env), but now classifies as warn — the operator
    // opted in, so they want to know.
    let line = stdout
        .lines()
        .find(|l| l.contains("cli-mirror · resident-store"))
        .unwrap_or_else(|| panic!("no resident-store line; stdout:\n{stdout}"));
    assert!(
        line.contains("[warn]"),
        "with [deployment].selfdef_mirror_dir set, missing resident store MUST be warn \
         (operator onboarded M060). line: {line}",
    );
    assert!(
        line.contains("· fix:"),
        "warn row must carry the operator-actionable `· fix:` segment; line: {line}",
    );
}
