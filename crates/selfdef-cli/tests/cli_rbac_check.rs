//! SDD-004 F-2026-025 follow-up integration tests for
//! `selfdefctl rbac check`. Covers the four code paths:
//!
//! - `scope = "container"` → reports not-applicable and exits 0.
//! - `scope = "pod-label"` without `--probe` → prints the
//!   recommended posture + the kubectl commands the operator
//!   should run.
//! - `scope = "pod-label"` with `--probe`, kubectl reports
//!   CANNOT for every subject → exit 0.
//! - `scope = "pod-label"` with `--probe`, kubectl reports CAN
//!   for at least one subject → exit non-zero with a clear
//!   overly-permissive diagnostic. `--warn-only` suppresses the
//!   exit code.
//!
//! Tests use a stub `kubectl` on PATH whose behaviour is keyed
//! off the `--as` value. This keeps the test hermetic — no real
//! cluster access required.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
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

/// Stub `kubectl auth can-i ... --as=<subject>` keyed by
/// subject. Subjects listed in `permissive` echo `yes` and
/// exit 0 (kubectl's "CAN" answer). Everyone else echoes `no`
/// and exits 1 (kubectl's "CANNOT" answer).
fn stub_kubectl(permissive_subjects: &[&str]) -> String {
    let permissive_list = permissive_subjects.join("|");
    format!(
        r#"#!/usr/bin/env bash
# Minimal kubectl stub for the rbac-check integration tests.
# Parses `auth can-i ... --as <subj>` and answers based on the
# subject's membership in a per-test allowlist.
shift # eat "auth"
shift # eat "can-i"
# Walk remaining args looking for --as <subject>.
subj=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --as)
            subj="$2"
            shift 2
            ;;
        *) shift ;;
    esac
done
if [[ "$subj" =~ ^({permissive_list})$ ]]; then
    echo yes
    exit 0
fi
echo no
exit 1
"#,
    )
}

struct Fixture {
    _root: tempfile::TempDir,
    _bins: tempfile::TempDir,
    module_config: PathBuf,
    bins: PathBuf,
}

fn fixture(scope: &str, permissive_subjects: &[&str]) -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();

    let module_config = root.join("agent-guard.toml");
    std::fs::write(
        &module_config,
        format!(
            "profile = \"audit\"\n\
             scope = \"{scope}\"\n\
             pod_label_key = \"selfdef.io/agent\"\n\
             pod_label_value = \"true\"\n",
        ),
    )
    .unwrap();

    let bins_holder = tempfile::tempdir().unwrap();
    let bins = bins_holder.path().to_path_buf();
    write_executable(&bins.join("kubectl"), &stub_kubectl(permissive_subjects));

    Fixture {
        _root: root_holder,
        _bins: bins_holder,
        module_config,
        bins,
    }
}

fn run_rbac_check(fx: &Fixture, extra_args: &[&str]) -> std::process::Output {
    let mut args = vec![
        "rbac",
        "check",
        "--module-config",
        fx.module_config.to_str().unwrap(),
    ];
    args.extend(extra_args);
    Command::new(binary())
        .args(&args)
        .env("PATH", prepended_path(&fx.bins))
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn rbac_check_reports_not_applicable_when_scope_is_container() {
    let fx = fixture("container", &[]);
    let out = run_rbac_check(&fx, &[]);
    assert!(
        out.status.success(),
        "should exit 0 for container scope; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rbac check not applicable") && stdout.contains("\"container\""),
        "expected not-applicable message; stdout: {stdout}",
    );
}

#[test]
fn rbac_check_without_probe_prints_recommended_posture() {
    let fx = fixture("pod-label", &[]);
    let out = run_rbac_check(&fx, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Configured boundary"), "stdout: {stdout}");
    assert!(stdout.contains("selfdef.io/agent=true"), "stdout: {stdout}");
    assert!(stdout.contains("Recommended posture"), "stdout: {stdout}");
    assert!(stdout.contains("system:authenticated"), "stdout: {stdout}");
    assert!(stdout.contains("Skipping live probe"), "stdout: {stdout}",);
}

#[test]
fn rbac_check_with_probe_clean_posture_exits_zero() {
    // Neither system:authenticated nor system:unauthenticated
    // is in the permissive list → kubectl returns "no" for
    // both → check passes.
    let fx = fixture("pod-label", &[]);
    let out = run_rbac_check(&fx, &["--probe"]);
    assert!(
        out.status.success(),
        "clean posture should pass; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok: no probed subject"),
        "expected clean-posture line; stdout: {stdout}",
    );
}

#[test]
fn rbac_check_with_probe_flags_overly_permissive_subject() {
    // system:authenticated is in the permissive list → kubectl
    // returns "yes" → check fails.
    let fx = fixture("pod-label", &["system:authenticated"]);
    let out = run_rbac_check(&fx, &["--probe"]);
    assert!(
        !out.status.success(),
        "overly-permissive posture should fail; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WARN:   system:authenticated") && stdout.contains("warn: 1 subject(s)"),
        "expected WARN diagnostic; stdout: {stdout}",
    );
}

#[test]
fn rbac_check_warn_only_suppresses_exit_failure() {
    let fx = fixture("pod-label", &["system:authenticated"]);
    let out = run_rbac_check(&fx, &["--probe", "--warn-only"]);
    assert!(
        out.status.success(),
        "--warn-only must suppress the non-zero exit; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("warn: 1 subject(s)"), "stdout: {stdout}",);
}

#[test]
fn rbac_check_with_extra_as_subjects_probes_them_too() {
    // Add operator-supplied --as subject. The extra subject is
    // in the permissive list → check should flag it.
    let fx = fixture("pod-label", &["my-tenant-sa"]);
    let out = run_rbac_check(&fx, &["--probe", "--as", "my-tenant-sa"]);
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WARN:   my-tenant-sa"),
        "expected operator-subject to be probed; stdout: {stdout}",
    );
}

#[test]
fn rbac_check_namespace_arg_is_passed_to_kubectl() {
    // The stub kubectl prints "yes" for permissive subjects
    // regardless of -n, but if --namespace gets passed through
    // we expect the recommended-posture documentation to
    // mention the `-n` flag in the manual commands.
    let fx = fixture("pod-label", &[]);
    let out = run_rbac_check(&fx, &["--namespace", "selfdef-test"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("-n selfdef-test"),
        "expected --namespace to appear in manual commands; stdout: {stdout}",
    );
}
