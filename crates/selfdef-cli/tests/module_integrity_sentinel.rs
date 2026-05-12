//! Smoke-tests for the `integrity-sentinel` module.
//!
//! Hermetic: every test builds its own scratch fixture with a few
//! tracked files, a paths_file, and a host config, then invokes the
//! module's apply.sh / check.sh against it. No fake binaries are
//! shimmed — sha256sum and diff come from the system PATH.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn module_dir() -> PathBuf {
    workspace_root().join("modules/integrity-sentinel")
}

fn write_file(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
    baseline_path: PathBuf,
}

/// Build a scratch host with three tracked files under <root>/tracked
/// and a paths_file that includes them. The fixture exposes the
/// config path so each test can edit profile / on_missing.
fn fixture(profile: &str, on_missing: &str) -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();

    let tracked = root.join("tracked");
    std::fs::create_dir_all(&tracked).unwrap();
    write_file(&tracked.join("a.toml"), "version = \"1.0\"\n");
    write_file(&tracked.join("b.toml"), "key = \"value\"\n");
    write_file(&tracked.join("c.yml"), "rule:\n  id: 42\n");

    let paths_file = root.join("paths.txt");
    write_file(
        &paths_file,
        &format!(
            "# scratch paths\n{}/*.toml\n{}/c.yml\n",
            tracked.display(),
            tracked.display(),
        ),
    );

    let baseline_path = root.join("baseline.sha256");
    let config_path = root.join("integrity-sentinel.toml");
    write_file(
        &config_path,
        &format!(
            "profile = \"{profile}\"\npaths_file = \"{}\"\nbaseline_path = \"{}\"\non_missing = \"{on_missing}\"\n",
            paths_file.display(),
            baseline_path.display(),
        ),
    );

    Fixture {
        _root: root_holder,
        root,
        config_path,
        baseline_path,
    }
}

fn run_script(script: &str, fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install").join(script))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_INTEGRITY_SENTINEL_CONFIG", &fx.config_path)
        .output()
        .expect("spawn script")
}

fn last_stdout_line(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

#[test]
fn first_run_with_on_missing_create_seals_baseline() {
    let fx = fixture("strict", "create");
    assert!(!fx.baseline_path.exists(), "precondition");

    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("baseline created"),
        "got: {line}"
    );
    assert!(fx.baseline_path.exists(), "baseline file was not written");
    let baseline = std::fs::read_to_string(&fx.baseline_path).unwrap();
    let line_count = baseline.lines().count();
    assert_eq!(line_count, 3, "expected 3 hashed paths, got:\n{baseline}");
}

#[test]
fn on_missing_fail_refuses_to_seal() {
    let fx = fixture("strict", "fail");
    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should refuse: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("on_missing=fail"),
        "got: {line}"
    );
    assert!(
        !fx.baseline_path.exists(),
        "baseline must not be written under on_missing=fail"
    );
}

#[test]
fn matching_baseline_reports_ok() {
    let fx = fixture("strict", "create");
    let first = run_script("apply.sh", &fx);
    assert!(first.status.success(), "seal failed");
    let second = run_script("apply.sh", &fx);
    let line = last_stdout_line(&second);
    assert!(second.status.success(), "got: {line}");
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("baseline matches"),
        "got: {line}"
    );
}

#[test]
fn strict_profile_fails_on_modified_file() {
    let fx = fixture("strict", "create");
    run_script("apply.sh", &fx);
    // Tamper with one tracked file.
    write_file(&fx.root.join("tracked/a.toml"), "version = \"99.0\"\n");

    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail on drift: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("DRIFT"),
        "got: {line}"
    );
}

#[test]
fn warn_only_profile_reports_ok_on_drift() {
    let fx = fixture("warn-only", "create");
    run_script("apply.sh", &fx);
    write_file(&fx.root.join("tracked/a.toml"), "version = \"99.0\"\n");

    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(
        out.status.success(),
        "warn-only should not block: {line}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("\"status\":\"ok\"") && line.contains("DRIFT") && line.contains("warn-only"),
        "got: {line}"
    );
}

#[test]
fn strict_profile_fails_when_baselined_file_is_deleted() {
    let fx = fixture("strict", "create");
    run_script("apply.sh", &fx);
    std::fs::remove_file(fx.root.join("tracked/b.toml")).unwrap();

    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail on missing file: {line}");
    assert!(line.contains("DRIFT"), "got: {line}");
}

#[test]
fn strict_profile_fails_when_new_file_appears_under_glob() {
    let fx = fixture("strict", "create");
    run_script("apply.sh", &fx);
    write_file(&fx.root.join("tracked/d.toml"), "new_file = true\n");

    let out = run_script("apply.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "should fail on new file: {line}");
    assert!(line.contains("DRIFT"), "got: {line}");
}

#[test]
fn check_refuses_when_baseline_missing() {
    let fx = fixture("strict", "create");
    // Don't seal.
    let out = run_script("check.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(!out.status.success(), "check should fail: {line}");
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("no baseline at"),
        "got: {line}"
    );
}

#[test]
fn paths_file_rejects_non_absolute_path() {
    let fx = fixture("strict", "create");
    // Overwrite paths_file with a relative path.
    let paths_file = fx.root.join("paths.txt");
    write_file(&paths_file, "tracked/a.toml\n");

    let out = run_script("apply.sh", &fx);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should refuse relative path");
    assert!(
        stderr.contains("refusing non-absolute path"),
        "stderr: {stderr}"
    );
}

#[test]
fn uninstall_removes_baseline() {
    let fx = fixture("strict", "create");
    run_script("apply.sh", &fx);
    assert!(fx.baseline_path.exists());

    let out = run_script("uninstall.sh", &fx);
    let line = last_stdout_line(&out);
    assert!(out.status.success(), "got: {line}");
    assert!(line.contains("\"status\":\"ok\""), "got: {line}");
    assert!(!fx.baseline_path.exists(), "baseline still present");
    // paths_file is operator-managed; must not be touched.
    assert!(fx.root.join("paths.txt").exists());
}
