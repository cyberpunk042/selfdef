//! End-to-end integration test for `selfdefctl modules apply` and friends.
//!
//! Builds a hermetic catalog of two stub modules in a tempdir, writes
//! a host config that activates both, then runs the binary with
//! `--host-config` + `--dir` overrides. Exercises the CLI from the
//! same surface an operator uses.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn binary() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is populated by cargo for integration tests.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
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

fn write_module(catalog: &Path, slug: &str, deps: &[&str], apply_body: &str) {
    let depline = if deps.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = deps.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on = [{}]\n", q.join(", "))
    };
    let manifest = format!(
        "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"stub\"\ncategory = \"test\"\n{depline}\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\ncheck = \"install/check.sh\"\n"
    );
    std::fs::create_dir_all(catalog.join(slug)).unwrap();
    std::fs::write(catalog.join(slug).join("module.toml"), manifest).unwrap();
    write_executable(&catalog.join(slug).join("install/apply.sh"), apply_body);
    // A trivial check.sh that always reports ok — exercised by
    // `selfdefctl modules check`.
    let check = format!(
        "#!/usr/bin/env bash\necho '{{\"module\":\"{slug}\",\"status\":\"ok\",\"message\":\"check ok\"}}'\n"
    );
    write_executable(&catalog.join(slug).join("install/check.sh"), &check);
}

struct Fixture {
    _root: tempfile::TempDir,
    catalog: std::path::PathBuf,
    host_config: std::path::PathBuf,
}

fn fixture(host_body: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    // alpha (no deps); beta depends on alpha. Both emit "ok" so apply
    // and check are happy.
    let body_alpha = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"alpha applied\"}'\n";
    let body_beta = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"beta applied\"}'\n";
    write_module(&catalog, "alpha", &[], body_alpha);
    write_module(&catalog, "beta", &["alpha"], body_beta);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, host_body).unwrap();

    Fixture {
        _root: root,
        catalog,
        host_config,
    }
}

fn run(bin: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        // Use any config file we don't depend on — `--config` is the
        // global flag; pass /dev/null so the daemon config loader
        // doesn't refuse.
        .arg("--config")
        .arg("/dev/null")
        .args(args)
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn apply_runs_modules_in_dependency_order() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Alpha must appear before beta.
    let i_alpha = stdout.find("alpha [apply]").expect("alpha line");
    let i_beta = stdout.find("beta [apply]").expect("beta line");
    assert!(i_alpha < i_beta, "alpha did not run before beta:\n{stdout}");
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn apply_only_filter_skips_excluded_modules() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--only",
            "alpha",
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("alpha [apply]"));
    assert!(!stdout.contains("beta [apply]"), "stdout: {stdout}");
}

#[test]
fn check_reports_ok_for_active_modules() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    let out = run(
        &binary(),
        &[
            "modules",
            "check",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn apply_returns_nonzero_when_any_module_fails() {
    let fx = fixture("[modules.alpha]\n[modules.beta]\n");
    // Overwrite beta's apply.sh to fail.
    let bad = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"failed\",\"message\":\"boom\"}'\nexit 1\n";
    write_executable(&fx.catalog.join("beta/install/apply.sh"), bad);

    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    assert!(
        !out.status.success(),
        "should exit non-zero on module failure"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Summary: 1 ok, 0 skipped, 1 failed"),
        "stdout: {stdout}"
    );
}

#[test]
fn empty_host_config_is_a_noop() {
    let fx = fixture(""); // no [modules.*] sections
    let out = run(
        &binary(),
        &[
            "modules",
            "apply",
            "--host-config",
            fx.host_config.to_str().unwrap(),
            "--dir",
            fx.catalog.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Applying 0 module(s)"), "stdout: {stdout}");
}
