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
    write_module_full(catalog, slug, deps, /*instanced*/ false, apply_body);
}

fn write_module_full(catalog: &Path, slug: &str, deps: &[&str], instanced: bool, apply_body: &str) {
    let depline = if deps.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = deps.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on = [{}]\n", q.join(", "))
    };
    let inst = if instanced { "instanced = true\n" } else { "" };
    let manifest = format!(
        "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"stub\"\ncategory = \"test\"\n{inst}{depline}\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\ncheck = \"install/check.sh\"\n"
    );
    std::fs::create_dir_all(catalog.join(slug)).unwrap();
    std::fs::write(catalog.join(slug).join("module.toml"), manifest).unwrap();
    write_executable(&catalog.join(slug).join("install/apply.sh"), apply_body);
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

#[test]
fn apply_runs_multiple_instances_of_a_multi_instance_module() {
    // Two instances of the same `multi` module run in alphabetical
    // order. Each instance gets its own SELFDEF_MULTI_CONFIG path
    // (defaulting to /etc/selfdef/modules/multi.<instance>.toml,
    // overridable per host entry).
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    // The stub echoes whichever config path it received, so we can
    // assert each instance is invoked with the expected env var.
    let body = "#!/usr/bin/env bash\necho \"{\\\"module\\\":\\\"multi\\\",\\\"status\\\":\\\"ok\\\",\\\"message\\\":\\\"$SELFDEF_MULTI_CONFIG\\\"}\"\n";
    write_module_full(&catalog, "multi", &[], /*instanced*/ true, body);

    let host_config = root.path().join("modules.toml");
    let tunnel_cfg = root.path().join("tunnel.toml");
    let publish_cfg = root.path().join("publish.toml");
    std::fs::write(&tunnel_cfg, "x = 1\n").unwrap();
    std::fs::write(&publish_cfg, "x = 2\n").unwrap();
    std::fs::write(
        &host_config,
        format!(
            "[modules.\"multi#tunnel\"]\nconfig = \"{}\"\n[modules.\"multi#publish\"]\nconfig = \"{}\"\n",
            tunnel_cfg.display(),
            publish_cfg.display(),
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_selfdefctl"))
        .args([
            "--config",
            "/dev/null",
            "modules",
            "apply",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Both instances show in alphabetical order — publish before tunnel.
    let i_pub = stdout.find("multi#publish").expect("publish line");
    let i_tun = stdout.find("multi#tunnel").expect("tunnel line");
    assert!(
        i_pub < i_tun,
        "expected multi#publish before multi#tunnel:\n{stdout}"
    );
    // Each instance got its instance-specific config path on stdout.
    assert!(
        stdout.contains(publish_cfg.to_str().unwrap()),
        "stdout did not mention publish cfg: {stdout}"
    );
    assert!(
        stdout.contains(tunnel_cfg.to_str().unwrap()),
        "stdout did not mention tunnel cfg: {stdout}"
    );
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn apply_rejects_instance_keys_against_non_instanced_module() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let body =
        "#!/usr/bin/env bash\necho '{\"module\":\"single\",\"status\":\"ok\",\"message\":\"\"}'\n";
    write_module_full(&catalog, "single", &[], /*instanced*/ false, body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.\"single#a\"]\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_selfdefctl"))
        .args([
            "--config",
            "/dev/null",
            "modules",
            "apply",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(!out.status.success(), "should refuse non-instanced module");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not declared `instanced = true`"),
        "stderr: {stderr}"
    );
}
