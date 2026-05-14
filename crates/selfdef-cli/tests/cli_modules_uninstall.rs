//! End-to-end coverage for `selfdefctl modules uninstall`.
//!
//! The destructive verb has two operator-facing constraints we want a
//! regression net for:
//!
//! 1. Tear-down order is the inverse of apply order — a module's
//!    dependents must come down before the module itself.
//! 2. Non-dry-run runs refuse to proceed without `--confirm <hostname>`
//!    matching the current host, mirroring the `panic` subcommand.
//!
//! Modules without an uninstall script are reported as `skipped` so
//! the run remains a useful aggregate even when some manifests
//! never declared rollback.

use std::path::Path;
use std::process::Command;

// F-2027-051: helpers live in common/mod.rs.
mod common;
use common::write_executable;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Write a module that declares `apply` + `uninstall` scripts. The
/// uninstall body is fed in so each test can shape its own outcome.
fn write_module_with_uninstall(
    catalog: &Path,
    slug: &str,
    deps: &[&str],
    apply_body: &str,
    uninstall_body: &str,
) {
    let depline = if deps.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = deps.iter().map(|d| format!("\"{d}\"")).collect();
        format!("depends_on = [{}]\n", q.join(", "))
    };
    let manifest = format!(
        "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"stub\"\ncategory = \"test\"\n{depline}\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\nuninstall = \"install/uninstall.sh\"\n"
    );
    std::fs::create_dir_all(catalog.join(slug)).unwrap();
    std::fs::write(catalog.join(slug).join("module.toml"), manifest).unwrap();
    write_executable(&catalog.join(slug).join("install/apply.sh"), apply_body);
    write_executable(
        &catalog.join(slug).join("install/uninstall.sh"),
        uninstall_body,
    );
}

/// Write a module that declares only an `apply` script — no
/// `uninstall` key — so the runner exercises the missing-script
/// "skipped" path.
fn write_module_without_uninstall(catalog: &Path, slug: &str, apply_body: &str) {
    let manifest = format!(
        "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"stub\"\ncategory = \"test\"\n\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\n"
    );
    std::fs::create_dir_all(catalog.join(slug)).unwrap();
    std::fs::write(catalog.join(slug).join("module.toml"), manifest).unwrap();
    write_executable(&catalog.join(slug).join("install/apply.sh"), apply_body);
}

fn run(bin: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .arg("--config")
        .arg("/dev/null")
        .args(args)
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn uninstall_runs_modules_in_reverse_dependency_order() {
    // alpha (no deps), beta (depends on alpha). Apply order: alpha,
    // beta. Uninstall order must be beta, alpha.
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    let apply_alpha =
        "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"a\"}'\n";
    let unins_alpha = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"alpha down\"}'\n";
    let apply_beta =
        "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"b\"}'\n";
    let unins_beta = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"beta down\"}'\n";
    write_module_with_uninstall(&catalog, "alpha", &[], apply_alpha, unins_alpha);
    write_module_with_uninstall(&catalog, "beta", &["alpha"], apply_beta, unins_beta);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n[modules.beta]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let i_beta = stdout.find("beta [uninstall]").expect("beta line");
    let i_alpha = stdout.find("alpha [uninstall]").expect("alpha line");
    assert!(
        i_beta < i_alpha,
        "beta (dependent) must uninstall before alpha:\n{stdout}",
    );
    assert!(stdout.contains("Summary: 2 ok"), "stdout: {stdout}");
}

#[test]
fn uninstall_skips_modules_without_uninstall_script() {
    // bare has no uninstall script in its manifest; the runner must
    // surface that as `skipped` rather than failing the whole run.
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();

    let apply_bare =
        "#!/usr/bin/env bash\necho '{\"module\":\"bare\",\"status\":\"ok\",\"message\":\"a\"}'\n";
    write_module_without_uninstall(&catalog, "bare", apply_bare);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.bare]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        stdout.contains("skipped: no uninstall script declared"),
        "stdout: {stdout}",
    );
    assert!(
        stdout.contains("Summary: 0 ok, 1 skipped, 0 failed"),
        "stdout: {stdout}",
    );
}

#[test]
fn uninstall_refuses_without_confirm() {
    // Non-dry-run, no --confirm → exit 2 with a clear refusal. We
    // deliberately don't depend on a real hostname here.
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let apply_body =
        "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"a\"}'\n";
    let unins_body = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"down\"}'\n";
    write_module_with_uninstall(&catalog, "alpha", &[], apply_body, unins_body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "expected refusal");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--confirm <hostname>"), "stderr: {stderr}",);
}

#[test]
fn uninstall_refuses_when_confirm_does_not_match_host() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let apply_body =
        "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"a\"}'\n";
    let unins_body = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"down\"}'\n";
    write_module_with_uninstall(&catalog, "alpha", &[], apply_body, unins_body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n").unwrap();

    // Force a known HOSTNAME so the mismatch check is deterministic.
    let out = Command::new(binary())
        .env("HOSTNAME", "real-host")
        .args([
            "--config",
            "/dev/null",
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--confirm",
            "wrong-host",
        ])
        .output()
        .expect("spawn selfdefctl");
    assert!(!out.status.success(), "expected mismatch refusal");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Confirm mismatch"), "stderr: {stderr}");
}

#[test]
fn uninstall_with_matching_confirm_proceeds() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let apply_body =
        "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"a\"}'\n";
    // The uninstall script verifies SELFDEF_DRY_RUN is unset for a
    // real (non-dry-run) invocation — i.e. confirm-gated runs really
    // do execute the destructive path.
    let unins_body = "#!/usr/bin/env bash\nif [[ \"${SELFDEF_DRY_RUN:-0}\" == \"1\" ]]; then echo '{\"module\":\"alpha\",\"status\":\"failed\",\"message\":\"should not be dry-run\"}'; exit 1; fi\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"live uninstall\"}'\n";
    write_module_with_uninstall(&catalog, "alpha", &[], apply_body, unins_body);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n").unwrap();

    let out = Command::new(binary())
        .env("HOSTNAME", "real-host")
        .args([
            "--config",
            "/dev/null",
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--confirm",
            "real-host",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(stdout.contains("live uninstall"), "stdout: {stdout}");
    assert!(stdout.contains("Summary: 1 ok"), "stdout: {stdout}");
}

#[test]
fn uninstall_only_filter_restricts_modules() {
    let root = tempfile::tempdir().unwrap();
    let catalog = root.path().join("catalog");
    std::fs::create_dir_all(&catalog).unwrap();
    let apply_a =
        "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"\"}'\n";
    let unins_a = "#!/usr/bin/env bash\necho '{\"module\":\"alpha\",\"status\":\"ok\",\"message\":\"a-down\"}'\n";
    let apply_b =
        "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"\"}'\n";
    let unins_b = "#!/usr/bin/env bash\necho '{\"module\":\"beta\",\"status\":\"ok\",\"message\":\"b-down\"}'\n";
    write_module_with_uninstall(&catalog, "alpha", &[], apply_a, unins_a);
    write_module_with_uninstall(&catalog, "beta", &[], apply_b, unins_b);

    let host_config = root.path().join("modules.toml");
    std::fs::write(&host_config, "[modules.alpha]\n[modules.beta]\n").unwrap();

    let out = run(
        &binary(),
        &[
            "modules",
            "uninstall",
            "--host-config",
            host_config.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--only",
            "beta",
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("beta [uninstall]"), "stdout: {stdout}");
    assert!(!stdout.contains("alpha [uninstall]"), "stdout: {stdout}");
    assert!(stdout.contains("Summary: 1 ok"), "stdout: {stdout}");
}
