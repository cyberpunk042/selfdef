//! Dry-run smoke tests for the `observability` module.
//!
//! Hermetic: each test points the module at a writable scratch tree
//! and runs apply.sh in both `bundled` and `external` profiles. We
//! never actually have Prometheus / Grafana available; the bundled
//! profile's `systemctl reload-or-restart` call is wrapped in
//! `command -v systemctl` and `|| log` so its absence is a warning,
//! not a failure.

use std::path::PathBuf;
use std::process::{Command, Output};

// F-2027-049 / -050: helpers live in common/mod.rs.
mod common;
use common::{assert_tree_unchanged, last_stdout_line, snapshot_tree, write_file};

fn module_dir() -> PathBuf {
    common::module_dir("observability")
}

/// Each test allocates its own scratch root and config path. Config
/// body is written after the root exists so test code can reference
/// paths under it.
struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
    /// F-2027-024: per-test override of the shared module-lib's
    /// install-manifest path so parallel tests don't trample
    /// `/var/lib/selfdef/installed/observability.manifest`.
    manifest_path: PathBuf,
}

fn new_fixture() -> Fixture {
    let root_holder = tempfile::tempdir().unwrap();
    let root = root_holder.path().to_path_buf();
    let config_path = root.join("observability.toml");
    let manifest_path = root.join("installed.manifest");
    Fixture {
        _root: root_holder,
        root,
        config_path,
        manifest_path,
    }
}

fn write_bundled_config(fx: &Fixture, scrape_targets: &str) {
    write_file(
        &fx.config_path,
        &format!(
            "profile = \"bundled\"\n\
             prometheus_conf_dir    = \"{}\"\n\
             grafana_dashboards_dir = \"{}\"\n\
             prometheus_rules_dir   = \"{}\"\n\
             scrape_targets = \"{scrape_targets}\"\n",
            fx.root.join("prom").display(),
            fx.root.join("grafana").display(),
            fx.root.join("prom-rules").display(),
        ),
    );
}

fn run_apply(fx: &Fixture) -> Output {
    Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_OBSERVABILITY_CONFIG", &fx.config_path)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        // Restricted PATH so systemctl reload is a no-op warning,
        // not a real call into the host's service manager.
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("spawn apply.sh")
}

#[test]
fn bundled_profile_writes_scrape_and_dashboard_to_configured_dirs() {
    let fx = new_fixture();
    write_bundled_config(&fx, "localhost:2112, host-b:2112");
    let out = run_apply(&fx);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let scrape = fx.root.join("prom/selfdef.yml");
    let dashboard = fx.root.join("grafana/selfdef.json");
    assert!(scrape.is_file(), "scrape config not written");
    assert!(dashboard.is_file(), "dashboard not written");

    let scrape_body = std::fs::read_to_string(&scrape).unwrap();
    assert!(
        scrape_body.contains("- \"localhost:2112\""),
        "first target missing:\n{scrape_body}",
    );
    assert!(
        scrape_body.contains("- \"host-b:2112\""),
        "second target missing:\n{scrape_body}",
    );
    assert!(
        !scrape_body.contains("__SELFDEF_SCRAPE_TARGETS__"),
        "marker was not replaced:\n{scrape_body}",
    );

    let dash_body = std::fs::read_to_string(&dashboard).unwrap();
    assert!(
        dash_body.contains("\"uid\": \"selfdef\""),
        "dashboard uid not substituted:\n{dash_body}",
    );
    assert!(
        dash_body.contains("\"title\": \"selfdef \u{2014} Host Self-Defense\""),
        "dashboard title not substituted:\n{dash_body}",
    );
    let _: serde_json::Value = serde_json::from_str(&dash_body).expect("dashboard JSON must parse");

    // MS027 four-watchdog alert rules: bundled profile drops the
    // alerts template to prometheus_rules_dir.
    let alerts = fx.root.join("prom-rules/selfdef.yml");
    assert!(alerts.is_file(), "alerts rules not written: {}", alerts.display());
    let alerts_body = std::fs::read_to_string(&alerts).unwrap();
    for alert_name in [
        "SelfdefFrictionAuditFailingGate",
        "SelfdefPerimeterSigkill",
        "SelfdefPerimeterPolicyMissing",
        "SelfdefPerimeterChainBroken",
        "SelfdefGuardianFailedResponse",
        "SelfdefGuardianTetragonSocketMissing",
        "SelfdefGuardianChainBroken",
        "SelfdefSchedulerSustainedBackpressure",
        "SelfdefSchedulerChainBroken",
    ] {
        assert!(
            alerts_body.contains(alert_name),
            "alert {alert_name} missing from deployed rules:\n{alerts_body}",
        );
    }
    // alerts must reference info-hub runbooks (operator-clickable from
    // Alertmanager UIs).
    assert!(
        alerts_body.contains("wiki/runbooks/"),
        "alerts missing info-hub runbook_url linkage:\n{alerts_body}",
    );
}

#[test]
fn external_profile_writes_to_staging_dir() {
    let fx = new_fixture();
    let staging_path = fx.root.join("staging");
    write_file(
        &fx.config_path,
        &format!(
            "profile = \"external\"\nstaging_dir = \"{}\"\nscrape_targets = \"localhost:2112\"\n",
            staging_path.display(),
        ),
    );
    let out = run_apply(&fx);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        staging_path.join("prometheus/selfdef.yml").is_file(),
        "external scrape not staged",
    );
    assert!(
        staging_path.join("grafana/selfdef.json").is_file(),
        "external dashboard not staged",
    );
    // MS027 four-watchdog alert rules: external profile drops the
    // alerts template to staging_dir/prometheus/rules/selfdef.yml.
    let staged_alerts = staging_path.join("prometheus/rules/selfdef.yml");
    assert!(
        staged_alerts.is_file(),
        "external alerts not staged at {}",
        staged_alerts.display(),
    );
}

#[test]
fn reapply_is_idempotent_no_change() {
    let fx = new_fixture();
    write_bundled_config(&fx, "localhost:2112");
    let first = run_apply(&fx);
    assert!(first.status.success());
    let second = run_apply(&fx);
    let line = last_stdout_line(&second);
    assert!(
        line.contains("already at desired state"),
        "expected no-op reapply, got: {line}",
    );
}

#[test]
fn refuses_empty_scrape_targets() {
    let fx = new_fixture();
    write_bundled_config(&fx, "");
    let out = run_apply(&fx);
    assert!(!out.status.success(), "should refuse empty scrape_targets");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("scrape_targets"),
        "got: {line}",
    );
}

#[test]
fn rejects_invalid_profile() {
    let fx = new_fixture();
    write_file(&fx.config_path, "profile = \"nope\"\n");
    let out = run_apply(&fx);
    assert!(!out.status.success(), "should refuse invalid profile");
    let line = last_stdout_line(&out);
    assert!(
        line.contains("\"status\":\"failed\"") && line.contains("bundled|external"),
        "got: {line}",
    );
}

#[test]
fn check_fails_before_apply_passes_after() {
    let fx = new_fixture();
    write_bundled_config(&fx, "localhost:2112");
    let pre = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_OBSERVABILITY_CONFIG", &fx.config_path)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .unwrap();
    assert!(!pre.status.success(), "check should fail before apply");

    run_apply(&fx);

    let post = Command::new("bash")
        .arg(module_dir().join("install/check.sh"))
        .env("SELFDEF_OBSERVABILITY_CONFIG", &fx.config_path)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .output()
        .unwrap();
    assert!(
        post.status.success(),
        "check should pass after apply: stdout={} stderr={}",
        String::from_utf8_lossy(&post.stdout),
        String::from_utf8_lossy(&post.stderr),
    );
}

#[test]
fn uninstall_removes_rendered_files() {
    let fx = new_fixture();
    write_bundled_config(&fx, "localhost:2112");
    run_apply(&fx);
    let scrape = fx.root.join("prom/selfdef.yml");
    let dashboard = fx.root.join("grafana/selfdef.json");
    assert!(scrape.exists());
    assert!(dashboard.exists());

    let out = Command::new("bash")
        .arg(module_dir().join("install/uninstall.sh"))
        .env("SELFDEF_DRY_RUN", "0")
        .env("SELFDEF_OBSERVABILITY_CONFIG", &fx.config_path)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(out.status.success(), "uninstall failed");
    assert!(!scrape.exists(), "scrape file still present");
    assert!(!dashboard.exists(), "dashboard still present");
}

/// SDD-005 D-2a / Test-1: dry-run must be a no-op on disk.
/// observability's apply writes scrape + dashboard files into
/// the configured dirs; dry-run must skip the writes.
#[test]
fn dry_run_apply_must_be_a_noop_on_disk() {
    let fx = new_fixture();
    write_bundled_config(&fx, "localhost:2112,otherhost:2112");
    let scope = fx.root.clone();
    let before = snapshot_tree(&scope);
    let out = Command::new("bash")
        .arg(module_dir().join("install/apply.sh"))
        .env("SELFDEF_DRY_RUN", "1")
        .env("SELFDEF_OBSERVABILITY_CONFIG", &fx.config_path)
        .env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "dry-run apply must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let after = snapshot_tree(&scope);
    assert_tree_unchanged(&before, &after);
}
