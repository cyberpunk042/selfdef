//! SD-R100 (E2.M7) — Advanced module-features lifecycle. Operator-named
//! (§1b verbatim, mandate row): "Advanced module-features lifecycle
//! (enable/disable individual features within a module)".
//!
//! Three surfaces under test:
//!   - `selfdefctl modules features <slug> --enabled-only / --disabled-only`
//!   - `selfdefctl modules feature-set <slug> <key> <value>`
//!   - `selfdefctl modules feature-clear <slug> <key>`

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn fixture_module(body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let name = body
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("name").and_then(|rest| {
                let rest = rest.trim_start().strip_prefix('=')?.trim();
                let rest = rest.trim_start_matches('"');
                rest.find('"').map(|end| &rest[..end])
            })
        })
        .expect("fixture body must declare name");
    let mdir = dir.path().join(name);
    std::fs::create_dir(&mdir).unwrap();
    std::fs::write(mdir.join("module.toml"), body).unwrap();
    dir
}

const FIXTURE: &str = r#"
name    = "lifecycle-mod"
version = "0.1.0"
summary = "SD-R100 fixture"
category = "test"

[features]
auditd                = true
fail2ban              = true
unattended_upgrades   = false
retry_count           = 3
notes                 = "boolean-only filter must drop strings"

[features.advanced]
deep_scan          = true
experimental_hash  = false
budget_pct         = 25
"#;

fn run_features(slug: &str, dir: &std::path::Path, extra: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("--config")
        .arg("/dev/null")
        .args(["modules", "features", slug, "--dir"])
        .arg(dir);
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd.output().expect("spawn selfdefctl");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn sdr100_features_enabled_only_emits_only_true_booleans() {
    let dir = fixture_module(FIXTURE);
    let (ok, stdout, stderr) = run_features("lifecycle-mod", dir.path(), &["--enabled-only"]);
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["round"], "SD-R100");
    assert_eq!(v["filter"], "enabled-only");
    let feats = v["features"].as_object().unwrap();
    // Booleans true at the root.
    assert_eq!(feats.get("auditd"), Some(&serde_json::json!(true)));
    assert_eq!(feats.get("fail2ban"), Some(&serde_json::json!(true)));
    // False booleans dropped.
    assert!(feats.get("unattended_upgrades").is_none(), "{feats:?}");
    // Non-boolean leaves dropped — lifecycle is per-toggle, not per-knob.
    assert!(feats.get("retry_count").is_none(), "{feats:?}");
    assert!(feats.get("notes").is_none(), "{feats:?}");
    // Nested table — only deep_scan (true) survives.
    let advanced = feats.get("advanced").unwrap().as_object().unwrap();
    assert_eq!(advanced.get("deep_scan"), Some(&serde_json::json!(true)));
    assert!(advanced.get("experimental_hash").is_none(), "{advanced:?}");
    assert!(advanced.get("budget_pct").is_none(), "{advanced:?}");
}

#[test]
fn sdr100_features_disabled_only_emits_only_false_booleans() {
    let dir = fixture_module(FIXTURE);
    let (ok, stdout, stderr) = run_features("lifecycle-mod", dir.path(), &["--disabled-only"]);
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["filter"], "disabled-only");
    let feats = v["features"].as_object().unwrap();
    assert_eq!(
        feats.get("unattended_upgrades"),
        Some(&serde_json::json!(false))
    );
    assert!(feats.get("auditd").is_none());
    assert!(feats.get("fail2ban").is_none());
    let advanced = feats.get("advanced").unwrap().as_object().unwrap();
    assert_eq!(
        advanced.get("experimental_hash"),
        Some(&serde_json::json!(false))
    );
    assert!(advanced.get("deep_scan").is_none());
}

#[test]
fn sdr100_features_enabled_and_disabled_are_mutually_exclusive() {
    let dir = fixture_module(FIXTURE);
    let mut cmd = Command::new(binary());
    cmd.arg("--config")
        .arg("/dev/null")
        .args(["modules", "features", "lifecycle-mod", "--dir"])
        .arg(dir.path())
        .args(["--enabled-only", "--disabled-only"]);
    let out = cmd.output().expect("spawn selfdefctl");
    assert!(
        !out.status.success(),
        "clap should reject the mutex flag pair"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot be used with") || err.contains("conflict"),
        "expected clap mutex error; got: {err}"
    );
}

#[test]
fn sdr100_feature_set_writes_overlay_with_boolean() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    // Start with an empty overlay file.
    std::fs::write(overlay.path(), "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-set",
            "lifecycle-mod",
            "auditd",
            "false",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["round"], "SD-R100");
    assert_eq!(v["set"]["key"], "auditd");
    assert_eq!(v["set"]["value"], false);

    let written = std::fs::read_to_string(overlay.path()).unwrap();
    assert!(written.contains("auditd"), "{written}");
    assert!(written.contains("false"), "{written}");

    // Now `features` shows the operator override winning.
    let (ok, stdout, _) = run_features(
        "lifecycle-mod",
        dir.path(),
        &["--overlay", &overlay.path().display().to_string()],
    );
    assert!(ok);
    let v2: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v2["features"]["auditd"], false);
    assert!(
        v2["overlay_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "auditd"),
        "overlay_keys must list auditd: {}",
        v2["overlay_keys"]
    );
}

#[test]
fn sdr100_feature_set_supports_dotted_keys_and_creates_tables() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "").unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-set",
            "lifecycle-mod",
            "advanced.deep_scan",
            "false",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Confirm the overlay parses + the nested key won.
    let (ok, stdout, _) = run_features(
        "lifecycle-mod",
        dir.path(),
        &["--overlay", &overlay.path().display().to_string()],
    );
    assert!(ok, "{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["features"]["advanced"]["deep_scan"], false);
    // Sibling default preserved.
    assert_eq!(v["features"]["advanced"]["budget_pct"], 25);
    assert!(
        v["overlay_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "advanced.deep_scan"),
        "overlay_keys must include `advanced.deep_scan`: {}",
        v["overlay_keys"]
    );
}

#[test]
fn sdr100_feature_set_accepts_non_boolean_scalars() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "").unwrap();

    for (key, value, want_json) in [
        ("retry_count", "9", serde_json::json!(9)),
        ("notes", "\"new value\"", serde_json::json!("new value")),
        ("advanced.budget_pct", "75", serde_json::json!(75)),
    ] {
        let out = Command::new(binary())
            .arg("--config")
            .arg("/dev/null")
            .args([
                "modules",
                "feature-set",
                "lifecycle-mod",
                key,
                value,
                "--dir",
            ])
            .arg(dir.path())
            .arg("--overlay")
            .arg(overlay.path())
            .output()
            .expect("spawn selfdefctl");
        assert!(
            out.status.success(),
            "set {key}={value} failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = want_json;
    }

    let (ok, stdout, _) = run_features(
        "lifecycle-mod",
        dir.path(),
        &["--overlay", &overlay.path().display().to_string()],
    );
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["features"]["retry_count"], 9);
    assert_eq!(v["features"]["notes"], "new value");
    assert_eq!(v["features"]["advanced"]["budget_pct"], 75);
}

#[test]
fn sdr100_feature_set_rejects_malformed_scalar() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "").unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-set",
            "lifecycle-mod",
            "auditd",
            "[unterminated",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(!out.status.success(), "should reject malformed TOML scalar");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("invalid TOML scalar") || err.contains("TOML"),
        "expected scalar-parse error; got: {err}"
    );
}

#[test]
fn sdr100_feature_clear_removes_key_idempotently() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        overlay.path(),
        "auditd = false\n[advanced]\ndeep_scan = false\n",
    )
    .unwrap();

    // First clear — should succeed and report cleared=true.
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-clear",
            "lifecycle-mod",
            "auditd",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["cleared"], true);
    let body = std::fs::read_to_string(overlay.path()).unwrap();
    assert!(!body.contains("auditd"), "expected auditd removed: {body}");
    // advanced.deep_scan still present.
    assert!(body.contains("deep_scan"), "{body}");

    // Second clear of the same (now-absent) key — idempotent, cleared=false.
    let out2 = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-clear",
            "lifecycle-mod",
            "auditd",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(out2.status.success());
    let v2: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out2.stdout)).unwrap();
    assert_eq!(v2["cleared"], false);
}

#[test]
fn sdr100_feature_clear_handles_dotted_key() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        overlay.path(),
        "[advanced]\ndeep_scan = false\nbudget_pct = 99\n",
    )
    .unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-clear",
            "lifecycle-mod",
            "advanced.deep_scan",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let body = std::fs::read_to_string(overlay.path()).unwrap();
    assert!(!body.contains("deep_scan"), "{body}");
    assert!(body.contains("budget_pct"), "{body}");
}

#[test]
fn sdr100_feature_clear_no_overlay_is_no_op() {
    let dir = fixture_module(FIXTURE);
    let nowhere = dir.path().join("does-not-exist.toml");
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-clear",
            "lifecycle-mod",
            "auditd",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(&nowhere)
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["cleared"], false);
    assert_eq!(v["overlay_present"], false);
    // The file MUST NOT have been created.
    assert!(!nowhere.exists(), "no-op clear must not create the file");
}

#[test]
fn sdr100_feature_set_rejects_unknown_module() {
    let dir = fixture_module(FIXTURE);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "feature-set",
            "no-such-module",
            "k",
            "true",
            "--dir",
        ])
        .arg(dir.path())
        .arg("--overlay")
        .arg(overlay.path())
        .output()
        .expect("spawn selfdefctl");
    assert!(!out.status.success(), "must fail on unknown module");
}
