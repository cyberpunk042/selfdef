//! SD-R99 (E2.M6) — `selfdefctl modules features <slug>`
//! operator-pull TOML overrides per module. Operator-named (§1b
//! verbatim, mandate row): "Module features sub-configuration
//! (operator-pull TOML overrides per module)".

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Create a one-shot fixture module dir with the given module.toml body.
/// The directory name must match the manifest's `name` field — load_all
/// rejects manifests whose name diverges from their directory.
fn fixture_module(body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Extract `name = "<x>"` from the body to pick the directory name.
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

fn run(
    slug: &str,
    dir: &std::path::Path,
    config: Option<&std::path::Path>,
) -> (bool, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("--config").arg("/dev/null");
    cmd.args(["modules", "features", slug, "--dir"]).arg(dir);
    if let Some(p) = config {
        cmd.arg("--overlay").arg(p);
    }
    let out = cmd.output().expect("spawn selfdefctl");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

const FIXTURE_BODY: &str = r#"
name    = "probe-mod"
version = "0.1.0"
summary = "SD-R99 fixture"
category = "test"

[features]
threshold_pct = 25
retry_count   = 3
enabled       = true
tags          = ["default-a", "default-b"]

[features.limits]
warn = 100
critical = 200
"#;

#[test]
fn sdr99_features_with_no_overlay_returns_defaults() {
    let dir = fixture_module(FIXTURE_BODY);
    let (ok, stdout, stderr) = run("probe-mod", dir.path(), None);
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["round"], "SD-R99");
    assert_eq!(v["module"], "probe-mod");
    assert!(
        v["source"].as_str().unwrap().contains("defaults"),
        "expected (defaults) marker; got {}",
        v["source"]
    );
    assert!(v["overlay_keys"].as_array().unwrap().is_empty());
    assert_eq!(v["features"]["threshold_pct"], 25);
    assert_eq!(v["features"]["retry_count"], 3);
    assert_eq!(v["features"]["enabled"], true);
    assert_eq!(v["features"]["tags"][0], "default-a");
    assert_eq!(v["features"]["limits"]["warn"], 100);
    assert_eq!(v["features"]["limits"]["critical"], 200);
}

#[test]
fn sdr99_features_explicit_overlay_deep_merges() {
    let dir = fixture_module(FIXTURE_BODY);
    // Operator's per-module overlay — flat-table form accepted.
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        overlay.path(),
        r#"
threshold_pct = 90
[limits]
critical = 999
"#,
    )
    .unwrap();
    let (ok, stdout, stderr) = run("probe-mod", dir.path(), Some(overlay.path()));
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Operator scalar wins.
    assert_eq!(v["features"]["threshold_pct"], 90);
    // Default-only key survives.
    assert_eq!(v["features"]["retry_count"], 3);
    // Operator nested wins.
    assert_eq!(v["features"]["limits"]["critical"], 999);
    // Sibling default in same nested table preserved.
    assert_eq!(v["features"]["limits"]["warn"], 100);
    // Overlay keys advertised.
    let keys: Vec<String> = v["overlay_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert!(keys.contains(&"threshold_pct".to_string()), "{keys:?}");
    assert!(keys.contains(&"limits.critical".to_string()), "{keys:?}");
}

#[test]
fn sdr99_features_overlay_nested_under_features_table_accepted() {
    // Operators may write `[features]` at the top OR a flat table —
    // both shapes must merge identically. This guards the second
    // form (matches the manifest section name 1:1).
    let dir = fixture_module(FIXTURE_BODY);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        overlay.path(),
        r#"
[features]
threshold_pct = 77
"#,
    )
    .unwrap();
    let (ok, stdout, stderr) = run("probe-mod", dir.path(), Some(overlay.path()));
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["features"]["threshold_pct"], 77);
    assert_eq!(v["features"]["retry_count"], 3);
}

#[test]
fn sdr99_features_lists_replace_not_concatenate() {
    let dir = fixture_module(FIXTURE_BODY);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "tags = [\"only-this\"]\n").unwrap();
    let (ok, stdout, stderr) = run("probe-mod", dir.path(), Some(overlay.path()));
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let tags = v["features"]["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0], "only-this");
}

#[test]
fn sdr99_features_malformed_overlay_falls_back_to_defaults() {
    let dir = fixture_module(FIXTURE_BODY);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "this is not valid toml [[[[ }}}}\n").unwrap();
    let (ok, stdout, stderr) = run("probe-mod", dir.path(), Some(overlay.path()));
    assert!(ok, "must NOT crash on malformed overlay; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Defaults still apply.
    assert_eq!(v["features"]["threshold_pct"], 25);
    // parse_error surfaced for the operator.
    assert!(v.get("parse_error").is_some(), "expected parse_error: {v}");
    // No overlay keys were applied.
    assert!(v["overlay_keys"].as_array().unwrap().is_empty());
}

#[test]
fn sdr99_features_unknown_module_errors() {
    let dir = fixture_module(FIXTURE_BODY);
    let mut cmd = Command::new(binary());
    cmd.arg("--config").arg("/dev/null");
    cmd.args(["modules", "features", "no-such-module", "--dir"])
        .arg(dir.path());
    let out = cmd.output().expect("spawn selfdefctl");
    assert!(!out.status.success(), "should fail on unknown slug");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no module named") || err.contains("no-such-module"),
        "expected unknown-module error; got: {err}"
    );
}

#[test]
fn sdr99_features_empty_features_section_renders_clean() {
    // A module without [features] declared must still respond — empty
    // features map, defaults source.
    let dir = fixture_module(
        r#"
name    = "no-features-mod"
version = "0.1.0"
summary = "no features declared"
category = "test"
"#,
    );
    let (ok, stdout, stderr) = run("no-features-mod", dir.path(), None);
    assert!(ok, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let features = v["features"].as_object().unwrap();
    assert!(features.is_empty(), "expected empty features: {features:?}");
    assert!(v["overlay_keys"].as_array().unwrap().is_empty());
}

#[test]
fn sdr99_features_env_var_overlay_precedence() {
    // $SELFDEF_MODULE_FEATURES_<SLUG> is consulted between explicit
    // --config and /etc; verify it lands when no explicit flag.
    let dir = fixture_module(FIXTURE_BODY);
    let overlay = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(overlay.path(), "threshold_pct = 42\n").unwrap();
    let mut cmd = Command::new(binary());
    cmd.arg("--config").arg("/dev/null");
    cmd.args(["modules", "features", "probe-mod", "--dir"])
        .arg(dir.path())
        .env("SELFDEF_MODULE_FEATURES_PROBE_MOD", overlay.path());
    let out = cmd.output().expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["features"]["threshold_pct"], 42);
    // retry_count unchanged.
    assert_eq!(v["features"]["retry_count"], 3);
    // source path advertises the env-resolved file.
    assert_eq!(
        v["source"].as_str().unwrap(),
        overlay.path().display().to_string()
    );
}

#[test]
fn sdr99_features_includes_round_and_schema_version() {
    let dir = fixture_module(FIXTURE_BODY);
    let (ok, stdout, _) = run("probe-mod", dir.path(), None);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], "1.0.0");
    assert_eq!(v["round"], "SD-R99");
}
