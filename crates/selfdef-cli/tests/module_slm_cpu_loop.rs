//! Integration tests for the SD-R72 `slm-cpu-loop` module.
//!
//! Third real selfdef demonstrator (after SD-R28 bitnet-gpu-inference
//! and SD-R48 wasm-aot-cache). Showcases the cycle-3 SD-R64 + SD-R68
//! predicates (zmm_int8_lanes_min + host_features_required) and the
//! R212 (sovereign-os) model-class taxonomy as a [metadata] hint.
//!
//! Composes with:
//!   - SD-R67 hardware posture (operator confirms VNNI lane width)
//!   - SD-R68 host_features_required (gates on avx2+fma)
//!   - R212 sovereign-os models query --class slm (model discovery)

use std::process::Command;

mod common;

fn module_dir() -> std::path::PathBuf {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../modules/slm-cpu-loop")
}

#[test]
fn sdr72_manifest_declares_cycle3_predicates() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    for needle in [
        "[requires_hardware]",
        "memory_gib_min",
        "zmm_int8_lanes_min",
        "host_features_required",
        "avx2,fma",
    ] {
        assert!(
            manifest.contains(needle),
            "manifest must declare `{needle}`: {manifest}"
        );
    }
}

#[test]
fn sdr72_manifest_carries_r212_metadata_class_hint() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    assert!(
        manifest.contains("[metadata]"),
        "module must carry [metadata] table: {manifest}"
    );
    assert!(
        manifest.contains("intended_model_class = \"slm\""),
        "must cite R212 model class taxonomy (slm): {manifest}"
    );
    assert!(
        manifest.contains("intended_purpose"),
        "must cite R212 purpose taxonomy: {manifest}"
    );
}

#[test]
fn sdr72_manifest_depends_on_hardware_tune_cache() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    assert!(
        manifest.contains("depends_on  = [\"hardware-tune-cache\"]"),
        "must depend on hardware-tune-cache: {manifest}"
    );
}

#[test]
fn sdr72_install_scripts_present_and_executable() {
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = module_dir().join("install").join(s);
        let meta = std::fs::metadata(&p)
            .unwrap_or_else(|_| panic!("missing install script: {}", p.display()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(
                meta.permissions().mode() & 0o111 != 0,
                "install script not executable: {}",
                p.display()
            );
        }
        let _ = meta;
    }
}

#[test]
fn sdr72_apply_writes_env_file_under_override() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new("bash")
        .arg(&apply)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .env("SELFDEF_DRY_RUN", "0")
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "apply.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        env_path.exists(),
        "env file missing: {}",
        env_path.display()
    );
    let body = std::fs::read_to_string(&env_path).unwrap();
    // Canonical knobs the SD-R72 contract pins
    for needle in [
        "SELFDEF_SLM_AFFINITY",
        "SELFDEF_SLM_THREADS",
        "SELFDEF_SLM_MODEL",
        "SELFDEF_SLM_MODEL_PATH",
        "SELFDEF_SLM_ENGINE",
        "SELFDEF_SLM_CONTEXT_TOKENS",
        "SELFDEF_SLM_KV_DTYPE",
        "taskset", // worked invocation example
    ] {
        assert!(
            body.contains(needle),
            "env file missing knob `{needle}`: {body}"
        );
    }
}

#[test]
fn sdr72_apply_emits_ok_json_status_line() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new("bash")
        .arg(&apply)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn apply.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(r#""module":"slm-cpu-loop""#),
        "stdout: {stdout}"
    );
    assert!(stdout.contains(r#""status":"ok""#), "stdout: {stdout}");
}

#[test]
fn sdr72_apply_dry_run_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new("bash")
        .arg(&apply)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .env("SELFDEF_DRY_RUN", "1")
        .output()
        .expect("spawn apply.sh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""status":"skipped""#), "stdout: {stdout}");
    assert!(!env_path.exists(), "DRY-RUN must not write the env file");
}

#[test]
fn sdr72_check_fails_when_env_file_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let check = module_dir().join("install/check.sh");
    let out = Command::new("bash")
        .arg(&check)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn check.sh");
    assert!(!out.status.success(), "check.sh should fail on missing env");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""status":"failed""#), "stdout: {stdout}");
    assert!(
        stdout.contains("run apply first"),
        "remediation hint missing: {stdout}"
    );
}

#[test]
fn sdr72_check_passes_after_apply() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let apply = module_dir().join("install/apply.sh");
    let check = module_dir().join("install/check.sh");
    Command::new("bash")
        .arg(&apply)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn apply.sh");
    let out = Command::new("bash")
        .arg(&check)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn check.sh");
    assert!(
        out.status.success(),
        "check.sh post-apply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""status":"ok""#), "stdout: {stdout}");
}

#[test]
fn sdr72_uninstall_removes_env_file() {
    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("slm-loop.env");
    let apply = module_dir().join("install/apply.sh");
    let uninstall = module_dir().join("install/uninstall.sh");
    Command::new("bash")
        .arg(&apply)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn apply.sh");
    assert!(env_path.exists());
    Command::new("bash")
        .arg(&uninstall)
        .env("SELFDEF_SLM_LOOP_ENV", &env_path)
        .output()
        .expect("spawn uninstall.sh");
    assert!(!env_path.exists(), "uninstall must remove env file");
}
