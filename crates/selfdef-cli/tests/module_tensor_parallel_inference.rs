//! Integration tests for the SD-R58 `tensor-parallel-inference` module.
//!
//! The third real selfdef module after SD-R28 (bitnet-gpu-inference)
//! and SD-R48 (wasm-aot-cache). Demonstrates the SD-R51 ALL-semantics
//! VRAM predicate composing with the SD-R55 [signing] block.

use std::process::Command;

mod common;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn module_dir() -> std::path::PathBuf {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../modules/tensor-parallel-inference")
}

#[test]
fn sdr58_manifest_uses_each_min_and_signing_blocks() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    for needle in [
        "gpu_count_min",
        "gpu_vram_gib_each_min",
        "avx512_bf16",
        "[signing]",
        "required = false",
    ] {
        assert!(
            manifest.contains(needle),
            "manifest must declare `{needle}`: {manifest}"
        );
    }
}

#[test]
fn sdr58_apply_provisions_etc_dir_with_slice_plan() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    let tune = dir.path().join("hw-tune.env");
    std::fs::write(&tune, "SELFDEF_HARDWARE_MARCH=znver5\n").unwrap();

    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("SELFDEF_TENSOR_PARALLEL_ETC_DIR", etc.to_str().unwrap())
        .env("SELFDEF_HARDWARE_TUNE_ENV", tune.to_str().unwrap())
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "apply failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        etc.join("slice-plan.json").exists(),
        "slice-plan.json missing"
    );
    assert!(etc.join("runtime.env").exists(), "runtime.env missing");

    // slice-plan.json is valid JSON.
    let body = std::fs::read_to_string(etc.join("slice-plan.json")).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&body).expect("slice-plan.json must be valid JSON");
    assert_eq!(v["schema_version"], "1.0.0");
    assert!(v["slices"].is_array());
    assert!(v["ranks"].is_number());
}

#[test]
fn sdr58_apply_dry_run_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("SELFDEF_TENSOR_PARALLEL_ETC_DIR", etc.to_str().unwrap())
        .env("SELFDEF_DRY_RUN", "1")
        .output()
        .expect("spawn apply.sh");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"status\":\"skipped\""), "{stdout}");
    assert!(!etc.exists(), "dry-run should not create the etc dir");
}

#[test]
fn sdr58_check_rejects_missing_etc_dir() {
    let dir = tempfile::tempdir().unwrap();
    let check = module_dir().join("install/check.sh");
    let out = Command::new(&check)
        .env(
            "SELFDEF_TENSOR_PARALLEL_ETC_DIR",
            dir.path().join("nope").to_str().unwrap(),
        )
        .output()
        .expect("spawn check.sh");
    assert!(!out.status.success(), "check should fail on absent etc");
}

#[test]
fn sdr58_info_surfaces_each_min_and_signing_block() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "info",
            "tensor-parallel-inference",
            "--dir",
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../modules")
                .to_str()
                .unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}\n{stdout}"));
    // SD-R51 predicate visible in requires_hardware
    assert_eq!(v["requires_hardware"]["gpu_vram_gib_each_min"], 16);
    // SD-R55 signing state visible
    assert_eq!(v["signing"]["state"], "signed_optional");
    assert_eq!(v["signing"]["required"], false);
}
