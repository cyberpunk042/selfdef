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

/// SD-R60 (closes SDD-021 W-1): the slice-plan.json emitted by
/// the tensor-parallel-inference module's apply.sh must conform
/// to the documented schema at
/// docs/schemas/tensor-parallel-slice-plan.schema.json.
#[test]
fn sdr60_slice_plan_conforms_to_documented_schema() {
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
    assert!(out.status.success());

    let body = std::fs::read_to_string(etc.join("slice-plan.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Required top-level keys
    for k in ["schema_version", "ranks", "slices"] {
        assert!(
            doc.get(k).is_some(),
            "slice-plan.json missing required top-level key '{k}': {body}"
        );
    }
    // schema_version is N.N.N
    let v = doc["schema_version"]
        .as_str()
        .expect("schema_version is string");
    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(parts.len(), 3, "schema_version not N.N.N: {v}");
    for p in &parts {
        assert!(p.chars().all(|c| c.is_ascii_digit()), "non-numeric: {p}");
    }
    // ranks is non-negative integer
    let ranks = doc["ranks"].as_i64().expect("ranks must be integer");
    assert!(ranks >= 0, "ranks must be >= 0: {ranks}");
    // slices array entries each have rank/gpu_index/share_pct
    let slices = doc["slices"].as_array().expect("slices must be array");
    for entry in slices {
        let rank = entry["rank"].as_i64().expect("rank must be integer");
        assert!(rank >= 0, "rank must be >= 0: {rank}");
        let gpu = entry["gpu_index"]
            .as_i64()
            .expect("gpu_index must be integer");
        assert!(gpu >= 0, "gpu_index must be >= 0: {gpu}");
        let share = entry["share_pct"]
            .as_i64()
            .expect("share_pct must be integer");
        assert!(
            (0..=100).contains(&share),
            "share_pct must be in [0, 100]: {share}"
        );
    }
}

#[test]
fn sdr60_slice_plan_schema_file_exists_and_is_valid_json() {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema = crate_root.join("../../docs/schemas/tensor-parallel-slice-plan.schema.json");
    assert!(schema.exists(), "schema missing: {}", schema.display());
    let body = std::fs::read_to_string(&schema).unwrap();
    let _v: serde_json::Value = serde_json::from_str(&body).expect("schema must be valid JSON");
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
