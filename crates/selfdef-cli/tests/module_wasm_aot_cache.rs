//! Integration tests for the SD-R48 `wasm-aot-cache` module.
//!
//! This is the second real selfdef module (after SD-R28's
//! bitnet-gpu-inference). It demonstrates the SD-R32 predicate
//! `wasm_aot_features_required` in a manifest the operator can
//! actually drop into /etc/selfdef/modules.toml.

use std::process::Command;

mod common;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn module_dir() -> std::path::PathBuf {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../modules/wasm-aot-cache")
}

#[test]
fn sdr48_manifest_declares_wasm_aot_features_required() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    for needle in [
        "[requires_hardware]",
        "avx512_vnni",
        "memory_gib_min",
        "wasm_aot_features_required",
    ] {
        assert!(
            manifest.contains(needle),
            "manifest must declare `{needle}`: {manifest}"
        );
    }
    // The SD-R32 predicate value SHOULD include +avx512bf16 — that's
    // the load-bearing claim this demonstrator makes.
    assert!(
        manifest.contains("+avx512bf16"),
        "manifest's wasm_aot_features_required should include +avx512bf16: {manifest}"
    );
}

#[test]
fn sdr48_manifest_depends_on_hardware_tune_cache() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    assert!(
        manifest.contains("depends_on  = [\"hardware-tune-cache\"]"),
        "must depend on hardware-tune-cache (SD-R23): {manifest}"
    );
}

#[test]
fn sdr48_apply_provisions_cache_dir_under_override() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm-aot");
    let tune_env = dir.path().join("hw-tune.env");
    // Pre-create a hw-tune.env so the symlink target exists.
    std::fs::write(&tune_env, "SELFDEF_HARDWARE_MARCH=znver5\n").unwrap();

    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("SELFDEF_WASM_AOT_CACHE_DIR", cache.to_str().unwrap())
        .env("SELFDEF_HARDWARE_TUNE_ENV", tune_env.to_str().unwrap())
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "apply.sh failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\":\"ok\""),
        "expected ok: {stdout}"
    );
    assert!(cache.exists(), "cache root must exist");
    assert!(cache.join("cwasm").is_dir(), "cwasm subdir must exist");
    assert!(cache.join("meta").is_dir(), "meta subdir must exist");
    // .last-tune symlink → hw-tune.env
    let last_tune = cache.join(".last-tune");
    assert!(last_tune.is_symlink(), ".last-tune must be a symlink");
    let target = std::fs::read_link(&last_tune).unwrap();
    assert_eq!(target, tune_env, "symlink target must match");
}

#[test]
fn sdr48_apply_dry_run_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm-aot");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("SELFDEF_WASM_AOT_CACHE_DIR", cache.to_str().unwrap())
        .env("SELFDEF_DRY_RUN", "1")
        .output()
        .expect("spawn apply.sh");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\":\"skipped\""),
        "expected skipped: {stdout}"
    );
    assert!(!cache.exists(), "dry-run must not create the cache");
}

#[test]
fn sdr48_check_rejects_missing_cache_dir() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm-aot");
    let check = module_dir().join("install/check.sh");
    let out = Command::new(&check)
        .env("SELFDEF_WASM_AOT_CACHE_DIR", cache.to_str().unwrap())
        .output()
        .expect("spawn check.sh");
    assert!(!out.status.success(), "check should fail on absent cache");
}

#[test]
fn sdr48_uninstall_preserves_cwasm_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm-aot");
    std::fs::create_dir_all(cache.join("cwasm")).unwrap();
    std::fs::create_dir_all(cache.join("meta")).unwrap();
    // Stage a fake cached artifact + meta entry.
    std::fs::write(cache.join("cwasm/test.cwasm"), b"fake").unwrap();
    std::fs::write(cache.join("meta/test.json"), b"{}").unwrap();
    std::fs::write(cache.join(".last-tune"), b"").unwrap();

    let uninstall = module_dir().join("install/uninstall.sh");
    let out = Command::new(&uninstall)
        .env("SELFDEF_WASM_AOT_CACHE_DIR", cache.to_str().unwrap())
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success());
    // .last-tune + meta gone
    assert!(
        !cache.join(".last-tune").exists(),
        ".last-tune should be removed"
    );
    assert!(!cache.join("meta").exists(), "meta dir should be removed");
    // cwasm artifacts preserved (operator's expensive cache stays)
    assert!(
        cache.join("cwasm/test.cwasm").exists(),
        "cwasm artifact MUST be preserved per uninstall.sh contract"
    );
}

/// SD-R48 ties back into the SD-R15 dry-run surface: on a host
/// without AVX-512 BF16 (CI runner), the module skips citing the
/// wasm_aot_features_required predicate.
#[test]
fn sdr48_check_hardware_cites_wasm_aot_features_predicate_on_gap() {
    let root = tempfile::tempdir().unwrap();
    let cat = root.path().join("catalog");
    std::fs::create_dir_all(&cat).unwrap();
    for slug in ["hardware-tune-cache", "wasm-aot-cache"] {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules")
            .join(slug);
        let dst = cat.join(slug);
        std::fs::create_dir_all(dst.join("install")).unwrap();
        std::fs::copy(src.join("module.toml"), dst.join("module.toml")).unwrap();
        for s in ["apply.sh", "check.sh", "uninstall.sh"] {
            let p = src.join("install").join(s);
            if p.exists() {
                std::fs::copy(&p, dst.join("install").join(s)).unwrap();
            }
        }
    }
    let host_cfg = root.path().join("modules.toml");
    std::fs::write(
        &host_cfg,
        "[modules.hardware-tune-cache]\n[modules.wasm-aot-cache]\n",
    )
    .unwrap();

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "check-hardware",
            "--dir",
            cat.to_str().unwrap(),
            "--host-config",
            host_cfg.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("wasm-aot-cache"),
        "module missing in output: {stdout}"
    );
    // On a CI host without AVX-512 BF16, the gate cites
    // wasm_aot_features_required OR memory_gib_min (the gate may
    // print just the first failing predicate).
    assert!(
        stdout.contains("wasm_aot_features_required")
            || stdout.contains("memory_gib_min")
            || stdout.contains("avx512_vnni"),
        "no relevant predicate cited: {stdout}"
    );
}
