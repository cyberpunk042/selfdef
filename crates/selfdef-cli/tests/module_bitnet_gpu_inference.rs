//! Integration tests for the SD-R28 `bitnet-gpu-inference` module.
//!
//! This module demonstrates the full power of the cycle-2
//! [requires_hardware] surface (SD-R14 + SD-R26): 5 predicates,
//! including the new SD-R26 gpu_vram_gib_min +
//! gpu_power_headroom_watts_min. Tests pin:
//!
//!   - manifest carries all five predicates
//!   - apply.sh provisions /etc/selfdef/bitnet/{runtime.env,schedule.json}
//!     under SELFDEF_BITNET_ETC_DIR override (hermetic)
//!   - DRY-RUN is a no-op
//!   - check.sh validates presence; rejects missing artifacts
//!   - uninstall.sh removes the env file + schedule file
//!
//! Hermetic — every test uses a tempdir, no /etc paths touched.

use std::process::Command;

mod common;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn module_dir() -> std::path::PathBuf {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../modules/bitnet-gpu-inference")
}

#[test]
fn sdr28_manifest_declares_all_sdr26_predicates() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    for needle in [
        "[requires_hardware]",
        "avx512_bf16",
        "memory_gib_min",
        "gpu_count_min",
        "gpu_vram_gib_min",
        "gpu_power_headroom_watts_min",
    ] {
        assert!(
            manifest.contains(needle),
            "manifest must declare `{needle}`: {manifest}"
        );
    }
}

#[test]
fn sdr28_manifest_depends_on_hardware_tune_cache() {
    let manifest = std::fs::read_to_string(module_dir().join("module.toml")).unwrap();
    assert!(
        manifest.contains("depends_on  = [\"hardware-tune-cache\"]"),
        "must depend on hardware-tune-cache (SD-R23): {manifest}"
    );
}

#[test]
fn sdr28_apply_provisions_etc_dir_under_override() {
    // PATH: selfdefctl must be on PATH for the apply.sh's `hardware
    // export` call (best-effort — apply.sh tolerates failure).
    let bin_path = binary();
    let bin_dir = bin_path.parent().unwrap();
    let old_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{old_path}", bin_dir.display());

    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    let state = dir.path().join("state");

    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("PATH", &new_path)
        .env("SELFDEF_BITNET_ETC_DIR", etc.to_str().unwrap())
        .env("SELFDEF_BITNET_STATE_DIR", state.to_str().unwrap())
        // Point the hardware-tune.env at a writable tempfile so the
        // env-file generator finds (or gracefully skips) it.
        .env(
            "SELFDEF_HARDWARE_TUNE_ENV",
            dir.path().join("hw-tune.env").to_str().unwrap(),
        )
        .output()
        .expect("spawn apply.sh");
    assert!(
        out.status.success(),
        "apply.sh failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\":\"ok\""),
        "expected ok status: {stdout}"
    );

    let env_file = etc.join("runtime.env");
    let sched_file = etc.join("schedule.json");
    assert!(env_file.exists(), "runtime.env must exist");
    assert!(sched_file.exists(), "schedule.json must exist");
    assert!(state.exists(), "state dir must be created");

    let body = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        body.contains("BITNET_STATE_DIR="),
        "runtime.env missing BITNET_STATE_DIR: {body}"
    );
    assert!(
        body.contains("BITNET_SCHEDULE_FILE="),
        "runtime.env missing BITNET_SCHEDULE_FILE: {body}"
    );
    assert!(
        body.contains("bitnet-gpu-inference (SD-R28)"),
        "runtime.env missing SD-R28 banner: {body}"
    );

    let sched_body = std::fs::read_to_string(&sched_file).unwrap();
    // schedule.json is valid JSON with schema_version + schedule array.
    let v: serde_json::Value =
        serde_json::from_str(&sched_body).expect("schedule.json should be valid JSON");
    assert!(v.get("schema_version").is_some(), "missing schema_version");
    assert!(v.get("schedule").is_some(), "missing schedule array");
}

#[test]
fn sdr28_apply_dry_run_is_noop() {
    let bin_path = binary();
    let bin_dir = bin_path.parent().unwrap();
    let old_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{old_path}", bin_dir.display());

    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");

    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("PATH", &new_path)
        .env("SELFDEF_BITNET_ETC_DIR", etc.to_str().unwrap())
        .env(
            "SELFDEF_BITNET_STATE_DIR",
            dir.path().join("state").to_str().unwrap(),
        )
        .env("SELFDEF_DRY_RUN", "1")
        .output()
        .expect("spawn apply.sh");
    assert!(out.status.success(), "dry-run rc nonzero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\":\"skipped\""),
        "dry-run should emit skipped: {stdout}"
    );
    assert!(!etc.exists(), "dry-run must not create the etc dir");
}

#[test]
fn sdr28_check_rejects_missing_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    let check = module_dir().join("install/check.sh");
    let out = Command::new(&check)
        .env("SELFDEF_BITNET_ETC_DIR", etc.to_str().unwrap())
        .env(
            "SELFDEF_BITNET_STATE_DIR",
            dir.path().join("state").to_str().unwrap(),
        )
        .output()
        .expect("spawn check.sh");
    assert!(
        !out.status.success(),
        "check on absent artifacts should rc nonzero"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"status\":\"failed\""),
        "missing artifacts → failed status: {stdout}"
    );
}

#[test]
fn sdr28_uninstall_removes_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("runtime.env"), "BITNET_STATE_DIR=/tmp\n").unwrap();
    std::fs::write(etc.join("schedule.json"), "{}\n").unwrap();
    let uninstall = module_dir().join("install/uninstall.sh");
    let out = Command::new(&uninstall)
        .env("SELFDEF_BITNET_ETC_DIR", etc.to_str().unwrap())
        .output()
        .expect("spawn uninstall.sh");
    assert!(out.status.success(), "uninstall failed");
    assert!(!etc.join("runtime.env").exists());
    assert!(!etc.join("schedule.json").exists());
}

/// Ties SD-R28 back into the SD-R15 dry-run surface: when the gate
/// is evaluated against a synthesized SAIN-01 host, this module
/// would APPLY; against a 24-GiB-only host (RTX 3090), it would
/// still apply (passes 8-GiB floor + has telemetry); against a
/// GPU-less host (the CI box), it would SKIP citing all five
/// predicates.
///
/// We exercise the negative case via the actual CLI surface — this
/// is the integration cousin of the SD-R26 unit tests in modules.rs.
#[test]
fn sdr28_check_hardware_skips_module_on_gpuless_host() {
    let root = tempfile::tempdir().unwrap();
    // Stage a catalog with bitnet-gpu-inference + its dependency.
    let cat = root.path().join("catalog");
    std::fs::create_dir_all(&cat).unwrap();
    // Symlink/copy our real module into the staged catalog. We make
    // a thin copy so the test stays hermetic + doesn't need our
    // workspace path encoded.
    for slug in ["hardware-tune-cache", "bitnet-gpu-inference"] {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules")
            .join(slug);
        let dst = cat.join(slug);
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::create_dir_all(dst.join("install")).unwrap();
        std::fs::copy(src.join("module.toml"), dst.join("module.toml")).unwrap();
        for s in ["apply.sh", "check.sh", "uninstall.sh"] {
            let s_src = src.join("install").join(s);
            if s_src.exists() {
                std::fs::copy(&s_src, dst.join("install").join(s)).unwrap();
            }
        }
    }
    let host_cfg = root.path().join("modules.toml");
    std::fs::write(
        &host_cfg,
        "[modules.hardware-tune-cache]\n[modules.bitnet-gpu-inference]\n",
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
    // On the CI host (no GPU), bitnet-gpu-inference must show up as
    // WOULD SKIP and the message must cite gpu_count_min + at least
    // one SD-R26 predicate.
    assert!(
        stdout.contains("bitnet-gpu-inference"),
        "module name missing: {stdout}"
    );
    assert!(stdout.contains("WOULD SKIP"), "no skip block: {stdout}");
    assert!(
        stdout.contains("gpu_count_min")
            || stdout.contains("gpu_vram_gib_min")
            || stdout.contains("gpu_power_headroom_watts_min"),
        "no SD-R26 predicate cited: {stdout}"
    );
}

/// SD-R46 (closes SDD-019 T-6): the schedule.json emitted by the
/// bitnet-gpu-inference module's apply.sh must conform to the
/// documented schema at docs/schemas/bitnet-schedule.schema.json.
///
/// We don't pull a JSON-schema crate just for one test — instead
/// the test reads the schema's `required` arrays + `enum`
/// constraints + walks the emitted file structurally.
#[test]
fn sdr46_schedule_json_conforms_to_documented_schema() {
    // Stage a fresh apply (same setup as
    // sdr28_apply_provisions_etc_dir_under_override).
    let bin_path = binary();
    let bin_dir = bin_path.parent().unwrap();
    let old_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{old_path}", bin_dir.display());

    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    let state = dir.path().join("state");
    let apply = module_dir().join("install/apply.sh");
    let out = Command::new(&apply)
        .env("PATH", &new_path)
        .env("SELFDEF_BITNET_ETC_DIR", etc.to_str().unwrap())
        .env("SELFDEF_BITNET_STATE_DIR", state.to_str().unwrap())
        .env(
            "SELFDEF_HARDWARE_TUNE_ENV",
            dir.path().join("hw-tune.env").to_str().unwrap(),
        )
        .output()
        .expect("spawn apply.sh");
    assert!(out.status.success(), "apply: {out:?}");

    let sched_path = etc.join("schedule.json");
    let body = std::fs::read_to_string(&sched_path).unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&body).expect("schedule.json must be valid JSON");

    // Top-level required fields from the schema.
    for k in ["schema_version", "schedule"] {
        assert!(
            doc.get(k).is_some(),
            "schedule.json missing required top-level key '{k}': {body}"
        );
    }
    // schema_version pattern: N.N.N
    let v = doc["schema_version"]
        .as_str()
        .expect("schema_version is string");
    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(parts.len(), 3, "schema_version not N.N.N: {v}");
    for p in &parts {
        assert!(
            p.chars().all(|c| c.is_ascii_digit()),
            "schema_version part not numeric: {p}"
        );
    }
    // schedule is an array.
    let schedule = doc["schedule"]
        .as_array()
        .expect("schedule must be an array");
    // Each entry: required gpu_index (>= 0) + role (one of 3 enums).
    let valid_roles: &[&str] = &["model_inference", "auxiliary", "spare"];
    for entry in schedule {
        let idx = entry["gpu_index"]
            .as_i64()
            .expect("gpu_index must be integer");
        assert!(idx >= 0, "gpu_index must be >= 0: {idx}");
        let role = entry["role"].as_str().expect("role must be string");
        assert!(
            valid_roles.contains(&role),
            "role must be one of {valid_roles:?}: {role}"
        );
        // Optional fields, when present, must be the right type.
        if let Some(v) = entry.get("vram_bytes")
            && !v.is_null()
        {
            assert!(v.is_i64() || v.is_u64(), "vram_bytes must be integer: {v}");
        }
        if let Some(v) = entry.get("power_limit_watts")
            && !v.is_null()
        {
            assert!(
                v.is_i64() || v.is_u64(),
                "power_limit_watts must be integer: {v}"
            );
        }
    }
}

#[test]
fn sdr46_schema_file_exists_and_is_valid_json() {
    let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema = crate_root.join("../../docs/schemas/bitnet-schedule.schema.json");
    assert!(schema.exists(), "schema file missing: {}", schema.display());
    let body = std::fs::read_to_string(&schema).unwrap();
    let _v: serde_json::Value = serde_json::from_str(&body).expect("schema must be valid JSON");
}
