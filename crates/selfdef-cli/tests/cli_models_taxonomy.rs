//! SD-R71 — `selfdefctl models list` surfaces the R212 model-class
//! taxonomy (class, size_class, quantization/weight_format) so the
//! selfdef-side registry stays operator-readable in lockstep with the
//! sovereign-os catalog.
//!
//! Cross-repo doctrine: SDD-022 (hardware-exploit + cross-repo
//! mirror cadence) + sovereign-os schemas/model-catalog.schema.yaml
//! 1.1.0 (R212). This test pins the surface so a future round can't
//! silently regress.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Registry layout: `<dir>/<slug>/model.toml` per SD-R34. Each test
/// scaffolds its own per-slug subdir.
fn write_registry(dir: &std::path::Path, slug: &str, body: &str) {
    let sub = dir.join(slug);
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("model.toml"), body).unwrap();
}

#[test]
fn sdr71_models_list_renders_taxonomy_columns() {
    let dir = tempfile::tempdir().unwrap();
    // Two registry entries — one ternary-lm + one rlm — exercising
    // distinct R212 class / size_class / quantization values.
    write_registry(
        dir.path(),
        "bitnet-1p58-2b",
        r#"
[model]
name           = "bitnet-1p58-2b"
version        = "0.1.0"
summary        = "Ternary LM demonstrator"
weight_format  = "ternary-1.58bit"
size_bytes     = 1500000000
class          = "ternary-lm"
size_class     = "s"
purpose        = ["chat", "agent"]
vram_gib_min   = 1.5
context_window_tokens = 4096
"#,
    );
    write_registry(
        dir.path(),
        "deepseek-r1-70b",
        r#"
[model]
name           = "deepseek-r1-70b"
version        = "1.0.0"
summary        = "Reasoning LM"
weight_format  = "gguf-q4_k_m"
size_bytes     = 42000000000
class          = "rlm"
size_class     = "xl"
purpose        = ["reasoning"]
vram_gib_min   = 42.0
context_window_tokens = 131072
"#,
    );

    let out = Command::new(binary())
        .args(["models", "list", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Header columns include the R212 fields.
    assert!(stdout.contains("class"), "missing 'class' header: {stdout}");
    assert!(
        stdout.contains("size"),
        "missing 'size' (size_class) header: {stdout}"
    );
    assert!(stdout.contains("quant"), "missing 'quant' header: {stdout}");
    // Per-row taxonomy values render.
    assert!(
        stdout.contains("ternary-lm"),
        "ternary-lm row missing: {stdout}"
    );
    assert!(stdout.contains("rlm"), "rlm row missing: {stdout}");
    assert!(
        stdout.contains("ternary-1.58bit"),
        "quant ternary-1.58bit missing: {stdout}"
    );
    assert!(
        stdout.contains("gguf-q4_k_m"),
        "quant gguf-q4_k_m missing: {stdout}"
    );
    // size_class column shows xs/s/m/l/xl/xxl
    assert!(stdout.contains(" s "), "size_class 's' missing: {stdout}");
    assert!(stdout.contains(" xl "), "size_class 'xl' missing: {stdout}");
}

#[test]
fn sdr71_models_list_tolerates_pre_r71_registries() {
    // Pre-SD-R71 registry: no class / size_class / purpose fields.
    // The list verb MUST still render — fields default to "?" /
    // empty, never crash on the operator's older registries.
    let dir = tempfile::tempdir().unwrap();
    write_registry(
        dir.path(),
        "legacy-model",
        r#"
[model]
name           = "legacy-model"
version        = "0.0.1"
summary        = "Pre-SD-R71 entry"
weight_format  = "fp16"
size_bytes     = 5000000000
"#,
    );
    let out = Command::new(binary())
        .args(["models", "list", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("legacy-model"),
        "missing legacy model: {stdout}"
    );
    // class column shows "?" for missing field — operator sees the
    // gap explicitly + can fill it in their next registry update.
    assert!(stdout.contains("?"), "fallback '?' missing: {stdout}");
}

#[test]
fn sdr71_models_list_handles_lora_adapter_with_base_model() {
    let dir = tempfile::tempdir().unwrap();
    write_registry(
        dir.path(),
        "code-lora",
        r#"
[model]
name           = "code-lora"
version        = "0.1.0"
summary        = "LoRA adapter demo"
weight_format  = "bf16"
size_bytes     = 50000000
class          = "lora-adapter"
size_class     = "xs"
purpose        = ["code"]
vram_gib_min   = 0.5
base_model     = "Qwen3-Coder-32B-Instruct"
"#,
    );
    let out = Command::new(binary())
        .args(["models", "list", "--dir", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("code-lora"));
    assert!(stdout.contains("lora-adapter"));
}
