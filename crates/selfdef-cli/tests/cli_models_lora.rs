//! SD-R81 (SDD-025 Y-2) — LoRA adapter state-file surface.
//! Foundation brick for the X-4 LoRA lifecycle arc. Ships only the
//! `list` verb and the on-disk JSON state-file format; attach and
//! detach land in subsequent rounds.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn write_state(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
}

#[test]
fn sdr81_lora_list_missing_state_file_is_empty_view() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    // No write — file absent.
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["models", "lora", "list", "--state", state.to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no LoRA adapters attached"),
        "expected empty-state banner: {stdout}"
    );
    assert!(
        stdout.contains(state.to_str().unwrap()),
        "expected state file path in banner: {stdout}"
    );
}

#[test]
fn sdr81_lora_list_renders_table_when_adapters_present() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    write_state(
        &state,
        r#"{
  "schema_version": "1.0.0",
  "adapters": [
    {
      "adapter_id":  "code-systems-rust",
      "base_model":  "Qwen3-Coder-32B-Instruct",
      "attached_at": "2026-05-17T04:00:00Z",
      "status":      "active"
    },
    {
      "adapter_id":  "math-proofs-v1",
      "base_model":  "DeepSeek-R1-Distill-Llama-70B-Q4_K_M",
      "attached_at": "2026-05-17T04:01:00Z",
      "status":      "active"
    }
  ]
}"#,
    );
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["models", "lora", "list", "--state", state.to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "adapter_id",
        "base_model",
        "status", // header
        "code-systems-rust",
        "Qwen3-Coder-32B-Instruct",
        "math-proofs-v1",
        "DeepSeek-R1-Distill-Llama-70B-Q4_K_M",
        "active",
        "2026-05-17T04:00:00Z",
    ] {
        assert!(stdout.contains(needle), "missing `{needle}`: {stdout}");
    }
}

#[test]
fn sdr81_lora_list_tolerates_missing_optional_fields() {
    // adapter_id + base_model required; attached_at + status default.
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    write_state(
        &state,
        r#"{
  "adapters": [
    { "adapter_id": "minimal", "base_model": "BaseX" }
  ]
}"#,
    );
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["models", "lora", "list", "--state", state.to_str().unwrap()])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("minimal"));
    assert!(stdout.contains("BaseX"));
    // attached_at empty → "?" placeholder
    assert!(
        stdout.contains("?"),
        "expected '?' placeholder for empty attached_at: {stdout}"
    );
    // status defaults to "active"
    assert!(stdout.contains("active"));
}

#[test]
fn sdr81_lora_list_json_round_trips_through_serde() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    write_state(
        &state,
        r#"{
  "schema_version": "1.0.0",
  "adapters": [
    {
      "adapter_id": "x",
      "base_model": "y",
      "attached_at": "2026-05-17T05:00:00Z",
      "status": "active"
    }
  ]
}"#,
    );
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "models",
            "lora",
            "list",
            "--state",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["schema_version"], "1.0.0");
    assert_eq!(v["adapters"][0]["adapter_id"], "x");
    assert_eq!(v["adapters"][0]["base_model"], "y");
    assert_eq!(v["adapters"][0]["status"], "active");
}

#[test]
fn sdr81_lora_list_honors_env_override() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("env-loras.json");
    write_state(
        &state,
        r#"{
  "adapters": [
    { "adapter_id": "via-env", "base_model": "BaseZ" }
  ]
}"#,
    );
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["models", "lora", "list"])
        .env("SELFDEF_LORA_STATE", state.to_str().unwrap())
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("via-env"),
        "env override not honored: {stdout}"
    );
}

#[test]
fn sdr81_lora_list_help_documents_state_flag() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["models", "lora", "list", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--state"), "help missing --state: {stdout}");
    assert!(stdout.contains("--json"), "help missing --json: {stdout}");
    assert!(
        stdout.contains("SELFDEF_LORA_STATE") || stdout.contains("loras.json"),
        "help should reference env or default path: {stdout}"
    );
}
