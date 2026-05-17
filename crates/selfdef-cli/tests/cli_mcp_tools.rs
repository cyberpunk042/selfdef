//! SD-R84 (SDD-026 Z-11 foundation) — `selfdefctl mcp tools` MCP
//! tool manifest surface. Verifies CLI dispatch + the two render
//! shapes (JSON default + --human terminal-readable).

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

#[test]
fn sdr84_mcp_tools_default_emits_json_manifest() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "tools"])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["schema_version"], "1.0.0");
    assert_eq!(v["round"], "SD-R84");
    let arr = v["tools"].as_array().expect("tools array");
    assert!(arr.len() >= 6, "expected ≥6 tools, got {}", arr.len());
}

#[test]
fn sdr84_mcp_tools_human_renders_table_with_backing_cli() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "tools", "--human"])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("SD-R84 selfdef MCP tool manifest"),
        "{stdout}"
    );
    assert!(
        stdout.contains("doctrine: read-only verbs only in cycle 8"),
        "{stdout}"
    );
    // Curated cycle-8 tools — at least these load-bearing names must
    // surface in --human output.
    for needle in [
        "selfdef.hardware.posture",
        "selfdef.modules.list",
        "selfdef.modules.diff",
        "selfdef.models.lora.list",
    ] {
        assert!(stdout.contains(needle), "missing tool {needle}: {stdout}");
    }
    // Backing CLI invocations are quoted verbatim so operators
    // know what the future server runs internally.
    assert!(
        stdout.contains("selfdefctl modules diff"),
        "backing_cli missing: {stdout}"
    );
}

#[test]
fn sdr84_mcp_tools_every_entry_has_well_formed_input_schema() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "tools"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    for t in v["tools"].as_array().unwrap() {
        let schema = &t["input_schema"];
        assert_eq!(schema["type"], "object", "tool {}: {schema}", t["name"]);
        assert_eq!(
            schema["additionalProperties"], false,
            "tool {} schema must lock down additionalProperties: {schema}",
            t["name"]
        );
        assert!(t["name"].is_string());
        assert!(t["description"].is_string());
        assert!(t["backing_cli"].is_string());
        assert_eq!(t["category"], "read-only");
    }
}

#[test]
fn sdr84_mcp_tools_help_documents_subcommand() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "tools", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--human"), "{stdout}");
}
