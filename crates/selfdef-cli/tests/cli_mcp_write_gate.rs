//! SD-R96 (E7.M4) — `selfdefctl mcp serve` write-tool authorization
//! gate. Write-category tools (SD-R89 LoRA mutations) are
//! filtered out by default; opt-in via SELFDEF_MCP_ALLOW_WRITES=YES.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn rpc_exchange(requests: &[&str], extra_env: &[(&str, &str)]) -> Vec<serde_json::Value> {
    let n = requests.len();
    let mut cmd = Command::new(binary());
    cmd.arg("--config")
        .arg("/dev/null")
        .args(["mcp", "serve", "--exit-after", &n.to_string()]);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn selfdefctl");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for r in requests {
            writeln!(stdin, "{r}").unwrap();
        }
    }
    let out = child.wait_with_output().expect("wait");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("response not JSON"))
        .collect()
}

#[test]
fn sdr96_tools_list_default_excludes_write_tools() {
    let resps = rpc_exchange(
        &[r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#],
        &[],
    );
    let result = &resps[0]["result"];
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    // Read-only tool present.
    assert!(names.contains(&"selfdef.modules.list"), "{names:?}");
    // Write tools EXCLUDED by default.
    for write_tool in [
        "selfdef.models.lora.attach",
        "selfdef.models.lora.detach",
        "selfdef.models.lora.set_status",
    ] {
        assert!(
            !names.contains(&write_tool),
            "default tools/list must NOT contain {write_tool}: {names:?}"
        );
    }
    // x_selfdef_writes_allowed surfaces.
    assert_eq!(result["x_selfdef_writes_allowed"], false);
    // Every tool carries its category.
    for t in tools {
        assert_eq!(t["x_selfdef_category"], "read-only", "{t}");
    }
}

#[test]
fn sdr96_tools_list_with_env_gate_includes_write_tools() {
    let resps = rpc_exchange(
        &[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#],
        &[("SELFDEF_MCP_ALLOW_WRITES", "YES")],
    );
    let result = &resps[0]["result"];
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    // Write tools NOW present.
    for write_tool in [
        "selfdef.models.lora.attach",
        "selfdef.models.lora.detach",
        "selfdef.models.lora.set_status",
    ] {
        assert!(
            names.contains(&write_tool),
            "gated tools/list MUST contain {write_tool}: {names:?}"
        );
    }
    assert_eq!(result["x_selfdef_writes_allowed"], true);
    // Per-tool category attribution still present.
    let attach = tools
        .iter()
        .find(|t| t["name"] == "selfdef.models.lora.attach")
        .unwrap();
    assert_eq!(attach["x_selfdef_category"], "write");
}

#[test]
fn sdr96_tools_list_env_non_yes_value_treated_as_off() {
    for v in ["yes", "true", "1", "Y", ""] {
        let resps = rpc_exchange(
            &[r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#],
            &[("SELFDEF_MCP_ALLOW_WRITES", v)],
        );
        let result = &resps[0]["result"];
        assert_eq!(
            result["x_selfdef_writes_allowed"], false,
            "value {v:?} must NOT count as opt-in (only literal 'YES' does)"
        );
    }
}

#[test]
fn sdr96_tools_call_write_tool_default_returns_write_gated_error() {
    // Without SELFDEF_MCP_ALLOW_WRITES=YES, calling a write tool
    // returns the new -32604 code with the actionable env hint.
    let resps = rpc_exchange(
        &[
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"selfdef.models.lora.attach","arguments":{"adapter_id":"x","base_model":"y"}}}"#,
        ],
        &[],
    );
    let r = &resps[0];
    assert!(r["result"].is_null(), "{r}");
    let err = &r["error"];
    assert_eq!(err["code"], -32604, "{r}");
    let msg = err["message"].as_str().unwrap();
    assert!(msg.contains("write-category"), "{msg}");
    assert!(msg.contains("SELFDEF_MCP_ALLOW_WRITES"), "{msg}");
}

#[test]
fn sdr96_tools_call_unknown_tool_still_returns_dash_32601() {
    // -32601 reserved for "tool not exposed" (legitimately doesn't
    // exist), distinct from -32604 (write-gated).
    let resps = rpc_exchange(
        &[
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"selfdef.nonexistent.fictional","arguments":{}}}"#,
        ],
        &[],
    );
    let r = &resps[0];
    assert_eq!(r["error"]["code"], -32601);
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not exposed")
    );
}

#[test]
fn sdr96_tools_call_write_tool_with_gate_dispatches() {
    // With the gate ON, a write tool actually dispatches (call lora
    // attach pointed at a tmp state file so the call doesn't corrupt
    // a real state).
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("loras.json");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"selfdef.models.lora.attach","arguments":{{"adapter_id":"gated-test","base_model":"base/gate","state":"{}","json":true}}}}}}"#,
        state_path.to_str().unwrap()
    );
    let resps = rpc_exchange(&[req.as_str()], &[("SELFDEF_MCP_ALLOW_WRITES", "YES")]);
    let r = &resps[0];
    assert!(r["error"].is_null() || r["error"]["code"].is_null(), "{r}");
    let result = &r["result"];
    assert!(result["content"].is_array(), "{r}");
    assert_eq!(result["exit_code"], 0);
    // The attach actually wrote the state file.
    assert!(state_path.exists());
    let body = std::fs::read_to_string(&state_path).unwrap();
    assert!(body.contains("gated-test"), "{body}");
}
