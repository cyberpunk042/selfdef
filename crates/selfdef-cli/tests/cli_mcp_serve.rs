//! SD-R91 (SDD-026 Z-11 closure) — `selfdefctl mcp serve` stdio
//! JSON-RPC MCP server. Implements initialize / tools/list /
//! tools/call. Cycle-8 read-only doctrine: write-category tools are
//! NOT in tools/list and return -32601 on tools/call.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Pipe `requests` (one JSON-RPC message per element) into `mcp serve
/// --exit-after N`. Returns parsed responses (one per request).
fn rpc_exchange(requests: &[&str]) -> Vec<serde_json::Value> {
    let n = requests.len();
    let mut child = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "serve", "--exit-after", &n.to_string()])
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
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("response not JSON"))
        .collect()
}

#[test]
fn sdr91_initialize_returns_server_info() {
    let resps = rpc_exchange(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#]);
    assert_eq!(resps.len(), 1);
    let r = &resps[0];
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 1);
    let info = &r["result"]["serverInfo"];
    assert_eq!(info["name"], "selfdefctl-mcp");
    assert!(info["version"].is_string());
    assert!(r["result"]["protocolVersion"].is_string());
    assert_eq!(r["result"]["capabilities"]["tools"]["listChanged"], false);
}

#[test]
fn sdr91_tools_list_exposes_only_read_only_tools() {
    let resps = rpc_exchange(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#]);
    let tools = resps[0]["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty(), "tools/list must return ≥1 tool");
    // A handful of expected read-only tools must surface.
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for needle in [
        "selfdef.hardware.posture",
        "selfdef.modules.list",
        "selfdef.modules.diff",
        "selfdef.modules.install_options",
        "selfdef.modules.install_plan",
        "selfdef.repl.tier2_examples",
    ] {
        assert!(names.contains(&needle), "missing tool {needle}: {names:?}");
    }
    // SD-R89 write tools (cycle-8 doctrine) must NOT be exposed.
    for write_tool in [
        "selfdef.models.lora.attach",
        "selfdef.models.lora.detach",
        "selfdef.models.lora.set_status",
    ] {
        assert!(
            !names.contains(&write_tool),
            "write tool {write_tool} should not be in tools/list"
        );
    }
    // Every tool has a well-formed inputSchema (passes existing
    // SD-R84 contract: type=object + additionalProperties=false).
    for t in tools {
        assert!(t["name"].is_string());
        assert!(t["description"].is_string());
        assert_eq!(t["inputSchema"]["type"], "object", "{t}");
        assert_eq!(t["inputSchema"]["additionalProperties"], false, "{t}");
    }
}

#[test]
fn sdr91_tools_call_dispatches_to_selfdefctl_subprocess() {
    // Use selfdef.repl.tier2_examples — it's a pure CLI verb (no host
    // probing) so rc is deterministic across runners. The
    // selfdef.hardware.posture tool can rc=2 (NoMatch) on hosts
    // without AVX-512 (typical CI runner), which would surface as an
    // MCP error rather than the success path this test exercises.
    let resps = rpc_exchange(&[
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"selfdef.repl.tier2_examples","arguments":{"json":true}}}"#,
    ]);
    let r = &resps[0];
    assert_eq!(r["id"], 3);
    let result = &r["result"];
    // Spec MCP shape: { content: [...], isError, exit_code }
    let content = result["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    let text = content[0]["text"].as_str().expect("text");
    // tier2_examples --json returns the inventory with stable shape.
    let inv: serde_json::Value = serde_json::from_str(text).expect("examples JSON");
    assert_eq!(inv["round"], "SD-R90");
    assert!(inv["examples"].is_array());
    assert_eq!(result["isError"], false);
    assert_eq!(result["exit_code"], 0);
}

#[test]
fn sdr91_tools_call_write_tool_returns_write_gated() {
    // SD-R96 (E7.M4) refined the rejection semantics: write tools
    // now return -32604 with the actionable env-flag hint instead
    // of the generic -32601. The behavior (rejection by default)
    // is unchanged from SD-R91.
    let resps = rpc_exchange(&[
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"selfdef.models.lora.attach","arguments":{"adapter_id":"x","base_model":"y"}}}"#,
    ]);
    let r = &resps[0];
    assert_eq!(r["id"], 4);
    assert!(r["result"].is_null());
    assert_eq!(r["error"]["code"], -32604, "{r}");
    let msg = r["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("write-category") && msg.contains("SELFDEF_MCP_ALLOW_WRITES"),
        "expected write-gate hint; got: {msg}"
    );
}

#[test]
fn sdr91_unknown_method_returns_method_not_found() {
    let resps =
        rpc_exchange(&[r#"{"jsonrpc":"2.0","id":5,"method":"nonexistent/method","params":{}}"#]);
    let r = &resps[0];
    assert_eq!(r["error"]["code"], -32601);
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Method not found")
    );
}

#[test]
fn sdr91_parse_error_returns_dash_32700() {
    let resps = rpc_exchange(&["not valid json at all"]);
    let r = &resps[0];
    assert_eq!(r["error"]["code"], -32700);
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Parse error")
    );
}

#[test]
fn sdr91_handles_multiple_requests_in_one_session() {
    // tier2_examples is deterministic across runners; use it instead
    // of hardware.posture which can rc=2 on non-AVX-512 hosts.
    let resps = rpc_exchange(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"selfdef.repl.tier2_examples","arguments":{"json":true}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"shutdown","params":{}}"#,
    ]);
    assert_eq!(resps.len(), 4);
    assert_eq!(resps[0]["id"], 1);
    assert_eq!(resps[1]["id"], 2);
    assert_eq!(resps[2]["id"], 3);
    assert_eq!(resps[3]["id"], 4);
    assert!(resps[3]["result"].is_null());
}

#[test]
fn sdr91_tools_call_with_required_arg_missing_returns_invalid_params() {
    // selfdef.modules.info requires `slug`. Call without it.
    let resps = rpc_exchange(&[
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"selfdef.modules.info","arguments":{}}}"#,
    ]);
    let r = &resps[0];
    // Either subprocess returns rc=2 (translated to -32000) or our
    // argv builder catches it as -32602. Both are valid signals.
    assert!(r["error"].is_object(), "{r}");
    let code = r["error"]["code"].as_i64().unwrap();
    assert!(code == -32602 || code == -32000, "got {code}");
}
