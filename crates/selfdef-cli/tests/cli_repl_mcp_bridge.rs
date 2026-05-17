//! SD-R101 (E8.M5) — zero-subprocess Tier 1 via SD-R94 MCP TCP bridge.
//!
//! Operator-named (§1b mandate row): "Tier 3 native pyo3 bindings
//! (zero-subprocess Tier 1)". The workspace's #![forbid(unsafe_code)]
//! rule blocks adding a pyo3 crate; this round delivers the
//! parenthetical goal — zero-subprocess Tier 1 — via the existing
//! SD-R94 MCP TCP transport.
//!
//! Tests the in-bootstrap dispatcher:
//!   - argv → MCP tool-name translation
//!   - end-to-end JSON-RPC roundtrip against a real `selfdefctl mcp
//!     serve --tcp` listener
//!   - SD-R95 history records the `transport` field
//!   - fallback to subprocess when argv is outside the MCP catalog
//!   - clear error when SELFDEF_MCP_URL is malformed

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// SD-R101 (CI hardening v2): serialize the 2 tests that spawn
/// `selfdefctl mcp serve --tcp` subprocesses. Empirically, running
/// them in parallel under cargo test on GitHub-hosted runners
/// flakes intermittently (passes on one of ubuntu-latest /
/// ubuntu-24.04, fails on the other — order varies across reruns).
/// Both tests only need ~100ms of mcp-server real-time once the
/// listener binds, so serializing them costs effectively nothing.
static MCP_TCP_TEST_LOCK: Mutex<()> = Mutex::new(());

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// SD-R101: the bootstrap script's _shutil.which("selfdefctl") only
/// finds the binary when the directory holding selfdefctl is on PATH.
/// In `cargo test` runs the binary lives under target/debug/ which
/// isn't usually exported. Return a PATH string with the binary's
/// parent directory prepended so the subprocess fallback works.
fn path_with_selfdefctl() -> String {
    let bin_dir = binary().parent().unwrap().to_path_buf();
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", bin_dir.display(), existing)
}

fn bootstrap_source() -> String {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "bootstrap"])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn wait_for_bind(port: u16, deadline: Duration) -> bool {
    let start = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    while start.elapsed() < deadline {
        if TcpListener::bind(addr).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    false
}

fn spawn_mcp_tcp(port: u16, exit_after: u32) -> Child {
    let bind = format!("127.0.0.1:{port}");
    // SD-R101 (CI hardening): inherit stderr instead of piping it so a
    // verbose MCP server (line-per-connect accept logs) can't deadlock
    // on a full pipe buffer. Output lands in the cargo test capture,
    // visible on failure.
    Command::new(binary())
        .args([
            "--config",
            "/dev/null",
            "mcp",
            "serve",
            "--tcp",
            &bind,
            "--exit-after",
            &exit_after.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn mcp serve --tcp")
}

fn run_probe_with_env(probe_body: &str, env: &[(&str, &str)]) -> (bool, String, String) {
    let src = bootstrap_source();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe_body}")).unwrap();
    let mut cmd = Command::new("python3");
    cmd.arg(&script);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn python3");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn sdr101_bootstrap_advertises_mcp_bridge() {
    let src = bootstrap_source();
    for needle in [
        "def _ctl_via_mcp(",
        "def _argv_to_mcp_call(",
        "def _record_history_v2(",
        "SELFDEF_MCP_URL",
        "SELFDEF_MCP_BEARER",
        "SD-R101",
    ] {
        assert!(
            src.contains(needle),
            "missing `{needle}` in bootstrap source"
        );
    }
}

#[test]
fn sdr101_banner_advertises_mcp_url_env() {
    let src = bootstrap_source();
    assert!(src.contains("zero-subprocess Tier 1 via MCP TCP"));
    assert!(src.contains("export SELFDEF_MCP_URL=tcp://"));
    assert!(src.contains("SELFDEF_MCP_BEARER"));
}

#[test]
fn sdr101_argv_to_mcp_call_covers_tier1_surface() {
    // Drive the in-Python translator through a probe — verifies the
    // argv shapes used by every Tier 1 callable end up in the MCP
    // tool catalog.
    let probe = r#"
def check(argv, want_name, want_extra_args=None, expect_json_arg=True):
    got = _argv_to_mcp_call(argv)
    assert got is not None, f"no mapping for {argv}"
    tn, args = got
    assert tn == want_name, (argv, tn, want_name)
    # Every translation auto-injects json=true — except for tools that
    # have no `json` knob in their MCP schema (hardware.export is
    # JSON-only by design).
    if expect_json_arg:
        assert args.get("json") is True, (argv, args)
    else:
        assert "json" not in args, (argv, args)
    if want_extra_args is not None:
        rest = {k: v for k, v in args.items() if k != "json"}
        assert rest == want_extra_args, (argv, rest, want_extra_args)

# Hardware. `hardware.export` schema has no `json` field — JSON-only.
check(("hardware", "--json"), "selfdef.hardware.export", {}, expect_json_arg=False)
check(("hardware", "posture", "--json"), "selfdef.hardware.posture")

# Modules.
check(("modules", "list", "--json"), "selfdef.modules.list", {})
check(
    ("modules", "list", "--category", "network", "--phase", "main", "--json"),
    "selfdef.modules.list",
    {"category": "network", "phase": "main"},
)
check(("modules", "info", "bridge-l2", "--json"),
      "selfdef.modules.info", {"slug": "bridge-l2"})
check(("modules", "info", "bridge-l2", "--resolved", "--json"),
      "selfdef.modules.info", {"slug": "bridge-l2", "resolved": True})
check(("modules", "diff", "--json"), "selfdef.modules.diff")
check(("modules", "install-options", "--json"), "selfdef.modules.install_options")
check(("modules", "install-plan", "--json"), "selfdef.modules.install_plan")
check(("modules", "config-scaffold", "bridge-l2", "--json"),
      "selfdef.modules.config_scaffold", {"slug": "bridge-l2"})
check(("modules", "apply-plan", "--json"), "selfdef.modules.apply_plan")

# LoRA.
check(("lora", "list", "--json"), "selfdef.models.lora.list")
check(("lora", "attach", "adapter-1", "Qwen/Qwen2-7B", "--json"),
      "selfdef.models.lora.attach",
      {"adapter_id": "adapter-1", "base_model": "Qwen/Qwen2-7B"})
check(("lora", "detach", "adapter-1", "--json"),
      "selfdef.models.lora.detach", {"adapter_id": "adapter-1"})
check(("lora", "set-status", "adapter-1", "active", "--json"),
      "selfdef.models.lora.set_status",
      {"adapter_id": "adapter-1", "status": "active"})

# REPL history.
check(("repl", "history", "--limit", "10", "--json"),
      "selfdef.repl.history", {"limit": "10"})

# Out-of-catalog argv returns None (falls back to subprocess).
assert _argv_to_mcp_call(("some-unknown-verb",)) is None
assert _argv_to_mcp_call(()) is None

print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe_with_env(probe, &[]);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"), "expected PASS; got {stdout}");
}

#[test]
fn sdr101_malformed_mcp_url_raises_clear_error() {
    let probe = r#"
try:
    _ctl_via_mcp(("hardware", "--json"), "not-a-url")
    print("SHOULD_HAVE_RAISED")
    raise SystemExit(1)
except RuntimeError as e:
    assert "tcp://" in str(e), str(e)

try:
    _ctl_via_mcp(("hardware", "--json"), "tcp://no-port")
    print("SHOULD_HAVE_RAISED")
    raise SystemExit(1)
except RuntimeError as e:
    assert "host:port" in str(e), str(e)

print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe_with_env(probe, &[]);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"));
}

#[test]
fn sdr101_end_to_end_mcp_bridge_returns_real_tool_payload() {
    // Serialize w/ the other TCP-spawning test in this file —
    // parallel execution flaked across both runners.
    let _guard = MCP_TCP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Spin up a real selfdefctl MCP TCP listener with exit_after=2 —
    // we drive one tools/call + one auth-less call from Python.
    let port = pick_port();
    let mut child = spawn_mcp_tcp(port, 4);
    let ready = wait_for_bind(port, Duration::from_secs(15));
    if !ready {
        let _ = child.kill();
        panic!("mcp serve --tcp did not bind on 127.0.0.1:{port}");
    }
    let mcp_url = format!("tcp://127.0.0.1:{port}");

    // SD-R101 CI-portability: avoid hardware-probe tools — they exit
    // with code 2 (Sain01 NoMatch) on GitHub-hosted runners since
    // those VMs aren't the operator's SAIN-01 reference rig. The MCP
    // server's handle_tools_call rejects rc!=0 + rc!=1 as -32000,
    // which propagates back as a Python RuntimeError. modules.list
    // has no hardware-verdict exit code, so it's CI-portable.
    let probe = r#"
import os, json
# Call modules.list via the MCP bridge — no hardware verdict exit.
result = _ctl_via_mcp(("modules", "list", "--json"), os.environ["SELFDEF_MCP_URL"])
assert isinstance(result, dict), f"expected dict; got {type(result).__name__}: {result!r}"
print("PASS:modules1")

# A second modules call (different argv shape).
result2 = _ctl_via_mcp(("modules", "diff", "--json"), os.environ["SELFDEF_MCP_URL"])
assert isinstance(result2, dict), result2
print("PASS:modules2")
"#;
    let path_with = path_with_selfdefctl();
    let (ok, stdout, stderr) = run_probe_with_env(
        probe,
        &[
            ("SELFDEF_MCP_URL", mcp_url.as_str()),
            ("PATH", path_with.as_str()),
        ],
    );

    // Always reap the child.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        ok,
        "MCP-bridge probe failed:\n  stdout={stdout}\n  stderr={stderr}"
    );
    assert!(
        stdout.contains("PASS:modules1"),
        "missing modules1 PASS: {stdout}"
    );
    assert!(
        stdout.contains("PASS:modules2"),
        "missing modules2 PASS: {stdout}"
    );
}

#[test]
fn sdr101_history_records_transport_field_for_mcp_calls() {
    // Serialize w/ the other TCP-spawning test in this file —
    // parallel execution flaked across both runners.
    let _guard = MCP_TCP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Verify that when SELFDEF_MCP_URL is set + SELFDEF_REPL_HISTORY
    // is set, the appended history row carries transport=mcp-tcp.
    let port = pick_port();
    let mut child = spawn_mcp_tcp(port, 4);
    let ready = wait_for_bind(port, Duration::from_secs(15));
    if !ready {
        let _ = child.kill();
        panic!("mcp serve --tcp did not bind");
    }
    let mcp_url = format!("tcp://127.0.0.1:{port}");

    let dir = tempfile::tempdir().unwrap();
    let hist_path = dir.path().join("hist.jsonl");
    // CI-portability: use modules() not hardware() — hardware probes
    // exit 2 (Sain01 NoMatch) on GitHub-hosted runners since those
    // VMs lack AVX-512 VNNI + the operator's RTX rig.
    let probe = r#"
result = modules()  # high-level Tier 1 caller — must route through MCP.
assert isinstance(result, dict), result
print("PASS")
"#;
    let src = bootstrap_source();
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe}")).unwrap();
    let out = Command::new("python3")
        .arg(&script)
        .env("SELFDEF_MCP_URL", &mcp_url)
        .env("SELFDEF_REPL_HISTORY", &hist_path)
        .env("PATH", path_with_selfdefctl())
        .output()
        .expect("spawn python3");

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        out.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let history = std::fs::read_to_string(&hist_path).expect("history file");
    assert!(
        history.contains("\"transport\": \"mcp-tcp\""),
        "expected transport=mcp-tcp in history; got: {history}"
    );
    // The SD-R95 _record_history row also lands for compatibility —
    // but the SD-R101 row MUST be present.
    assert!(
        history.contains("\"round\": \"SD-R101\""),
        "expected SD-R101 round marker in history; got: {history}"
    );
}

#[test]
fn sdr101_subprocess_path_records_transport_subprocess() {
    // No SELFDEF_MCP_URL → uses subprocess. The history row must
    // carry transport=subprocess.
    let dir = tempfile::tempdir().unwrap();
    let hist_path = dir.path().join("hist.jsonl");
    // CI-portability: see comment above — use modules() not hardware().
    let probe = r#"
# `modules()` falls back to subprocess (no MCP URL set).
result = modules()
assert isinstance(result, dict), result
print("PASS")
"#;
    let src = bootstrap_source();
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe}")).unwrap();
    let out = Command::new("python3")
        .arg(&script)
        .env("SELFDEF_REPL_HISTORY", &hist_path)
        .env("PATH", path_with_selfdefctl())
        // Explicitly clear any inherited MCP env.
        .env_remove("SELFDEF_MCP_URL")
        .output()
        .expect("spawn python3");
    assert!(
        out.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let history = std::fs::read_to_string(&hist_path).expect("history file");
    assert!(
        history.contains("\"transport\": \"subprocess\""),
        "expected transport=subprocess in history; got: {history}"
    );
}
