//! SD-R94 (SDD-026 Z-11 TCP transport) — `selfdefctl mcp serve --tcp`.
//! Binds a TCP listener, dispatches each connection through the same
//! per-line/per-LSP-message machinery stdio uses. Cycle-8 doctrine:
//! read-only tools only; per-connection Bearer-style auth optional.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Allocate an ephemeral port the OS picks for us.
fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

/// Poll until the server binds. We DON'T actually connect (would
/// consume a connection slot when exit_after is small); instead we
/// check whether the bind would fail (kernel reports EADDRINUSE
/// when the server is holding the port).
fn wait_for_bind(port: u16, deadline: Duration) -> bool {
    let start = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    while start.elapsed() < deadline {
        // If we CAN'T bind, the server is holding the port → ready.
        if TcpListener::bind(addr).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn spawn_tcp_server(port: u16, extra_args: &[&str]) -> Child {
    spawn_tcp_server_env(port, extra_args, &[])
}

fn spawn_tcp_server_env(port: u16, extra_args: &[&str], env: &[(&str, &str)]) -> Child {
    let bind = format!("127.0.0.1:{port}");
    let mut args: Vec<&str> = vec!["--config", "/dev/null", "mcp", "serve", "--tcp", &bind];
    args.extend_from_slice(extra_args);
    let mut cmd = Command::new(binary());
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn selfdefctl")
}

fn send_line(port: u16, line: &str) -> String {
    let mut s = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(5),
    )
    .expect("tcp connect");
    s.write_all(line.as_bytes()).expect("write");
    s.write_all(b"\n").expect("nl");
    s.shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read");
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn sdr94_tcp_initialize_round_trip_no_auth() {
    let port = pick_port();
    let mut child = spawn_tcp_server(port, &["--exit-after", "1"]);
    assert!(
        wait_for_bind(port, Duration::from_secs(5)),
        "server did not bind on {port}"
    );
    let resp = send_line(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    let _ = child.wait();
    let line = resp.lines().next().expect("response line");
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"]["serverInfo"]["name"], "selfdefctl-mcp");
}

#[test]
fn sdr94_tcp_auth_required_missing_preamble_returns_unauthorized() {
    let port = pick_port();
    let mut child = spawn_tcp_server_env(
        port,
        &["--token-env", "SDR94_TEST_TOKEN", "--exit-after", "1"],
        &[("SDR94_TEST_TOKEN", "secret-r94")],
    );
    assert!(wait_for_bind(port, Duration::from_secs(5)));
    // Skip the Authorization preamble.
    let resp = send_line(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    let _ = child.wait();
    let line = resp.lines().next().expect("response");
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
    assert_eq!(v["error"]["code"], -32001);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unauthorized")
    );
}

#[test]
fn sdr94_tcp_auth_correct_preamble_handles_requests() {
    let port = pick_port();
    let mut child = spawn_tcp_server_env(
        port,
        &["--token-env", "SDR94_TEST_TOKEN", "--exit-after", "1"],
        &[("SDR94_TEST_TOKEN", "secret-r94")],
    );
    assert!(wait_for_bind(port, Duration::from_secs(5)));
    // Send Authorization line then a JSON-RPC request.
    let mut s = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(5),
    )
    .expect("connect");
    s.write_all(b"Authorization: Bearer secret-r94\n").unwrap();
    s.write_all(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#)
        .unwrap();
    s.write_all(b"\n").unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let _ = child.wait();
    let resp = String::from_utf8_lossy(&buf).into_owned();
    let line = resp.lines().next().expect("response");
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
    assert_eq!(v["id"], 2);
    let tools = v["result"]["tools"].as_array().expect("tools array");
    assert!(!tools.is_empty());
}

#[test]
fn sdr94_tcp_bad_framing_returns_rc2() {
    let port = pick_port();
    let out = Command::new(binary())
        .args([
            "--config",
            "/dev/null",
            "mcp",
            "serve",
            "--tcp",
            &format!("127.0.0.1:{port}"),
            "--framing",
            "nope",
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn sdr94_tcp_bind_failure_returns_rc2() {
    // Bind a TcpListener first, then have selfdefctl try to bind the
    // same port → second bind fails.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let out = Command::new(binary())
        .args([
            "--config",
            "/dev/null",
            "mcp",
            "serve",
            "--tcp",
            &format!("127.0.0.1:{port}"),
            "--exit-after",
            "1",
        ])
        .output()
        .expect("spawn");
    drop(listener);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bind"), "{stderr}");
}
