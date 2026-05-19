//! SD-R92 (SDD-026 Z-11 wire-compat) — LSP-style Content-Length framing.
//! SD-R91 ships line-delimited JSON-RPC (testable, jq-able). Real MCP
//! clients (claude-code et al.) speak LSP framing. SD-R92 adds it as
//! a `--framing lsp` option; the SD-R91 line framing remains the
//! default for backwards compat.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Pipe LSP-framed `requests` into `mcp serve --framing lsp
/// --exit-after N`. Parse stdout (also LSP-framed) into a list of
/// {headers, payload} pairs.
fn lsp_exchange(payloads: &[&str]) -> Vec<serde_json::Value> {
    let n = payloads.len();
    let mut child = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "mcp",
            "serve",
            "--framing",
            "lsp",
            "--exit-after",
            &n.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn selfdefctl");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for p in payloads {
            let header = format!(
                "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n",
                p.len()
            );
            stdin.write_all(header.as_bytes()).unwrap();
            stdin.write_all(p.as_bytes()).unwrap();
        }
    }
    let mut stdout = child.stdout.take().expect("stdout");
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).expect("read stdout");
    let _ = child.wait();

    // Parse LSP-framed responses out of `buf`.
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        // Find header/body separator (\r\n\r\n).
        let sep = match find_subslice(&buf[i..], b"\r\n\r\n") {
            Some(s) => s,
            None => break,
        };
        let header_str = std::str::from_utf8(&buf[i..i + sep]).expect("utf8 header");
        let mut content_length: Option<usize> = None;
        for line in header_str.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if let Some(rest) = line
                .strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
            {
                if let Ok(v) = rest.trim().parse::<usize>() {
                    content_length = Some(v);
                }
            }
        }
        let len = content_length.expect("Content-Length header");
        let payload_start = i + sep + 4;
        let payload_end = payload_start + len;
        let payload_bytes = &buf[payload_start..payload_end];
        let json: serde_json::Value =
            serde_json::from_slice(payload_bytes).expect("payload not JSON");
        out.push(json);
        i = payload_end;
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn sdr92_lsp_initialize_round_trip() {
    let resps = lsp_exchange(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#]);
    assert_eq!(resps.len(), 1);
    let r = &resps[0];
    assert_eq!(r["id"], 1);
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["result"]["serverInfo"]["name"], "selfdefctl-mcp");
}

#[test]
fn sdr92_lsp_multi_request_session() {
    let resps = lsp_exchange(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"selfdef.repl.tier2_examples","arguments":{"json":true}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"shutdown","params":{}}"#,
    ]);
    assert_eq!(resps.len(), 4);
    assert_eq!(resps[0]["id"], 1);
    assert_eq!(resps[1]["id"], 2);
    let tools = resps[1]["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty());
    let content = resps[2]["result"]["content"].as_array().unwrap();
    assert_eq!(content[0]["type"], "text");
    assert!(resps[3]["result"].is_null());
}

#[test]
fn sdr92_lsp_unknown_method_returns_method_not_found() {
    let resps =
        lsp_exchange(&[r#"{"jsonrpc":"2.0","id":5,"method":"nonexistent/method","params":{}}"#]);
    assert_eq!(resps[0]["error"]["code"], -32601);
}

#[test]
fn sdr92_line_framing_remains_default_for_backcompat() {
    // Without --framing, the server still uses SD-R91 line framing.
    let mut child = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "serve", "--exit-after", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Line framing: response is on a single line, no Content-Length
    // header.
    assert!(
        !stdout.contains("Content-Length:"),
        "default framing should still be line-delimited (no LSP headers)"
    );
    let line = stdout.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
    assert_eq!(v["id"], 1);
}

#[test]
fn sdr92_bad_framing_value_returns_rc2() {
    let mut child = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["mcp", "serve", "--framing", "nope", "--exit-after", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown framing"), "{stderr}");
}
