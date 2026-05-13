//! Integration tests for `selfdefctl events follow`.
//!
//! Each test stands up a tiny UNIX-socket "fake daemon" that
//! speaks HTTP/1.1 + chunked SSE frames, then runs the CLI verb
//! against it and asserts the stdout shape.
//!
//! No real daemon required — the fake server is ~30 lines of
//! tokio glue that handles one connection, writes the canned
//! 200 OK + chunked body, then exits.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Spawn a fake SSE-over-UNIX-socket server. The closure builds
/// the chunked body the test wants to emit. Returns the socket
/// path; the server exits after serving one connection.
fn spawn_fake_daemon(
    dir: &std::path::Path,
    body_builder: impl FnOnce() -> Vec<u8> + Send + 'static,
) -> std::path::PathBuf {
    let socket = dir.join("selfdef.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    let body = body_builder();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            // Drain the request — we don't actually parse it,
            // we just need to consume the bytes so the
            // client's write_all doesn't block.
            let mut buf = [0u8; 4096];
            let _ = conn.read(&mut buf).await;
            // Write the canned response.
            let resp = build_response(&body);
            let _ = conn.write_all(&resp).await;
            let _ = conn.shutdown().await;
        }
    });
    socket
}

fn build_response(body_bytes: &[u8]) -> Vec<u8> {
    let mut resp = Vec::new();
    resp.extend_from_slice(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/event-stream\r\n\
          Transfer-Encoding: chunked\r\n\
          \r\n",
    );
    // One big chunk holding the full SSE body. Real daemon
    // streams many small chunks; the parser handles both.
    resp.extend_from_slice(format!("{:x}\r\n", body_bytes.len()).as_bytes());
    resp.extend_from_slice(body_bytes);
    resp.extend_from_slice(b"\r\n0\r\n\r\n");
    resp
}

/// Build an Event with the right wire-shape, using selfdef-core
/// directly so we don't drift from the daemon's JSON format.
fn evt_json(class_uid: u32, finding: bool, source: &str, msg: &str) -> String {
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    let class = if finding {
        ClassUid::DETECTION_FINDING
    } else {
        ClassUid::new(class_uid)
    };
    let ev = selfdef_core::Event::new(class, 1, SeverityId::Informational, "host-test", source, 0)
        .with_message(msg);
    serde_json::to_string(&ev).unwrap()
}

#[tokio::test]
async fn follow_streams_each_event_as_a_json_line() {
    let tmp = tempfile::tempdir().unwrap();
    let body = format!(
        "data: {}\n\ndata: {}\n\n",
        evt_json(1001, false, "test.collector", "first"),
        evt_json(1001, false, "test.collector", "second"),
    );
    let socket = spawn_fake_daemon(tmp.path(), move || body.into_bytes());

    let out = tokio::task::spawn_blocking(move || {
        Command::new(binary())
            .args([
                "events",
                "follow",
                "--unix-socket",
                socket.to_str().unwrap(),
                "-n",
                "2",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn selfdefctl")
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "follow should exit 0 after limit; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 event lines; got: {stdout}");
    // Each line should be valid JSON containing the source.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        assert_eq!(v["source"], "test.collector");
    }
}

#[tokio::test]
async fn follow_alerts_only_filters_to_findings_category() {
    let tmp = tempfile::tempdir().unwrap();
    let body = format!(
        "data: {}\n\ndata: {}\n\ndata: {}\n\n",
        evt_json(1001, false, "test", "normal-event"),
        evt_json(2004, true, "test", "this-is-a-finding"),
        evt_json(1001, false, "test", "another-normal"),
    );
    let socket = spawn_fake_daemon(tmp.path(), move || body.into_bytes());

    let out = tokio::task::spawn_blocking(move || {
        Command::new(binary())
            .args([
                "events",
                "follow",
                "--unix-socket",
                socket.to_str().unwrap(),
                "--alerts-only",
                "-n",
                "1",
            ])
            .output()
            .expect("spawn selfdefctl")
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("this-is-a-finding") && !stdout.contains("normal-event"),
        "expected only the finding; got: {stdout}",
    );
}

#[tokio::test]
async fn follow_surfaces_lagged_events_as_stderr_comments() {
    let tmp = tempfile::tempdir().unwrap();
    let body = format!(
        "event: lagged\ndata: missed 5 events\n\ndata: {}\n\n",
        evt_json(1001, false, "test", "after-lag"),
    );
    let socket = spawn_fake_daemon(tmp.path(), move || body.into_bytes());

    let out = tokio::task::spawn_blocking(move || {
        Command::new(binary())
            .args([
                "events",
                "follow",
                "--unix-socket",
                socket.to_str().unwrap(),
                "-n",
                "1",
            ])
            .output()
            .expect("spawn selfdefctl")
    })
    .await
    .unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("# lagged") && stderr.contains("missed 5 events"),
        "expected lagged comment on stderr; got: {stderr}",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("after-lag"),
        "expected post-lag event on stdout; got: {stdout}",
    );
}

#[tokio::test]
async fn follow_fails_with_clear_error_when_socket_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("not-a-socket.sock");
    let out = tokio::task::spawn_blocking(move || {
        Command::new(binary())
            .args(["events", "follow", "--unix-socket", bogus.to_str().unwrap()])
            .output()
            .expect("spawn selfdefctl")
    })
    .await
    .unwrap();

    assert!(!out.status.success(), "should fail when socket missing");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("connecting to") && stderr.contains("not-a-socket.sock"),
        "expected connect-failure diagnostic; got: {stderr}",
    );
}
