//! F-2027-010: end-to-end test for `selfdefctl events follow
//! --url <http>`. Boots the selfdef-api router on `127.0.0.1:0`,
//! invokes the CLI binary as a subprocess pointed at the
//! ephemeral port, publishes events on the bus, asserts the
//! CLI prints them on stdout.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use selfdef_api::{ApiState, router, with_full_capability};
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Run the api router on an ephemeral 127.0.0.1 port. Returns
/// the bound `SocketAddr` and a handle to the bus the test will
/// publish into. The router is wrapped with `with_full_capability`
/// so the test request bypasses bearer-auth — the CLI side still
/// sends an `Authorization` header to exercise the request shape,
/// but the test server accepts every request.
async fn spawn_api_on_loopback() -> (std::net::SocketAddr, Arc<Bus>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.sqlite");
    let store = Arc::new(SqliteStore::open(&path).expect("store"));
    let bus = Arc::new(Bus::new(64));
    let state = ApiState::new(Arc::clone(&store), Arc::clone(&bus), "test-host".into());
    let app = with_full_capability(router(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        // We don't expose a shutdown signal: the test holds the
        // TempDir, drops it on return, and the OS reaps the
        // listener when the runtime ends.
        let _ = axum::serve(listener, app).await;
    });
    (addr, bus, dir)
}

fn mk_event(message: &str) -> selfdef_core::Event {
    selfdef_core::Event::new(
        ClassUid::PROCESS_ACTIVITY,
        1,
        SeverityId::Informational,
        "test-host",
        "follow.test",
        0,
    )
    .with_message(message)
}

#[tokio::test(flavor = "current_thread")]
async fn events_follow_url_streams_one_event_then_exits() {
    let (addr, bus, _dir) = spawn_api_on_loopback().await;
    let publisher = bus.publisher();

    // Spawn the CLI as a subprocess. `-n 1` makes it exit after
    // a single event so the test is deterministic + bounded.
    let mut child = Command::new(binary())
        .arg("events")
        .arg("follow")
        .arg("--url")
        .arg(format!("http://{addr}"))
        .arg("-n")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn selfdefctl");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout_reader = BufReader::new(stdout);

    // The CLI needs a beat to connect + the server needs a beat
    // to accept + spawn its writer task. Publish a few times to
    // ensure at least one event lands after the subscriber is wired.
    for tick in 0..20 {
        publisher.publish_lossy(mk_event(&format!("tick-{tick}")));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Drain incrementally so the child's pipe doesn't block
        // the server-side send. We read one line and break.
    }

    // Block on the child's first stdout line. The CLI exits
    // after `-n 1`, so the spawned thread-blocking BufRead is OK
    // (it won't hang forever — the child closes stdout on exit).
    let line = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        stdout_reader.read_line(&mut buf).expect("read_line");
        buf
    })
    .await
    .expect("blocking join");
    let line = line.trim();

    let parsed: selfdef_core::Event =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("parse line {line:?}: {e}"));
    assert!(
        parsed.message.as_deref().unwrap_or("").starts_with("tick-"),
        "got: {parsed:?}",
    );

    let status = tokio::task::spawn_blocking(move || child.wait().expect("child wait"))
        .await
        .expect("blocking join");
    assert!(status.success(), "child exit status: {status:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn events_follow_url_with_bad_url_fails_fast() {
    // Port 1 is reserved + unbound — connect fails immediately.
    let out = Command::new(binary())
        .arg("events")
        .arg("follow")
        .arg("--url")
        .arg("http://127.0.0.1:1")
        .arg("-n")
        .arg("1")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should fail to connect");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The exact message depends on reqwest's connect-error wording;
    // we just assert *some* error mentioning the URL was printed.
    assert!(
        stderr.contains("127.0.0.1:1") || stderr.contains("GET"),
        "expected a connect-error mention; stderr: {stderr}",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn events_follow_url_with_token_file_passes_bearer_header() {
    let (addr, _bus, _dir) = spawn_api_on_loopback().await;
    // The test server's `with_full_capability` middleware accepts
    // every request regardless of `Authorization`, so we don't
    // verify the header was *required* — only that the CLI
    // accepts the `--token-file` flag, reads the contents, and
    // still produces a working stream. Pair with the
    // `cli_api_rotate_token` suite which exercises the daemon-side
    // bearer-auth contract.
    let token_dir = tempfile::tempdir().expect("token dir");
    let token_path = token_dir.path().join("api.token");
    std::fs::write(&token_path, "test-bearer-token-not-secret\n").unwrap();

    let mut child = Command::new(binary())
        .arg("events")
        .arg("follow")
        .arg("--url")
        .arg(format!("http://{addr}"))
        .arg("--token-file")
        .arg(&token_path)
        .arg("-n")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn selfdefctl");
    // Publish once so the subscriber gets an event.
    let publisher = _bus.publisher();
    for tick in 0..20 {
        publisher.publish_lossy(mk_event(&format!("token-tick-{tick}")));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stdout = child.stdout.take().expect("child stdout");
    let line = tokio::task::spawn_blocking(move || {
        let mut buf = String::new();
        BufReader::new(stdout)
            .read_line(&mut buf)
            .expect("read_line");
        buf
    })
    .await
    .expect("blocking join");
    assert!(
        line.contains("token-tick-"),
        "expected an event line; got: {line:?}",
    );
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
}

#[test]
fn events_follow_url_and_unix_socket_are_mutually_exclusive() {
    let out = Command::new(binary())
        .arg("events")
        .arg("follow")
        .arg("--unix-socket")
        .arg("/run/selfdef.sock")
        .arg("--url")
        .arg("http://127.0.0.1:80")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should reject both flags together");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected clap conflict error; stderr: {stderr}",
    );
}

#[test]
fn events_follow_token_file_requires_url() {
    let out = Command::new(binary())
        .arg("events")
        .arg("follow")
        .arg("--token-file")
        .arg("/etc/selfdef/api.token")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should reject --token-file alone");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("required arguments") || stderr.contains("--url"),
        "expected clap requires-error; stderr: {stderr}",
    );
}
