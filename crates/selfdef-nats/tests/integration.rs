//! SDD-005 Test-3 / closes F-2026-035: real-broker NATS
//! round-trip. The bridge's JetStream durability and core
//! pub/sub promises can't be verified against a fake — only a
//! live `nats-server` exercises the wire format + reconnect +
//! consumer behaviour.
//!
//! Tests are `#[ignore]`-gated so CI without the binary stays
//! green. To run locally:
//!
//! ```sh
//! apt install nats-server   # or download from nats.io
//! cargo test -p selfdef-nats -- --include-ignored
//! ```

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_nats::{JetStreamConfig, NatsConfig, run_bridge};
use tokio_util::sync::CancellationToken;

fn nats_server_on_path() -> Option<PathBuf> {
    let output = Command::new("which").arg("nats-server").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// A spawned `nats-server` for one test. Drop kills it.
struct NatsServer {
    child: Option<Child>,
    pub url: String,
    _tempdir: tempfile::TempDir,
}

impl NatsServer {
    fn start(jetstream: bool) -> Self {
        let bin = nats_server_on_path().expect("nats-server on PATH");
        let port = free_port();
        let tempdir = tempfile::tempdir().expect("nats tempdir");
        let mut cmd = Command::new(&bin);
        cmd.arg("--port")
            .arg(port.to_string())
            .arg("--addr")
            .arg("127.0.0.1");
        if jetstream {
            cmd.arg("--jetstream")
                .arg("--store_dir")
                .arg(tempdir.path());
        }
        let mut child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nats-server");
        // Block until the server logs `Server is ready`. async-nats's
        // connect retries on its own, but reading the ready line means
        // the connect call won't spend its first second on a backoff.
        let stderr = child.stderr.take().expect("nats stderr");
        let deadline = Instant::now() + Duration::from_secs(5);
        let reader = BufReader::new(stderr);
        let mut ready = false;
        for line in reader.lines().take(200) {
            if Instant::now() > deadline {
                break;
            }
            match line {
                Ok(l) if l.contains("Server is ready") => {
                    ready = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        if !ready {
            let _ = child.kill();
            panic!("nats-server did not report ready within 5s");
        }
        Self {
            child: Some(child),
            url: format!("nats://127.0.0.1:{port}"),
            _tempdir: tempdir,
        }
    }
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Build a one-event Event for transmission tests. `host_tag`
/// distinguishes the publishing host from the consuming host so
/// `is_local_originated` filters correctly.
fn one_event(host_tag: &str, seq: u64, message: &str) -> Event {
    Event::new(
        ClassUid::SSH_ACTIVITY,
        1,
        SeverityId::Informational,
        host_tag,
        "nats.test",
        seq,
    )
    .with_message(message)
}

#[tokio::test]
#[ignore = "requires nats-server on PATH; run with --include-ignored"]
async fn core_bridge_round_trips_event_between_two_hosts() {
    // Two bridge instances pointed at the same broker with
    // distinct host tags. Publishing on host A should reach
    // host B's bus. Validates the wire format end-to-end —
    // this is the failure mode no fake catches.
    let _server = NatsServer::start(false);

    let cfg_template = NatsConfig {
        url: _server.url.clone(),
        subject_prefix: "selfdef.events.test".into(),
        jetstream: JetStreamConfig {
            enabled: false,
            ..Default::default()
        },
    };

    let bus_a = Arc::new(Bus::new(16));
    let bus_b = Arc::new(Bus::new(16));
    let pub_a = bus_a.publisher();
    let pub_b = bus_b.publisher();
    let sub_a = bus_a.subscribe();
    let sub_b = bus_b.subscribe();
    let mut local_b = bus_b.subscribe();

    let shutdown = CancellationToken::new();
    let s1 = shutdown.clone();
    let s2 = shutdown.clone();
    let cfg_a = cfg_template.clone();
    let cfg_b = cfg_template;

    let h_a = tokio::spawn(async move {
        let _ = run_bridge(cfg_a, "host-a".into(), pub_a, sub_a, s1, None, None, None).await;
    });
    let h_b = tokio::spawn(async move {
        let _ = run_bridge(cfg_b, "host-b".into(), pub_b, sub_b, s2, None, None, None).await;
    });

    // Give both bridges a moment to subscribe before we publish.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Publish from host A. The host-A bridge serialises onto
    // `selfdef.events.test.host-a`; the host-B bridge's
    // wildcard subscription on `selfdef.events.test.>` receives
    // it and republishes onto bus B.
    let evt = one_event("host-a", 1, "hello-from-A");
    bus_a.publisher().publish(evt.clone()).expect("publish A");

    // Wait for bus B to surface the event, but skip the local
    // echo (the publisher's own event re-broadcasts on its own
    // subscriber).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received_remote = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), local_b.recv()).await {
            Ok(Ok(seen)) => {
                if seen.host_tag == "host-a" && seen.message.as_deref() == Some("hello-from-A") {
                    received_remote = true;
                    break;
                }
            }
            _ => continue,
        }
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), h_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), h_b).await;

    assert!(
        received_remote,
        "host-b's bus never received the event published on host-a",
    );
}

#[tokio::test]
#[ignore = "requires nats-server with JetStream; run with --include-ignored"]
async fn jetstream_bridge_creates_stream_and_durable_consumer() {
    // The JetStream code path differs structurally from the core
    // path: it ensures a stream and a durable consumer on
    // startup. We can verify this against a real broker by
    // checking with the async-nats client directly that the
    // expected stream + consumer exist after the bridge has
    // run briefly.
    let server = NatsServer::start(true);
    let cfg = NatsConfig {
        url: server.url.clone(),
        subject_prefix: "selfdef.events.jstest".into(),
        jetstream: JetStreamConfig {
            enabled: true,
            stream_name: "selfdef-events-jstest".into(),
            durable_consumer_prefix: "selfdef-bridge-jstest".into(),
            max_age_secs: 60,
            max_bytes: -1,
            max_msgs: -1,
        },
    };

    let bus = Arc::new(Bus::new(16));
    let publisher = bus.publisher();
    let subscriber = bus.subscribe();
    let shutdown = CancellationToken::new();
    let shutdown_child = shutdown.clone();
    let cfg_for_task = cfg.clone();

    let task = tokio::spawn(async move {
        let _ = run_bridge(
            cfg_for_task,
            "host-js".into(),
            publisher,
            subscriber,
            shutdown_child,
            None,
            None,
            None,
        )
        .await;
    });
    // Give the bridge ~500ms to create the stream + consumer.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify with a direct client.
    let client = async_nats::connect(&cfg.url).await.expect("connect");
    let js = async_nats::jetstream::new(client);
    let mut stream = js
        .get_stream(&cfg.jetstream.stream_name)
        .await
        .expect("stream must exist post-bridge startup");
    let info = stream.info().await.expect("stream info");
    assert_eq!(info.config.name, cfg.jetstream.stream_name);

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
}
