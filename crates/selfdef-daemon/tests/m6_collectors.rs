//! M6 integration test: replay corpora for each of the three new collectors
//! and assert the events land in SQLite with the right shape.

use std::path::PathBuf;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_journald::{InputMode as JInput, JournaldCollector, ReadFrom as JReadFrom};
use selfdef_collector_suricata::{ReadFrom as SReadFrom, SuricataCollector};
use selfdef_collector_tetragon::{ReadFrom as TReadFrom, TetragonCollector};
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

fn workspace_replay_path(suffix: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../tests/replay").join(suffix)
}

#[tokio::test(flavor = "current_thread")]
async fn journald_file_mode_emits_classified_events() {
    let bus = Bus::new(128);
    let pub_ = bus.publisher();
    let mut sub = bus.subscribe();

    let path = workspace_replay_path("journald/sshd_login.jsonl");
    assert!(path.exists(), "missing corpus: {}", path.display());

    let collector = JournaldCollector::new(
        JInput::File {
            path,
            read_from: JReadFrom::Start,
        },
        pub_,
        "test-host".into(),
    );
    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let task = tokio::spawn(async move { collector.run(sd).await });

    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while received.len() < 3 {
        if tokio::time::Instant::now() > deadline {
            panic!("only got {} of 3 expected events", received.len());
        }
        if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
            received.push(e);
        }
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

    // First two are sshd, third is sudo. All from journald.
    for e in &received {
        assert_eq!(e.source, "journald");
    }
    assert_eq!(received[0].class_uid, ClassUid::SSH_ACTIVITY);
    assert_eq!(received[1].class_uid, ClassUid::SSH_ACTIVITY);
    assert_eq!(received[2].class_uid, ClassUid::AUTHENTICATION);
}

#[tokio::test(flavor = "current_thread")]
async fn tetragon_replay_emits_typed_events() {
    let bus = Bus::new(128);
    let pub_ = bus.publisher();
    let mut sub = bus.subscribe();

    let path = workspace_replay_path("tetragon/sensitive_file.jsonl");
    assert!(path.exists(), "missing corpus: {}", path.display());

    let collector = TetragonCollector::new(path, TReadFrom::Start, pub_, "test-host".into());
    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let task = tokio::spawn(async move { collector.run(sd).await });

    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while received.len() < 4 {
        if tokio::time::Instant::now() > deadline {
            panic!("only got {} of 4 expected events", received.len());
        }
        if let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
            received.push(e);
        }
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

    assert_eq!(received[0].class_uid, ClassUid::PROCESS_ACTIVITY);
    assert_eq!(received[1].class_uid, ClassUid::FILE_SYSTEM_ACTIVITY);
    let file = received[1].file.clone().unwrap();
    assert_eq!(file.path.as_deref(), Some("/etc/shadow"));
    assert_eq!(received[2].class_uid, ClassUid::PROCESS_ACTIVITY);
    assert_eq!(received[3].activity_id, 2); // process_exit → Terminate
}

#[tokio::test(flavor = "current_thread")]
async fn suricata_alert_becomes_detection_finding() {
    // Build a tempdir-backed pipeline so we can persist + assert.
    let dir = tempdir().unwrap();
    let sqlite = dir.path().join("state.sqlite");
    let store = SqliteStore::open(&sqlite).unwrap();
    let sink_store = SqliteStore::open(&sqlite).unwrap();

    let bus = Bus::new(128);
    let pub_ = bus.publisher();
    let mut sub = bus.subscribe();

    let path = workspace_replay_path("suricata/scan_alert.jsonl");
    assert!(path.exists(), "missing corpus: {}", path.display());

    // Sink in the background.
    let shutdown = CancellationToken::new();
    let sink_shutdown = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sink_shutdown.cancelled() => return,
                res = sub.recv() => if let Ok(e) = res {
                    sink_store.insert(&e).await.unwrap();
                }
            }
        }
    });

    let collector = SuricataCollector::new(path, SReadFrom::Start, pub_, "test-host".into());
    let coll_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { collector.run(coll_shutdown).await });

    // Wait for the alert finding to appear.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let alert = loop {
        let findings = store.recent_findings(10).await.unwrap();
        if !findings.is_empty() {
            break findings.into_iter().next().unwrap();
        }
        if tokio::time::Instant::now() > deadline {
            panic!("no finding from suricata alert");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), sink).await;

    assert_eq!(alert.source, "suricata");
    assert_eq!(alert.severity_id, SeverityId::Medium); // suricata sev=2 → Medium
    assert!(
        alert.message.as_deref().unwrap_or("").contains("SCAN"),
        "unexpected message: {:?}",
        alert.message
    );
}
