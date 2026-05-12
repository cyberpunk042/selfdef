//! M9 integration test: simulate `selfdef-ssh-wrap` writing events to a
//! JSONL file, run the eventstream collector against that file, and check
//! the events land in SQLite with the right shape.
//!
//! We write the JSONL directly (using the same OCSF Event struct the
//! wrapper would produce) — the test exercises the collector's contract,
//! not the wrapper's internals.

use std::io::Write;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_eventstream::{EventstreamCollector, ReadFrom};
use selfdef_core::Event;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

fn append_event(file: &mut std::fs::File, event: &Event) {
    let line = serde_json::to_string(event).unwrap();
    writeln!(file, "{line}").unwrap();
    file.flush().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_wrap_events_reach_sqlite_through_eventstream_collector() {
    let dir = tempdir().unwrap();
    let events_path = dir.path().join("ssh-wrap.jsonl");
    let sqlite = dir.path().join("state.sqlite");

    // Create the JSONL file empty up front so the collector finds it.
    std::fs::File::create(&events_path).unwrap();

    let store = SqliteStore::open(&sqlite).unwrap();
    let sink_store = SqliteStore::open(&sqlite).unwrap();
    let bus = Bus::new(32);
    let publisher = bus.publisher();
    let mut sub = bus.subscribe();

    let shutdown = CancellationToken::new();
    let sink_sd = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sink_sd.cancelled() => return,
                r = sub.recv() => match r {
                    Ok(e) => { let _ = sink_store.insert(&e).await; }
                    Err(_) => return,
                }
            }
        }
    });

    let collector = EventstreamCollector::new(
        events_path.clone(),
        ReadFrom::Start,
        publisher,
    );
    let coll_sd = shutdown.clone();
    let coll = tokio::spawn(async move { collector.run(coll_sd).await });

    // Brief delay so the collector opens the file before we start writing.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Simulate what the wrapper would emit: session start, policy strip,
    // session end.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&events_path)
        .unwrap();

    let session_start = Event::new(
        ClassUid::SSH_ACTIVITY,
        1,
        SeverityId::Informational,
        "wrap-host",
        "selfdef.ssh-wrap",
        0,
    )
    .with_message("ssh session opening: alice@bastion.example.com");
    append_event(&mut file, &session_start);

    let policy_strip = Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Low,
        "wrap-host",
        "selfdef.ssh-wrap",
        1,
    )
    .with_message("stripped 1 arg(s) from ssh invocation per policy: -A");
    append_event(&mut file, &policy_strip);

    let session_end = Event::new(
        ClassUid::SSH_ACTIVITY,
        2,
        SeverityId::Informational,
        "wrap-host",
        "selfdef.ssh-wrap",
        2,
    )
    .with_message("ssh session ended: alice@bastion.example.com (12.4s, exit 0)")
    .with_status(StatusId::Success);
    append_event(&mut file, &session_end);

    // Wait for all three events to land in SQLite.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let recent = loop {
        if tokio::time::Instant::now() > deadline {
            panic!("events did not appear in SQLite in time");
        }
        let r = store.recent(10).await.unwrap();
        if r.iter().filter(|e| e.source == "selfdef.ssh-wrap").count() >= 3 {
            break r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), coll).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), sink).await;

    let from_wrap: Vec<_> = recent
        .into_iter()
        .filter(|e| e.source == "selfdef.ssh-wrap")
        .collect();

    let starts: Vec<_> = from_wrap
        .iter()
        .filter(|e| e.class_uid == ClassUid::SSH_ACTIVITY && e.activity_id == 1)
        .collect();
    assert!(!starts.is_empty(), "no session start");

    let ends: Vec<_> = from_wrap
        .iter()
        .filter(|e| e.class_uid == ClassUid::SSH_ACTIVITY && e.activity_id == 2)
        .collect();
    assert!(!ends.is_empty(), "no session end");
    assert_eq!(ends[0].status_id, Some(StatusId::Success));

    let strips: Vec<_> = from_wrap
        .iter()
        .filter(|e| e.class_uid == ClassUid::DETECTION_FINDING)
        .collect();
    assert!(!strips.is_empty(), "no policy-strip finding");
}
