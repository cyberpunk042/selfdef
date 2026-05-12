//! M10 integration tests for the eBPF collector.
//!
//! Real BPF loading needs root + CAP_BPF + a real kernel — out of scope
//! for `cargo test`. These tests cover:
//!
//! 1. The collector starts cleanly when no BPF object is present (the
//!    daemon must stay up on hosts without eBPF support).
//! 2. The userspace decode path (`ProcessExecEvent` → OCSF `Event`) is
//!    correct, and synthesized events flow through the bus into SQLite
//!    with the right shape.
//!
//! When you have a real BPF-capable host, run the daemon with
//! `[collectors.ebpf] enabled = true` and inspect `selfdefctl events tail`.

use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_ebpf::EbpfCollector;
use selfdef_core::category::ClassUid;
use selfdef_ebpf_common::{ARGV_BUF_LEN, COMM_LEN, EventKind, ProcessExecEvent};
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

fn make_exec(
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: &[u8],
    argv: &[u8],
    argc: u8,
) -> ProcessExecEvent {
    let mut ev = ProcessExecEvent {
        kind: EventKind::ProcessExec as u8,
        _pad0: [0; 3],
        pid,
        tgid: pid,
        ppid,
        uid,
        gid: uid,
        comm: [0; COMM_LEN],
        argv: [0; ARGV_BUF_LEN],
        argv_len: 0,
        argc,
        argv_truncated: 0,
    };
    let n = comm.len().min(COMM_LEN);
    ev.comm[..n].copy_from_slice(&comm[..n]);
    let n = argv.len().min(ARGV_BUF_LEN);
    ev.argv[..n].copy_from_slice(&argv[..n]);
    ev.argv_len = n as u16;
    ev
}

#[tokio::test(flavor = "current_thread")]
async fn collector_runs_idle_when_bpf_object_missing() {
    let bus = Bus::new(8);
    let coll = EbpfCollector::new(
        std::path::PathBuf::from("/nonexistent/never-exists.bpf.o"),
        bus.publisher(),
        "test-host".into(),
    );
    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let task = tokio::spawn(async move { coll.run(sd).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    shutdown.cancel();
    let res = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("task hung")
        .expect("task panicked");
    assert!(res.is_ok(), "expected graceful idle Ok, got {res:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn synthetic_exec_events_round_trip_through_bus_to_sqlite() {
    let dir = tempdir().unwrap();
    let sqlite = dir.path().join("state.sqlite");
    let store = SqliteStore::open(&sqlite).unwrap();
    let sink_store = SqliteStore::open(&sqlite).unwrap();

    let bus = Bus::new(32);
    let publisher = bus.publisher();
    let mut sub = bus.subscribe();

    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sd.cancelled() => return,
                r = sub.recv() => match r {
                    Ok(e) => { let _ = sink_store.insert(&e).await; }
                    Err(_) => return,
                }
            }
        }
    });

    // The collector exposes its conversion path as public methods so tests
    // (and future replay tooling) can exercise them without loading BPF.
    let coll = Arc::new(EbpfCollector::new(
        std::path::PathBuf::from("/unused"),
        publisher.clone(),
        "test-host".into(),
    ));

    let ev_ls = make_exec(1234, 1, 1000, b"ls", b"ls\0-la\0/etc\0", 3);
    let ev_curl = make_exec(
        2345,
        1234,
        1000,
        b"curl",
        b"curl\0-s\0https://example.org/\0",
        3,
    );
    let ev_sshd = make_exec(78, 1, 0, b"sshd", b"sshd\0-D\0", 2);

    publisher.publish_lossy(coll.process_exec_to_event(&ev_ls));
    publisher.publish_lossy(coll.process_exec_to_event(&ev_curl));
    publisher.publish_lossy(coll.process_exec_to_event(&ev_sshd));

    // Wait for all three to land.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let recent = loop {
        if tokio::time::Instant::now() > deadline {
            panic!("events did not land in SQLite in time");
        }
        let r = store.recent(10).await.unwrap();
        if r.iter().filter(|e| e.source == "selfdef.ebpf").count() >= 3 {
            break r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), sink).await;

    let ebpf_events: Vec<_> = recent
        .into_iter()
        .filter(|e| e.source == "selfdef.ebpf")
        .collect();
    assert_eq!(ebpf_events.len(), 3);

    for ev in &ebpf_events {
        assert_eq!(ev.class_uid, ClassUid::PROCESS_ACTIVITY);
        assert_eq!(ev.activity_id, 1);
        let p = ev.process.as_ref().expect("process attached");
        assert!(p.pid > 0);
        assert!(p.cmdline.is_some());
    }

    // Spot-check one entry: ls should have parent_pid=1 and joined argv.
    let ls = ebpf_events
        .iter()
        .find(|e| e.process.as_ref().unwrap().pid == 1234)
        .unwrap();
    let p = ls.process.as_ref().unwrap();
    assert_eq!(p.parent_pid, Some(1));
    assert_eq!(p.cmdline.as_deref(), Some("ls -la /etc"));
    assert_eq!(p.name.as_deref(), Some("ls"));
}
