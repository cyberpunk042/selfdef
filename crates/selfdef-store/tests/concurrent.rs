//! SDD-005 Test-5 / closes F-2026-034: concurrent-insert +
//! crash-recovery for `SqliteStore`.
//!
//! Pre-SDD-005 the store had unit tests only. Two contracts were
//! unverified at the integration level:
//!
//! 1. **Concurrent inserts** from many `tokio` tasks against one
//!    `SqliteStore` handle don't lose rows. WAL mode + the
//!    `spawn_blocking` wrapper claim this works; this test
//!    exercises it.
//! 2. **Crash recovery**: dropping the store mid-test and
//!    re-opening the same on-disk file must surface every row
//!    that completed an insert (the SQLite COMMIT happened on
//!    the same call's return). Verifies the durability promise
//!    we make to operators.

use std::sync::Arc;

use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;

fn one_event(seq: u64, tag: &str) -> Event {
    Event::new(
        ClassUid::PROCESS_ACTIVITY,
        1,
        SeverityId::Informational,
        "host-test",
        "store.test",
        seq,
    )
    .with_message(tag.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_do_not_lose_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.sqlite");
    let store = Arc::new(SqliteStore::open(&path).unwrap());

    const TASKS: u64 = 8;
    const PER_TASK: u64 = 200;
    let mut handles = Vec::new();
    for t in 0..TASKS {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            for i in 0..PER_TASK {
                let seq = t * PER_TASK + i;
                let evt = one_event(seq, &format!("task-{t}-evt-{i}"));
                s.insert(&evt).await.expect("insert");
            }
        }));
    }
    for h in handles {
        h.await.expect("task joins");
    }

    let total = store.count().await.expect("count");
    assert_eq!(
        total,
        TASKS * PER_TASK,
        "expected exactly {} rows across {TASKS} concurrent tasks, got {total}",
        TASKS * PER_TASK,
    );
}

#[tokio::test]
async fn crash_recovery_surfaces_every_committed_insert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.sqlite");

    // Phase 1: open, insert, drop (simulating a crash). We
    // intentionally drop without an explicit flush — SQLite's
    // WAL + per-insert commit must persist the rows on its own.
    {
        let store = SqliteStore::open(&path).unwrap();
        for i in 0..50 {
            store
                .insert(&one_event(i, &format!("pre-crash-{i}")))
                .await
                .unwrap();
        }
        // Drop happens at scope end.
    }

    // Phase 2: re-open the same path. Every row must be visible.
    let reopened = SqliteStore::open(&path).unwrap();
    let total = reopened.count().await.unwrap();
    assert_eq!(
        total, 50,
        "post-recovery row count should match pre-crash inserts; got {total}",
    );
    let recent = reopened.recent(100).await.unwrap();
    assert_eq!(recent.len(), 50);
    // Spot-check that the most recent message is intact (and
    // that the data — not just the count — is durable).
    let messages: Vec<_> = recent.iter().filter_map(|e| e.message.clone()).collect();
    assert!(
        messages.iter().any(|m| m == "pre-crash-49"),
        "expected pre-crash-49 message after reopen; got: {messages:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_then_reopen_preserves_count() {
    // Composes the two contracts: hammer with concurrent
    // inserts, then drop + reopen and verify durability of
    // every row across the simulated crash.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compose.sqlite");
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        const TASKS: u64 = 4;
        const PER_TASK: u64 = 100;
        let mut handles = Vec::new();
        for t in 0..TASKS {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                for i in 0..PER_TASK {
                    let seq = t * PER_TASK + i;
                    s.insert(&one_event(seq, &format!("c-{t}-{i}")))
                        .await
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(store.count().await.unwrap(), TASKS * PER_TASK);
    }

    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.count().await.unwrap(), 400);
}
