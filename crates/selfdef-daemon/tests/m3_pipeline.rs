//! Integration test for the M3 pipeline:
//!   auditd file → AuditdCollector → Bus → store sink → SqliteStore
//!
//! We don't launch the daemon binary itself; we wire the components up in
//! the test process and assert the loop closes. This is faster and more
//! debuggable than driving the binary.

use std::io::Write;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_auditd::{AuditdCollector, ReadFrom};
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

const SAMPLE_AUDIT_LINES: &[&str] = &[
    // Failed SSH password
    r#"type=USER_AUTH msg=audit(1736944496.789:1234567): pid=1234 uid=0 msg='op=PAM:authentication acct="alice" addr=192.0.2.5 res=failed'"#,
    // Successful login
    r#"type=USER_LOGIN msg=audit(1736944500.123:1234568): pid=4567 uid=0 acct="alice" exe="/usr/sbin/sshd" hostname=10.0.0.4 res=success"#,
    // Account check (success)
    r#"type=USER_ACCT msg=audit(1736944501.000:1234569): pid=4568 uid=1000 msg='op=PAM:accounting acct="alice" res=success'"#,
    // Other type
    r#"type=ANOM_PROMISCUOUS msg=audit(1736944600.000:1234570): dev=eth0 prom=256 old_prom=0"#,
];

#[tokio::test(flavor = "current_thread")]
async fn auditd_to_sqlite_pipeline() {
    let dir = tempdir().expect("tempdir");
    let audit_file = dir.path().join("audit.log");
    let sqlite_path = dir.path().join("state.sqlite");

    // Write the audit log up front; collector reads from start.
    {
        let mut f = std::fs::File::create(&audit_file).expect("create audit file");
        for line in SAMPLE_AUDIT_LINES {
            writeln!(f, "{line}").expect("write line");
        }
    }

    let bus = Bus::new(64);
    let publisher = bus.publisher();
    let store = SqliteStore::open(&sqlite_path).expect("open store");

    // Sink: subscribe and persist every event.
    let mut sub = bus.subscribe();
    let sink_store = SqliteStore::open(&sqlite_path).expect("re-open for sink");
    let sink = tokio::spawn(async move {
        let mut n = 0usize;
        while let Ok(event) = sub.recv().await {
            sink_store.insert(&event).await.expect("insert");
            n += 1;
            if n >= SAMPLE_AUDIT_LINES.len() {
                break;
            }
        }
        n
    });

    // Collector: read from start, feed events to the bus.
    let shutdown = CancellationToken::new();
    let collector = AuditdCollector::new(
        audit_file.clone(),
        ReadFrom::Start,
        publisher,
        "test-host".to_string(),
    );
    let coll_shutdown = shutdown.clone();
    let coll_task = tokio::spawn(async move {
        let _ = collector.run(coll_shutdown).await;
    });

    // Wait for the sink to acknowledge all events.
    let written = tokio::time::timeout(Duration::from_secs(5), sink)
        .await
        .expect("sink timed out")
        .expect("sink panicked");

    assert_eq!(
        written,
        SAMPLE_AUDIT_LINES.len(),
        "sink did not receive all expected events"
    );

    // Stop the collector.
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), coll_task).await;

    // Now assert what landed in the store.
    let count = store.count().await.expect("count");
    assert_eq!(count as usize, SAMPLE_AUDIT_LINES.len());

    let events = store.recent(100).await.expect("recent");
    assert_eq!(events.len(), SAMPLE_AUDIT_LINES.len());

    // The failed auth should be Medium severity and class AUTHENTICATION.
    let failed = events
        .iter()
        .find(|e| e.class_uid == ClassUid::AUTHENTICATION && e.status_id == Some(StatusId::Failure))
        .expect("a failed-auth event");
    assert_eq!(failed.severity_id, SeverityId::Medium);
    assert!(
        !failed.attack.is_empty(),
        "failed auth should be tagged with ATT&CK technique"
    );
    assert_eq!(failed.attack[0].id, "T1110");

    // The unknown record type should still land, with raw payload.
    let other = events
        .iter()
        .find(|e| e.class_uid == ClassUid::new(0))
        .expect("other event");
    assert!(
        other.raw.is_some(),
        "unknown record types must preserve raw payload"
    );

    // The successful login should be Informational + Success.
    let success = events
        .iter()
        .find(|e| e.class_uid == ClassUid::AUTHENTICATION && e.status_id == Some(StatusId::Success))
        .expect("a successful auth");
    assert_eq!(success.severity_id, SeverityId::Informational);
}
