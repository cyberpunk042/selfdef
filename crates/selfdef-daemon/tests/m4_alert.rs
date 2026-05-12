//! Integration test for the M4 alert path:
//!   auditd file → collector → bus → correlator → bus → responder → ntfy mock
//!
//! We feed 3 failed-auth lines from the same source IP, expect exactly one
//! HTTP POST to land on the mock ntfy server.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_auditd::{AuditdCollector, ReadFrom};
use selfdef_core::category::CategoryUid;
use selfdef_core::prelude::*;
use selfdef_correlator::Correlator;
use selfdef_notifier::{Notifier, NotifierChain, NtfyNotifier};
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, NotifyAction};
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SRC_IP: &str = "192.0.2.55";

fn audit_failure_line(serial: u64) -> String {
    format!(
        r#"type=USER_AUTH msg=audit(173694450{serial}.000:{serial}): pid=1234 uid=0 msg='op=PAM:authentication acct="alice" addr={SRC_IP} res=failed'"#
    )
}

#[tokio::test(flavor = "current_thread")]
async fn end_to_end_alert_fires_one_notification() {
    // ---- ntfy mock ----
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/selfdef-alerts"))
        .and(header("Priority", "5"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1) // exactly one POST expected
        .mount(&server)
        .await;

    // ---- fs ----
    let dir = tempdir().expect("tempdir");
    let audit_file = dir.path().join("audit.log");
    let sqlite_path = dir.path().join("state.sqlite");
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).expect("rules dir");
    std::fs::write(
        rules_dir.join("ssh_bruteforce.yml"),
        r#"
title: SSH Brute Force
id: 8a7f3e2c-1234-4abc-9def-fedcba654321
status: experimental
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  service: auditd
detection:
  failed_auth:
    class_uid: 3002
    status_id: 2
  timeframe: 60s
  condition: failed_auth | count() by src_endpoint.ip > 2
level: high
"#,
    )
    .expect("write rule");

    // Three failed auths from same IP, well within a 60s window.
    {
        let mut f = std::fs::File::create(&audit_file).expect("create audit file");
        for serial in 1..=3u64 {
            writeln!(f, "{}", audit_failure_line(serial)).expect("write");
        }
    }

    // ---- runtime ----
    let bus = Bus::new(256);
    let publisher = bus.publisher();
    let store = SqliteStore::open(&sqlite_path).expect("store");
    let sink_store = SqliteStore::open(&sqlite_path).expect("sink store");

    let shutdown = CancellationToken::new();

    // Store sink — persist everything.
    let mut store_sub = bus.subscribe();
    let sink_shutdown = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sink_shutdown.cancelled() => return,
                res = store_sub.recv() => {
                    if let Ok(event) = res {
                        sink_store.insert(&event).await.expect("insert");
                    }
                }
            }
        }
    });

    // Correlator — loads rules from rules_dir.
    let corr_sub = bus.subscribe();
    let correlator = Arc::new(Correlator::new(
        publisher.clone(),
        "test-host".into(),
        rules_dir.clone(),
    ));
    correlator.load_rules().expect("load rules");
    let corr_shutdown = shutdown.clone();
    let corr_task = tokio::spawn({
        let c = Arc::clone(&correlator);
        async move { c.run(corr_sub, corr_shutdown).await }
    });

    // Notifier pointing at the wiremock server.
    let notifier: Box<dyn Notifier> = Box::new(NtfyNotifier::new(
        server.uri(),
        "selfdef-alerts",
        None,
    ));
    let chain = NotifierChain::new(vec![notifier]);

    // Responder — dry_run = false so it actually notifies.
    let resp_sub = bus.subscribe();
    let notifier: Arc<dyn Notifier> = Arc::new(chain);
    let actions: Vec<Arc<dyn Action>> = vec![Arc::new(NotifyAction::new(notifier))];
    let responder = Arc::new(Responder::new(actions, vec!["notify".into()], false));
    let resp_shutdown = shutdown.clone();
    let resp_task = tokio::spawn({
        let r = Arc::clone(&responder);
        async move { r.run(resp_sub, resp_shutdown).await }
    });

    // Collector — read from start.
    let coll = AuditdCollector::new(
        audit_file.clone(),
        ReadFrom::Start,
        publisher.clone(),
        "test-host".into(),
    );
    let coll_shutdown = shutdown.clone();
    let coll_task = tokio::spawn(async move {
        let _ = coll.run(coll_shutdown).await;
    });

    // Wait until we see a finding in the store, with timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if store.recent_findings(10).await.unwrap_or_default().len() >= 1 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("no finding appeared in store within timeout");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Give the responder a moment to dispatch.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- assertions ----
    let findings = store.recent_findings(10).await.expect("findings");
    assert_eq!(findings.len(), 1, "expected exactly one finding");
    let f = &findings[0];
    assert_eq!(f.category_uid, CategoryUid::Findings);
    assert_eq!(f.severity_id, SeverityId::High);
    assert!(
        f.message
            .as_deref()
            .unwrap_or("")
            .contains(SRC_IP),
        "finding message should mention source IP, got: {:?}",
        f.message
    );
    assert!(!f.attack.is_empty());
    assert_eq!(f.attack[0].id, "T1110");

    // ---- shutdown ----
    shutdown.cancel();
    for task in [coll_task, corr_task, resp_task, sink] {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // wiremock's `.expect(1)` was asserted at mount; verify_on_drop confirms.
    // Explicit verification:
    server.verify().await;
}
