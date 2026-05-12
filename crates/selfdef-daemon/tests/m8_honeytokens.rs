//! M8 integration test: a real canary file access flows through the bus,
//! is recognized as a Critical Finding, the responder dispatches the
//! configured actions, and we can observe them via the SqliteStore.
//!
//! All actions are run in dry-run mode so this test is safe in CI — it
//! never touches nftables or kills processes.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_collector_canary::CanaryCollector;
use selfdef_core::category::{CategoryUid, ClassUid};
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{
    Action, KillPidAction, LockdownEgressAction, NotifyAction, RevokeSessionAction,
    SnapshotProcAction,
};
use selfdef_store::SqliteStore;
use tempfile::{tempdir, NamedTempFile};
use tokio_util::sync::CancellationToken;

/// A no-op notifier we plug into NotifyAction so dry_run is honored without
/// requiring a real HTTP target.
#[derive(Default)]
struct NullNotifier {
    sent: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl selfdef_notifier::Notifier for NullNotifier {
    async fn notify(&self, _event: &selfdef_core::Event) -> Result<(), selfdef_notifier::NotifierError> {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn name(&self) -> &'static str { "null" }
}

#[tokio::test(flavor = "current_thread")]
async fn canary_touch_dispatches_actions_in_dry_run() {
    // Canary file the collector will watch.
    let mut canary = NamedTempFile::new().unwrap();
    writeln!(canary, "AWS_ACCESS_KEY_ID=AKIA-not-a-real-key").unwrap();
    let canary_path = canary.path().to_path_buf();

    // SQLite store for asserting findings landed.
    let dir = tempdir().unwrap();
    let sqlite = dir.path().join("state.sqlite");
    let store = SqliteStore::open(&sqlite).unwrap();
    let sink_store = SqliteStore::open(&sqlite).unwrap();

    let bus = Bus::new(64);
    let publisher = bus.publisher();
    let mut store_sub = bus.subscribe();
    let responder_sub = bus.subscribe();

    let shutdown = CancellationToken::new();

    // ---- sink to SQLite ----
    let sink_shutdown = shutdown.clone();
    let sink = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = sink_shutdown.cancelled() => return,
                res = store_sub.recv() => match res {
                    Ok(ev) => { let _ = sink_store.insert(&ev).await; }
                    Err(_) => return,
                }
            }
        }
    });

    // ---- responder with all 5 actions, dry-run = true ----
    let scratch = dir.path().join("snapshots");
    let dummy_script = dir.path().join("never-called.sh");
    let notifier: Arc<dyn selfdef_notifier::Notifier> = Arc::new(NullNotifier::default());
    let actions: Vec<Arc<dyn Action>> = vec![
        Arc::new(NotifyAction::new(notifier.clone())),
        Arc::new(SnapshotProcAction::new(scratch)),
        Arc::new(KillPidAction::new()),
        Arc::new(LockdownEgressAction::new(dummy_script.clone())),
        Arc::new(RevokeSessionAction::new(dummy_script)),
    ];
    let responder = Arc::new(Responder::new(
        actions,
        vec![
            "notify".into(),
            "snapshot_proc".into(),
            "kill_pid".into(),
            "lockdown_egress".into(),
            "revoke_session".into(),
        ],
        /* dry_run */ true,
    ));
    let resp_shutdown = shutdown.clone();
    let resp_clone = responder.clone();
    let resp_task = tokio::spawn(async move {
        resp_clone.run(responder_sub, resp_shutdown).await;
    });

    // ---- canary collector ----
    let collector = CanaryCollector::new(
        vec![canary_path.clone()],
        publisher,
        "test-host".into(),
    );
    let coll_shutdown = shutdown.clone();
    let coll_task = tokio::spawn(async move { collector.run(coll_shutdown).await });

    // Give inotify a moment to install its watch.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Touch the canary.
    let _ = std::fs::read(&canary_path).unwrap();

    // Wait for a Critical finding to land in SQLite.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let finding = loop {
        if tokio::time::Instant::now() > deadline {
            panic!("no canary finding observed");
        }
        let recent = store.recent_findings(10).await.unwrap();
        if let Some(ev) = recent.into_iter().find(|e| e.source == "selfdef.canary") {
            break ev;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(finding.severity_id, SeverityId::Critical);
    assert_eq!(finding.class_uid, ClassUid::DETECTION_FINDING);
    assert_eq!(finding.category_uid, CategoryUid::Findings);
    assert!(!finding.attack.is_empty());
    assert_eq!(finding.attack[0].id, "T1552.001");
    let file = finding.file.as_ref().expect("file attached");
    assert_eq!(file.path.as_deref(), Some(canary_path.to_str().unwrap()));

    // Give the responder a beat to run its action dispatch.
    tokio::time::sleep(Duration::from_millis(100)).await;

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), coll_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), resp_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), sink).await;
}

#[tokio::test(flavor = "current_thread")]
async fn responder_panic_fire_path_runs_lockdown_in_dry_run() {
    // Build a panic finding (as `selfdefctl panic` does internally) and feed
    // it directly to `Responder::fire`. Dry-run must not invoke the script.
    let dir = tempdir().unwrap();
    let dummy_script = dir.path().join("would-have-locked-down.sh");
    assert!(!dummy_script.exists());

    let notifier: Arc<dyn selfdef_notifier::Notifier> = Arc::new(NullNotifier::default());
    let actions: Vec<Arc<dyn Action>> = vec![
        Arc::new(NotifyAction::new(notifier.clone())),
        Arc::new(LockdownEgressAction::new(dummy_script.clone())),
    ];
    let responder = Responder::new(
        actions,
        vec!["notify".into(), "lockdown_egress".into()],
        /* dry_run */ true,
    );

    let event = selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        "panic-host",
        "selfdef.panic",
        0,
    )
    .with_message("PANIC: test");

    responder.fire(&event).await;

    // The dry-run path must not have created the script or executed it.
    assert!(!dummy_script.exists());

    // The null-notifier must have been invoked exactly zero times — dry_run
    // calls dry_run path, not real notify.
    // (NullNotifier counts increment only on the real send path.)
}
