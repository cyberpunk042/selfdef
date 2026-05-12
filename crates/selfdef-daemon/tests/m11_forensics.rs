//! M11 integration test: a Critical finding on the bus triggers the
//! responder's `forensics_bundle` action, which writes a per-event directory
//! containing at minimum the triggering event JSON and a manifest. The
//! companion `velociraptor_escalate` action is exercised in dry-run with
//! placeholder substitution so we cover both new actions without needing a
//! real Velociraptor binary on the test host.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{
    Action, ForensicsBundleAction, NotifyAction, VelociraptorEscalateAction,
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct NullNotifier;

#[async_trait::async_trait]
impl selfdef_notifier::Notifier for NullNotifier {
    async fn notify(
        &self,
        _event: &selfdef_core::Event,
    ) -> Result<(), selfdef_notifier::NotifierError> {
        Ok(())
    }
    fn name(&self) -> &'static str { "null" }
}

fn make_finding(host: &str) -> selfdef_core::Event {
    selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        host,
        "m11.test",
        0,
    )
    .with_message("synthetic critical finding for M11 forensics test")
}

#[tokio::test(flavor = "current_thread")]
async fn forensics_bundle_runs_on_critical_finding() {
    let dir = tempdir().unwrap();
    let forensics_dir = dir.path().join("forensics");

    // Responder with notify + forensics_bundle + velociraptor_escalate.
    // velociraptor binary is intentionally a path that doesn't exist so a
    // real-run misfire would fail loudly — but we keep dry_run=false for
    // forensics_bundle to exercise the actual file writes.
    let notifier: Arc<dyn selfdef_notifier::Notifier> = Arc::new(NullNotifier);
    let actions: Vec<Arc<dyn Action>> = vec![
        Arc::new(NotifyAction::new(notifier)),
        Arc::new(ForensicsBundleAction::new(forensics_dir.clone())),
        // velociraptor stays in dry-run via the responder's global flag below.
        Arc::new(VelociraptorEscalateAction::new(
            PathBuf::from("/nonexistent/velociraptor"),
            vec!["collect".into(), "--label={host_tag}".into(), "--tag={event_id}".into()],
        )),
    ];

    let responder = Arc::new(Responder::new(
        actions,
        vec![
            "notify".into(),
            "forensics_bundle".into(),
            "velociraptor_escalate".into(),
        ],
        /* dry_run */ false,
    ));

    let bus = Bus::new(16);
    let publisher = bus.publisher();
    let sub = bus.subscribe();
    let shutdown = CancellationToken::new();

    let resp_shutdown = shutdown.clone();
    let resp_clone = responder.clone();
    let resp_task =
        tokio::spawn(async move { resp_clone.run(sub, resp_shutdown).await });

    // Publish a synthetic Critical finding onto the bus. The responder
    // subscribes to Findings-class events and dispatches actions.
    let event = make_finding("m11-host");
    let event_id = event.id;
    publisher.publish(event).expect("publish ok");

    // Poll the forensics directory for the per-event subdir to appear.
    let bundle = forensics_dir.join(event_id.to_string());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if bundle.join("manifest.txt").exists() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "forensics bundle never appeared at {}",
                bundle.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The event JSON should round-trip back to the same event id.
    let event_json = std::fs::read_to_string(bundle.join("event.json")).unwrap();
    let parsed: selfdef_core::Event = serde_json::from_str(&event_json).unwrap();
    assert_eq!(parsed.id, event_id);
    assert_eq!(parsed.severity_id, SeverityId::Critical);

    // Manifest should record the event.json line and a proc skip line for
    // the pidless event.
    let manifest = std::fs::read_to_string(bundle.join("manifest.txt")).unwrap();
    assert!(manifest.contains("event.json"));
    assert!(manifest.contains("proc/* SKIP"));

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), resp_task).await;
}

#[tokio::test]
async fn forensics_dry_run_doesnt_create_directory() {
    let dir = tempdir().unwrap();
    let forensics_dir = dir.path().join("forensics");
    let action = ForensicsBundleAction::new(forensics_dir.clone());

    let outcome = action
        .execute(&make_finding("m11-host"), /* dry_run */ true)
        .await
        .unwrap();
    assert!(outcome.notes.contains("would write forensics bundle"));
    // No on-disk side effects in dry-run.
    assert!(!forensics_dir.exists());
}

#[tokio::test]
async fn velociraptor_dry_run_substitutes_event_placeholders() {
    let action = VelociraptorEscalateAction::new(
        PathBuf::from("/usr/local/bin/velociraptor"),
        vec![
            "client".into(),
            "collect".into(),
            "--artifact=Generic.Forensic.LocalT1059".into(),
            "--label={host_tag}".into(),
            "--tag={event_id}".into(),
        ],
    );
    let event = make_finding("m11-host");
    let outcome = action.execute(&event, /* dry_run */ true).await.unwrap();
    assert!(outcome.notes.contains(&event.id.to_string()));
    assert!(outcome.notes.contains("--label=m11-host"));
}
