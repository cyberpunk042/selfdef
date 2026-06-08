//! F-2026-063: isolation tests for the Responder dispatch surface.
//!
//! The concrete actions have unit tests, but the *dispatcher* (allowlist
//! gating, dry-run propagation, unknown-action handling) had none. These
//! drive `Responder` through its public API with a mock `Action` that
//! records whether — and with what `dry_run` flag — it was executed, so a
//! regression in the dispatch path (e.g. firing a disallowed action, or
//! dropping the dry-run flag) is caught.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, ActionError, ActionOutcome, Status};

use async_trait::async_trait;

/// Records each execution + the dry_run flag it was handed.
struct MockAction {
    called: Arc<AtomicBool>,
    saw_dry_run: Arc<AtomicBool>,
}

#[async_trait]
impl Action for MockAction {
    fn name(&self) -> &'static str {
        "mock-action"
    }
    async fn execute(&self, _event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        self.called.store(true, Ordering::SeqCst);
        self.saw_dry_run.store(dry_run, Ordering::SeqCst);
        Ok(if dry_run {
            ActionOutcome::dry_run("mock")
        } else {
            ActionOutcome::ok("mock")
        })
    }
}

fn mock() -> (Arc<MockAction>, Arc<AtomicBool>, Arc<AtomicBool>) {
    let called = Arc::new(AtomicBool::new(false));
    let dry = Arc::new(AtomicBool::new(false));
    let a = Arc::new(MockAction {
        called: called.clone(),
        saw_dry_run: dry.clone(),
    });
    (a, called, dry)
}

fn finding() -> Event {
    Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        "host",
        "test",
        0,
    )
}

#[tokio::test]
async fn dispatch_single_runs_a_known_action_and_propagates_live_mode() {
    let (a, called, dry) = mock();
    let r = Responder::new(vec![a], vec!["mock-action".into()], false);
    let out = r.dispatch_single("mock-action", &finding()).await;
    assert!(matches!(out, Some(Ok(_))), "known action returns Some(Ok)");
    assert!(called.load(Ordering::SeqCst), "the action ran");
    assert!(!dry.load(Ordering::SeqCst), "dry_run=false was propagated");
}

#[tokio::test]
async fn dispatch_single_unknown_action_returns_none_and_runs_nothing() {
    let (a, called, _dry) = mock();
    let r = Responder::new(vec![a], vec!["mock-action".into()], false);
    assert!(
        r.dispatch_single("no-such-action", &finding())
            .await
            .is_none(),
        "unknown action → None"
    );
    assert!(!called.load(Ordering::SeqCst), "no action ran");
}

#[tokio::test]
async fn dispatch_single_propagates_dry_run_to_the_action() {
    let (a, _called, dry) = mock();
    let r = Responder::new(vec![a], vec!["mock-action".into()], true);
    let out = r
        .dispatch_single("mock-action", &finding())
        .await
        .expect("registered")
        .expect("ok");
    assert_eq!(out.status, Status::DryRun, "dry-run outcome status");
    assert!(
        dry.load(Ordering::SeqCst),
        "dry_run=true reached the action"
    );
}

#[tokio::test]
async fn fire_executes_an_allowlisted_action() {
    let (a, called, _dry) = mock();
    let r = Responder::new(vec![a], vec!["mock-action".into()], false);
    r.fire(&finding()).await;
    assert!(called.load(Ordering::SeqCst), "allowlisted action fires");
}

#[tokio::test]
async fn fire_does_not_execute_a_disallowed_action() {
    // Registered but NOT in the allowlist — fire() must skip it.
    let (a, called, _dry) = mock();
    let r = Responder::new(vec![a], vec![], false);
    r.fire(&finding()).await;
    assert!(
        !called.load(Ordering::SeqCst),
        "a disallowed action must never fire through the dispatcher"
    );
}
