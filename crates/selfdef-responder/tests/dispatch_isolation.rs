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

/// Stalls far past any test deadline — a stand-in for a wedged operator
/// script / loginctl / journalctl / Velociraptor CLI.
struct StallAction;

#[async_trait]
impl Action for StallAction {
    fn name(&self) -> &'static str {
        "stall-action"
    }
    async fn execute(&self, _event: &Event, _dry_run: bool) -> Result<ActionOutcome, ActionError> {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        Ok(ActionOutcome::ok("never reached"))
    }
}

/// The engine's no-hang contract: actions run sequentially, so a wedged
/// action must be cut at the deadline and the REMAINING actions must still
/// run — one hung subprocess must not stall the whole autonomous-response
/// engine.
#[tokio::test]
async fn hung_action_is_cut_at_deadline_and_remaining_actions_still_run() {
    let (after, called_after, _dry) = mock();
    let r = Responder::new(
        vec![Arc::new(StallAction), after],
        vec!["stall-action".into(), "mock-action".into()],
        false,
    )
    .with_action_deadline(std::time::Duration::from_millis(100));

    let start = std::time::Instant::now();
    r.fire(&finding()).await;
    let elapsed = start.elapsed();

    assert!(
        called_after.load(Ordering::SeqCst),
        "the action AFTER the hung one must still run — the engine must not stall"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "dispatch must return promptly after the deadline, took {elapsed:?}"
    );
}

/// dispatch_single (the operator-authenticated API path) honors the same
/// deadline, surfacing a timed-out action as an error rather than hanging
/// the API request forever.
#[tokio::test]
async fn dispatch_single_times_out_a_hung_action() {
    let r = Responder::new(vec![Arc::new(StallAction)], vec![], false)
        .with_action_deadline(std::time::Duration::from_millis(100));

    let start = std::time::Instant::now();
    let out = r.dispatch_single("stall-action", &finding()).await;
    let elapsed = start.elapsed();

    match out {
        Some(Err(e)) => {
            let msg = e.to_string();
            assert!(msg.contains("timed out"), "expected timeout error: {msg}");
        }
        other => panic!("expected Some(Err(timeout)), got {other:?}"),
    }
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "must return promptly after the deadline, took {elapsed:?}"
    );
}

#[test]
fn unknown_allowed_actions_flags_typos_not_real_names() {
    let (a, _, _) = mock(); // registers "mock-action"
    // allowlist mixes the real action with two names that match nothing — a
    // typo and a plausible-but-unregistered action. Both are inert (the
    // dispatch loop only runs registered+allowed actions), so they should be
    // surfaced; the real "mock-action" must NOT be.
    let r = Responder::new(
        vec![a],
        vec![
            "mock-action".into(),
            "kil_pid".into(), // typo of a real action elsewhere
            "notify".into(),  // not registered in this responder
        ],
        false,
    );
    assert_eq!(
        r.unknown_allowed_actions(),
        vec!["kil_pid".to_string(), "notify".to_string()]
    );

    // an allowlist with only real names yields nothing.
    let (a2, _, _) = mock();
    let clean = Responder::new(vec![a2], vec!["mock-action".into()], false);
    assert!(clean.unknown_allowed_actions().is_empty());
}
