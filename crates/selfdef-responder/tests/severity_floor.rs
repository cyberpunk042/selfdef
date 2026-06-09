//! F-2026-092: the autonomous-response severity floor.
//!
//! Before the floor, the responder ran every allowed action on every Findings
//! event regardless of grade — so an Informational/Low finding that happened to
//! carry an actor PID could get `kill_pid`'d. `with_min_severity(floor)` lets a
//! deployment require a minimum grade before the *autonomous* bus path
//! dispatches. The default (`Responder::new`) keeps the pre-floor behavior:
//! every finding is processed. These tests drive the real `run()` bus loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, ActionError, ActionOutcome};
use tokio_util::sync::CancellationToken;

/// Counts how many times it was dispatched.
struct CountingAction {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Action for CountingAction {
    fn name(&self) -> &'static str {
        "counter"
    }
    async fn execute(&self, _event: &Event, _dry_run: bool) -> Result<ActionOutcome, ActionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ActionOutcome::ok("counted"))
    }
}

fn responder_with(
    floor: Option<SeverityId>,
) -> (Arc<Responder>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let action: Arc<dyn Action> = Arc::new(CountingAction { calls: calls.clone() });
    let mut r = Responder::new(vec![action], vec!["counter".into()], false);
    if let Some(f) = floor {
        r = r.with_min_severity(f);
    }
    (Arc::new(r), calls)
}

fn finding(sev: SeverityId, seq: u64) -> Event {
    Event::new(ClassUid::DETECTION_FINDING, 1, sev, "host", "test", seq)
}

/// Poll the counter up to a deadline so the test isn't flaky under scheduler
/// jitter, but never waits longer than it must.
async fn reached(counter: &AtomicUsize, want: usize) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if counter.load(Ordering::SeqCst) >= want {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn floor_drops_below_and_passes_at_or_above() {
    let bus = Bus::new(64);
    let (responder, calls) = responder_with(Some(SeverityId::High));
    let sub = bus.subscribe();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let r = Arc::clone(&responder);
        let sd = shutdown.clone();
        async move { r.run(sub, sd).await }
    });

    let publisher = bus.publisher();
    // Below the floor: Medium < High → must be dropped.
    publisher.publish(finding(SeverityId::Medium, 1)).unwrap();
    publisher.publish(finding(SeverityId::Low, 2)).unwrap();
    // At/above the floor: High and Critical → must dispatch.
    publisher.publish(finding(SeverityId::High, 3)).unwrap();
    publisher.publish(finding(SeverityId::Critical, 4)).unwrap();

    assert!(
        reached(&calls, 2).await,
        "the two at-or-above-floor findings must dispatch"
    );
    // Give any erroneously-dispatched low-grade findings a chance to land, then
    // confirm exactly the two above-floor ones ran.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "Medium and Low must NOT have dispatched under a High floor"
    );

    shutdown.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn default_responder_processes_every_grade() {
    let bus = Bus::new(64);
    // No floor → default `Unknown`, the pre-fix behavior.
    let (responder, calls) = responder_with(None);
    let sub = bus.subscribe();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let r = Arc::clone(&responder);
        let sd = shutdown.clone();
        async move { r.run(sub, sd).await }
    });

    let publisher = bus.publisher();
    publisher.publish(finding(SeverityId::Informational, 1)).unwrap();
    publisher.publish(finding(SeverityId::Low, 2)).unwrap();
    publisher.publish(finding(SeverityId::Critical, 3)).unwrap();

    assert!(
        reached(&calls, 3).await,
        "default responder must dispatch every finding regardless of grade"
    );

    shutdown.cancel();
    let _ = task.await;
}
