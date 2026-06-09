//! F-2026-094: the responder counts findings it drops to a broadcast lag.
//!
//! A lagging responder silently drops findings before any action runs — no
//! notify / kill / quarantine. The opt-in lag counter (wired by the daemon to
//! `selfdef_responder_lag_events_total`) must be bumped by the missed count so
//! that loss is observable. This drives a real lag by overrunning a tiny bus
//! before the responder starts consuming.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, ActionError, ActionOutcome};
use tokio_util::sync::CancellationToken;

struct NoopAction;

#[async_trait]
impl Action for NoopAction {
    fn name(&self) -> &'static str {
        "noop"
    }
    async fn execute(&self, _event: &Event, _dry_run: bool) -> Result<ActionOutcome, ActionError> {
        Ok(ActionOutcome::ok("noop"))
    }
}

fn finding(seq: u64) -> Event {
    Event::new(ClassUid::DETECTION_FINDING, 1, SeverityId::Critical, "host", "test", seq)
}

#[tokio::test]
async fn lag_counter_counts_findings_dropped_to_a_bus_lag() {
    // Capacity 2: publishing 5 before the responder consumes drops the 3
    // oldest, so the first recv() returns Lagged(3).
    let bus = Bus::new(2);
    let sub = bus.subscribe(); // exists before publish so publishes succeed
    let publisher = bus.publisher();
    for i in 0..5 {
        publisher.publish(finding(i)).unwrap();
    }

    let lag = Arc::new(AtomicU64::new(0));
    let action: Arc<dyn Action> = Arc::new(NoopAction);
    let responder = Arc::new(
        Responder::new(vec![action], vec!["noop".into()], false)
            .with_lag_counter(Arc::clone(&lag)),
    );

    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let r = Arc::clone(&responder);
        let sd = shutdown.clone();
        async move { r.run(sub, sd).await }
    });

    // Give the run loop time to hit the Lagged branch.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if lag.load(Ordering::SeqCst) >= 3 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("lag counter never reached the 3 dropped findings (got {})", lag.load(Ordering::SeqCst));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(lag.load(Ordering::SeqCst), 3, "exactly 3 findings were dropped");

    shutdown.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn no_lag_counter_is_fine_default() {
    // A responder without a lag counter must still run (no panic) on a lag.
    let bus = Bus::new(2);
    let sub = bus.subscribe();
    let publisher = bus.publisher();
    for i in 0..5 {
        publisher.publish(finding(i)).unwrap();
    }
    let action: Arc<dyn Action> = Arc::new(NoopAction);
    let responder = Arc::new(Responder::new(vec![action], vec!["noop".into()], false));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let r = Arc::clone(&responder);
        let sd = shutdown.clone();
        async move { r.run(sub, sd).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.cancel();
    let _ = task.await; // completes without panicking
}
