//! Opt-in destructive-action burst-dedup (decision-discipline).
//!
//! The responder fires destructive actions (kill / quarantine / block) with no
//! rate-limiting by default, so a finding burst can hammer the same action on
//! the same target. `with_dedup_window(w)` opts a deployment into suppressing a
//! destructive action repeated on the same `(action, target)` within `w`. The
//! default (`Responder::new`) is disabled — exact prior behavior. Notify /
//! snapshot / forensic actions are never deduped (every alert/evidence kept).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, ActionError, ActionOutcome};

/// Counts dispatches; `name` lets a test mark the action destructive or not.
struct CountingAction {
    name: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Action for CountingAction {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn execute(&self, _event: &Event, _dry_run: bool) -> Result<ActionOutcome, ActionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ActionOutcome::ok("counted"))
    }
}

fn responder(name: &'static str, window: Option<Duration>) -> (Responder, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let action: Arc<dyn Action> = Arc::new(CountingAction {
        name,
        calls: calls.clone(),
    });
    let mut r = Responder::new(vec![action], vec![name.into()], false);
    if let Some(w) = window {
        r = r.with_dedup_window(w);
    }
    (r, calls)
}

fn finding(seq: u64) -> Event {
    Event::new(ClassUid::DETECTION_FINDING, 1, SeverityId::High, "host", "test", seq)
}

#[tokio::test]
async fn dedup_window_suppresses_repeated_destructive_action() {
    // kill_pid is destructive; two findings against the same (target-less ⇒
    // identical) target fired within the window run ONCE.
    let (r, calls) = responder("kill_pid", Some(Duration::from_secs(60)));
    r.fire(&finding(1)).await;
    r.fire(&finding(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second destructive fire on the same target must be suppressed within the window"
    );
}

#[tokio::test]
async fn dedup_disabled_by_default_runs_every_time() {
    // No with_dedup_window ⇒ disabled ⇒ exact prior behavior (no suppression).
    let (r, calls) = responder("kill_pid", None);
    r.fire(&finding(1)).await;
    r.fire(&finding(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "default (disabled) must preserve the pre-dedup behavior"
    );
}

#[tokio::test]
async fn dedup_never_suppresses_non_destructive_actions() {
    // notify is NOT destructive: every alert must be preserved even with dedup on.
    let (r, calls) = responder("notify", Some(Duration::from_secs(60)));
    r.fire(&finding(1)).await;
    r.fire(&finding(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "notify must never be deduped — every alert is delivered"
    );
}

#[tokio::test]
async fn rate_cap_suppresses_destructive_flood_beyond_cap() {
    // cap=2: with dedup OFF, three destructive fires — first two run, the
    // third trips the circuit breaker (catches a multi-target flood).
    let calls = Arc::new(AtomicUsize::new(0));
    let action: Arc<dyn Action> = Arc::new(CountingAction {
        name: "kill_pid",
        calls: calls.clone(),
    });
    let r = Responder::new(vec![action], vec!["kill_pid".into()], false)
        .with_destructive_cap_per_min(2);
    r.fire(&finding(1)).await;
    r.fire(&finding(2)).await;
    r.fire(&finding(3)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "destructive actions beyond the per-minute cap must be suppressed"
    );
}

#[tokio::test]
async fn rate_cap_never_caps_non_destructive_actions() {
    // notify is not destructive — never circuit-broken, every alert delivered.
    let calls = Arc::new(AtomicUsize::new(0));
    let action: Arc<dyn Action> = Arc::new(CountingAction {
        name: "notify",
        calls: calls.clone(),
    });
    let r = Responder::new(vec![action], vec!["notify".into()], false)
        .with_destructive_cap_per_min(1);
    r.fire(&finding(1)).await;
    r.fire(&finding(2)).await;
    r.fire(&finding(3)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "notify must never be rate-capped — every alert is delivered"
    );
}

#[tokio::test]
async fn suppressed_counter_increments_when_a_destructive_action_is_suppressed() {
    // Observability: each suppression (dedup here) bumps the counter the daemon
    // exposes as `selfdef_responder_suppressed_destructive_total`.
    use std::sync::atomic::AtomicU64;
    let calls = Arc::new(AtomicUsize::new(0));
    let suppressed = Arc::new(AtomicU64::new(0));
    let action: Arc<dyn Action> = Arc::new(CountingAction {
        name: "kill_pid",
        calls: calls.clone(),
    });
    let r = Responder::new(vec![action], vec!["kill_pid".into()], false)
        .with_dedup_window(Duration::from_secs(60))
        .with_suppressed_counter(suppressed.clone());
    r.fire(&finding(1)).await; // fires
    r.fire(&finding(2)).await; // same target ⇒ suppressed
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        suppressed.load(Ordering::SeqCst),
        1,
        "a suppressed destructive action must bump the metric counter"
    );
}
