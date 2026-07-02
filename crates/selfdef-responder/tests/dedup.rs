//! Opt-in destructive-action decision-discipline: burst-dedup + rate-cap.
//!
//! These gates apply ONLY to the autonomous bus path (`run`), never to the
//! operator-commanded `fire`/panic path — exactly like the severity floor. So
//! the tests drive the real bus loop; one test pins that `fire` bypasses the
//! gates. Default (no `with_*`) is disabled — exact prior behavior. Notify /
//! snapshot / forensic actions are never suppressed (every alert/evidence kept).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_responder::Responder;
use selfdef_responder::actions::{Action, ActionError, ActionOutcome};
use tokio_util::sync::CancellationToken;

/// Counts dispatches; `name` marks the action destructive (e.g. `kill_pid`) or
/// not (`notify`).
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

fn action(name: &'static str) -> (Arc<dyn Action>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let a: Arc<dyn Action> = Arc::new(CountingAction {
        name,
        calls: calls.clone(),
    });
    (a, calls)
}

/// Counts dispatch attempts but always fails — models a `kill_pid` that
/// can't reap its target (race, permission, vanished pid). Used to pin that
/// a FAILED destructive action stays retryable (not dedup-suppressed).
struct FailingAction {
    name: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Action for FailingAction {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn execute(&self, _event: &Event, _dry_run: bool) -> Result<ActionOutcome, ActionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ActionError::Exec("could not reap target".into()))
    }
}

fn failing_action(name: &'static str) -> (Arc<dyn Action>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let a: Arc<dyn Action> = Arc::new(FailingAction {
        name,
        calls: calls.clone(),
    });
    (a, calls)
}

fn finding(seq: u64) -> Event {
    Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::High,
        "host",
        "test",
        seq,
    )
}

/// A finding whose trigger came from another host via NATS (F-2026-111).
fn federated_finding(seq: u64) -> Event {
    finding(seq).with_federated(true)
}

/// A federated finding whose trigger carried a valid trusted-peer signature
/// (F-2026-111 c) — authenticated, so it bypasses the fail-closed gate.
fn verified_federated_finding(seq: u64) -> Event {
    finding(seq)
        .with_federated(true)
        .with_federation_verified(true)
}

/// Drive findings through the autonomous bus path and let the responder drain.
/// The subscriber is created before `run` is spawned, so events published
/// afterward are received.
async fn run_findings(responder: Arc<Responder>, events: Vec<Event>) {
    let bus = Bus::new(64);
    let sub = bus.subscribe();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let r = Arc::clone(&responder);
        let sd = shutdown.clone();
        async move { r.run(sub, sd).await }
    });
    let publisher = bus.publisher();
    for e in events {
        publisher.publish(e).unwrap();
    }
    // Generous settle for an in-process bus + atomic-increment actions.
    tokio::time::sleep(Duration::from_millis(250)).await;
    shutdown.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn dedup_window_suppresses_repeated_destructive_action() {
    let (a, calls) = action("kill_pid");
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_dedup_window(Duration::from_secs(60)),
    );
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second destructive fire on the same target must be suppressed within the window"
    );
}

#[tokio::test]
async fn dedup_disabled_by_default_runs_every_time() {
    let (a, calls) = action("kill_pid");
    let r = Arc::new(Responder::new(vec![a], vec!["kill_pid".into()], false));
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "default (disabled) must preserve the pre-dedup behavior"
    );
}

#[tokio::test]
async fn dedup_does_not_suppress_retry_of_a_failed_destructive_action() {
    // A destructive action that FAILED (e.g. kill_pid lost the race / the pid
    // had vanished) must remain retryable on the next finding — dedup is meant
    // to suppress a redundant *successful* repeat, not to permanently shield an
    // attacker process because the first kill attempt errored. The dedup record
    // is therefore committed only on Success; a failed attempt leaves no entry.
    let (a, calls) = failing_action("kill_pid");
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_dedup_window(Duration::from_secs(60)),
    );
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a failed destructive action must be retried, not dedup-suppressed"
    );
}

#[tokio::test]
async fn dedup_never_suppresses_non_destructive_actions() {
    let (a, calls) = action("notify");
    let r = Arc::new(
        Responder::new(vec![a], vec!["notify".into()], false)
            .with_dedup_window(Duration::from_secs(60)),
    );
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "notify must never be deduped — every alert is delivered"
    );
}

#[tokio::test]
async fn rate_cap_suppresses_destructive_flood_beyond_cap() {
    let (a, calls) = action("kill_pid");
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false).with_destructive_cap_per_min(2),
    );
    run_findings(r, vec![finding(1), finding(2), finding(3)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "destructive actions beyond the per-minute cap must be suppressed"
    );
}

#[tokio::test]
async fn rate_cap_never_caps_non_destructive_actions() {
    let (a, calls) = action("notify");
    let r = Arc::new(
        Responder::new(vec![a], vec!["notify".into()], false).with_destructive_cap_per_min(1),
    );
    run_findings(r, vec![finding(1), finding(2), finding(3)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "notify must never be rate-capped — every alert is delivered"
    );
}

#[tokio::test]
async fn suppressed_counter_increments_when_a_destructive_action_is_suppressed() {
    // Observability: each suppression bumps the counter the daemon exposes as
    // `selfdef_responder_suppressed_destructive_total`.
    let (a, calls) = action("kill_pid");
    let suppressed = Arc::new(AtomicU64::new(0));
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_dedup_window(Duration::from_secs(60))
            .with_suppressed_counter(suppressed.clone()),
    );
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        suppressed.load(Ordering::SeqCst),
        1,
        "a suppressed destructive action must bump the metric counter"
    );
}

#[tokio::test]
async fn dedup_suppression_does_not_trip_the_circuit_breaker_counter() {
    // The circuit-breaker alert keys on the rate-cap counter ONLY. Routine
    // per-target dedup is benign and must NOT raise it — otherwise a single
    // duplicate finding would fire a "circuit breaker tripped" warning (alert
    // fatigue). Dedup still bumps the aggregate `suppressed` total.
    let (a, calls) = action("kill_pid");
    let suppressed = Arc::new(AtomicU64::new(0));
    let ratecap = Arc::new(AtomicU64::new(0));
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_dedup_window(Duration::from_secs(60))
            .with_suppressed_counter(suppressed.clone())
            .with_ratecap_counter(ratecap.clone()),
    );
    run_findings(r, vec![finding(1), finding(2)]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        suppressed.load(Ordering::SeqCst),
        1,
        "dedup bumps the aggregate total"
    );
    assert_eq!(
        ratecap.load(Ordering::SeqCst),
        0,
        "routine dedup must NOT trip the rate-cap circuit-breaker counter"
    );
}

#[tokio::test]
async fn rate_cap_trip_increments_both_the_total_and_the_circuit_breaker_counter() {
    // A genuine flood (rate-cap reached) is the real circuit-breaker trip: it
    // bumps BOTH the aggregate `suppressed` total AND the dedicated rate-cap
    // counter the alert keys on.
    let (a, calls) = action("kill_pid");
    let suppressed = Arc::new(AtomicU64::new(0));
    let ratecap = Arc::new(AtomicU64::new(0));
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_destructive_cap_per_min(2)
            .with_suppressed_counter(suppressed.clone())
            .with_ratecap_counter(ratecap.clone()),
    );
    run_findings(r, vec![finding(1), finding(2), finding(3)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "two fire, the third is capped"
    );
    assert_eq!(
        suppressed.load(Ordering::SeqCst),
        1,
        "the capped action bumps the total"
    );
    assert_eq!(
        ratecap.load(Ordering::SeqCst),
        1,
        "a rate-cap trip is a genuine circuit-breaker event"
    );
}

#[tokio::test]
async fn fail_closed_refuses_destructive_action_for_a_federated_finding() {
    // act_on_federated=false: a destructive action for a federated-origin
    // finding must be refused (a compromised peer can't drive a local kill).
    let (a, calls) = action("kill_pid");
    let refused = Arc::new(AtomicU64::new(0));
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_act_on_federated(false)
            .with_federated_refused_counter(refused.clone()),
    );
    run_findings(r, vec![federated_finding(1)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "federated destructive action must be refused"
    );
    assert_eq!(
        refused.load(Ordering::SeqCst),
        1,
        "the refusal must bump the counter"
    );
}

#[tokio::test]
async fn fail_closed_acts_on_a_signature_verified_federated_finding() {
    // F-2026-111 (c): even fail-closed, a federated finding authenticated to a
    // trusted peer (federation_verified) bypasses the refusal and fires — an
    // authenticated peer is trusted like a local source.
    let (a, calls) = action("kill_pid");
    let refused = Arc::new(AtomicU64::new(0));
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false)
            .with_act_on_federated(false)
            .with_federated_refused_counter(refused.clone()),
    );
    run_findings(r, vec![verified_federated_finding(1)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a verified federated finding must be acted on"
    );
    assert_eq!(
        refused.load(Ordering::SeqCst),
        0,
        "a verified finding is not a refusal"
    );
}

#[tokio::test]
async fn default_acts_on_federated_findings_preserving_prior_behavior() {
    // Default (act_on_federated=true): a federated finding still drives the
    // destructive action — no behavior change for cross-host-response setups.
    let (a, calls) = action("kill_pid");
    let r = Arc::new(Responder::new(vec![a], vec!["kill_pid".into()], false));
    run_findings(r, vec![federated_finding(1)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "default must preserve cross-host response"
    );
}

#[tokio::test]
async fn fail_closed_still_acts_on_local_findings() {
    // act_on_federated=false must only gate FEDERATED findings — a local finding
    // fires normally.
    let (a, calls) = action("kill_pid");
    let r = Arc::new(
        Responder::new(vec![a], vec!["kill_pid".into()], false).with_act_on_federated(false),
    );
    run_findings(r, vec![finding(1)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "local findings are unaffected by the federation gate"
    );
}

#[tokio::test]
async fn operator_panic_acts_on_a_federated_finding_even_when_fail_closed() {
    // The federation gate is autonomous-only: an operator-commanded fire (panic)
    // on a federated finding must STILL act even with act_on_federated=false —
    // the human is the authority in an emergency.
    let (a, calls) = action("kill_pid");
    let r = Responder::new(vec![a], vec!["kill_pid".into()], false).with_act_on_federated(false);
    r.fire(&federated_finding(1)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "operator panic must bypass the federation gate"
    );
}

#[tokio::test]
async fn fail_closed_never_refuses_non_destructive_actions_for_federated_findings() {
    // Even fail-closed, a federated finding must still produce its alert/evidence
    // — notify is never refused.
    let (a, calls) = action("notify");
    let r = Arc::new(
        Responder::new(vec![a], vec!["notify".into()], false).with_act_on_federated(false),
    );
    run_findings(r, vec![federated_finding(1)]).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "notify must always fire, even for federated findings"
    );
}

#[tokio::test]
async fn operator_panic_fire_bypasses_the_discipline_gates() {
    // `fire` (selfdefctl panic) is operator-commanded: it must bypass dedup +
    // rate-cap, exactly as it bypasses the severity floor. With dedup AND a
    // cap=1 both enabled, two panics on the same target STILL both fire.
    let (a, calls) = action("kill_pid");
    let r = Responder::new(vec![a], vec!["kill_pid".into()], false)
        .with_dedup_window(Duration::from_secs(60))
        .with_destructive_cap_per_min(1);
    r.fire(&finding(1)).await;
    r.fire(&finding(1)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "operator panic must bypass the autonomous-only circuit-breakers"
    );
}
