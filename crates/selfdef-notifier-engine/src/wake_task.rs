//! Wake task: deadline-driven re-fire of unacked escalations.
//!
//! D-5c (this module, first ship): the loop that turns the engine +
//! dispatcher into actual escalation. Without it, `submit()` fires
//! once and the row sits in the engine forever. With it, an
//! unacked row's deadline expires → the wake task re-fires the
//! channels → advances the row to the next rung with a new deadline
//! → eventually closes when max rungs are reached.
//!
//! v1 rung policy (D-5c, hardcoded):
//! - `rung_index = 0` is the initial attempt (fired by `submit`)
//! - `rung_index = 1` is one retry by the wake task
//! - `rung_index >= MAX_RUNG` (= 1) → close without further attempts
//! - Each rung gets a fresh deadline = `now + RUNG_INTERVAL`
//!
//! Operator-tunable rung sequences land in D-6 (mode profiles). For
//! v1 the policy is **two attempts total** (initial + one retry)
//! with a 5-minute ack window per rung.
//!
//! The loop is cancellable via [`tokio_util::sync::CancellationToken`].
//! The daemon spawns the task at startup and cancels it on shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use selfdef_notifier_orchestrator::Payload;

use crate::{EngineError, PayloadDispatcher, PendingEscalation};

/// Maximum rung index. After a row reaches this rung, the next wake
/// closes it without re-firing. `0` = first attempt (by `submit`),
/// `1` = one retry by the wake task.
pub const MAX_RUNG: u32 = 1;

/// Default wait between rungs (operator ack window). D-6 lifts this
/// to a per-profile setting; v1 hardcodes 5 minutes as a sensible
/// default for "on-call hears within an hour overall".
pub const DEFAULT_RUNG_INTERVAL_SECS: i64 = 300;

/// Idle poll interval — how long the wake task sleeps when the
/// engine reports no pending rows. Keeps the task alive without
/// burning CPU.
pub const IDLE_POLL_INTERVAL_SECS: u64 = 60;

/// Maximum rows the wake task pulls per iteration. Keeps a busy
/// engine from monopolising one wake cycle; subsequent iterations
/// catch any leftover.
pub const TAKE_DUE_LIMIT: usize = 100;

/// Run the wake-task loop. Drives the [`PayloadDispatcher`] forward
/// on persisted-row deadlines. Returns when `cancel` is cancelled.
///
/// Loop body:
/// 1. Compute the wait: `engine.next_pending_at()` returns the
///    earliest deadline (unix seconds). Sleep until `max(now,
///    deadline)`. If `None`, sleep [`IDLE_POLL_INTERVAL_SECS`].
/// 2. On wake: `take_due(now, TAKE_DUE_LIMIT)` claims due rows.
/// 3. For each row:
///    - If `rung_index >= MAX_RUNG`: close (max attempts hit).
///    - Else: re-fire via `dispatcher.dispatch_payload`, then
///      `engine.advance_rung(rung_index + 1, now + RUNG_INTERVAL)`.
/// 4. Loop. Cancellation short-circuits the sleep.
pub async fn run(dispatcher: Arc<PayloadDispatcher>, cancel: CancellationToken) {
    info!(
        max_rung = MAX_RUNG,
        rung_interval_secs = DEFAULT_RUNG_INTERVAL_SECS,
        "wake_task: starting",
    );
    loop {
        let sleep_for = compute_sleep(dispatcher.as_ref()).await;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("wake_task: cancelled, exiting");
                return;
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }
        process_due(dispatcher.as_ref()).await;
    }
}

/// Decide how long to sleep before the next wake. Public so tests
/// can verify the sleep-duration logic in isolation.
async fn compute_sleep(dispatcher: &PayloadDispatcher) -> Duration {
    let now = unix_now();
    match dispatcher.engine().next_pending_at().await {
        Ok(Some(deadline_at)) => {
            if deadline_at <= now {
                Duration::ZERO
            } else {
                let secs = (deadline_at - now) as u64;
                Duration::from_secs(secs.min(IDLE_POLL_INTERVAL_SECS))
            }
        }
        Ok(None) => Duration::from_secs(IDLE_POLL_INTERVAL_SECS),
        Err(e) => {
            warn!(error = %e, "wake_task: next_pending_at failed; falling back to idle poll");
            Duration::from_secs(IDLE_POLL_INTERVAL_SECS)
        }
    }
}

/// Process whatever rows are due now. One iteration of the wake
/// loop's body. Test-friendly: callers can drive it manually with a
/// fixed `now`.
async fn process_due(dispatcher: &PayloadDispatcher) {
    let now = unix_now();
    let due = match dispatcher.engine().take_due(now, TAKE_DUE_LIMIT).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "wake_task: take_due failed; skipping iteration");
            return;
        }
    };
    if due.is_empty() {
        return;
    }
    debug!(count = due.len(), "wake_task: processing due rows");
    for row in due {
        handle_row(dispatcher, row, now).await;
    }
}

/// Handle one due row: either close (max rungs hit) or re-fire +
/// advance.
async fn handle_row(dispatcher: &PayloadDispatcher, row: PendingEscalation, now: i64) {
    if row.rung_index >= MAX_RUNG {
        info!(
            event_id = %row.event_id,
            rung = row.rung_index,
            "wake_task: max rungs reached; closing",
        );
        if let Err(e) = dispatcher.close_event(row.event_id).await {
            warn!(event_id = %row.event_id, error = %e, "wake_task: close_event failed");
        }
        return;
    }

    let payload = Payload {
        id: row.payload_id,
        event_id: Some(row.event_id),
        title: row.title,
        body: row.body,
        severity: row.severity,
        ack_link: row.ack_link,
    };
    let outcome = dispatcher.dispatch_payload(&payload).await;
    info!(
        event_id = %row.event_id,
        rung = row.rung_index,
        delivered = outcome.delivered(),
        "wake_task: re-fired",
    );

    let next_rung = row.rung_index + 1;
    let next_deadline = now + DEFAULT_RUNG_INTERVAL_SECS;
    match dispatcher
        .engine()
        .advance_rung(row.event_id, next_rung, next_deadline)
        .await
    {
        Ok(true) => {
            debug!(
                event_id = %row.event_id,
                new_rung = next_rung,
                new_deadline = next_deadline,
                "wake_task: advanced rung",
            );
        }
        Ok(false) => {
            // The row was acked between take_due and advance_rung,
            // OR it was already past next_rung. Either way the
            // operator's intent takes precedence — no further
            // action needed.
            debug!(
                event_id = %row.event_id,
                "wake_task: advance_rung was a no-op (acked or already past rung)",
            );
        }
        Err(e) => {
            warn!(event_id = %row.event_id, error = %e, "wake_task: advance_rung failed");
        }
    }
}

/// Convert system time to unix seconds. Test-friendly seam — tests
/// drive `process_due` directly so they don't depend on real time.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Re-export the engine error type for callers that want to bubble
/// wake-task errors uniformly.
pub type WakeError = EngineError;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use selfdef_notifier_orchestrator::{
        AckReplyHint, Channel, ChannelError, DeliveryReceipt, EventId, PayloadId, SeverityId,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    use crate::EscalationEngine;

    /// Stub channel that records send invocations.
    struct MockChannel {
        name: &'static str,
        sent: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Channel for MockChannel {
        fn name(&self) -> &str {
            self.name
        }
        async fn send(&self, _payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
            self.sent.fetch_add(1, Ordering::AcqRel);
            Ok(DeliveryReceipt::empty())
        }
        fn supports_ack_reply(&self) -> bool {
            false
        }
        fn ack_reply_format(&self) -> Option<AckReplyHint> {
            None
        }
    }

    fn stub_channel(name: &'static str) -> (Arc<dyn Channel>, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let ch = Arc::new(MockChannel {
            name,
            sent: Arc::clone(&counter),
        });
        (ch, counter)
    }

    async fn fresh_dispatcher() -> (Arc<PayloadDispatcher>, Arc<AtomicUsize>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let (ch, counter) = stub_channel("ok");
        let dispatcher = Arc::new(PayloadDispatcher::new(engine, vec![ch]));
        (dispatcher, counter, dir)
    }

    fn mk_payload(title: &str) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: title.to_owned(),
            body: format!("body for {title}"),
            severity: SeverityId::High,
            ack_link: None,
        }
    }

    #[tokio::test]
    async fn process_due_fires_channels_and_advances_rung() {
        let (dispatcher, counter, _dir) = fresh_dispatcher().await;
        let payload = mk_payload("alert");
        let event_id = payload.event_id.unwrap();
        dispatcher.submit(&payload, 0, 0).await; // deadline_at = 0 → immediately due
        assert_eq!(counter.load(Ordering::Acquire), 1, "submit fires once");

        // Wake task picks it up: re-fires channel, advances rung.
        process_due(dispatcher.as_ref()).await;
        assert_eq!(
            counter.load(Ordering::Acquire),
            2,
            "wake re-fires the channel"
        );

        // The row is now at rung 1 with a future deadline.
        let next = dispatcher.engine().next_pending_at().await.unwrap();
        assert!(next.is_some(), "row still pending at next rung");
        // Take_due with the original deadline (0) returns nothing.
        let still_due = dispatcher.engine().take_due(0, 10).await.unwrap();
        assert!(
            still_due.is_empty(),
            "row should no longer be due at the original deadline"
        );
        // Take_due with a far-future cutoff returns the row at rung 1.
        let later = dispatcher
            .engine()
            .take_due(i64::MAX / 2, 10)
            .await
            .unwrap();
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].rung_index, 1);
        assert_eq!(later[0].event_id, event_id);
    }

    #[tokio::test]
    async fn process_due_closes_row_at_max_rung() {
        let (dispatcher, counter, _dir) = fresh_dispatcher().await;
        let payload = mk_payload("max-rung");
        let event_id = payload.event_id.unwrap();
        dispatcher.submit(&payload, 0, 0).await;
        assert_eq!(counter.load(Ordering::Acquire), 1);

        // Advance to MAX_RUNG manually + reset deadline to 0 so it's
        // due again. This simulates the engine state after one full
        // escalation cycle.
        dispatcher
            .engine()
            .advance_rung(event_id, MAX_RUNG, 0)
            .await
            .unwrap();

        // Now process_due should see the row at MAX_RUNG and close it,
        // NOT re-fire the channel.
        let pre_close_count = counter.load(Ordering::Acquire);
        process_due(dispatcher.as_ref()).await;
        assert_eq!(
            counter.load(Ordering::Acquire),
            pre_close_count,
            "at max rung the channel must NOT fire again"
        );

        // Row is gone.
        assert_eq!(dispatcher.engine().row_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn process_due_skips_acked_rows() {
        let (dispatcher, counter, _dir) = fresh_dispatcher().await;
        let payload = mk_payload("acked");
        let event_id = payload.event_id.unwrap();
        dispatcher.submit(&payload, 0, 0).await;
        // Operator acks the event before the wake task runs.
        dispatcher.record_ack(event_id, 1).await.unwrap();

        let pre = counter.load(Ordering::Acquire);
        process_due(dispatcher.as_ref()).await;
        assert_eq!(
            counter.load(Ordering::Acquire),
            pre,
            "acked row must not trigger re-fire"
        );
        // Row still exists (we keep acked rows for audit) but is
        // never returned by take_due.
    }

    #[tokio::test]
    async fn process_due_handles_empty_queue() {
        let (dispatcher, counter, _dir) = fresh_dispatcher().await;
        // No submit → empty engine.
        process_due(dispatcher.as_ref()).await;
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let (dispatcher, _counter, _dir) = fresh_dispatcher().await;
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let d = Arc::clone(&dispatcher);
            let c = cancel.clone();
            async move { run(d, c).await }
        });
        // Give the task a moment to enter the loop, then cancel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        // The task should exit promptly after cancellation. Allow
        // a generous timeout to absorb scheduler jitter, but
        // anything > 1s indicates a bug in the select arm.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("wake_task did not exit within 2s of cancellation")
            .expect("wake_task panicked");
    }

    #[tokio::test]
    async fn compute_sleep_uses_idle_when_empty() {
        let (dispatcher, _counter, _dir) = fresh_dispatcher().await;
        let sleep = compute_sleep(dispatcher.as_ref()).await;
        assert_eq!(sleep, Duration::from_secs(IDLE_POLL_INTERVAL_SECS));
    }

    #[tokio::test]
    async fn compute_sleep_returns_zero_when_past_deadline() {
        let (dispatcher, _counter, _dir) = fresh_dispatcher().await;
        let p = mk_payload("past");
        dispatcher.submit(&p, 0, 0).await; // deadline = 0 → far past
        let sleep = compute_sleep(dispatcher.as_ref()).await;
        assert_eq!(sleep, Duration::ZERO);
    }
}
