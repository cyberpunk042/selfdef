//! Payload dispatcher: the engine + channel set, glued into one
//! façade.
//!
//! D-5b (this module, first ship): single `submit()` call that
//! persists the payload via [`EscalationEngine`] then fires the
//! channel set first-success-wins. Callers no longer have to
//! coordinate "persist before send" vs "send before persist" —
//! the dispatcher gets the order right and exposes a single
//! Result.
//!
//! The wake task that re-fires unacked rows on deadline expiry
//! lands in D-5c. This module deliberately stops short of that —
//! it locks in the dispatcher API + integration tests without
//! committing to wake-loop semantics yet (rung advancement is a
//! D-6 concern once operator profiles are in scope).

use std::sync::Arc;

use selfdef_notifier_orchestrator::{Channel, ChannelError, EventId, Payload};
use tracing::{info, warn};

use crate::{EngineError, EscalationEngine};

/// Result of a single [`PayloadDispatcher::submit`] call.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// Persistence and at least one channel-send both succeeded.
    /// The dispatcher logged which channel won. The persisted row
    /// stays in the engine until `record_ack` arrives or the wake
    /// task (D-5c) advances / closes it.
    Delivered {
        /// Slug of the channel that took the message.
        channel: String,
    },
    /// Persistence succeeded; every channel returned an error. The
    /// row is in the engine so the wake task can retry later
    /// (D-5c). Returned alongside the last channel's error so
    /// operators see the failure mode in logs.
    PersistedButAllChannelsFailed(ChannelError),
    /// Persistence failed — neither sent nor recorded. The caller's
    /// only option is to retry. We surface the engine error so they
    /// know whether SQLite is full / WAL is corrupt / etc.
    PersistFailed(EngineError),
}

impl DispatchOutcome {
    /// Convenience predicate: did at least one channel acknowledge
    /// receipt? Useful for callers that want to distinguish "no
    /// notification went out" from "notification persisted but
    /// every channel was down".
    #[must_use]
    pub fn delivered(&self) -> bool {
        matches!(self, Self::Delivered { .. })
    }
}

/// The dispatcher façade.
///
/// Owns:
/// - an [`EscalationEngine`] (persistence)
/// - an ordered list of [`Arc<dyn Channel>`] (the channel set;
///   first-success-wins matches the M4 NotifierChain semantics)
///
/// Construction: `PayloadDispatcher::new(engine, channels)`.
/// Use: `dispatcher.submit(&payload, deadline_at, now).await`.
///
/// The channel set is captured at construction. Future Ds may
/// grow a builder (D-3 subscriptions per-channel, D-6 mode
/// profiles); for now the channels fire in the order supplied.
pub struct PayloadDispatcher {
    engine: Arc<EscalationEngine>,
    channels: Vec<Arc<dyn Channel>>,
}

impl std::fmt::Debug for PayloadDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadDispatcher")
            .field("engine", &self.engine)
            .field("channel_count", &self.channels.len())
            .finish_non_exhaustive()
    }
}

impl PayloadDispatcher {
    /// Construct from the persistence engine + an ordered channel
    /// set. Channels are tried in the supplied order during
    /// `submit`; the first one that returns `Ok` wins.
    #[must_use]
    pub fn new(engine: Arc<EscalationEngine>, channels: Vec<Arc<dyn Channel>>) -> Self {
        Self { engine, channels }
    }

    /// Number of channels held by this dispatcher. Diagnostic
    /// helper; not part of the runtime contract.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Persist the payload via the engine, then dispatch to the
    /// channels in order. First channel that returns `Ok` wins.
    ///
    /// - On persist failure: [`DispatchOutcome::PersistFailed`].
    /// - On persist success + at least one channel success:
    ///   [`DispatchOutcome::Delivered`] naming the winning channel.
    /// - On persist success + every channel failed:
    ///   [`DispatchOutcome::PersistedButAllChannelsFailed`] with
    ///   the last channel's error. The row stays in the engine so
    ///   D-5c's wake task can retry once it lands.
    ///
    /// `payload.event_id` MUST be `Some`; the engine rejects
    /// otherwise (it keys persistence by event_id). For ad-hoc
    /// payloads with no event_id, callers should mint one with
    /// `EventId::from(Uuid::now_v7())`.
    pub async fn submit(&self, payload: &Payload, deadline_at: i64, now: i64) -> DispatchOutcome {
        if let Err(e) = self.engine.enqueue(payload, deadline_at, now).await {
            warn!(error = %e, "dispatcher: persist failed; not attempting channel sends");
            return DispatchOutcome::PersistFailed(e);
        }
        let mut last_err: Option<ChannelError> = None;
        for channel in &self.channels {
            match channel.send(payload).await {
                Ok(_receipt) => {
                    info!(channel = channel.name(), "dispatcher: channel accepted");
                    return DispatchOutcome::Delivered {
                        channel: channel.name().to_owned(),
                    };
                }
                Err(e) => {
                    warn!(channel = channel.name(), error = %e, "dispatcher: channel failed; trying next");
                    last_err = Some(e);
                }
            }
        }
        DispatchOutcome::PersistedButAllChannelsFailed(
            last_err.unwrap_or_else(|| {
                ChannelError::Other("dispatcher: no channels configured".into())
            }),
        )
    }

    /// Mark an event acked via the engine. Returns `Ok(true)` if
    /// a row was updated, `Ok(false)` if the event was unknown or
    /// already acked. Passthrough to [`EscalationEngine::record_ack`].
    pub async fn record_ack(&self, event_id: EventId, acked_at: i64) -> Result<bool, EngineError> {
        self.engine.record_ack(event_id, acked_at).await
    }

    /// Close an event (delete the row). Operator "forget" path.
    /// Passthrough to [`EscalationEngine::close_event`].
    pub async fn close_event(&self, event_id: EventId) -> Result<bool, EngineError> {
        self.engine.close_event(event_id).await
    }

    /// Engine access for callers that need it (e.g. the future
    /// wake task in D-5c, the CLI ack verb in D-4). Returned as an
    /// `Arc` so callers can clone without taking the dispatcher's
    /// inner reference.
    #[must_use]
    pub fn engine(&self) -> Arc<EscalationEngine> {
        Arc::clone(&self.engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use selfdef_notifier_orchestrator::{
        AckReplyHint, DeliveryReceipt, EventId, Payload, PayloadId, SeverityId,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    /// A test-only channel that records send invocations and can be
    /// told to fail. Useful for verifying dispatch ordering + the
    /// first-success-wins contract.
    struct MockChannel {
        name: &'static str,
        sent: Arc<AtomicUsize>,
        fail_with: Option<ChannelError>,
    }

    impl MockChannel {
        fn always_ok(name: &'static str) -> (Arc<Self>, Arc<AtomicUsize>) {
            let counter = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    name,
                    sent: Arc::clone(&counter),
                    fail_with: None,
                }),
                counter,
            )
        }

        fn always_fail(name: &'static str, err: ChannelError) -> (Arc<Self>, Arc<AtomicUsize>) {
            let counter = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    name,
                    sent: Arc::clone(&counter),
                    fail_with: Some(err),
                }),
                counter,
            )
        }
    }

    #[async_trait]
    impl Channel for MockChannel {
        fn name(&self) -> &str {
            self.name
        }
        async fn send(&self, _payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
            self.sent.fetch_add(1, Ordering::AcqRel);
            if let Some(e) = &self.fail_with {
                Err(match e {
                    ChannelError::Transport(s) => ChannelError::Transport(s.clone()),
                    ChannelError::Remote { status, body } => ChannelError::Remote {
                        status: *status,
                        body: body.clone(),
                    },
                    ChannelError::Timeout => ChannelError::Timeout,
                    ChannelError::Other(s) => ChannelError::Other(s.clone()),
                })
            } else {
                Ok(DeliveryReceipt::native(format!("{}-receipt", self.name)))
            }
        }
        fn supports_ack_reply(&self) -> bool {
            false
        }
        fn ack_reply_format(&self) -> Option<AckReplyHint> {
            None
        }
    }

    async fn fresh_engine() -> (Arc<EscalationEngine>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        (Arc::new(EscalationEngine::open(&path).unwrap()), dir)
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
    async fn submit_delivers_on_first_channel_success() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_ok, ok_counter) = MockChannel::always_ok("ok-1");
        let (ch_skip, skip_counter) = MockChannel::always_ok("ok-2");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_ok, ch_skip]);
        let payload = mk_payload("first-wins");
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "ok-1"),
            other => panic!("expected Delivered, got {other:?}"),
        }
        assert_eq!(ok_counter.load(Ordering::Acquire), 1);
        assert_eq!(
            skip_counter.load(Ordering::Acquire),
            0,
            "second channel must not be tried"
        );
    }

    #[tokio::test]
    async fn submit_falls_through_failing_channels_to_first_success() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_fail, fail_counter) =
            MockChannel::always_fail("fail-1", ChannelError::Transport("synthetic".into()));
        let (ch_ok, ok_counter) = MockChannel::always_ok("ok-1");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_fail, ch_ok]);
        let outcome = dispatcher.submit(&mk_payload("fallthrough"), 100, 0).await;
        assert!(outcome.delivered());
        assert_eq!(fail_counter.load(Ordering::Acquire), 1);
        assert_eq!(ok_counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn submit_persists_even_when_all_channels_fail() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_a, _a_counter) =
            MockChannel::always_fail("fail-a", ChannelError::Transport("a".into()));
        let (ch_b, _b_counter) = MockChannel::always_fail(
            "fail-b",
            ChannelError::Remote {
                status: 500,
                body: "b".into(),
            },
        );
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![ch_a, ch_b]);
        let payload = mk_payload("all-fail");
        let event_id = payload.event_id.unwrap();
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        assert!(!outcome.delivered());
        match outcome {
            DispatchOutcome::PersistedButAllChannelsFailed(err) => {
                // Last channel's error surfaces, not the first.
                assert!(matches!(err, ChannelError::Remote { status: 500, .. }));
            }
            other => panic!("expected PersistedButAllChannelsFailed, got {other:?}"),
        }
        // Row is in the engine even though every channel failed — the
        // wake task (D-5c) can retry.
        assert_eq!(eng.row_count().await.unwrap(), 1);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id, event_id);
    }

    #[tokio::test]
    async fn submit_persists_then_returns_no_channels_configured() {
        let (eng, _dir) = fresh_engine().await;
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![]);
        let payload = mk_payload("no-channels");
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::PersistedButAllChannelsFailed(ChannelError::Other(s)) => {
                assert!(s.contains("no channels configured"), "msg: {s}");
            }
            other => panic!("expected no-channels-configured, got {other:?}"),
        }
        // Persist still happened; row exists.
        assert_eq!(eng.row_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn submit_returns_persist_failed_on_missing_event_id() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_ok, ok_counter) = MockChannel::always_ok("ok");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_ok]);
        let payload = Payload {
            id: PayloadId::new(),
            event_id: None, // ← engine refuses
            title: "no-id".into(),
            body: "no-id".into(),
            severity: SeverityId::High,
            ack_link: None,
        };
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::PersistFailed(EngineError::PayloadMissingEventId) => {}
            other => panic!("expected PersistFailed(PayloadMissingEventId), got {other:?}"),
        }
        // No channel attempt was made.
        assert_eq!(ok_counter.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn record_ack_passes_through() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_ok, _) = MockChannel::always_ok("ok");
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![ch_ok]);
        let payload = mk_payload("acked");
        let event_id = payload.event_id.unwrap();
        let _ = dispatcher.submit(&payload, 100, 0).await;

        let acked = dispatcher.record_ack(event_id, 50).await.unwrap();
        assert!(acked);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert!(due.is_empty(), "acked row should not be due");
    }

    #[tokio::test]
    async fn close_event_passes_through() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_ok, _) = MockChannel::always_ok("ok");
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![ch_ok]);
        let payload = mk_payload("forgotten");
        let event_id = payload.event_id.unwrap();
        let _ = dispatcher.submit(&payload, 100, 0).await;
        assert_eq!(eng.row_count().await.unwrap(), 1);

        let removed = dispatcher.close_event(event_id).await.unwrap();
        assert!(removed);
        assert_eq!(eng.row_count().await.unwrap(), 0);
    }

    #[test]
    fn dispatch_outcome_delivered_predicate() {
        assert!(
            DispatchOutcome::Delivered {
                channel: "ntfy".into()
            }
            .delivered()
        );
        assert!(!DispatchOutcome::PersistedButAllChannelsFailed(ChannelError::Timeout).delivered());
        assert!(!DispatchOutcome::PersistFailed(EngineError::PayloadMissingEventId).delivered());
    }
}
