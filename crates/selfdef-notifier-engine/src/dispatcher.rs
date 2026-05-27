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

use std::collections::HashMap;

use selfdef_notifier_orchestrator::{
    Channel, ChannelError, EventId, Payload, SeverityId, Subscription,
};
use tracing::{debug, info, warn};

use crate::{EngineError, EscalationEngine, Profile};

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

/// SDD-008 D-6a: operating mode of the dispatcher. Orthogonal to
/// profiles (which control rung sequences); a mode is a per-process
/// switch that influences whether channel sends are real, audit-
/// only, or absent.
///
/// v1 ships two modes; `Test` (route everything to a designated
/// test_destination) lands in a follow-up once per-channel
/// test-target config is in scope.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Production: persist + fire channels for real. The default.
    #[default]
    Enforce,
    /// Dry-run: persist rows in the engine (so audit trails + ack
    /// behaviour work) but DO NOT call `channel.send`. Useful for
    /// pre-deployment verification that the orchestrator wiring is
    /// correct without actually paging anyone. The wake task still
    /// advances rungs / closes rows on schedule; channels see no
    /// traffic.
    Audit,
}

impl Mode {
    /// Parse the operator-facing string form (case-insensitive):
    /// `enforce` | `audit`. Returns `None` for unknown strings; the
    /// caller logs a warn and falls back to the default.
    #[must_use]
    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => Some(Self::Enforce),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }

    /// Stable lowercase label for logging.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Audit => "audit",
        }
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
    mode: Mode,
    profile: Profile,
    /// SDD-008 D-7: severity threshold at or above which the
    /// dispatcher fires channels for real **regardless of mode**.
    /// `None` (default) → no override; `Mode::Audit` suppresses
    /// every send. `Some(SeverityId::Critical)` → audit mode still
    /// dry-runs `Low`/`Medium`/`High` events but `Critical` /
    /// `Fatal` always page real channels. The escape hatch for
    /// "operator misconfiguration cannot leave a blocker un-
    /// notified".
    panic_floor: Option<SeverityId>,
    /// SDD-008 D-5e: per-channel subscription filter. Keyed by
    /// `channel.name()` (e.g. `"discord"`); each value is the
    /// operator-configured `[notifier.subscriptions.<channel>]`.
    /// Channels without an entry run unfiltered (legacy default).
    /// Empty map (the default after `new`) restores the pre-D-5e
    /// behaviour where every channel sees every event.
    subscriptions: HashMap<String, Subscription>,
}

impl std::fmt::Debug for PayloadDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadDispatcher")
            .field("engine", &self.engine)
            .field("channel_count", &self.channels.len())
            .field("mode", &self.mode)
            .field("panic_floor", &self.panic_floor)
            .finish_non_exhaustive()
    }
}

impl PayloadDispatcher {
    /// Construct from the persistence engine + an ordered channel
    /// set. Channels are tried in the supplied order during
    /// `submit`; the first one that returns `Ok` wins.
    #[must_use]
    pub fn new(engine: Arc<EscalationEngine>, channels: Vec<Arc<dyn Channel>>) -> Self {
        Self {
            engine,
            channels,
            mode: Mode::default(),
            profile: Profile::default(),
            panic_floor: None,
            subscriptions: HashMap::new(),
        }
    }

    /// SDD-008 D-5e: builder-style per-channel subscription map.
    /// Keys are channel `name()` slugs (`"ntfy"`, `"slack"`, …).
    /// Channels without a map entry run unfiltered (legacy default).
    ///
    /// The map is consulted by [`fire_channels_filtered`] before
    /// each `channel.send`; a channel whose `Subscription::matches`
    /// returns `false` is skipped just as if it weren't configured.
    /// Audit mode (D-6a) and panic-floor (D-7) still take
    /// precedence — a panic-floor event fires every channel even if
    /// its subscription would otherwise filter it out, so an
    /// operator misconfiguration cannot leave a blocker
    /// un-notified.
    #[must_use]
    pub fn with_subscriptions(mut self, subscriptions: HashMap<String, Subscription>) -> Self {
        self.subscriptions = subscriptions;
        self
    }

    /// Current per-channel subscription map.
    #[must_use]
    pub fn subscriptions(&self) -> &HashMap<String, Subscription> {
        &self.subscriptions
    }

    /// Builder-style: set the operating mode. Defaults to
    /// `Mode::Enforce` (production) when omitted.
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// SDD-008 D-6b: builder-style profile selection. Defaults to
    /// [`Profile::auto`] (2 attempts, 5-minute ack window) when
    /// omitted — matches the D-5c hardcoded behaviour so existing
    /// callers see zero change.
    #[must_use]
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// Current escalation profile.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// SDD-008 D-7: builder-style panic-floor selection. Events at
    /// or above this severity bypass `Mode::Audit` (always fire
    /// channels for real). Defaults to `None` — no override; audit
    /// mode suppresses every send.
    #[must_use]
    pub fn with_panic_floor(mut self, floor: SeverityId) -> Self {
        self.panic_floor = Some(floor);
        self
    }

    /// Current panic floor, if any. `None` = audit mode suppresses
    /// every send regardless of severity.
    #[must_use]
    pub fn panic_floor(&self) -> Option<SeverityId> {
        self.panic_floor
    }

    /// Returns `true` when the payload's severity crosses the
    /// panic floor (`panic_floor.is_some()` AND `severity >= floor`).
    /// Used internally to decide whether audit-mode suppression
    /// applies; exposed for tests + future operator-tunable bypass
    /// rules.
    #[must_use]
    pub fn crosses_panic_floor(&self, severity: SeverityId) -> bool {
        match self.panic_floor {
            Some(floor) => (severity as u32) >= (floor as u32),
            None => false,
        }
    }

    /// Current operating mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
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
        if self.mode == Mode::Audit && !self.crosses_panic_floor(payload.severity) {
            // Dry-run: row IS in the engine, but no channel sees
            // the payload. Log per-channel "would have fired" so
            // operators verifying wiring can grep the daemon log.
            for channel in &self.channels {
                info!(
                    mode = "audit",
                    channel = channel.name(),
                    "dispatcher: would have fired (audit mode)"
                );
            }
            return DispatchOutcome::Delivered {
                channel: "audit".to_owned(),
            };
        }
        if self.mode == Mode::Audit {
            // Panic-floor crossed → bypass audit mode and fire for
            // real. SDD-008 D-7: operator misconfig must not be
            // able to leave a blocker un-notified.
            info!(
                mode = "audit",
                severity = %payload.severity,
                panic_floor = ?self.panic_floor,
                "dispatcher: panic floor crossed; bypassing audit mode",
            );
        }
        self.fire_channels(payload).await
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

    /// Fire the channel set against a [`Payload`] **without**
    /// touching persistence. Used by the D-5c wake task when re-
    /// firing a row that's already in the engine: the persistence
    /// state is updated separately via [`EscalationEngine::advance_rung`]
    /// or [`EscalationEngine::close_event`].
    ///
    /// Semantics mirror [`Self::submit`]'s channel walk:
    /// first-success-wins; returns either [`DispatchOutcome::Delivered`]
    /// naming the winning channel, or
    /// [`DispatchOutcome::PersistedButAllChannelsFailed`] when every
    /// channel returned an error (variant name kept for return-type
    /// uniformity — no persist happened here, but the wake task
    /// owns the row's lifecycle and is what makes the variant
    /// accurate for the caller).
    pub async fn dispatch_payload(&self, payload: &Payload) -> DispatchOutcome {
        if self.mode == Mode::Audit && !self.crosses_panic_floor(payload.severity) {
            for channel in &self.channels {
                info!(
                    mode = "audit",
                    channel = channel.name(),
                    "dispatcher: would have re-fired (audit mode)"
                );
            }
            return DispatchOutcome::Delivered {
                channel: "audit".to_owned(),
            };
        }
        if self.mode == Mode::Audit {
            info!(
                mode = "audit",
                severity = %payload.severity,
                panic_floor = ?self.panic_floor,
                "dispatcher: panic floor crossed on re-fire; bypassing audit mode",
            );
        }
        self.fire_channels(payload).await
    }

    /// Shared channel walk used by both `submit` (initial fire) and
    /// `dispatch_payload` (wake-task re-fire). First-success-wins;
    /// last error surfaces in the `PersistedButAllChannelsFailed`
    /// variant when every channel rejects.
    async fn fire_channels(&self, payload: &Payload) -> DispatchOutcome {
        self.fire_channels_filtered(payload, &[]).await
    }

    /// SDD-008 D-6c + D-5e: channel walk with a per-rung allow-list
    /// AND a per-channel subscription filter.
    /// Empty `rung_filter` = "every configured channel" (the pre-
    /// D-6c default). Non-empty list = only channels whose `name()`
    /// matches an entry. First-success-wins among the matched set.
    ///
    /// D-5e adds: each channel that survives the `rung_filter` is
    /// then checked against the dispatcher's `subscriptions` map. A
    /// channel whose `Subscription::matches(payload)` returns
    /// `false` is **skipped** (not counted as a failed attempt;
    /// it's filtered out, not unreachable). Channels without a
    /// subscription entry run unfiltered.
    ///
    /// Panic-floor bypass (D-7) takes precedence: when the
    /// dispatcher caller has already decided to fire (because the
    /// payload crosses the panic floor in audit mode, or because
    /// we're in enforce mode), the subscription filter still
    /// applies for routine routing — operators don't expect
    /// `severity_floor = "critical"` to mean "even louder than
    /// usual on Critical events". A panic-floor crossing widens
    /// the *mode* (audit → fire-anyway), not the *channel set*.
    async fn fire_channels_filtered(
        &self,
        payload: &Payload,
        rung_filter: &[String],
    ) -> DispatchOutcome {
        let mut last_err: Option<ChannelError> = None;
        let mut attempted = 0usize;
        let mut filtered = 0usize;
        for channel in &self.channels {
            if !rung_filter.is_empty() && !rung_filter.iter().any(|n| n == channel.name()) {
                continue;
            }
            if let Some(sub) = self.subscriptions.get(channel.name())
                && !sub.matches(payload)
            {
                debug!(
                    channel = channel.name(),
                    severity = %payload.severity,
                    event_kind = ?payload.event_kind,
                    "dispatcher: channel filtered by subscription",
                );
                filtered += 1;
                continue;
            }
            attempted += 1;
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
        DispatchOutcome::PersistedButAllChannelsFailed(last_err.unwrap_or_else(|| {
            if attempted == 0 && filtered > 0 {
                ChannelError::Other(format!(
                    "dispatcher: every configured channel filtered out by [notifier.subscriptions.*] ({filtered} channels filtered)"
                ))
            } else if attempted == 0 && !rung_filter.is_empty() {
                ChannelError::Other(format!(
                    "dispatcher: rung's channel allow-list {rung_filter:?} matched none of the configured channels"
                ))
            } else {
                ChannelError::Other("dispatcher: no channels configured".into())
            }
        }))
    }

    /// SDD-008 D-6c: wake-task re-fire for a specific rung. Looks
    /// up the rung's channel allow-list from the active profile and
    /// filters the channel walk to it. Audit-mode + below panic
    /// floor still suppresses (D-6a + D-7).
    pub async fn dispatch_payload_for_rung(
        &self,
        payload: &Payload,
        rung_index: u32,
    ) -> DispatchOutcome {
        let filter = self.profile.channels_for(rung_index).to_vec();
        if self.mode == Mode::Audit && !self.crosses_panic_floor(payload.severity) {
            for channel in &self.channels {
                if !filter.is_empty() && !filter.iter().any(|n| n == channel.name()) {
                    continue;
                }
                info!(
                    mode = "audit",
                    rung = rung_index,
                    channel = channel.name(),
                    "dispatcher: would have re-fired (audit mode + rung filter)"
                );
            }
            return DispatchOutcome::Delivered {
                channel: "audit".to_owned(),
            };
        }
        self.fire_channels_filtered(payload, &filter).await
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
            event_kind: None,
            ack_token: None,
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
            event_kind: None,
            ack_token: None,
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

    #[tokio::test]
    async fn dispatch_payload_does_not_touch_persistence() {
        // Empty engine — dispatch_payload must NOT enqueue a row.
        let (eng, _dir) = fresh_engine().await;
        let (ch_ok, ok_counter) = MockChannel::always_ok("ok");
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![ch_ok]);
        let payload = mk_payload("no-persist");
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(outcome.delivered());
        assert_eq!(ok_counter.load(Ordering::Acquire), 1);
        // Persistence is untouched: row_count stays at zero.
        assert_eq!(eng.row_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn dispatch_payload_first_success_wins() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_fail, fail_counter) =
            MockChannel::always_fail("fail-1", ChannelError::Transport("synthetic".into()));
        let (ch_ok, ok_counter) = MockChannel::always_ok("ok-1");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_fail, ch_ok]);
        let outcome = dispatcher.dispatch_payload(&mk_payload("walk")).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "ok-1"),
            other => panic!("expected Delivered, got {other:?}"),
        }
        assert_eq!(fail_counter.load(Ordering::Acquire), 1);
        assert_eq!(ok_counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn dispatch_payload_returns_failure_when_all_fail() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_a, _a) = MockChannel::always_fail("a", ChannelError::Transport("a".into()));
        let (ch_b, _b) = MockChannel::always_fail(
            "b",
            ChannelError::Remote {
                status: 500,
                body: "b".into(),
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_a, ch_b]);
        let outcome = dispatcher.dispatch_payload(&mk_payload("all-fail")).await;
        assert!(!outcome.delivered());
    }

    #[test]
    fn mode_default_is_enforce() {
        assert_eq!(Mode::default(), Mode::Enforce);
    }

    #[test]
    fn mode_from_str_ci_parses_known_strings() {
        assert_eq!(Mode::from_str_ci("enforce"), Some(Mode::Enforce));
        assert_eq!(Mode::from_str_ci("ENFORCE"), Some(Mode::Enforce));
        assert_eq!(Mode::from_str_ci("Enforce"), Some(Mode::Enforce));
        assert_eq!(Mode::from_str_ci("audit"), Some(Mode::Audit));
        assert_eq!(Mode::from_str_ci("AUDIT"), Some(Mode::Audit));
    }

    #[test]
    fn mode_from_str_ci_returns_none_for_unknown() {
        assert!(Mode::from_str_ci("yolo").is_none());
        assert!(Mode::from_str_ci("").is_none());
    }

    #[test]
    fn mode_name_round_trips() {
        for m in [Mode::Enforce, Mode::Audit] {
            assert_eq!(Mode::from_str_ci(m.name()), Some(m));
        }
    }

    #[tokio::test]
    async fn audit_mode_persists_but_does_not_fire_channels() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("would-fire");
        let dispatcher = PayloadDispatcher::new(Arc::clone(&eng), vec![ch]).with_mode(Mode::Audit);
        let payload = mk_payload("audit-mode");
        let event_id = payload.event_id.unwrap();
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        // Outcome reports "delivered" via the synthetic "audit"
        // channel so callers in enforce-tuned code paths see a
        // success, but the real channel never saw the payload.
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "audit"),
            other => panic!("expected Delivered(audit), got {other:?}"),
        }
        // Real channel was NOT invoked.
        assert_eq!(
            counter.load(Ordering::Acquire),
            0,
            "audit mode must not call channel.send"
        );
        // BUT the row IS in the engine — operators can ack / list
        // / forget it via D-4 CLI verbs in dry-run.
        assert_eq!(eng.row_count().await.unwrap(), 1);
        let due = eng.take_due(1_000, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id, event_id);
    }

    #[tokio::test]
    async fn audit_mode_dispatch_payload_does_not_fire_channels() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("would-refire");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_mode(Mode::Audit);
        let payload = mk_payload("audit-refire");
        // dispatch_payload is the wake-task path. Same audit semantics
        // apply: it must NOT call channel.send.
        let outcome = dispatcher.dispatch_payload(&payload).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "audit"),
            other => panic!("expected Delivered(audit), got {other:?}"),
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn enforce_mode_default_fires_channels() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("should-fire");
        // No .with_mode() → Mode::Enforce by default.
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]);
        assert_eq!(dispatcher.mode(), Mode::Enforce);
        let payload = mk_payload("enforce-default");
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "should-fire"),
            other => panic!("expected Delivered(should-fire), got {other:?}"),
        }
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    // ---------------- SDD-008 D-7: panic floor ----------------

    fn mk_payload_with_severity(title: &str, severity: SeverityId) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: title.into(),
            body: format!("body for {title}"),
            severity,
            ack_link: None,
            event_kind: None,
            ack_token: None,
        }
    }

    #[test]
    fn panic_floor_default_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let dispatcher = PayloadDispatcher::new(engine, vec![]);
        assert!(dispatcher.panic_floor().is_none());
    }

    #[test]
    fn crosses_panic_floor_returns_false_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let dispatcher = PayloadDispatcher::new(engine, vec![]);
        // No floor set; nothing crosses.
        for s in [SeverityId::Low, SeverityId::High, SeverityId::Fatal] {
            assert!(!dispatcher.crosses_panic_floor(s), "{s:?}");
        }
    }

    #[test]
    fn crosses_panic_floor_uses_repr_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let dispatcher =
            PayloadDispatcher::new(engine, vec![]).with_panic_floor(SeverityId::Critical);
        // Below the floor:
        assert!(!dispatcher.crosses_panic_floor(SeverityId::Low));
        assert!(!dispatcher.crosses_panic_floor(SeverityId::Medium));
        assert!(!dispatcher.crosses_panic_floor(SeverityId::High));
        // At and above the floor:
        assert!(dispatcher.crosses_panic_floor(SeverityId::Critical));
        assert!(dispatcher.crosses_panic_floor(SeverityId::Fatal));
    }

    // SDD-062 D-5 contract: the watchdog warn tier is routed as an
    // Informational finding precisely so it stays NON-PAGING. This locks the
    // mechanism it relies on — an Informational severity must NOT cross the
    // Medium default panic floor (so the notifier suppresses it), while the
    // alert tier (High) must. If the severity mapping or the floor ordering
    // ever regresses, the warn tier would silently start paging; this fails.
    #[test]
    fn warn_tier_informational_stays_below_medium_floor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let dispatcher =
            PayloadDispatcher::new(engine, vec![]).with_panic_floor(SeverityId::Medium);
        // warn tier (selfdef_watchdog_warn.yml level: informational) → no page.
        assert!(!dispatcher.crosses_panic_floor(SeverityId::Informational));
        assert!(!dispatcher.crosses_panic_floor(SeverityId::Low));
        // alert tier (selfdef_watchdog_alert.yml level: high) → pages.
        assert!(dispatcher.crosses_panic_floor(SeverityId::High));
    }

    #[tokio::test]
    async fn audit_mode_suppresses_below_panic_floor() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("would-fire");
        // Audit + panic floor = Critical. A High event must STAY
        // suppressed because High < Critical.
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::Critical);
        let payload = mk_payload_with_severity("below-floor", SeverityId::High);
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "audit"),
            other => panic!("expected Delivered(audit), got {other:?}"),
        }
        // Channel was NOT invoked.
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn audit_mode_bypassed_above_panic_floor() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("must-fire");
        // Audit + panic floor = Critical. A Critical event MUST
        // page real channels even though we're in audit mode.
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::Critical);
        let payload = mk_payload_with_severity("crosses-floor", SeverityId::Critical);
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "must-fire"),
            other => panic!("expected Delivered(must-fire), got {other:?}"),
        }
        // Real channel WAS invoked.
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn audit_mode_bypassed_at_fatal_when_floor_critical() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("must-fire");
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::Critical);
        let payload = mk_payload_with_severity("fatal-above-floor", SeverityId::Fatal);
        let outcome = dispatcher.submit(&payload, 100, 0).await;
        assert!(outcome.delivered());
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn dispatch_payload_honors_panic_floor_on_refire() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("refire");
        // Audit + panic floor = Critical. dispatch_payload is the
        // wake-task re-fire path; panic-floor bypass must apply
        // there too.
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::High);
        let payload = mk_payload_with_severity("refire-floor", SeverityId::High);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "refire"),
            other => panic!("expected Delivered(refire), got {other:?}"),
        }
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn enforce_mode_with_panic_floor_unchanged() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("enforce-fire");
        // Enforce mode + panic floor is a no-op (panic floor only
        // matters when mode would otherwise suppress).
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_mode(Mode::Enforce)
            .with_panic_floor(SeverityId::Critical);
        // Both below-floor AND above-floor events fire.
        let low = mk_payload_with_severity("low", SeverityId::Low);
        let crit = mk_payload_with_severity("crit", SeverityId::Critical);
        dispatcher.submit(&low, 100, 0).await;
        dispatcher.submit(&crit, 100, 0).await;
        assert_eq!(counter.load(Ordering::Acquire), 2);
    }

    // ---------------- SDD-008 D-6c: rung-aware dispatch ----------------

    use crate::Rung;

    #[tokio::test]
    async fn dispatch_payload_for_rung_filters_by_channel_name() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_a, counter_a) = MockChannel::always_ok("ntfy");
        let (ch_b, counter_b) = MockChannel::always_ok("smtp");
        // Profile: rung 0 = ntfy only; rung 1 = smtp only.
        let profile = Profile::custom(
            "test-rungs",
            vec![
                Rung::with_channels(60, vec!["ntfy".into()]),
                Rung::with_channels(120, vec!["smtp".into()]),
            ],
        )
        .unwrap();
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_a, ch_b]).with_profile(profile);
        let payload = mk_payload("rung-filter");

        // Rung 0 → only ntfy fires.
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 0).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "ntfy"),
            other => panic!("expected Delivered(ntfy), got {other:?}"),
        }
        assert_eq!(counter_a.load(Ordering::Acquire), 1);
        assert_eq!(
            counter_b.load(Ordering::Acquire),
            0,
            "smtp must not fire at rung 0"
        );

        // Rung 1 → only smtp fires.
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 1).await;
        match outcome {
            DispatchOutcome::Delivered { channel } => assert_eq!(channel, "smtp"),
            other => panic!("expected Delivered(smtp), got {other:?}"),
        }
        assert_eq!(
            counter_a.load(Ordering::Acquire),
            1,
            "ntfy must not fire at rung 1"
        );
        assert_eq!(counter_b.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn dispatch_payload_for_rung_empty_filter_fires_all() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_a, counter_a) = MockChannel::always_ok("a");
        let (ch_b, counter_b) = MockChannel::always_ok("b");
        // Profile with one rung, empty channels = WUPHF / all.
        let profile = Profile::custom("wuphf-style", vec![Rung::new(60)]).unwrap();
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_a, ch_b]).with_profile(profile);
        let payload = mk_payload("wuphf");
        // First-success-wins: "a" wins, "b" never invoked.
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 0).await;
        assert!(matches!(outcome, DispatchOutcome::Delivered { ref channel } if channel == "a"));
        assert_eq!(counter_a.load(Ordering::Acquire), 1);
        assert_eq!(counter_b.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dispatch_payload_for_rung_no_channel_matches_filter() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, _counter) = MockChannel::always_ok("ntfy");
        // Operator-defined profile names a channel that doesn't exist
        // in the configured set. Should surface a clear error.
        let profile = Profile::custom(
            "bad-rungs",
            vec![Rung::with_channels(60, vec!["nonexistent".into()])],
        )
        .unwrap();
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_profile(profile);
        let payload = mk_payload("orphan");
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 0).await;
        match outcome {
            DispatchOutcome::PersistedButAllChannelsFailed(ChannelError::Other(msg)) => {
                assert!(
                    msg.contains("allow-list") && msg.contains("nonexistent"),
                    "expected helpful error message, got: {msg}",
                );
            }
            other => panic!("expected allow-list-matches-none error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_payload_for_rung_audit_mode_below_floor_skips() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("ntfy");
        let profile =
            Profile::custom("test", vec![Rung::with_channels(60, vec!["ntfy".into()])]).unwrap();
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_profile(profile)
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::Critical);
        let payload = mk_payload_with_severity("audit-rung", SeverityId::High); // below floor
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 0).await;
        assert!(
            matches!(outcome, DispatchOutcome::Delivered { ref channel } if channel == "audit")
        );
        assert_eq!(
            counter.load(Ordering::Acquire),
            0,
            "audit + below floor must not fire"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_for_rung_audit_mode_above_floor_fires() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("ntfy");
        let profile =
            Profile::custom("test", vec![Rung::with_channels(60, vec!["ntfy".into()])]).unwrap();
        let dispatcher = PayloadDispatcher::new(eng, vec![ch])
            .with_profile(profile)
            .with_mode(Mode::Audit)
            .with_panic_floor(SeverityId::Critical);
        let payload = mk_payload_with_severity("audit-rung-crit", SeverityId::Critical);
        let outcome = dispatcher.dispatch_payload_for_rung(&payload, 0).await;
        assert!(matches!(outcome, DispatchOutcome::Delivered { ref channel } if channel == "ntfy"));
        assert_eq!(
            counter.load(Ordering::Acquire),
            1,
            "panic floor must bypass audit"
        );
    }

    // ---------------- SDD-008 D-5e: subscription filter ----------------

    fn mk_payload_with_kind(
        title: &str,
        severity: SeverityId,
        event_kind: Option<&str>,
    ) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: title.into(),
            body: format!("body for {title}"),
            severity,
            ack_link: None,
            event_kind: event_kind.map(str::to_owned),
            ack_token: None,
        }
    }

    #[tokio::test]
    async fn subscription_severity_floor_filters_below() {
        let (eng, _dir) = fresh_engine().await;
        let (ch_ntfy, ntfy_counter) = MockChannel::always_ok("ntfy");
        let (ch_slack, slack_counter) = MockChannel::always_ok("slack");
        let mut subs = HashMap::new();
        subs.insert(
            "slack".to_string(),
            Subscription {
                severity_floor: Some(SeverityId::Critical),
                event_kinds: vec![],
            },
        );
        let dispatcher =
            PayloadDispatcher::new(eng, vec![ch_ntfy, ch_slack]).with_subscriptions(subs);
        // Low-severity payload: slack filter drops it; ntfy
        // (no filter entry) accepts; first-success-wins picks ntfy.
        let payload = mk_payload_with_kind("low-sev", SeverityId::Low, None);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(matches!(outcome, DispatchOutcome::Delivered { ref channel } if channel == "ntfy"));
        assert_eq!(ntfy_counter.load(Ordering::Acquire), 1);
        assert_eq!(slack_counter.load(Ordering::Acquire), 0, "slack filtered");
    }

    #[tokio::test]
    async fn subscription_event_kinds_filters_unmatched() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("discord");
        let mut subs = HashMap::new();
        subs.insert(
            "discord".to_string(),
            Subscription {
                severity_floor: None,
                event_kinds: vec!["security".into()],
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_subscriptions(subs);
        let payload = mk_payload_with_kind("noisy", SeverityId::High, Some("Process Activity"));
        let outcome = dispatcher.dispatch_payload(&payload).await;
        // Only configured channel filtered out → AllChannelsFailed.
        assert!(matches!(
            outcome,
            DispatchOutcome::PersistedButAllChannelsFailed(_),
        ));
        assert_eq!(counter.load(Ordering::Acquire), 0, "discord filtered");
    }

    #[tokio::test]
    async fn subscription_pass_through_when_matches() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("discord");
        let mut subs = HashMap::new();
        subs.insert(
            "discord".to_string(),
            Subscription {
                severity_floor: Some(SeverityId::High),
                event_kinds: vec!["security".into(), "detection".into()],
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_subscriptions(subs);
        let payload = mk_payload_with_kind("passes", SeverityId::High, Some("Security Finding"));
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(matches!(
            outcome,
            DispatchOutcome::Delivered { ref channel } if channel == "discord",
        ));
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn subscription_no_entry_runs_unfiltered() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("ntfy");
        // Map has an entry for slack only — ntfy is unfiltered.
        let mut subs = HashMap::new();
        subs.insert(
            "slack".to_string(),
            Subscription {
                severity_floor: Some(SeverityId::Critical),
                event_kinds: vec![],
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_subscriptions(subs);
        let payload = mk_payload_with_kind("low", SeverityId::Informational, None);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(matches!(
            outcome,
            DispatchOutcome::Delivered { ref channel } if channel == "ntfy",
        ));
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn subscription_empty_map_is_pre_d5e_behaviour() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("ntfy");
        // Empty subscriptions map → pre-D-5e: every channel fires.
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_subscriptions(HashMap::new());
        let payload = mk_payload_with_kind("any", SeverityId::Informational, None);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(matches!(
            outcome,
            DispatchOutcome::Delivered { ref channel } if channel == "ntfy",
        ));
        assert_eq!(counter.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn subscription_filter_skips_unmatched_keeps_first_match() {
        // Three channels in order: ntfy (filtered out), slack
        // (filter passes but channel errors), discord (no filter,
        // succeeds). First-success-wins picks discord.
        let (eng, _dir) = fresh_engine().await;
        let (ch_ntfy, ntfy_counter) = MockChannel::always_ok("ntfy");
        let (ch_slack, slack_counter) =
            MockChannel::always_fail("slack", ChannelError::Transport("slack down".into()));
        let (ch_discord, discord_counter) = MockChannel::always_ok("discord");
        let mut subs = HashMap::new();
        subs.insert(
            "ntfy".to_string(),
            Subscription {
                severity_floor: Some(SeverityId::Critical),
                event_kinds: vec![],
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch_ntfy, ch_slack, ch_discord])
            .with_subscriptions(subs);
        let payload = mk_payload_with_kind("med", SeverityId::Medium, None);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        assert!(matches!(
            outcome,
            DispatchOutcome::Delivered { ref channel } if channel == "discord",
        ));
        assert_eq!(ntfy_counter.load(Ordering::Acquire), 0, "ntfy filtered");
        assert_eq!(slack_counter.load(Ordering::Acquire), 1, "slack attempted");
        assert_eq!(discord_counter.load(Ordering::Acquire), 1, "discord won");
    }

    #[tokio::test]
    async fn subscription_all_filtered_returns_specific_error() {
        let (eng, _dir) = fresh_engine().await;
        let (ch, counter) = MockChannel::always_ok("ntfy");
        let mut subs = HashMap::new();
        subs.insert(
            "ntfy".to_string(),
            Subscription {
                severity_floor: Some(SeverityId::Critical),
                event_kinds: vec![],
            },
        );
        let dispatcher = PayloadDispatcher::new(eng, vec![ch]).with_subscriptions(subs);
        let payload = mk_payload_with_kind("low", SeverityId::Low, None);
        let outcome = dispatcher.dispatch_payload(&payload).await;
        match outcome {
            DispatchOutcome::PersistedButAllChannelsFailed(ChannelError::Other(msg)) => {
                assert!(msg.contains("filtered"), "got: {msg}");
            }
            other => panic!("expected filtered Other error, got {other:?}"),
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}
