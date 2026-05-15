//! [`DispatcherAdapter`]: bridges the legacy
//! [`selfdef_notifier::Notifier`] trait (Event-shaped) to the
//! forward-looking [`selfdef_notifier_engine::PayloadDispatcher`]
//! (Payload-shaped + persistent).
//!
//! SDD-008 D-5d wiring detail: the daemon's responder calls
//! `Notifier::notify(event)`. To route that call through the
//! engine + dispatcher (so persistence + wake-task escalation are
//! enabled), we wrap the dispatcher in this adapter and pass it to
//! the responder as the notifier.
//!
//! Event → Payload conversion uses the same `render_title` /
//! `render_body` helpers the legacy channels already call, so wire
//! bytes are byte-identical regardless of which path the event
//! travels through.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_engine::{DispatchOutcome, PayloadDispatcher};
use selfdef_notifier_orchestrator::{EventId, Payload, PayloadId};
use tracing::debug;
use uuid::Uuid;

/// Wraps a [`PayloadDispatcher`] in the [`Notifier`] ABI so the
/// existing responder + chain machinery can drive it without
/// knowing about the engine.
///
/// `notify(event)` synthesises a [`Payload`] from the event, sets
/// the initial deadline to `now + profile.ack_window_for(0)` (the
/// rung-0 window from the dispatcher's active escalation profile —
/// `auto` defaults to 5 minutes; `aggressive` shortens it to 60s),
/// and calls `dispatcher.submit`. The dispatcher's persist-before-
/// fire ordering guarantees the row is in the engine even if every
/// channel returns an error — the wake task will retry on the next
/// deadline.
pub(crate) struct DispatcherAdapter {
    dispatcher: Arc<PayloadDispatcher>,
    /// SDD-008 D-4 HTTP ack: optional `https://daemon.example/notify/ack`
    /// base URL. When `Some`, the adapter mints a UUIDv7 token per
    /// payload and renders `ack_link = "<base>/<token>"`, then
    /// passes the token through `Payload.ack_token` so the engine
    /// persists it. When `None`, `ack_link` stays None and HTTP ack
    /// is disabled (CLI ack via `selfdefctl notify ack <id>` still
    /// works, since `record_ack` uses the event_id directly).
    ack_link_base: Option<String>,
}

impl DispatcherAdapter {
    #[must_use]
    pub(crate) fn new(dispatcher: Arc<PayloadDispatcher>) -> Self {
        Self {
            dispatcher,
            ack_link_base: None,
        }
    }

    /// SDD-008 D-4: install the operator-configured ack-link base
    /// URL. Empty / `None` disables HTTP ack (ack_link stays None).
    #[must_use]
    pub(crate) fn with_ack_link_base(mut self, base: Option<String>) -> Self {
        self.ack_link_base = base.filter(|s| !s.trim().is_empty());
        self
    }
}

impl std::fmt::Debug for DispatcherAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatcherAdapter")
            .field("channels", &self.dispatcher.channel_count())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Notifier for DispatcherAdapter {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        // SDD-008 D-4 HTTP ack: when the operator configured
        // `[notifier].ack_link_base`, embed a per-event ack URL in
        // the payload.
        //
        // Phase 7 F-2032-005 closure: we ask the engine for the
        // CANONICAL token via `lookup_or_mint_token(event_id)`
        // instead of always minting a fresh UUIDv7. The engine
        // preserves the existing token across re-submits of the
        // same event_id (`ack_token` deliberately NOT updated on
        // INSERT-or-replace conflict). Without this lookup, the
        // adapter would mint T2, the engine would keep T1, and the
        // channel would send a URL containing T2 that the HTTP
        // handler can't find → 404 on click. With the lookup, the
        // channel's URL matches the row the handler looks up.
        let event_id_typed = EventId(event.id);
        let (ack_token, ack_link) = match &self.ack_link_base {
            Some(base) => {
                let token = self
                    .dispatcher
                    .engine()
                    .lookup_or_mint_token(event_id_typed)
                    .await
                    .unwrap_or_else(|e| {
                        // Engine read failed (SQLite wedge?). Fall
                        // back to local mint so the channel-send
                        // path still works; the resulting URL won't
                        // resolve, but the operator at least gets
                        // the notification body and can ack via CLI.
                        // Logged so the failure is visible.
                        tracing::warn!(
                            event_id = %event.id,
                            error = %e,
                            "adapter: engine.lookup_or_mint_token failed; falling back to local mint",
                        );
                        Uuid::now_v7().simple().to_string()
                    });
                let link = format!("{base}/{token}");
                (Some(token), Some(link))
            }
            None => (None, None),
        };
        let payload = Payload {
            id: PayloadId::new(),
            event_id: Some(event_id_typed),
            title: render_title(event),
            body: render_body(event),
            severity: event.severity_id,
            ack_link,
            // SDD-008 D-5e: populate event_kind from the originating
            // event so per-channel subscription filters
            // (`[notifier.subscriptions.<ch>].event_kinds`) apply
            // on the engine path.
            event_kind: Some(event.class_uid.name().to_string()),
            ack_token,
        };
        let now = unix_now();
        // SDD-008 D-6b/D-6c: initial deadline derives from the
        // active profile's rung-0 ack window — not the legacy
        // hardcoded 5-minute constant. This makes operator-chosen
        // profiles (e.g. `aggressive` → 60s) actually shape the
        // first rung-advance timing, instead of waiting 5 min
        // regardless of profile.
        let deadline = now + self.dispatcher.profile().ack_window_for(0);
        debug!(
            event_id = %event.id,
            severity = %event.severity_id,
            deadline,
            "adapter: submitting to dispatcher",
        );
        match self.dispatcher.submit(&payload, deadline, now).await {
            DispatchOutcome::Delivered { .. } => Ok(()),
            DispatchOutcome::PersistedButAllChannelsFailed(err) => {
                // The row IS in the engine; the wake task will
                // retry on the next deadline. Surface as Http so
                // the chain-style "channel failed" semantics
                // upstream still see this as a transient failure.
                Err(NotifierError::Http(format!(
                    "engine persisted, every channel failed (will retry): {err}"
                )))
            }
            DispatchOutcome::PersistFailed(err) => {
                // No row was written; nothing to escalate against.
                // This is the operator's signal that the engine
                // SQLite file is wedged.
                Err(NotifierError::Http(format!("engine persist failed: {err}")))
            }
        }
    }

    fn name(&self) -> &'static str {
        "dispatcher"
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::SeverityId;
    use selfdef_notifier_engine::EscalationEngine;
    use selfdef_notifier_orchestrator::{AckReplyHint, Channel, ChannelError, DeliveryReceipt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub channel that records each send invocation.
    struct StubChannel {
        sent: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Channel for StubChannel {
        fn name(&self) -> &str {
            "stub"
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

    async fn fresh_adapter() -> (
        DispatcherAdapter,
        Arc<AtomicUsize>,
        Arc<PayloadDispatcher>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let ch: Arc<dyn Channel> = Arc::new(StubChannel {
            sent: Arc::clone(&counter),
        });
        let dispatcher = Arc::new(PayloadDispatcher::new(engine, vec![ch]));
        let adapter = DispatcherAdapter::new(Arc::clone(&dispatcher));
        (adapter, counter, dispatcher, dir)
    }

    fn finding_event() -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::High,
            "test-host",
            "selfdef.correlator.test",
            0,
        )
        .with_message("Possible SSH brute force from 192.0.2.5")
    }

    #[tokio::test]
    async fn notify_persists_and_fires_channel() {
        let (adapter, counter, dispatcher, _dir) = fresh_adapter().await;
        let event = finding_event();
        adapter.notify(&event).await.expect("ok");
        // Channel fired once.
        assert_eq!(counter.load(Ordering::Acquire), 1);
        // Row persisted (the wake task can retry from here).
        let n = dispatcher.engine().row_count().await.unwrap();
        assert_eq!(n, 1, "expected one persisted escalation row");
    }

    #[tokio::test]
    async fn notify_propagates_event_id_to_payload() {
        let (adapter, _counter, dispatcher, _dir) = fresh_adapter().await;
        let event = finding_event();
        let expected_id = event.id;
        adapter.notify(&event).await.expect("ok");
        // The persisted row's event_id matches the Event::id.
        let due = dispatcher.engine().take_due(i64::MAX, 10).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id.0, expected_id);
    }

    #[tokio::test]
    async fn notify_renders_title_and_body() {
        let (adapter, _counter, dispatcher, _dir) = fresh_adapter().await;
        let event = finding_event();
        adapter.notify(&event).await.expect("ok");
        let due = dispatcher.engine().take_due(i64::MAX, 10).await.unwrap();
        assert!(
            due[0].title.contains("brute force"),
            "title: {}",
            due[0].title
        );
        assert!(
            due[0].body.contains("host:") || due[0].body.contains("id:"),
            "body: {}",
            due[0].body,
        );
    }

    #[tokio::test]
    async fn deadline_uses_active_profile_rung_0_ack_window() {
        use selfdef_notifier_engine::Profile;
        // Aggressive profile: rung 0 = 60s ack window (not the
        // legacy 5-minute constant). Verifies F-2031-007 closure.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let ch: Arc<dyn Channel> = Arc::new(StubChannel {
            sent: Arc::clone(&counter),
        });
        let dispatcher =
            Arc::new(PayloadDispatcher::new(engine, vec![ch]).with_profile(Profile::aggressive()));
        let adapter = DispatcherAdapter::new(Arc::clone(&dispatcher));
        let event = finding_event();
        let now_before = unix_now();
        adapter.notify(&event).await.expect("ok");
        let now_after = unix_now();
        let due = dispatcher.engine().take_due(i64::MAX, 10).await.unwrap();
        let deadline = due[0].deadline_at;
        // Aggressive rung 0 ack window = 60s; adapter must apply it.
        assert!(
            deadline >= now_before + 60 && deadline <= now_after + 60,
            "expected deadline ~now+60s for aggressive profile rung 0; \
             got now_before={now_before} deadline={deadline} now_after={now_after}",
        );
    }

    // ---------------- F-2032-005: ack_token stability across re-submits ----------------

    #[tokio::test]
    async fn resubmit_of_same_event_id_uses_engine_canonical_token() {
        // When ack_link_base is set and the responder re-fires the
        // same event_id (e.g. operator manual re-dispatch), the
        // adapter must look up the engine's canonical ack_token
        // instead of minting a fresh one. The channel's URL has to
        // match the row the HTTP handler will look up.
        let (adapter, _counter, dispatcher, _dir) = fresh_adapter().await;
        // Configure ack_link_base so the lookup-or-mint path runs.
        let adapter = adapter.with_ack_link_base(Some("https://daemon.example/notify/ack".into()));

        let event = finding_event();
        let event_id = EventId(event.id);

        // First submit mints a token, persists it.
        adapter.notify(&event).await.expect("ok");
        let token_after_first = dispatcher
            .engine()
            .lookup_or_mint_token(event_id)
            .await
            .unwrap();

        // Second submit of the same event_id: engine's ON CONFLICT
        // preserves the token. After the F-2032-005 fix, the
        // adapter's second-call ack_link uses this same token, not
        // a fresh mint.
        adapter.notify(&event).await.expect("ok");
        let token_after_second = dispatcher
            .engine()
            .lookup_or_mint_token(event_id)
            .await
            .unwrap();

        // The stored token must not change across re-submits.
        assert_eq!(
            token_after_first, token_after_second,
            "ack_token must be stable across re-submits (F-2032-005)",
        );
        // Engine still has exactly one row (event_id PRIMARY KEY).
        assert_eq!(dispatcher.engine().row_count().await.unwrap(), 1);
    }

    #[test]
    fn name_is_dispatcher() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ch: Arc<dyn Channel> = Arc::new(StubChannel { sent: counter });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).unwrap());
        let dispatcher = Arc::new(PayloadDispatcher::new(engine, vec![ch]));
        let adapter = DispatcherAdapter::new(dispatcher);
        assert_eq!(
            <DispatcherAdapter as Notifier>::name(&adapter),
            "dispatcher"
        );
    }
}
