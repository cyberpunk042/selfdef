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
}

impl DispatcherAdapter {
    #[must_use]
    pub(crate) fn new(dispatcher: Arc<PayloadDispatcher>) -> Self {
        Self { dispatcher }
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
        let payload = Payload {
            id: PayloadId::new(),
            event_id: Some(EventId(event.id)),
            title: render_title(event),
            body: render_body(event),
            severity: event.severity_id,
            // D-4 HTTP click-link ack arrives in a follow-up PR
            // once the daemon exposes the /notify/ack endpoint.
            // Today operators ack via `selfdefctl notify ack <id>`.
            ack_link: None,
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
