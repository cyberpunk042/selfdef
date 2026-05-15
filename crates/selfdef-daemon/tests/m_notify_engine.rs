//! Daemon-level pipeline tests for the SDD-008 engine path.
//!
//! Closes F-2031-013 from the Phase 6 audit programme: the 22-PR
//! SDD-008 cycle shipped 159 tests — zero Category-2 (pipeline)
//! tests under SDD-005's contract for the engine path. The
//! internal wake_task / dispatcher / engine tests cover the
//! surface in isolation via direct API calls; this file fills the
//! gap by composing the dispatcher + engine + a recording channel
//! together, mirroring the daemon's `build_notifier_path` engine
//! branch, and asserting the operator-visible promises end-to-end.
//!
//! ## Driving the wake task deterministically
//!
//! The runtime knob `tokio::test(start_paused = true)` advances
//! virtual time when every task is parked — fine for pure-tokio
//! pipelines, but the engine's SQLite ops go through
//! `tokio::task::spawn_blocking`, which runs on a real thread
//! pool. With paused time + multiple `spawn_blocking` calls in
//! flight (e.g. `take_due` and an ack-side `record_ack`), the
//! virtual-time advance can race the real-thread completions,
//! making the test see take_due BEFORE the ack write committed.
//!
//! Instead, these tests call [`wake_task::process_due`] **directly**
//! between submit / ack / advance steps. One explicit "tick" per
//! step, no spawned loop, no race. The `process_due` API was
//! promoted to `pub` under SDD-005's implementation-PR pattern so
//! tests inheriting this file's `EngineHarness` can use the same
//! shape.
//!
//! ## EngineHarness
//!
//! Scoped to this file at v1. If the second SDD-008 follow-up
//! (e.g. SDD-009 dashboard pipeline tests) needs the same pattern
//! we'll graduate it to `crates/selfdef-daemon/tests/common/`.

#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_notifier::{render_body, render_title};
use selfdef_notifier_engine::{
    EscalationEngine, Mode, PayloadDispatcher, Profile, Rung, wake_task,
};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, EventId, Payload, PayloadId,
};
use tempfile::TempDir;

/// Recording channel — increments `counter` on every `send`.
struct Recorder {
    name: &'static str,
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl Channel for Recorder {
    fn name(&self) -> &str {
        self.name
    }

    async fn send(&self, _payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        self.counter.fetch_add(1, Ordering::AcqRel);
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        false
    }

    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

/// Reusable engine-path test harness. Owns a tempdir-backed engine,
/// a PayloadDispatcher with a recording channel, and a `now`
/// counter that the test advances explicitly between steps.
struct EngineHarness {
    dir: TempDir,
    dispatcher: Arc<PayloadDispatcher>,
    counter: Arc<AtomicUsize>,
}

impl EngineHarness {
    /// Open a fresh engine with `profile` + `mode` and a single
    /// recording channel named `"recorder"`.
    fn open(profile: Profile, mode: Mode) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("escalations.sqlite");
        let engine = Arc::new(EscalationEngine::open(&path).expect("engine open"));
        let counter = Arc::new(AtomicUsize::new(0));
        let recorder: Arc<dyn Channel> = Arc::new(Recorder {
            name: "recorder",
            counter: Arc::clone(&counter),
        });
        let dispatcher = Arc::new(
            PayloadDispatcher::new(engine, vec![recorder])
                .with_profile(profile)
                .with_mode(mode),
        );
        Self {
            dir,
            dispatcher,
            counter,
        }
    }

    /// Submit an `Event` through the same `DispatcherAdapter`-shaped
    /// path the daemon's responder uses: synthesize a Payload from
    /// the event, set the initial deadline to
    /// `now + profile.ack_window_for(0)`, hand to
    /// `dispatcher.submit`.
    async fn submit_event(&self, event: &Event, now: i64) -> EventId {
        let event_id = EventId(event.id);
        let payload = Payload {
            id: PayloadId::new(),
            event_id: Some(event_id),
            title: render_title(event),
            body: render_body(event),
            severity: event.severity_id,
            ack_link: None,
            event_kind: Some(event.class_uid.name().to_string()),
        };
        let deadline = now + self.dispatcher.profile().ack_window_for(0);
        let _ = self.dispatcher.submit(&payload, deadline, now).await;
        event_id
    }

    fn counter(&self) -> usize {
        self.counter.load(Ordering::Acquire)
    }

    async fn engine_row_count(&self) -> i64 {
        self.dispatcher
            .engine()
            .row_count()
            .await
            .expect("row_count")
    }

    fn engine_path(&self) -> std::path::PathBuf {
        self.dir.path().join("escalations.sqlite")
    }
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
    .with_message("ssh brute force from 192.0.2.5")
}

/// Two-rung profile: 60s, 180s. Lets each test drive both rung-0
/// and rung-1 fires with explicit "now" advances.
fn fast_two_rung_profile() -> Profile {
    Profile::custom("test-fast", vec![Rung::new(60), Rung::new(180)]).expect("custom profile")
}

/// SDD-008 D-5c promise: an unacked notification re-fires when its
/// rung deadline expires, then closes when max_rung is reached.
#[tokio::test(flavor = "current_thread")]
async fn unacked_notification_refires_at_rung_deadline() {
    let h = EngineHarness::open(fast_two_rung_profile(), Mode::Enforce);

    // Submit at t=0. Initial fire → counter=1.
    let _eid = h.submit_event(&finding_event(), 0).await;
    assert_eq!(h.counter(), 1, "initial submit must fire once");
    assert_eq!(h.engine_row_count().await, 1, "row persisted");

    // Drive a wake-task iteration BEFORE rung-0 deadline. No row
    // due → no re-fire, no advance.
    wake_task::process_due_at(&h.dispatcher, 30).await;
    assert_eq!(h.counter(), 1, "no re-fire before deadline");

    // Drive AT rung-0 deadline (60s). Row due → re-fire → advance
    // rung_index=1, deadline_at=60+180=240.
    wake_task::process_due_at(&h.dispatcher, 60).await;
    assert_eq!(h.counter(), 2, "rung-1 re-fire on deadline");
    assert_eq!(h.engine_row_count().await, 1, "row still open");

    // Drive BEFORE rung-1 deadline. No re-fire.
    wake_task::process_due_at(&h.dispatcher, 200).await;
    assert_eq!(h.counter(), 2);

    // Drive AT rung-1 deadline. rung_index=1 >= max_rung=1 → close.
    wake_task::process_due_at(&h.dispatcher, 240).await;
    assert_eq!(h.counter(), 2, "max-rung close must not re-fire");
    assert_eq!(h.engine_row_count().await, 0, "row closed");
}

/// SDD-008 D-4 promise: `selfdefctl notify ack <id>` (which opens
/// the engine and calls `record_ack` directly) stops further re-
/// fires by the wake task. WAL permits the daemon's writer and the
/// CLI's separate-connection reader/writer to coexist.
#[tokio::test(flavor = "current_thread")]
async fn ack_from_separate_process_stops_refires() {
    let h = EngineHarness::open(fast_two_rung_profile(), Mode::Enforce);

    let eid = h.submit_event(&finding_event(), 0).await;
    assert_eq!(h.counter(), 1, "initial fire");

    // Simulate the CLI's path: open the engine on the same file
    // path (separate connection) and call record_ack.
    let cli_engine = EscalationEngine::open(h.engine_path()).expect("cli-side engine open");
    let acked = cli_engine.record_ack(eid, 30).await.expect("record_ack");
    assert!(acked, "first ack must update a row");

    // Drive wake-task iterations past both rung deadlines. The
    // monotonic-advance + acked-NULL guard means take_due returns
    // nothing for either tick.
    wake_task::process_due_at(&h.dispatcher, 60).await;
    assert_eq!(h.counter(), 1, "ack must stop rung-0 re-fire");

    wake_task::process_due_at(&h.dispatcher, 240).await;
    assert_eq!(h.counter(), 1, "ack must stop rung-1 re-fire too");

    // Row remains in the engine (ack records but doesn't delete;
    // the operator can `notify list` and see the acked history).
    // SDD-008 D-5c's wake-task does not GC acked rows in v1.
    assert_eq!(h.engine_row_count().await, 1, "acked row persists");
}

/// SDD-008 D-6a promise: `Mode::Audit` is honoured at every level
/// of the dispatch stack. The row IS persisted (so operator ack /
/// list / forget all work), but no channel.send fires — neither
/// on the initial submit nor on the wake task's deadline re-fire.
#[tokio::test(flavor = "current_thread")]
async fn audit_mode_persists_but_does_not_fire() {
    let h = EngineHarness::open(fast_two_rung_profile(), Mode::Audit);

    let _eid = h.submit_event(&finding_event(), 0).await;
    assert_eq!(h.counter(), 0, "audit must not fire on submit");
    assert_eq!(
        h.engine_row_count().await,
        1,
        "row persisted even in audit mode",
    );

    // Even at rung-0 deadline, audit mode suppresses the wake-
    // task's re-fire path (dispatch_payload_for_rung honours mode).
    wake_task::process_due_at(&h.dispatcher, 60).await;
    assert_eq!(h.counter(), 0, "audit must also suppress wake-task re-fire",);

    // At rung-1 deadline: the row advanced to max_rung; close path
    // runs and the row goes away. Channel still never fires.
    wake_task::process_due_at(&h.dispatcher, 240).await;
    assert_eq!(h.counter(), 0, "audit suppresses second rung too");
    assert_eq!(
        h.engine_row_count().await,
        0,
        "audit-mode row still closes at max rung",
    );
}
