//! SDD-066 MS1 — L1 unit-level contract test for the process-
//! quarantine backend trait. Written FIRST (TDD): each behaviour
//! the spec locks gets one assert; lib.rs implements just enough
//! to make them pass.

use std::time::Duration;

use selfdef_process_quarantine_backend::{
    AuthorityTier, FreezeRequest, FreezeScope, InMemoryBackend, PendingRelease,
    ProcessQuarantineBackend, QuarantineError, QuarantineHandle,
};

fn req(
    pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    reason: &str,
    scope: FreezeScope,
) -> FreezeRequest {
    FreezeRequest {
        pid,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key: format!("{pid}:{reason}:{tier:?}"),
    }
}

#[tokio::test]
async fn freeze_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        12345,
        300,
        AuthorityTier::Operator,
        "anomalous outbound",
        FreezeScope::Process,
    );
    let receipt = b.freeze_process(r).await.expect("freeze must succeed");
    assert!(matches!(receipt.handle, QuarantineHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(12345, 60, AuthorityTier::Operator, "", FreezeScope::Process);
    let err = b
        .freeze_process(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, QuarantineError::InvalidRequest(_)));
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1, -42] {
        let r = req(
            bad_pid,
            60,
            AuthorityTier::Operator,
            "x",
            FreezeScope::Process,
        );
        let err = b
            .freeze_process(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, QuarantineError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    // Autonomous max = 2 min per SDD-066 §4. Request 1h.
    let r = req(
        100,
        3600,
        AuthorityTier::Autonomous,
        "x",
        FreezeScope::Process,
    );
    let err = b.freeze_process(r).await.expect_err("over-tier must error");
    assert!(matches!(err, QuarantineError::AuthorityInsufficient { .. }));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_066_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(2 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(15 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(24 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_freeze_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        222,
        60,
        AuthorityTier::Operator,
        "test",
        FreezeScope::Process,
    );
    let r2 = req(
        222,
        60,
        AuthorityTier::Operator,
        "test",
        FreezeScope::Process,
    );
    let h1 = b.freeze_process(r1).await.unwrap().handle;
    let h2 = b.freeze_process(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn release_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        333,
        60,
        AuthorityTier::Operator,
        "test",
        FreezeScope::Process,
    );
    let receipt = b.freeze_process(r).await.unwrap();
    b.release_process(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_release_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        444,
        900,
        AuthorityTier::Responder,
        "correlator",
        FreezeScope::Process,
    );
    b.freeze_process(r).await.unwrap();
    let pending = b.pending_releases().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 444);
    assert_eq!(pending[0].original_authority, AuthorityTier::Responder);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        555,
        60,
        AuthorityTier::Operator,
        "manual",
        FreezeScope::Process,
    );
    b.freeze_process(r).await.unwrap();
    assert!(b.pending_releases().await.is_empty());
}

#[tokio::test]
async fn pending_releases_sorted_by_seconds_remaining_ascending() {
    let b = InMemoryBackend::new();
    for (pid, secs) in [(10, 900u64), (11, 300), (12, 600)] {
        let r = req(
            pid,
            secs,
            AuthorityTier::Responder,
            "test",
            FreezeScope::Process,
        );
        b.freeze_process(r).await.unwrap();
    }
    let pending = b.pending_releases().await;
    assert_eq!(pending.len(), 3);
    assert_eq!(pending[0].seconds_remaining, 300);
    assert_eq!(pending[1].seconds_remaining, 600);
    assert_eq!(pending[2].seconds_remaining, 900);
}

#[tokio::test]
async fn mark_release_decided_removes_from_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        666,
        300,
        AuthorityTier::Responder,
        "test",
        FreezeScope::Process,
    );
    let receipt = b.freeze_process(r).await.unwrap();
    assert_eq!(b.pending_releases().await.len(), 1);
    assert!(b.mark_release_decided(&receipt.handle).await);
    assert!(b.pending_releases().await.is_empty());
    // Underlying freeze remains active.
    assert_eq!(b.active_count().await, 1);
}

#[test]
fn pending_release_serializes_to_json() {
    let p = PendingRelease {
        handle: QuarantineHandle::Active("h-1".into()),
        pid: 12345,
        original_authority: AuthorityTier::Responder,
        original_reason: "anomaly".into(),
        seconds_remaining: 600,
        scope: FreezeScope::Process,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("anomaly"));
    assert!(json.contains("600"));
}

#[tokio::test]
async fn scope_tree_is_recorded_separately_from_process() {
    let b = InMemoryBackend::new();
    let p = req(
        700,
        60,
        AuthorityTier::Operator,
        "single",
        FreezeScope::Process,
    );
    let t = req(700, 60, AuthorityTier::Operator, "tree", FreezeScope::Tree);
    // Different idempotency keys (reason differs) → different handles.
    let h1 = b.freeze_process(p).await.unwrap().handle;
    let h2 = b.freeze_process(t).await.unwrap().handle;
    assert_ne!(h1, h2);
}
