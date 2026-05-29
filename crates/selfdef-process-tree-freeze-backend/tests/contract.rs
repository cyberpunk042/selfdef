//! SDD-072 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_process_tree_freeze_backend::{
    AuthorityTier, FreezeTreeRequest, InMemoryBackend, PendingTreeThaw, ProcessTreeFreezeBackend,
    ProcessTreeFreezeError, ProcessTreeHandle, TreeScope,
};

fn req(
    root_pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: TreeScope,
    reason: &str,
    include_self: bool,
) -> FreezeTreeRequest {
    let idempotency_key = format!("{root_pid}:{reason}:{tier:?}:{scope:?}");
    FreezeTreeRequest {
        root_pid,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        include_self,
        idempotency_key,
    }
}

#[tokio::test]
async fn freeze_tree_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::with_simulated_tree_size(7);
    let r = req(
        4242,
        1500,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "worker-pool exploit",
        true,
    );
    let receipt = b.freeze_tree(r).await.expect("freeze must succeed");
    assert!(matches!(receipt.handle, ProcessTreeHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.frozen_pid_count, 7);
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1, -42] {
        let r = req(
            bad_pid,
            60,
            AuthorityTier::Operator,
            TreeScope::Descendants,
            "x",
            true,
        );
        let err = b
            .freeze_tree(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, ProcessTreeFreezeError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn pid_one_init_is_refused() {
    let b = InMemoryBackend::new();
    let r = req(
        1,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "test",
        true,
    );
    let err = b.freeze_tree(r).await.expect_err("pid 1 must error");
    assert!(matches!(
        err,
        ProcessTreeFreezeError::PidRefused { pid: 1, .. }
    ));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "",
        true,
    );
    let err = b.freeze_tree(r).await.expect_err("empty reason must error");
    assert!(matches!(err, ProcessTreeFreezeError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        60 * 60 * 10,
        AuthorityTier::Autonomous,
        TreeScope::Descendants,
        "x",
        true,
    );
    let err = b.freeze_tree(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        ProcessTreeFreezeError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_072_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(5 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(30 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(4 * 60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(8 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_freeze_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        222,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "t",
        true,
    );
    let r2 = req(
        222,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "t",
        true,
    );
    let h1 = b.freeze_tree(r1).await.unwrap().handle;
    let h2 = b.freeze_tree(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn thaw_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        333,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "t",
        true,
    );
    let receipt = b.freeze_tree(r).await.unwrap();
    b.thaw_tree(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_thaw_queue() {
    let b = InMemoryBackend::with_simulated_tree_size(12);
    let r = req(
        444,
        900,
        AuthorityTier::Responder,
        TreeScope::StrictDescendants,
        "fork-bomb",
        true,
    );
    b.freeze_tree(r).await.unwrap();
    let pending = b.pending_thaws().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].root_pid, 444);
    assert_eq!(pending[0].frozen_pid_count, 12);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        555,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "manual",
        true,
    );
    b.freeze_tree(r).await.unwrap();
    assert!(b.pending_thaws().await.is_empty());
}

#[tokio::test]
async fn scoped_descendants_vs_children_only_distinct_handles() {
    let b = InMemoryBackend::new();
    let descendants = req(
        700,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "t",
        true,
    );
    let children = req(
        700,
        60,
        AuthorityTier::Operator,
        TreeScope::ChildrenOnly,
        "t",
        true,
    );
    let h1 = b.freeze_tree(descendants).await.unwrap().handle;
    let h2 = b.freeze_tree(children).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[tokio::test]
async fn strict_descendants_scope_distinct_from_plain_descendants() {
    let b = InMemoryBackend::new();
    let plain = req(
        800,
        60,
        AuthorityTier::Operator,
        TreeScope::Descendants,
        "t",
        true,
    );
    let strict = req(
        800,
        60,
        AuthorityTier::Operator,
        TreeScope::StrictDescendants,
        "t",
        true,
    );
    let h1 = b.freeze_tree(plain).await.unwrap().handle;
    let h2 = b.freeze_tree(strict).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn pending_tree_thaw_serializes_to_json() {
    let p = PendingTreeThaw {
        handle: ProcessTreeHandle::Active("h-1".into()),
        root_pid: 12345,
        original_authority: AuthorityTier::Responder,
        original_reason: "fork-bomb".into(),
        seconds_remaining: 600,
        scope: TreeScope::StrictDescendants,
        frozen_pid_count: 42,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("fork-bomb"));
    assert!(json.contains("600"));
    assert!(json.contains("42"));
}
