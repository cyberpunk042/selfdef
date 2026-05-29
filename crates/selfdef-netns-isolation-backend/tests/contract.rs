//! SDD-070 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_netns_isolation_backend::{
    AuthorityTier, InMemoryBackend, IsolatePidRequest, IsolationScope, NetnsIsolationBackend,
    NetnsIsolationError, NetnsIsolationHandle, PendingNetnsRelease,
};

fn req(
    pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: IsolationScope,
    reason: &str,
) -> IsolatePidRequest {
    let idempotency_key = format!("{pid}:{reason}:{tier:?}:{scope:?}");
    IsolatePidRequest {
        pid,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn isolate_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        12345,
        1800,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "suspected exfil — contain live for forensics",
    );
    let receipt = b.isolate_pid(r).await.expect("isolate must succeed");
    assert!(matches!(receipt.handle, NetnsIsolationHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1, -42] {
        let r = req(
            bad_pid,
            60,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
            "x",
        );
        let err = b
            .isolate_pid(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, NetnsIsolationError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "",
    );
    let err = b.isolate_pid(r).await.expect_err("empty reason must error");
    assert!(matches!(err, NetnsIsolationError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        3600,
        AuthorityTier::Autonomous,
        IsolationScope::NetOnly,
        "x",
    );
    let err = b.isolate_pid(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        NetnsIsolationError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_070_section_4() {
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
        Duration::from_secs(2 * 60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(12 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_isolate_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        222,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "t",
    );
    let r2 = req(
        222,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "t",
    );
    let h1 = b.isolate_pid(r1).await.unwrap().handle;
    let h2 = b.isolate_pid(r2).await.unwrap().handle;
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
        IsolationScope::NetOnly,
        "t",
    );
    let receipt = b.isolate_pid(r).await.unwrap();
    b.release_isolation(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_release_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        444,
        900,
        AuthorityTier::Responder,
        IsolationScope::NetOnly,
        "correlator",
    );
    b.isolate_pid(r).await.unwrap();
    let pending = b.pending_releases().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 444);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        555,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "manual",
    );
    b.isolate_pid(r).await.unwrap();
    assert!(b.pending_releases().await.is_empty());
}

#[tokio::test]
async fn scoped_net_only_vs_all_distinct_handles() {
    let b = InMemoryBackend::new();
    let net_only = req(
        700,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetOnly,
        "t",
    );
    let net_pid_ipc = req(
        700,
        60,
        AuthorityTier::Operator,
        IsolationScope::NetPidIpc,
        "t",
    );
    let h1 = b.isolate_pid(net_only).await.unwrap().handle;
    let h2 = b.isolate_pid(net_pid_ipc).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn pending_netns_release_serializes_to_json() {
    let p = PendingNetnsRelease {
        handle: NetnsIsolationHandle::Active("h-1".into()),
        pid: 12345,
        original_authority: AuthorityTier::Responder,
        original_reason: "exfil".into(),
        seconds_remaining: 600,
        scope: IsolationScope::NetOnly,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("exfil"));
    assert!(json.contains("600"));
}
