//! SDD-073 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_socket_fd_revocation_backend::{
    AuthorityTier, InMemoryBackend, PendingFdRestore, RevokeFdRequest, SocketFdHandle,
    SocketFdRevocationBackend, SocketFdRevocationError, SocketProtocol,
};

fn req(
    pid: i32,
    fd: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    protocol: SocketProtocol,
    reason: &str,
    expected_inode: Option<u64>,
) -> RevokeFdRequest {
    let idempotency_key = format!("{pid}:{fd}:{reason}:{tier:?}:{protocol:?}");
    RevokeFdRequest {
        pid,
        fd,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        protocol,
        expected_inode,
        idempotency_key,
    }
}

#[tokio::test]
async fn revoke_fd_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        17,
        900,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "active C2 socket — sever live",
        None,
    );
    let receipt = b.revoke_fd(r).await.expect("revoke must succeed");
    assert!(matches!(receipt.handle, SocketFdHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1, -42] {
        let r = req(
            bad_pid,
            5,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "x",
            None,
        );
        let err = b
            .revoke_fd(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, SocketFdRevocationError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn negative_fd_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        -1,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "x",
        None,
    );
    let err = b.revoke_fd(r).await.expect_err("negative fd must error");
    assert!(matches!(err, SocketFdRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn fd_zero_one_two_are_allowed() {
    // stdin/stdout/stderr are technically revokable (process becomes
    // very confused, but operator can choose).
    for fd in [0, 1, 2] {
        let b = InMemoryBackend::new();
        let r = req(
            100,
            fd,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Any,
            "test-fd",
            None,
        );
        let receipt = b.revoke_fd(r).await.expect("fd 0/1/2 must be allowed");
        assert!(matches!(receipt.handle, SocketFdHandle::Active(_)));
    }
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        5,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "",
        None,
    );
    let err = b.revoke_fd(r).await.expect_err("empty reason must error");
    assert!(matches!(err, SocketFdRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        5,
        60 * 60 * 6,
        AuthorityTier::Autonomous,
        SocketProtocol::Tcp,
        "x",
        None,
    );
    let err = b.revoke_fd(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        SocketFdRevocationError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_073_section_4() {
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
        Duration::from_secs(4 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_revoke_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        222,
        7,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "t",
        None,
    );
    let r2 = req(
        222,
        7,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "t",
        None,
    );
    let h1 = b.revoke_fd(r1).await.unwrap().handle;
    let h2 = b.revoke_fd(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        333,
        9,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "t",
        None,
    );
    let receipt = b.revoke_fd(r).await.unwrap();
    let restore = b.restore_fd(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        444,
        12,
        900,
        AuthorityTier::Responder,
        SocketProtocol::Tcp,
        "correlator",
        None,
    );
    b.revoke_fd(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 444);
    assert_eq!(pending[0].fd, 12);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        555,
        3,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Unix,
        "manual",
        None,
    );
    b.revoke_fd(r).await.unwrap();
    assert!(b.pending_restores().await.is_empty());
}

#[tokio::test]
async fn protocols_tcp_vs_unix_distinct_handles() {
    let b = InMemoryBackend::new();
    let tcp = req(
        700,
        5,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "t",
        None,
    );
    let unix = req(
        700,
        5,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Unix,
        "t",
        None,
    );
    let h1 = b.revoke_fd(tcp).await.unwrap().handle;
    let h2 = b.revoke_fd(unix).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[tokio::test]
async fn inode_race_returns_stale_handle() {
    // Backend simulates that the fd's CURRENT inode is 999.
    // Request says it expected inode 100 — i.e. fd was reused.
    let b = InMemoryBackend::with_simulated_current_inode(999);
    let r = req(
        800,
        5,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "race",
        Some(100),
    );
    let receipt = b.revoke_fd(r).await.unwrap();
    assert!(matches!(receipt.handle, SocketFdHandle::Stale(_)));
    // Stale revokes are NOT counted as active.
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn inode_match_proceeds_normally() {
    let b = InMemoryBackend::with_simulated_current_inode(999);
    let r = req(
        801,
        5,
        60,
        AuthorityTier::Operator,
        SocketProtocol::Tcp,
        "match",
        Some(999),
    );
    let receipt = b.revoke_fd(r).await.unwrap();
    assert!(matches!(receipt.handle, SocketFdHandle::Active(_)));
}

#[test]
fn pending_fd_restore_serializes_to_json() {
    let p = PendingFdRestore {
        handle: SocketFdHandle::Active("h-1".into()),
        pid: 12345,
        fd: 42,
        original_authority: AuthorityTier::Responder,
        original_reason: "C2-channel".into(),
        seconds_remaining: 600,
        protocol: SocketProtocol::Tcp,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("\"fd\":42"));
    assert!(json.contains("C2-channel"));
    assert!(json.contains("600"));
}
