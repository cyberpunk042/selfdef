//! SDD-065 MS1 — L1 unit-level contract test for the blockset
//! backend trait. Written FIRST (TDD): each behaviour the spec
//! locks gets one assert; lib.rs implements just enough to make
//! them pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use selfdef_blockset_backend::{
    AuthorityTier, BackendError, BlockHandle, BlockIpRequest, BlockReceipt, BlockSetBackend,
    InMemoryBackend,
};

fn req(addr: IpAddr, dur_secs: u64, tier: AuthorityTier, reason: &str) -> BlockIpRequest {
    BlockIpRequest {
        addr,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        idempotency_key: format!("{addr}:{reason}:{tier:?}"),
    }
}

#[tokio::test]
async fn block_ipv4_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
        3600,
        AuthorityTier::Operator,
        "sshd brute force",
    );
    let receipt: BlockReceipt = b.block_ip(r).await.expect("block must succeed");
    assert!(matches!(receipt.handle, BlockHandle::Active(_)));
    assert_eq!(receipt.scope_v4_count, 1);
    assert_eq!(receipt.scope_v6_count, 0);
}

#[tokio::test]
async fn block_ipv6_routes_to_v6_set() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)),
        300,
        AuthorityTier::Autonomous,
        "burst",
    );
    let receipt = b.block_ip(r).await.unwrap();
    assert_eq!(receipt.scope_v6_count, 1);
    assert_eq!(receipt.scope_v4_count, 0);
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        60,
        AuthorityTier::Operator,
        "",
    );
    let err = b.block_ip(r).await.expect_err("empty reason must error");
    assert!(matches!(err, BackendError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    // Autonomous tier max = 5 min. Request 1h.
    let r = req(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        3600,
        AuthorityTier::Autonomous,
        "auto",
    );
    let err = b.block_ip(r).await.expect_err("over-tier must error");
    assert!(matches!(err, BackendError::AuthorityInsufficient { .. }));
}

#[tokio::test]
async fn responder_tier_caps_at_one_hour() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        3600,
        AuthorityTier::Responder,
        "correlator",
    );
    b.block_ip(r).await.expect("responder@1h is allowed");
}

#[tokio::test]
async fn operator_overridden_tier_allows_30_days() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        720 * 3600,
        AuthorityTier::OperatorOverridden,
        "known-hostile ASN",
    );
    b.block_ip(r)
        .await
        .expect("operator-overridden@720h is allowed");
}

#[tokio::test]
async fn idempotent_block_returns_same_handle() {
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    let r1 = req(addr, 60, AuthorityTier::Operator, "test");
    let r2 = req(addr, 60, AuthorityTier::Operator, "test");
    let h1 = b.block_ip(r1).await.unwrap().handle;
    let h2 = b.block_ip(r2).await.unwrap().handle;
    // Same {addr, reason, tier} → same handle, no duplicate stack.
    assert_eq!(h1, h2);
    assert_eq!(b.active_v4_count().await, 1);
}

#[tokio::test]
async fn unblock_releases_handle() {
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
    let r = req(addr, 60, AuthorityTier::Operator, "test");
    let receipt = b.block_ip(r).await.unwrap();
    b.unblock_ip(receipt.handle)
        .await
        .expect("unblock must succeed");
    assert_eq!(b.active_v4_count().await, 0);
}

#[tokio::test]
async fn ipv6_link_local_is_never_blocked() {
    // SDD-065 open question resolved per spec body: fe80::/10
    // is always allowlisted to avoid breaking link-local discovery.
    let b = InMemoryBackend::new();
    let link_local = IpAddr::V6("fe80::1".parse().unwrap());
    let r = req(link_local, 60, AuthorityTier::Operator, "test");
    let err = b.block_ip(r).await.expect_err("link-local must be refused");
    assert!(matches!(err, BackendError::LinkLocalRefused(_)));
}
