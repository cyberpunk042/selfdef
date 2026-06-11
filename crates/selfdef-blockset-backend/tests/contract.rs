//! SDD-065 MS1 — L1 unit-level contract test for the blockset
//! backend trait. Written FIRST (TDD): each behaviour the spec
//! locks gets one assert; lib.rs implements just enough to make
//! them pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use selfdef_blockset_backend::{
    AuthorityTier, BackendError, BlockHandle, BlockIpRequest, BlockReceipt, BlockSetBackend,
    InMemoryBackend, PendingExtension,
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

// ───────────────────────── MS1b nftables-adapter unit tests ─────────────────────────

#[test]
fn nft_add_v4_builds_correct_args() {
    let r = req(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
        3600,
        AuthorityTier::Operator,
        "sshd brute force",
    );
    let args = selfdef_blockset_backend::nft_add_element_args(&r);
    assert_eq!(args[0], "add");
    assert_eq!(args[1], "element");
    assert_eq!(args[2], "inet");
    assert_eq!(args[3], "selfdef-blocks");
    assert_eq!(args[4], "v4");
    assert_eq!(args[5], "{ 203.0.113.42 timeout 3600s }");
}

#[test]
fn nft_add_v6_builds_correct_args() {
    let r = req(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)),
        300,
        AuthorityTier::Autonomous,
        "burst",
    );
    let args = selfdef_blockset_backend::nft_add_element_args(&r);
    assert_eq!(args[4], "v6");
    assert!(args[5].contains("2001:db8::42"));
    assert!(args[5].contains("timeout 300s"));
}

#[test]
fn nft_delete_v4_builds_correct_args() {
    let args = selfdef_blockset_backend::nft_delete_element_args(IpAddr::V4(Ipv4Addr::new(
        198, 51, 100, 7,
    )));
    assert_eq!(args[0], "delete");
    assert_eq!(args[1], "element");
    assert_eq!(args[4], "v4");
    assert_eq!(args[5], "{ 198.51.100.7 }");
}

#[test]
fn nft_bootstrap_script_is_idempotent() {
    let s = selfdef_blockset_backend::nft_bootstrap_script();
    assert!(s.contains("add table inet selfdef-blocks"));
    assert!(s.contains("add set inet selfdef-blocks v4"));
    assert!(s.contains("add set inet selfdef-blocks v6"));
    assert!(s.contains("flags timeout"));
    assert!(s.contains("hook input priority -100"));
    assert!(s.contains("@v4 drop"));
    assert!(s.contains("@v6 drop"));
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

#[tokio::test]
async fn special_addresses_are_never_blocked_self_dos_guard() {
    // An attacker-crafted (or misattributed) event naming a special address
    // must not make the IPS block its own host networking. Blocking loopback
    // self-DoSes local services; unspecified / broadcast / multicast / v4
    // link-local are nonsensical block targets.
    let b = InMemoryBackend::new();
    let cases: &[(IpAddr, &str)] = &[
        ("127.0.0.1".parse().unwrap(), "v4 loopback"),
        ("::1".parse().unwrap(), "v6 loopback"),
        ("0.0.0.0".parse().unwrap(), "v4 unspecified"),
        ("::".parse().unwrap(), "v6 unspecified"),
        ("169.254.0.5".parse().unwrap(), "v4 link-local"),
        ("255.255.255.255".parse().unwrap(), "v4 broadcast"),
        ("224.0.0.1".parse().unwrap(), "v4 multicast"),
        ("ff02::1".parse().unwrap(), "v6 multicast"),
    ];
    for (addr, label) in cases {
        let r = req(*addr, 60, AuthorityTier::Operator, "test");
        let err = b.block_ip(r).await.expect_err(label);
        assert!(
            matches!(
                err,
                BackendError::SpecialAddrRefused { .. } | BackendError::LinkLocalRefused(_)
            ),
            "{label} must be refused as a special address, got {err:?}"
        );
    }
}

#[tokio::test]
async fn a_normal_public_address_still_blocks() {
    // The guard must not over-refuse — a routable public IP still blocks.
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let r = req(addr, 60, AuthorityTier::Operator, "real threat");
    b.block_ip(r).await.expect("a public address must still block");
}

// ───────────────────────── MS5 pending-extension queue tests ─────────────────────────

#[tokio::test]
async fn responder_tier_block_enqueues_pending_extension() {
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100));
    let r = req(addr, 1800, AuthorityTier::Responder, "sshd brute force");
    b.block_ip(r).await.unwrap();
    let pending = b.pending_extensions().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].addr, addr);
    assert_eq!(pending[0].original_authority, AuthorityTier::Responder);
    assert_eq!(pending[0].original_reason, "sshd brute force");
    assert_eq!(pending[0].seconds_remaining, 1800);
}

#[tokio::test]
async fn operator_tier_block_does_not_enqueue() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 101)),
        3600,
        AuthorityTier::Operator,
        "operator manual",
    );
    b.block_ip(r).await.unwrap();
    let pending = b.pending_extensions().await;
    assert!(
        pending.is_empty(),
        "operator-tier blocks must not enter pending queue"
    );
}

#[tokio::test]
async fn autonomous_tier_block_does_not_enqueue() {
    let b = InMemoryBackend::new();
    let r = req(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 102)),
        60,
        AuthorityTier::Autonomous,
        "burst",
    );
    b.block_ip(r).await.unwrap();
    assert!(b.pending_extensions().await.is_empty());
}

#[tokio::test]
async fn pending_extensions_sorted_by_seconds_remaining_ascending() {
    let b = InMemoryBackend::new();
    for (oct, secs) in [(10, 3600u64), (11, 900), (12, 2400)] {
        let r = req(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, oct)),
            secs,
            AuthorityTier::Responder,
            "test",
        );
        b.block_ip(r).await.unwrap();
    }
    let pending = b.pending_extensions().await;
    assert_eq!(pending.len(), 3);
    // Most-urgent first (smallest seconds_remaining).
    assert_eq!(pending[0].seconds_remaining, 900);
    assert_eq!(pending[1].seconds_remaining, 2400);
    assert_eq!(pending[2].seconds_remaining, 3600);
}

#[tokio::test]
async fn mark_extension_decided_removes_from_queue() {
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 103));
    let r = req(addr, 1800, AuthorityTier::Responder, "test");
    let receipt = b.block_ip(r).await.unwrap();
    assert_eq!(b.pending_extensions().await.len(), 1);
    let removed = b.mark_extension_decided(&receipt.handle).await;
    assert!(removed);
    assert!(b.pending_extensions().await.is_empty());
    // Underlying block remains active until unblock_ip or kernel TTL.
    assert_eq!(b.active_v4_count().await, 1);
}

#[tokio::test]
async fn mark_extension_decided_returns_false_for_unknown_handle() {
    let b = InMemoryBackend::new();
    let bogus = BlockHandle::Active("never-existed".into());
    assert!(!b.mark_extension_decided(&bogus).await);
}

#[tokio::test]
async fn unblock_ip_also_removes_pending_entry() {
    let b = InMemoryBackend::new();
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 104));
    let r = req(addr, 1800, AuthorityTier::Responder, "test");
    let receipt = b.block_ip(r).await.unwrap();
    assert_eq!(b.pending_extensions().await.len(), 1);
    b.unblock_ip(receipt.handle).await.unwrap();
    assert!(
        b.pending_extensions().await.is_empty(),
        "unblock_ip must also clear the pending-extension entry"
    );
}

#[test]
fn pending_extension_serializes_to_json() {
    let p = PendingExtension {
        handle: BlockHandle::Active("h-1".into()),
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        original_authority: AuthorityTier::Responder,
        original_reason: "sshd".into(),
        seconds_remaining: 600,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("203.0.113.7"));
    assert!(json.contains("sshd"));
    assert!(json.contains("600"));
}
