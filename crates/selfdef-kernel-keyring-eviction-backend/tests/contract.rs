//! SDD-076 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_kernel_keyring_eviction_backend::{
    AuthorityTier, EvictKeyRequest, EvictionScope, InMemoryBackend, KernelKeyringEvictionBackend,
    KernelKeyringEvictionError, KernelKeyringHandle, PendingKeyRestore, parse_key_spec,
};

fn req(
    spec: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: EvictionScope,
    reason: &str,
) -> EvictKeyRequest {
    let idempotency_key = format!("{spec}:{reason}:{tier:?}:{scope:?}");
    EvictKeyRequest {
        key_spec: spec.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn evict_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "user:krb5cc/uid=1000",
        900,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "attacker has TGT — invalidate",
    );
    let receipt = b.evict_key(r).await.expect("evict must succeed");
    assert!(matches!(receipt.handle, KernelKeyringHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.keys_evicted, 1);
}

#[tokio::test]
async fn unparseable_key_spec_rejected() {
    let b = InMemoryBackend::new();
    for bad in ["", "no-colon", ":empty-type", "user:", "unknown_type:foo"] {
        let r = req(
            bad,
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "x",
        );
        let err = b
            .evict_key(r)
            .await
            .expect_err(&format!("malformed spec {bad:?} must error"));
        assert!(matches!(
            err,
            KernelKeyringEvictionError::UnparseableKeySpec { .. }
        ));
    }
}

#[tokio::test]
async fn hex_serial_key_spec_accepted() {
    let b = InMemoryBackend::new();
    let r = req(
        "0x12345abc",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "by-serial",
    );
    let receipt = b.evict_key(r).await.unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::Active(_)));
}

#[tokio::test]
async fn hex_serial_with_non_hex_chars_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "0xzzznot-hex",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "x",
    );
    let err = b.evict_key(r).await.expect_err("non-hex serial must error");
    assert!(matches!(
        err,
        KernelKeyringEvictionError::UnparseableKeySpec { .. }
    ));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "user:krb5cc/uid=1000",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "",
    );
    let err = b.evict_key(r).await.expect_err("empty reason must error");
    assert!(matches!(err, KernelKeyringEvictionError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "user:test",
        60 * 60 * 6,
        AuthorityTier::Autonomous,
        EvictionScope::Invalidate,
        "x",
    );
    let err = b.evict_key(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        KernelKeyringEvictionError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_076_section_4() {
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
async fn not_found_when_simulated_zero() {
    let b = InMemoryBackend::with_simulated_keys_evicted(0);
    let r = req(
        "user:already-gone",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "race",
    );
    let receipt = b.evict_key(r).await.unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::NotFound(_)));
    assert_eq!(receipt.keys_evicted, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn both_scope_carries_keys_evicted_two() {
    let b = InMemoryBackend::with_simulated_keys_evicted(2);
    let r = req(
        "user:both-test",
        60,
        AuthorityTier::Operator,
        EvictionScope::Both,
        "both-scope",
    );
    let receipt = b.evict_key(r).await.unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::Active(_)));
    assert_eq!(receipt.keys_evicted, 2);
}

#[tokio::test]
async fn idempotent_evict_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        "user:dup",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "t",
    );
    let r2 = req(
        "user:dup",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "t",
    );
    let h1 = b.evict_key(r1).await.unwrap().handle;
    let h2 = b.evict_key(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "user:r",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "t",
    );
    let receipt = b.evict_key(r).await.unwrap();
    let restore = b.restore_key(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::with_simulated_keys_evicted(1);
    let r = req(
        "logon:dm-crypt:luks-deadbeef",
        900,
        AuthorityTier::Responder,
        EvictionScope::Both,
        "luks-key-evict",
    );
    b.evict_key(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key_type, "logon");
    assert_eq!(pending[0].keys_evicted, 1);
}

#[tokio::test]
async fn scope_variants_distinct_handles() {
    let b = InMemoryBackend::new();
    let inv = req(
        "user:s",
        60,
        AuthorityTier::Operator,
        EvictionScope::Invalidate,
        "t",
    );
    let unl = req(
        "user:s",
        60,
        AuthorityTier::Operator,
        EvictionScope::Unlink,
        "t",
    );
    let h1 = b.evict_key(inv).await.unwrap().handle;
    let h2 = b.evict_key(unl).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn parse_key_spec_accepts_known_types() {
    assert_eq!(
        parse_key_spec("user:krb5cc/uid=1000"),
        Some(("user", "krb5cc/uid=1000"))
    );
    assert_eq!(
        parse_key_spec("logon:dm-crypt:luks-xyz"),
        Some(("logon", "dm-crypt:luks-xyz"))
    );
    assert_eq!(
        parse_key_spec("keyring:_uid.1000"),
        Some(("keyring", "_uid.1000"))
    );
    assert_eq!(
        parse_key_spec("big_key:hugepayload"),
        Some(("big_key", "hugepayload"))
    );
}

#[test]
fn parse_key_spec_accepts_hex_serial() {
    assert_eq!(parse_key_spec("0xdeadbeef"), Some(("serial", "0xdeadbeef")));
    assert_eq!(parse_key_spec("0x1"), Some(("serial", "0x1")));
}

#[test]
fn parse_key_spec_rejects_malformed() {
    assert_eq!(parse_key_spec(""), None);
    assert_eq!(parse_key_spec("no-colon"), None);
    assert_eq!(parse_key_spec(":empty-type"), None);
    assert_eq!(parse_key_spec("user:"), None);
    assert_eq!(parse_key_spec("unknown_type:desc"), None);
    assert_eq!(parse_key_spec("0x"), None);
    assert_eq!(parse_key_spec("0xnotahexnumber-zz"), None);
}

#[test]
fn pending_key_restore_serializes_to_json() {
    let p = PendingKeyRestore {
        handle: KernelKeyringHandle::Active("h-1".into()),
        key_spec: "user:krb5cc/uid=1000".into(),
        key_type: "user".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "TGT compromise".into(),
        seconds_remaining: 600,
        scope: EvictionScope::Invalidate,
        keys_evicted: 1,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("user:krb5cc/uid=1000"));
    assert!(json.contains("TGT compromise"));
    assert!(json.contains("600"));
    assert!(json.contains("\"keys_evicted\":1"));
}
