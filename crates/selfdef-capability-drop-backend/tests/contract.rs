//! SDD-075 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_capability_drop_backend::{
    AuthorityTier, CapScope, CapabilityDropBackend, CapabilityDropError, CapabilityDropHandle,
    DropCapsRequest, InMemoryBackend, PendingCapsRestore, canonicalize_cap,
};

fn req(
    pid: i32,
    caps: &[&str],
    dur_secs: u64,
    tier: AuthorityTier,
    scope: CapScope,
    reason: &str,
) -> DropCapsRequest {
    let cap_strs: Vec<String> = caps.iter().map(|s| (*s).to_string()).collect();
    let idempotency_key = format!("{pid}:{}:{reason}:{tier:?}:{scope:?}", cap_strs.join(","));
    DropCapsRequest {
        pid,
        caps: cap_strs,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn drop_caps_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        &["CAP_NET_ADMIN", "CAP_SYS_PTRACE"],
        1500,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "attacker has CAP_NET_ADMIN flipping nftables",
    );
    let receipt = b.drop_caps(r).await.expect("drop must succeed");
    assert!(matches!(receipt.handle, CapabilityDropHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.caps_dropped, 2);
}

#[tokio::test]
async fn invalid_pid_zero_or_negative_is_rejected() {
    let b = InMemoryBackend::new();
    for bad_pid in [0, -1] {
        let r = req(
            bad_pid,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "x",
        );
        let err = b
            .drop_caps(r)
            .await
            .expect_err("non-positive pid must error");
        assert!(matches!(err, CapabilityDropError::InvalidRequest(_)));
    }
}

#[tokio::test]
async fn pid_one_init_is_refused() {
    let b = InMemoryBackend::new();
    let r = req(
        1,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "test",
    );
    let err = b.drop_caps(r).await.expect_err("pid 1 must error");
    assert!(matches!(
        err,
        CapabilityDropError::PidRefused { pid: 1, .. }
    ));
}

#[tokio::test]
async fn empty_caps_list_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &[],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "x",
    );
    let err = b.drop_caps(r).await.expect_err("empty caps must error");
    assert!(matches!(err, CapabilityDropError::InvalidRequest(_)));
}

#[tokio::test]
async fn unknown_cap_name_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["CAP_NET_ADMIN", "CAP_FROBNICATE"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "x",
    );
    let err = b.drop_caps(r).await.expect_err("unknown cap must error");
    assert!(matches!(err, CapabilityDropError::UnknownCapability { .. }));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "",
    );
    let err = b.drop_caps(r).await.expect_err("empty reason must error");
    assert!(matches!(err, CapabilityDropError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        100,
        &["CAP_NET_ADMIN"],
        60 * 60 * 6,
        AuthorityTier::Autonomous,
        CapScope::AllSets,
        "x",
    );
    let err = b.drop_caps(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        CapabilityDropError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_075_section_4() {
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
async fn redundant_when_no_caps_to_drop() {
    let b = InMemoryBackend::with_simulated_caps_held(0);
    let r = req(
        222,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "stale-awareness",
    );
    let receipt = b.drop_caps(r).await.unwrap();
    assert!(matches!(receipt.handle, CapabilityDropHandle::Redundant(_)));
    assert_eq!(receipt.caps_dropped, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn partial_drop_active_with_dropped_count() {
    let b = InMemoryBackend::with_simulated_caps_held(1);
    let r = req(
        223,
        &["CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_BPF"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "partial-coverage",
    );
    let receipt = b.drop_caps(r).await.unwrap();
    assert!(matches!(receipt.handle, CapabilityDropHandle::Active(_)));
    assert_eq!(receipt.caps_dropped, 1);
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn idempotent_drop_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        333,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "t",
    );
    let r2 = req(
        333,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "t",
    );
    let h1 = b.drop_caps(r1).await.unwrap().handle;
    let h2 = b.drop_caps(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        444,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "t",
    );
    let receipt = b.drop_caps(r).await.unwrap();
    let restore = b.restore_caps(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::with_simulated_caps_held(2);
    let r = req(
        555,
        &["CAP_NET_ADMIN", "CAP_SYS_PTRACE"],
        900,
        AuthorityTier::Responder,
        CapScope::AllSets,
        "rotation",
    );
    b.drop_caps(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 555);
    assert_eq!(pending[0].caps_dropped, 2);
}

#[tokio::test]
async fn scope_variants_distinct_handles() {
    let b = InMemoryBackend::new();
    let bounding = req(
        700,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::BoundingOnly,
        "t",
    );
    let all = req(
        700,
        &["CAP_NET_ADMIN"],
        60,
        AuthorityTier::Operator,
        CapScope::AllSets,
        "t",
    );
    let h1 = b.drop_caps(bounding).await.unwrap().handle;
    let h2 = b.drop_caps(all).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn canonicalize_cap_accepts_with_and_without_prefix() {
    assert_eq!(canonicalize_cap("CAP_NET_ADMIN"), Some("CAP_NET_ADMIN"));
    assert_eq!(canonicalize_cap("cap_net_admin"), Some("CAP_NET_ADMIN"));
    assert_eq!(canonicalize_cap("NET_ADMIN"), Some("CAP_NET_ADMIN"));
    assert_eq!(canonicalize_cap("net_admin"), Some("CAP_NET_ADMIN"));
    assert_eq!(canonicalize_cap("  CAP_NET_ADMIN  "), Some("CAP_NET_ADMIN"));
}

#[test]
fn canonicalize_cap_returns_none_for_unknown() {
    assert_eq!(canonicalize_cap("CAP_FROBNICATE"), None);
    assert_eq!(canonicalize_cap("RANDOM"), None);
    assert_eq!(canonicalize_cap(""), None);
}

#[test]
fn canonicalize_cap_handles_modern_late_caps() {
    // CAP_BPF, CAP_PERFMON, CAP_CHECKPOINT_RESTORE added in 5.x.
    assert!(canonicalize_cap("CAP_BPF").is_some());
    assert!(canonicalize_cap("CAP_PERFMON").is_some());
    assert!(canonicalize_cap("CAP_CHECKPOINT_RESTORE").is_some());
}

#[test]
fn pending_caps_restore_serializes_to_json() {
    let p = PendingCapsRestore {
        handle: CapabilityDropHandle::Active("h-1".into()),
        pid: 12345,
        caps: vec!["CAP_NET_ADMIN".into(), "CAP_SYS_PTRACE".into()],
        original_authority: AuthorityTier::Responder,
        original_reason: "incident-2026-05-29".into(),
        seconds_remaining: 600,
        scope: CapScope::AllSets,
        caps_dropped: 2,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("12345"));
    assert!(json.contains("CAP_NET_ADMIN"));
    assert!(json.contains("\"caps_dropped\":2"));
    assert!(json.contains("600"));
}
