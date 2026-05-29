//! SDD-077 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_apparmor_profile_pivot_backend::{
    ApparmorProfilePivotBackend, ApparmorProfilePivotError, ApparmorProfilePivotHandle,
    AuthorityTier, InMemoryBackend, PendingProfileRestore, PivotProfileRequest, PivotScope,
    validate_profile_name,
};

fn req(
    pid: i32,
    profile: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: PivotScope,
    reason: &str,
) -> PivotProfileRequest {
    let idempotency_key = format!("{pid}:{profile}:{tier:?}:{scope:?}:{reason}");
    PivotProfileRequest {
        pid,
        target_profile: profile.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn pivot_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::with_original_profile("firefox");
    let r = req(
        4242,
        "selfdef-quarantine-strict",
        900,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "suspicious activity — narrow profile",
    );
    let receipt = b
        .pivot_profile(r)
        .await
        .expect("pivot under Operator tier must succeed");
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    assert_eq!(receipt.original_profile, "firefox");
}

#[tokio::test]
async fn invalid_profile_name_rejected() {
    let b = InMemoryBackend::new();
    for bad in [
        "",
        "with space",
        "with\nnewline",
        "with;semicolon",
        "with$shellvar",
        &"x".repeat(257),
    ] {
        let r = req(
            4242,
            bad,
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "x",
        );
        let err = b
            .pivot_profile(r)
            .await
            .expect_err(&format!("malformed profile {bad:?} must error"));
        assert!(
            matches!(err, ApparmorProfilePivotError::InvalidProfileName { .. }),
            "got {err:?}"
        );
    }
}

#[tokio::test]
async fn pid_one_is_sacrosanct() {
    let b = InMemoryBackend::new();
    let r = req(
        1,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "x",
    );
    let err = b.pivot_profile(r).await.expect_err("pid 1 must error");
    assert!(matches!(err, ApparmorProfilePivotError::PidSacrosanct { pid: 1, .. }));
}

#[tokio::test]
async fn pid_zero_is_sacrosanct() {
    let b = InMemoryBackend::new();
    let r = req(
        0,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "x",
    );
    let err = b.pivot_profile(r).await.expect_err("pid 0 must error");
    assert!(matches!(err, ApparmorProfilePivotError::PidSacrosanct { pid: 0, .. }));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "",
    );
    let err = b
        .pivot_profile(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, ApparmorProfilePivotError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "selfdef-observe-only",
        60 * 60 * 25,
        AuthorityTier::Autonomous,
        PivotScope::Profile,
        "x",
    );
    let err = b.pivot_profile(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        ApparmorProfilePivotError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_077_authority_table() {
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
        Duration::from_secs(24 * 60 * 60)
    );
}

#[tokio::test]
async fn autonomous_tier_limited_to_observe_only() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Autonomous,
        PivotScope::Profile,
        "x",
    );
    let err = b
        .pivot_profile(r)
        .await
        .expect_err("Autonomous can only pivot into observe-only");
    assert!(matches!(err, ApparmorProfilePivotError::InvalidRequest(_)));
}

#[tokio::test]
async fn responder_tier_limited_to_two_strict_profiles() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "selfdef-some-custom-profile",
        60,
        AuthorityTier::Responder,
        PivotScope::Profile,
        "x",
    );
    let err = b
        .pivot_profile(r)
        .await
        .expect_err("Responder cannot pivot into arbitrary profiles");
    assert!(matches!(err, ApparmorProfilePivotError::InvalidRequest(_)));
}

#[tokio::test]
async fn operator_tier_cannot_pivot_into_unconfined() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "unconfined",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "x",
    );
    let err = b
        .pivot_profile(r)
        .await
        .expect_err("Operator cannot un-confine");
    assert!(matches!(err, ApparmorProfilePivotError::InvalidRequest(_)));
}

#[tokio::test]
async fn operator_overridden_tier_may_pivot_into_unconfined() {
    let b = InMemoryBackend::with_original_profile("selfdef-quarantine-strict");
    let r = req(
        4242,
        "unconfined",
        60,
        AuthorityTier::OperatorOverridden,
        PivotScope::Profile,
        "forensic-capture",
    );
    let receipt = b.pivot_profile(r).await.unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Active(_)));
}

#[tokio::test]
async fn no_target_when_forced() {
    let b = InMemoryBackend::new().force_no_target();
    let r = req(
        4242,
        "selfdef-observe-only",
        60,
        AuthorityTier::Autonomous,
        PivotScope::Profile,
        "missing profile",
    );
    let receipt = b.pivot_profile(r).await.unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::NoTarget(_)));
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn denied_when_forced() {
    let b = InMemoryBackend::new().force_denied();
    let r = req(
        4242,
        "selfdef-observe-only",
        60,
        AuthorityTier::Autonomous,
        PivotScope::Profile,
        "current profile forbids",
    );
    let receipt = b.pivot_profile(r).await.unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Denied(_)));
}

#[tokio::test]
async fn stale_when_forced() {
    let b = InMemoryBackend::new().force_stale();
    let r = req(
        4242,
        "selfdef-observe-only",
        60,
        AuthorityTier::Autonomous,
        PivotScope::Profile,
        "process died",
    );
    let receipt = b.pivot_profile(r).await.unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Stale(_)));
}

#[tokio::test]
async fn idempotent_pivot_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "t",
    );
    let r2 = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "t",
    );
    let h1 = b.pivot_profile(r1).await.unwrap().handle;
    let h2 = b.pivot_profile(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle_but_signals_one_way_at_kernel() {
    let b = InMemoryBackend::new();
    let r = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "t",
    );
    let receipt = b.pivot_profile(r).await.unwrap();
    let restore = b.restore_profile(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue_with_restart_flag() {
    let b = InMemoryBackend::with_original_profile("firefox");
    let r = req(
        4242,
        "selfdef-quarantine-strict",
        900,
        AuthorityTier::Responder,
        PivotScope::Profile,
        "responder-driven pivot",
    );
    b.pivot_profile(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 4242);
    assert_eq!(pending[0].target_profile, "selfdef-quarantine-strict");
    assert_eq!(pending[0].original_profile, "firefox");
    assert!(pending[0].requires_process_restart);
}

#[tokio::test]
async fn hat_scope_distinct_handle_from_profile_scope() {
    let b = InMemoryBackend::new();
    let prof = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Profile,
        "t",
    );
    let hat = req(
        4242,
        "selfdef-quarantine-strict",
        60,
        AuthorityTier::Operator,
        PivotScope::Hat,
        "t",
    );
    let h1 = b.pivot_profile(prof).await.unwrap().handle;
    let h2 = b.pivot_profile(hat).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn validate_profile_name_accepts_typical_shapes() {
    assert!(validate_profile_name("selfdef-quarantine-strict").is_some());
    assert!(validate_profile_name("selfdef-observe-only").is_some());
    assert!(validate_profile_name("firefox").is_some());
    assert!(validate_profile_name("/usr/sbin/sshd").is_some());
    assert!(validate_profile_name("unconfined").is_some());
    assert!(validate_profile_name("nested.profile.sub-hat_v2").is_some());
}

#[test]
fn validate_profile_name_rejects_malformed() {
    assert!(validate_profile_name("").is_none());
    assert!(validate_profile_name("name with space").is_none());
    assert!(validate_profile_name("name\nwith-newline").is_none());
    assert!(validate_profile_name("name;rm -rf /").is_none());
    assert!(validate_profile_name("name$VAR").is_none());
    assert!(validate_profile_name(&"x".repeat(257)).is_none());
}

#[test]
fn pending_profile_restore_serializes_to_json() {
    let p = PendingProfileRestore {
        handle: ApparmorProfilePivotHandle::Active("h-1".into()),
        pid: 4242,
        target_profile: "selfdef-quarantine-strict".into(),
        original_profile: "firefox".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "suspicious activity".into(),
        seconds_remaining: 600,
        scope: PivotScope::Profile,
        requires_process_restart: true,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("selfdef-quarantine-strict"));
    assert!(json.contains("firefox"));
    assert!(json.contains("\"requires_process_restart\":true"));
    assert!(json.contains("\"pid\":4242"));
}
