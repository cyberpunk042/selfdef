//! SDD-069 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_mfa_grant_revocation_backend::{
    AuthorityTier, InMemoryBackend, MfaGrantRevocationBackend, MfaGrantRevocationError,
    MfaGrantRevocationHandle, MfaGrantRevokeRequest, MfaGrantScope, MfaGrantSurface,
    PendingMfaGrantRestore,
};

fn req(
    principal: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: MfaGrantScope,
    reason: &str,
) -> MfaGrantRevokeRequest {
    let idempotency_key = format!("{principal}:{reason}:{tier:?}:{scope:?}");
    MfaGrantRevokeRequest {
        principal: principal.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        grant_scope: scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn revoke_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        1800,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "suspected MFA token theft",
    );
    let receipt = b.revoke_mfa_grants(r).await.expect("revoke must succeed");
    assert!(matches!(
        receipt.handle,
        MfaGrantRevocationHandle::Active(_)
    ));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn empty_principal_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req("", 60, AuthorityTier::Operator, MfaGrantScope::All, "x");
    let err = b
        .revoke_mfa_grants(r)
        .await
        .expect_err("empty principal must error");
    assert!(matches!(err, MfaGrantRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req("alice", 60, AuthorityTier::Operator, MfaGrantScope::All, "");
    let err = b
        .revoke_mfa_grants(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, MfaGrantRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        3600,
        AuthorityTier::Autonomous,
        MfaGrantScope::All,
        "x",
    );
    let err = b
        .revoke_mfa_grants(r)
        .await
        .expect_err("over-tier must error");
    assert!(matches!(
        err,
        MfaGrantRevocationError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_069_section_4() {
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
async fn idempotent_revoke_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "t",
    );
    let r2 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "t",
    );
    let h1 = b.revoke_mfa_grants(r1).await.unwrap().handle;
    let h2 = b.revoke_mfa_grants(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "t",
    );
    let receipt = b.revoke_mfa_grants(r).await.unwrap();
    b.restore_mfa_grants(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        900,
        AuthorityTier::Responder,
        MfaGrantScope::All,
        "correlator",
    );
    b.revoke_mfa_grants(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].principal, "alice");
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "manual",
    );
    b.revoke_mfa_grants(r).await.unwrap();
    assert!(b.pending_restores().await.is_empty());
}

#[tokio::test]
async fn pending_restores_sorted_by_seconds_remaining_ascending() {
    let b = InMemoryBackend::new();
    for (u, secs) in [("u1", 1800u64), ("u2", 600), ("u3", 1200)] {
        let r = req(u, secs, AuthorityTier::Responder, MfaGrantScope::All, "t");
        b.revoke_mfa_grants(r).await.unwrap();
    }
    let pending = b.pending_restores().await;
    assert_eq!(pending[0].seconds_remaining, 600);
    assert_eq!(pending[1].seconds_remaining, 1200);
    assert_eq!(pending[2].seconds_remaining, 1800);
}

#[tokio::test]
async fn scoped_surfaces_distinct_handles() {
    let b = InMemoryBackend::new();
    let all = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::All,
        "t",
    );
    let pam_only = req(
        "alice",
        60,
        AuthorityTier::Operator,
        MfaGrantScope::Specific(vec![MfaGrantSurface::Pam]),
        "t",
    );
    let h1 = b.revoke_mfa_grants(all).await.unwrap().handle;
    let h2 = b.revoke_mfa_grants(pam_only).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[test]
fn pending_mfa_grant_restore_serializes_to_json() {
    let p = PendingMfaGrantRestore {
        handle: MfaGrantRevocationHandle::Active("h-1".into()),
        principal: "alice".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "suspected".into(),
        seconds_remaining: 600,
        grant_scope: MfaGrantScope::All,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("alice"));
    assert!(json.contains("600"));
}
