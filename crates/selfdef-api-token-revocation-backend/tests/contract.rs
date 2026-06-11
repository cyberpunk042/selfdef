//! SDD-068 MS1 — L1 contract test. TDD-first.
//!
//! Locks the SDD-068 §3 trait surface + InMemoryBackend behavior:
//! AuthorityTier matrix, scoped TokenClassMask, idempotency,
//! pending-restore queue, JSON serialization for cockpit consumer.

use std::time::Duration;

use selfdef_api_token_revocation_backend::{
    ApiTokenRevocationBackend, AuthorityTier, InMemoryBackend, PendingTokenRestore, TokenClass,
    TokenClassMask, TokenRevocationError, TokenRevocationHandle, TokenRevokeRequest,
};

fn req(
    principal: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    classes: TokenClassMask,
    reason: &str,
) -> TokenRevokeRequest {
    let idempotency_key = format!("{principal}:{reason}:{tier:?}:{classes:?}");
    TokenRevokeRequest {
        principal: principal.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        token_classes: classes,
        idempotency_key,
    }
}

#[tokio::test]
async fn revoke_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        3600,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "exfiltrated token",
    );
    let receipt = b.revoke_tokens(r).await.expect("revoke must succeed");
    assert!(matches!(receipt.handle, TokenRevocationHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn excluded_principals_are_never_revoked_self_lockout_guard() {
    // F-2026-117 sibling: a protected principal (operator / daemon user) must
    // NOT have its API tokens revoked, so an attacker-crafted event naming the
    // operator can't strip their API access mid-incident.
    let b = InMemoryBackend::new().with_excluded_principals(["operator-fp".to_string()]);
    let blocked = req(
        "operator-fp",
        3600,
        AuthorityTier::Responder,
        TokenClassMask::All,
        "crafted finding naming the operator",
    );
    let err = b
        .revoke_tokens(blocked)
        .await
        .expect_err("a protected principal must NOT be revoked");
    assert!(matches!(
        err,
        TokenRevocationError::ExcludedPrincipal { principal } if principal == "operator-fp"
    ));
    // A non-excluded principal still revokes.
    let ok = req(
        "mallory",
        3600,
        AuthorityTier::Responder,
        TokenClassMask::All,
        "real threat",
    );
    b.revoke_tokens(ok).await.expect("non-excluded principal must still revoke");
}

#[tokio::test]
async fn empty_principal_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req("", 60, AuthorityTier::Operator, TokenClassMask::All, "x");
    let err = b
        .revoke_tokens(r)
        .await
        .expect_err("empty principal must error");
    assert!(matches!(err, TokenRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "",
    );
    let err = b
        .revoke_tokens(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, TokenRevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    // Autonomous max = 2 min per SDD-068 §4. Request 1h.
    let r = req(
        "alice",
        3600,
        AuthorityTier::Autonomous,
        TokenClassMask::All,
        "x",
    );
    let err = b.revoke_tokens(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        TokenRevocationError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_068_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(2 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(8 * 60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(72 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_revoke_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "test",
    );
    let r2 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "test",
    );
    let h1 = b.revoke_tokens(r1).await.unwrap().handle;
    let h2 = b.revoke_tokens(r2).await.unwrap().handle;
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
        TokenClassMask::All,
        "test",
    );
    let receipt = b.revoke_tokens(r).await.unwrap();
    b.restore_tokens(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        1800,
        AuthorityTier::Responder,
        TokenClassMask::All,
        "correlator",
    );
    b.revoke_tokens(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].principal, "alice");
    assert_eq!(pending[0].original_authority, AuthorityTier::Responder);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "manual",
    );
    b.revoke_tokens(r).await.unwrap();
    assert!(b.pending_restores().await.is_empty());
}

#[tokio::test]
async fn pending_restores_sorted_by_seconds_remaining_ascending() {
    let b = InMemoryBackend::new();
    for (u, secs) in [("u1", 1800u64), ("u2", 600), ("u3", 1200)] {
        let r = req(
            u,
            secs,
            AuthorityTier::Responder,
            TokenClassMask::All,
            "test",
        );
        b.revoke_tokens(r).await.unwrap();
    }
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 3);
    assert_eq!(pending[0].seconds_remaining, 600);
    assert_eq!(pending[1].seconds_remaining, 1200);
    assert_eq!(pending[2].seconds_remaining, 1800);
}

#[tokio::test]
async fn mark_restore_decided_removes_from_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        600,
        AuthorityTier::Responder,
        TokenClassMask::All,
        "test",
    );
    let receipt = b.revoke_tokens(r).await.unwrap();
    assert_eq!(b.pending_restores().await.len(), 1);
    assert!(b.mark_restore_decided(&receipt.handle).await);
    assert!(b.pending_restores().await.is_empty());
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn scoped_token_classes_produce_distinct_handles() {
    let b = InMemoryBackend::new();
    let all = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "test",
    );
    let api_only = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::Specific(vec![TokenClass::Api]),
        "test",
    );
    let h1 = b.revoke_tokens(all).await.unwrap().handle;
    let h2 = b.revoke_tokens(api_only).await.unwrap().handle;
    assert_ne!(h1, h2, "All vs Specific(Api) must produce distinct handles");
}

#[tokio::test]
async fn specific_classes_recorded_on_pending_entry() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        300,
        AuthorityTier::Responder,
        TokenClassMask::Specific(vec![TokenClass::Cockpit, TokenClass::Mcp]),
        "test",
    );
    b.revoke_tokens(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    match &pending[0].token_classes {
        TokenClassMask::Specific(v) => {
            assert_eq!(v.len(), 2);
            assert!(v.contains(&TokenClass::Cockpit));
            assert!(v.contains(&TokenClass::Mcp));
        }
        _ => panic!("expected Specific variant"),
    }
}

#[test]
fn pending_token_restore_serializes_to_json() {
    let p = PendingTokenRestore {
        handle: TokenRevocationHandle::Active("h-1".into()),
        principal: "alice".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "exfiltrated".into(),
        seconds_remaining: 600,
        token_classes: TokenClassMask::All,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("alice"));
    assert!(json.contains("exfiltrated"));
    assert!(json.contains("600"));
}
