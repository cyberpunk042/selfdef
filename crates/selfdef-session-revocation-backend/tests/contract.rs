//! SDD-067 MS1 — L1 contract test. TDD-first: assertions for each
//! behaviour the spec locks, then lib.rs implementation just
//! enough to pass.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use selfdef_session_revocation_backend::{
    AuthorityTier, InMemoryBackend, PendingRestore, RevocationError, RevocationHandle,
    RevocationScope, RevokeRequest, SessionRevocationBackend,
};

fn req(
    user: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: RevocationScope,
    reason: &str,
) -> RevokeRequest {
    RevokeRequest {
        user: user.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key: format!("{user}:{reason}:{tier:?}:{scope:?}"),
    }
}

#[tokio::test]
async fn revoke_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "alice",
        1800,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "anomalous sudo",
    );
    let receipt = b.revoke_sessions(r).await.expect("revoke must succeed");
    assert!(matches!(receipt.handle, RevocationHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn excluded_users_are_never_revoked_self_lockout_guard() {
    // The ExcludedUser guard must actually fire: a protected principal (operator
    // / daemon user / break-glass admin) must NOT be revocable, so an attacker-
    // crafted event naming one of them can't lock the responder/operator out.
    let b =
        InMemoryBackend::new().with_excluded_users(["operator-fp".to_string(), "root".to_string()]);
    for protected in ["operator-fp", "root"] {
        let r = req(
            protected,
            600,
            AuthorityTier::Responder,
            RevocationScope::Local,
            "attacker-crafted finding naming a protected user",
        );
        let err = b
            .revoke_sessions(r)
            .await
            .expect_err("a protected user must NOT be revoked");
        assert!(
            matches!(err, RevocationError::ExcludedUser { user } if user == protected),
            "expected ExcludedUser for {protected}",
        );
    }
    // A non-excluded user still revokes — the guard doesn't over-refuse.
    let ok = req(
        "mallory",
        600,
        AuthorityTier::Responder,
        RevocationScope::Local,
        "real threat",
    );
    b.revoke_sessions(ok)
        .await
        .expect("non-excluded user must still revoke");
}

#[tokio::test]
async fn empty_user_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req("", 60, AuthorityTier::Operator, RevocationScope::Local, "x");
    let err = b
        .revoke_sessions(r)
        .await
        .expect_err("empty user must error");
    assert!(matches!(err, RevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "bob",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "",
    );
    let err = b
        .revoke_sessions(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, RevocationError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    // Autonomous max = 1 min per SDD-067 §4. Request 1h.
    let r = req(
        "carol",
        3600,
        AuthorityTier::Autonomous,
        RevocationScope::Local,
        "x",
    );
    let err = b
        .revoke_sessions(r)
        .await
        .expect_err("over-tier must error");
    assert!(matches!(err, RevocationError::AuthorityInsufficient { .. }));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_067_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(60)
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
        "dave",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "test",
    );
    let r2 = req(
        "dave",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "test",
    );
    let h1 = b.revoke_sessions(r1).await.unwrap().handle;
    let h2 = b.revoke_sessions(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn restore_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "eve",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "test",
    );
    let receipt = b.revoke_sessions(r).await.unwrap();
    b.restore_sessions(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_restore_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "frank",
        1800,
        AuthorityTier::Responder,
        RevocationScope::Local,
        "correlator",
    );
    b.revoke_sessions(r).await.unwrap();
    let pending = b.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].user, "frank");
    assert_eq!(pending[0].original_authority, AuthorityTier::Responder);
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "grace",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "manual",
    );
    b.revoke_sessions(r).await.unwrap();
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
            RevocationScope::Local,
            "test",
        );
        b.revoke_sessions(r).await.unwrap();
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
        "harry",
        600,
        AuthorityTier::Responder,
        RevocationScope::Local,
        "test",
    );
    let receipt = b.revoke_sessions(r).await.unwrap();
    assert_eq!(b.pending_restores().await.len(), 1);
    assert!(b.mark_restore_decided(&receipt.handle).await);
    assert!(b.pending_restores().await.is_empty());
    // Underlying revoke remains active until restore_sessions or TTL.
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn source_ip_scope_distinct_from_local_scope() {
    let b = InMemoryBackend::new();
    let local = req(
        "alice",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "test",
    );
    let from_ip = req(
        "alice",
        60,
        AuthorityTier::Operator,
        RevocationScope::SourceIp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        "test",
    );
    let h1 = b.revoke_sessions(local).await.unwrap().handle;
    let h2 = b.revoke_sessions(from_ip).await.unwrap().handle;
    assert_ne!(
        h1, h2,
        "Local vs SourceIp scopes must produce distinct handles"
    );
}

#[test]
fn pending_restore_serializes_to_json() {
    let p = PendingRestore {
        handle: RevocationHandle::Active("h-1".into()),
        user: "alice".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "anomaly".into(),
        seconds_remaining: 600,
        scope: RevocationScope::Local,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("alice"));
    assert!(json.contains("anomaly"));
    assert!(json.contains("600"));
}
