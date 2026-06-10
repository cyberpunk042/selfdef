//! SDD-071 MS1 — L1 contract test. TDD-first.

use std::time::Duration;

use selfdef_mount_binding_unbind_backend::{
    AuthorityTier, InMemoryBackend, MountBindingHandle, MountBindingUnbindBackend,
    MountBindingUnbindError, PendingMountRebind, UnbindMountRequest, UnbindScope,
};

fn req(
    mount_point: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: UnbindScope,
    reason: &str,
    lazy: bool,
) -> UnbindMountRequest {
    let idempotency_key = format!("{mount_point}:{reason}:{tier:?}:{scope:?}");
    UnbindMountRequest {
        mount_point: mount_point.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        lazy,
        idempotency_key,
    }
}

#[tokio::test]
async fn unbind_returns_receipt_with_active_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        1500,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "container-escape: host /etc bind-leaked",
        true,
    );
    let receipt = b.unbind_mount(r).await.expect("unbind must succeed");
    assert!(matches!(receipt.handle, MountBindingHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
}

#[tokio::test]
async fn empty_mount_point_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "x",
        true,
    );
    let err = b
        .unbind_mount(r)
        .await
        .expect_err("empty mount-point must error");
    assert!(matches!(err, MountBindingUnbindError::InvalidRequest(_)));
}

#[tokio::test]
async fn relative_mount_point_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "x",
        true,
    );
    let err = b
        .unbind_mount(r)
        .await
        .expect_err("relative path must error");
    assert!(matches!(err, MountBindingUnbindError::InvalidRequest(_)));
}

#[tokio::test]
async fn traversal_mount_point_is_rejected() {
    // umount2() VFS-resolves the path: a ".." component walks the unbind to a
    // different mount than named (e.g. `/mnt/data/../../proc` -> `/proc`). A
    // kernel-canonical mount point never contains "..", so every traversal
    // form must be rejected before this destructive op runs.
    let b = InMemoryBackend::new();
    for mp in [
        "/mnt/data/../../proc",
        "/mnt/../proc",
        "/..",
        "/a/b/../../../sys",
    ] {
        let r = req(
            mp,
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "traversal probe",
            true,
        );
        let err = b
            .unbind_mount(r)
            .await
            .expect_err("traversal mount-point must error");
        assert!(
            matches!(err, MountBindingUnbindError::InvalidRequest(_)),
            "{mp:?} should be InvalidRequest"
        );
    }
    // A legitimate deep absolute path with no traversal still works.
    let ok = b
        .unbind_mount(req(
            "/mnt/data/bind/leak",
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "legit",
            true,
        ))
        .await;
    assert!(ok.is_ok(), "clean absolute path must still be accepted");
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "",
        true,
    );
    let err = b
        .unbind_mount(r)
        .await
        .expect_err("empty reason must error");
    assert!(matches!(err, MountBindingUnbindError::InvalidRequest(_)));
}

#[tokio::test]
async fn duration_exceeding_tier_max_is_rejected() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        3600,
        AuthorityTier::Autonomous,
        UnbindScope::Bind,
        "x",
        true,
    );
    let err = b.unbind_mount(r).await.expect_err("over-tier must error");
    assert!(matches!(
        err,
        MountBindingUnbindError::AuthorityInsufficient { .. }
    ));
}

#[tokio::test]
async fn tier_max_durations_match_sdd_071_section_4() {
    assert_eq!(
        AuthorityTier::Autonomous.max_duration(),
        Duration::from_secs(5 * 60)
    );
    assert_eq!(
        AuthorityTier::Responder.max_duration(),
        Duration::from_secs(20 * 60)
    );
    assert_eq!(
        AuthorityTier::Operator.max_duration(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        AuthorityTier::OperatorOverridden.max_duration(),
        Duration::from_secs(6 * 60 * 60)
    );
}

#[tokio::test]
async fn idempotent_unbind_returns_same_handle() {
    let b = InMemoryBackend::new();
    let r1 = req(
        "/mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "t",
        true,
    );
    let r2 = req(
        "/mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "t",
        true,
    );
    let h1 = b.unbind_mount(r1).await.unwrap().handle;
    let h2 = b.unbind_mount(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    assert_eq!(b.active_count().await, 1);
}

#[tokio::test]
async fn rebind_clears_handle() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "t",
        true,
    );
    let receipt = b.unbind_mount(r).await.unwrap();
    b.rebind_mount(receipt.handle).await.unwrap();
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn responder_tier_enters_pending_rebind_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        900,
        AuthorityTier::Responder,
        UnbindScope::Bind,
        "correlator",
        true,
    );
    b.unbind_mount(r).await.unwrap();
    let pending = b.pending_rebinds().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].mount_point, "/mnt/leak");
}

#[tokio::test]
async fn operator_tier_does_not_enter_pending_queue() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/leak",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "manual",
        true,
    );
    b.unbind_mount(r).await.unwrap();
    assert!(b.pending_rebinds().await.is_empty());
}

#[tokio::test]
async fn scoped_bind_vs_overlay_distinct_handles() {
    let b = InMemoryBackend::new();
    let bind = req(
        "/mnt/x",
        60,
        AuthorityTier::Operator,
        UnbindScope::Bind,
        "t",
        true,
    );
    let overlay = req(
        "/mnt/x",
        60,
        AuthorityTier::Operator,
        UnbindScope::Overlay,
        "t",
        true,
    );
    let h1 = b.unbind_mount(bind).await.unwrap().handle;
    let h2 = b.unbind_mount(overlay).await.unwrap().handle;
    assert_ne!(h1, h2);
}

#[tokio::test]
async fn all_matching_requires_operator_overridden_tier() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/x",
        60,
        AuthorityTier::Operator,
        UnbindScope::AllMatching("/proc/*".into()),
        "broad sweep",
        true,
    );
    let err = b
        .unbind_mount(r)
        .await
        .expect_err("AllMatching with operator tier must error");
    assert!(matches!(
        err,
        MountBindingUnbindError::ScopeRequiresOverride { .. }
    ));
}

#[tokio::test]
async fn all_matching_permitted_at_operator_overridden_tier() {
    let b = InMemoryBackend::new();
    let r = req(
        "/mnt/x",
        60,
        AuthorityTier::OperatorOverridden,
        UnbindScope::AllMatching("/proc/*".into()),
        "broad sweep",
        true,
    );
    let receipt = b
        .unbind_mount(r)
        .await
        .expect("override tier accepts AllMatching");
    assert!(matches!(receipt.handle, MountBindingHandle::Active(_)));
}

#[test]
fn pending_mount_rebind_serializes_to_json() {
    let p = PendingMountRebind {
        handle: MountBindingHandle::Active("h-1".into()),
        mount_point: "/mnt/leak".into(),
        original_authority: AuthorityTier::Responder,
        original_reason: "container-escape".into(),
        seconds_remaining: 600,
        scope: UnbindScope::Bind,
    };
    let json = serde_json::to_string(&p).expect("must serialize");
    assert!(json.contains("/mnt/leak"));
    assert!(json.contains("container-escape"));
    assert!(json.contains("600"));
}
