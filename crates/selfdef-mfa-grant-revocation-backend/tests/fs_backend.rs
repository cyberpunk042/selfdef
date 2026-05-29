//! SDD-069 MS5a — L1 contract test for the filesystem-backed
//! production adapter. Verifies real on-disk JSON shape (matches
//! the 23rd-sibling textfile observer's scrape) + atomic-rename +
//! survives reopen.

use std::time::Duration;

use selfdef_mfa_grant_revocation_backend::{
    AuthorityTier, FsBackend, MfaGrantRevocationBackend, MfaGrantRevocationHandle,
    MfaGrantRevokeRequest, MfaGrantScope, MfaGrantSurface,
};
use tempfile::tempdir;

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
async fn fs_backend_persists_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .revoke_mfa_grants(req(
            "alice",
            60 * 30,
            AuthorityTier::Operator,
            MfaGrantScope::All,
            "post-rotation",
        ))
        .await
        .unwrap();
    assert!(matches!(
        receipt.handle,
        MfaGrantRevocationHandle::Active(_)
    ));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v
        .as_array()
        .expect("active.json must be an ARRAY for the observer");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["principal"].as_str().unwrap(), "alice");
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.revoke_mfa_grants(req(
        "bob",
        900,
        AuthorityTier::Responder,
        MfaGrantScope::Specific(vec![MfaGrantSurface::Pam, MfaGrantSurface::Api]),
        "correlator",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["principal"].as_str().unwrap(), "bob");
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.revoke_mfa_grants(req(
            "alice",
            60 * 30,
            AuthorityTier::Operator,
            MfaGrantScope::All,
            "before-restart",
        ))
        .await
        .unwrap();
        b.revoke_mfa_grants(req(
            "bob",
            900,
            AuthorityTier::Responder,
            MfaGrantScope::All,
            "before-restart",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].principal, "bob");
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .revoke_mfa_grants(req(
            "dan",
            60,
            AuthorityTier::Operator,
            MfaGrantScope::All,
            "t",
        ))
        .await
        .unwrap();
    let restore = b.restore_mfa_grants(receipt.handle).await.unwrap();
    assert!(restore.restored);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.revoke_mfa_grants(req(
            &format!("u{i}"),
            60,
            AuthorityTier::Operator,
            MfaGrantScope::All,
            "stress",
        ))
        .await
        .unwrap();
    }
    let mut entries: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["active.json", "pending-restores.json"]);
}

#[tokio::test]
async fn fs_backend_validates_inputs() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .revoke_mfa_grants(req(
            "",
            60,
            AuthorityTier::Operator,
            MfaGrantScope::All,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_mfa_grant_revocation_backend::MfaGrantRevocationError::InvalidRequest(_)
    ));
}

#[tokio::test]
async fn fs_backend_idempotent_does_not_duplicate() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
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
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
}
