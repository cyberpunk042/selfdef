//! SDD-067 MS5a — L1 contract test for the filesystem-backed
//! production adapter.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use selfdef_session_revocation_backend::{
    AuthorityTier, FsBackend, RevocationHandle, RevocationScope, RevokeRequest,
    SessionRevocationBackend,
};
use tempfile::tempdir;

fn req(
    user: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: RevocationScope,
    reason: &str,
) -> RevokeRequest {
    let idempotency_key = format!("{user}:{reason}:{tier:?}:{scope:?}");
    RevokeRequest {
        user: user.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .revoke_sessions(req(
            "alice",
            60 * 5,
            AuthorityTier::Operator,
            RevocationScope::Local,
            "suspected exfil",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, RevocationHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["user"].as_str().unwrap(), "alice");
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.revoke_sessions(req(
        "bob",
        900,
        AuthorityTier::Responder,
        RevocationScope::SourceIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
        "correlator",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["user"].as_str().unwrap(), "bob");
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.revoke_sessions(req(
            "alice",
            60,
            AuthorityTier::Operator,
            RevocationScope::Local,
            "before-restart",
        ))
        .await
        .unwrap();
        b.revoke_sessions(req(
            "bob",
            900,
            AuthorityTier::Responder,
            RevocationScope::Local,
            "before-restart",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].user, "bob");
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .revoke_sessions(req(
            "dan",
            60,
            AuthorityTier::Operator,
            RevocationScope::Local,
            "t",
        ))
        .await
        .unwrap();
    let restore = b.restore_sessions(receipt.handle).await.unwrap();
    assert!(restore.restored);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.revoke_sessions(req(
            &format!("u{i}"),
            60,
            AuthorityTier::Operator,
            RevocationScope::Local,
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
async fn fs_backend_idempotent_does_not_duplicate() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r1 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "t",
    );
    let r2 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        RevocationScope::Local,
        "t",
    );
    let h1 = b.revoke_sessions(r1).await.unwrap().handle;
    let h2 = b.revoke_sessions(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
}
