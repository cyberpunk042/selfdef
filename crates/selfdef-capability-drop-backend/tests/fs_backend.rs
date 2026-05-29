//! SDD-075 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_capability_drop_backend::{
    AuthorityTier, CapScope, CapabilityDropBackend, CapabilityDropHandle, DropCapsRequest,
    FsBackend,
};
use tempfile::tempdir;

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
async fn fs_backend_persists_active_with_caps_dropped() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_caps_held(tmp.path(), 2).unwrap();
    let receipt = b
        .drop_caps(req(
            4242,
            &["CAP_NET_ADMIN", "CAP_SYS_PTRACE"],
            1500,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "C2-cap-loss",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, CapabilityDropHandle::Active(_)));
    assert_eq!(receipt.caps_dropped, 2);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 4242);
    assert_eq!(arr[0]["caps_dropped"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn fs_backend_pid_one_refused() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .drop_caps(req(
            1,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "test",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_capability_drop_backend::CapabilityDropError::PidRefused { pid: 1, .. }
    ));
}

#[tokio::test]
async fn fs_backend_redundant_does_not_persist_to_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_caps_held(tmp.path(), 0).unwrap();
    let receipt = b
        .drop_caps(req(
            5555,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "stale-awareness",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, CapabilityDropHandle::Redundant(_)));
    assert_eq!(receipt.caps_dropped, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_caps_held(tmp.path(), 3).unwrap();
    b.drop_caps(req(
        555,
        &["CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_BPF"],
        900,
        AuthorityTier::Responder,
        CapScope::AllSets,
        "rotation",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 555);
    assert_eq!(arr[0]["caps_dropped"].as_u64().unwrap(), 3);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.drop_caps(req(
            1000,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "before",
        ))
        .await
        .unwrap();
        b.drop_caps(req(
            2000,
            &["CAP_SYS_PTRACE"],
            900,
            AuthorityTier::Responder,
            CapScope::BoundingOnly,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 2000);
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .drop_caps(req(
            333,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "t",
        ))
        .await
        .unwrap();
    let r = b.restore_caps(receipt.handle).await.unwrap();
    assert!(r.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.drop_caps(req(
            1000 + i,
            &["CAP_NET_ADMIN"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
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
async fn fs_backend_unknown_cap_rejected() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .drop_caps(req(
            100,
            &["CAP_NET_ADMIN", "CAP_FROBNICATE"],
            60,
            AuthorityTier::Operator,
            CapScope::AllSets,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_capability_drop_backend::CapabilityDropError::UnknownCapability { .. }
    ));
}
