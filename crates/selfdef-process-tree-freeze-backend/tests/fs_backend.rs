//! SDD-072 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_process_tree_freeze_backend::{
    AuthorityTier, FreezeTreeRequest, FsBackend, ProcessTreeFreezeBackend, ProcessTreeHandle,
    TreeScope,
};
use tempfile::tempdir;

fn req(
    root_pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: TreeScope,
    reason: &str,
) -> FreezeTreeRequest {
    let idempotency_key = format!("{root_pid}:{reason}:{tier:?}:{scope:?}");
    FreezeTreeRequest {
        root_pid,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        include_self: true,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active_with_frozen_pid_count() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_tree_size(tmp.path(), 7).unwrap();
    let receipt = b
        .freeze_tree(req(
            4242,
            1500,
            AuthorityTier::Operator,
            TreeScope::Descendants,
            "fork-bomb",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ProcessTreeHandle::Active(_)));
    assert_eq!(receipt.frozen_pid_count, 7);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["root_pid"].as_i64().unwrap(), 4242);
    assert_eq!(arr[0]["frozen_pid_count"].as_u64().unwrap(), 7);
}

#[tokio::test]
async fn fs_backend_pid_one_refused() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .freeze_tree(req(
            1,
            60,
            AuthorityTier::Operator,
            TreeScope::Descendants,
            "test",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_process_tree_freeze_backend::ProcessTreeFreezeError::PidRefused { pid: 1, .. }
    ));
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_tree_size(tmp.path(), 12).unwrap();
    b.freeze_tree(req(
        444,
        900,
        AuthorityTier::Responder,
        TreeScope::StrictDescendants,
        "fork-bomb",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-thaws.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["root_pid"].as_i64().unwrap(), 444);
    assert_eq!(arr[0]["frozen_pid_count"].as_u64().unwrap(), 12);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.freeze_tree(req(
            1000,
            60,
            AuthorityTier::Operator,
            TreeScope::Descendants,
            "before",
        ))
        .await
        .unwrap();
        b.freeze_tree(req(
            2000,
            900,
            AuthorityTier::Responder,
            TreeScope::ChildrenOnly,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_thaws().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].root_pid, 2000);
}

#[tokio::test]
async fn fs_backend_thaw_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .freeze_tree(req(
            333,
            60,
            AuthorityTier::Operator,
            TreeScope::Descendants,
            "t",
        ))
        .await
        .unwrap();
    let r = b.thaw_tree(receipt.handle).await.unwrap();
    assert!(r.thawed);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.freeze_tree(req(
            1000 + i,
            60,
            AuthorityTier::Operator,
            TreeScope::Descendants,
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
    assert_eq!(entries, vec!["active.json", "pending-thaws.json"]);
}
