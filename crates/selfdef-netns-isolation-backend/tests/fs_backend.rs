//! SDD-070 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_netns_isolation_backend::{
    AuthorityTier, FsBackend, IsolatePidRequest, IsolationScope, NetnsIsolationBackend,
    NetnsIsolationHandle,
};
use tempfile::tempdir;

fn req(
    pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: IsolationScope,
    reason: &str,
) -> IsolatePidRequest {
    let idempotency_key = format!("{pid}:{reason}:{tier:?}:{scope:?}");
    IsolatePidRequest {
        pid,
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
        .isolate_pid(req(
            12345,
            900,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
            "exfil-suspect",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, NetnsIsolationHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 12345);
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.isolate_pid(req(
        444,
        900,
        AuthorityTier::Responder,
        IsolationScope::NetOnly,
        "correlator",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-releases.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 444);
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.isolate_pid(req(
            1000,
            60,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
            "before",
        ))
        .await
        .unwrap();
        b.isolate_pid(req(
            2000,
            900,
            AuthorityTier::Responder,
            IsolationScope::NetPidIpc,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_releases().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 2000);
}

#[tokio::test]
async fn fs_backend_release_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .isolate_pid(req(
            333,
            60,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
            "t",
        ))
        .await
        .unwrap();
    let r = b.release_isolation(receipt.handle).await.unwrap();
    assert!(r.released);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.isolate_pid(req(
            1000 + i,
            60,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
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
    assert_eq!(entries, vec!["active.json", "pending-releases.json"]);
}

#[tokio::test]
async fn fs_backend_validates_inputs() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .isolate_pid(req(
            0,
            60,
            AuthorityTier::Operator,
            IsolationScope::NetOnly,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_netns_isolation_backend::NetnsIsolationError::InvalidRequest(_)
    ));
}
