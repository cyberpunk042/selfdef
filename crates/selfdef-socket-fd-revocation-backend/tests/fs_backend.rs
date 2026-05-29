//! SDD-073 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_socket_fd_revocation_backend::{
    AuthorityTier, FsBackend, RevokeFdRequest, SocketFdHandle, SocketFdRevocationBackend,
    SocketProtocol,
};
use tempfile::tempdir;

fn req(
    pid: i32,
    fd: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    protocol: SocketProtocol,
    reason: &str,
    expected_inode: Option<u64>,
) -> RevokeFdRequest {
    let idempotency_key = format!("{pid}:{fd}:{reason}:{tier:?}:{protocol:?}");
    RevokeFdRequest {
        pid,
        fd,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        protocol,
        expected_inode,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .revoke_fd(req(
            4242,
            17,
            900,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "active C2 socket",
            None,
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, SocketFdHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 4242);
    assert_eq!(arr[0]["fd"].as_i64().unwrap(), 17);
    assert_eq!(arr[0]["protocol"].as_str().unwrap(), "Tcp");
}

#[tokio::test]
async fn fs_backend_inode_race_yields_stale_handle() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_current_inode(tmp.path(), 999).unwrap();
    let receipt = b
        .revoke_fd(req(
            800,
            5,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "race",
            Some(100),
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, SocketFdHandle::Stale(_)));
    // Stale handles MUST NOT be persisted to active.json.
    assert_eq!(receipt.active_count, 0);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap_or_default();
    if !bytes.is_empty() {
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 0);
    }
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.revoke_fd(req(
        444,
        12,
        900,
        AuthorityTier::Responder,
        SocketProtocol::Tcp,
        "correlator",
        None,
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 444);
    assert_eq!(arr[0]["fd"].as_i64().unwrap(), 12);
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.revoke_fd(req(
            1000,
            5,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "before-restart",
            None,
        ))
        .await
        .unwrap();
        b.revoke_fd(req(
            2000,
            7,
            900,
            AuthorityTier::Responder,
            SocketProtocol::Tcp,
            "before-restart",
            None,
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
        .revoke_fd(req(
            333,
            9,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "t",
            None,
        ))
        .await
        .unwrap();
    let restore = b.restore_fd(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.revoke_fd(req(
            1000 + i,
            5,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "stress",
            None,
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
    // Negative fd.
    let err = b
        .revoke_fd(req(
            100,
            -1,
            60,
            AuthorityTier::Operator,
            SocketProtocol::Tcp,
            "x",
            None,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_socket_fd_revocation_backend::SocketFdRevocationError::InvalidRequest(_)
    ));
}
