//! SDD-066 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter. Closes the IPS-dectet MS5a 10/10
//! (state-journal layer).

use std::time::Duration;

use selfdef_process_quarantine_backend::{
    AuthorityTier, FreezeRequest, FreezeScope, FsBackend, ProcessQuarantineBackend,
    QuarantineHandle,
};
use tempfile::tempdir;

fn req(
    pid: i32,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: FreezeScope,
    reason: &str,
) -> FreezeRequest {
    let idempotency_key = format!("{pid}:{reason}:{tier:?}:{scope:?}");
    FreezeRequest {
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
        .freeze_process(req(
            4242,
            900,
            AuthorityTier::Operator,
            FreezeScope::Process,
            "exfil-suspect",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, QuarantineHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 4242);
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.freeze_process(req(
        444,
        900,
        AuthorityTier::Responder,
        FreezeScope::Tree,
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
        b.freeze_process(req(
            1000,
            60,
            AuthorityTier::Operator,
            FreezeScope::Process,
            "before",
        ))
        .await
        .unwrap();
        b.freeze_process(req(
            2000,
            900,
            AuthorityTier::Responder,
            FreezeScope::Tree,
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
        .freeze_process(req(
            333,
            60,
            AuthorityTier::Operator,
            FreezeScope::Process,
            "t",
        ))
        .await
        .unwrap();
    let r = b.release_process(receipt.handle).await.unwrap();
    assert!(r.released);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_shrink_rewrite_truncates_and_survives_reopen() {
    // The durable write switched from fs::write to File::create + fsync.
    // File::create truncates, so a shorter rewrite (after a release) must leave
    // no stale tail and must reload correctly — a regression here would
    // resurrect a freed process as still-quarantined on the next boot.
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.freeze_process(req(
            10,
            60,
            AuthorityTier::Operator,
            FreezeScope::Process,
            "keep",
        ))
        .await
        .unwrap();
        let r = b
            .freeze_process(req(
                20,
                60,
                AuthorityTier::Operator,
                FreezeScope::Process,
                "drop",
            ))
            .await
            .unwrap();
        assert_eq!(b.active_count().await, 2);
        // Release one → active.json rewritten SHORTER over the longer file.
        b.release_process(r.handle).await.unwrap();
        assert_eq!(b.active_count().await, 1);
    }

    // Reopen: the persisted (shorter) journal must parse cleanly to exactly the
    // surviving entry — no stale tail, no resurrected pid.
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 1);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 10);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.freeze_process(req(
            1000 + i,
            60,
            AuthorityTier::Operator,
            FreezeScope::Process,
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
        .freeze_process(req(
            0,
            60,
            AuthorityTier::Operator,
            FreezeScope::Process,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_process_quarantine_backend::QuarantineError::InvalidRequest(_)
    ));
}
