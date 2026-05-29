//! SDD-074 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_process_env_scrub_backend::{
    AuthorityTier, FsBackend, ProcessEnvScrubBackend, ProcessEnvScrubHandle, ScrubEnvRequest,
    ScrubSignal,
};
use tempfile::tempdir;

fn req(
    pid: i32,
    vars: &[&str],
    dur_secs: u64,
    tier: AuthorityTier,
    signal: ScrubSignal,
    reason: &str,
) -> ScrubEnvRequest {
    let var_strs: Vec<String> = vars.iter().map(|s| (*s).to_string()).collect();
    let idempotency_key = format!("{pid}:{}:{reason}:{tier:?}:{signal:?}", var_strs.join(","));
    ScrubEnvRequest {
        pid,
        vars: var_strs,
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        signal,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .scrub_env(req(
            4242,
            &["AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"],
            60 * 30,
            AuthorityTier::Operator,
            ScrubSignal::Sigusr2,
            "post-rotation",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ProcessEnvScrubHandle::Active(_)));
    assert_eq!(receipt.vars_scrubbed, 2);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be an ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 4242);
    assert_eq!(arr[0]["vars_scrubbed"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn fs_backend_no_match_does_not_populate_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_vars_matched(tmp.path(), 0).unwrap();
    let receipt = b
        .scrub_env(req(
            5555,
            &["X", "Y"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::None,
            "no-match",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ProcessEnvScrubHandle::NoMatch(_)));
    assert_eq!(receipt.vars_scrubbed, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_vars_matched(tmp.path(), 3).unwrap();
    b.scrub_env(req(
        555,
        &["A", "B", "C"],
        900,
        AuthorityTier::Responder,
        ScrubSignal::Sigusr2,
        "rotation",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), 555);
    assert_eq!(arr[0]["vars_scrubbed"].as_u64().unwrap(), 3);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.scrub_env(req(
            1000,
            &["A"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::Sigusr2,
            "before-restart",
        ))
        .await
        .unwrap();
        b.scrub_env(req(
            2000,
            &["B"],
            900,
            AuthorityTier::Responder,
            ScrubSignal::Sigusr2,
            "before-restart",
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
        .scrub_env(req(
            333,
            &["X"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::None,
            "t",
        ))
        .await
        .unwrap();
    let restore = b.restore_env(receipt.handle).await.unwrap();
    assert!(restore.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.scrub_env(req(
            1000 + i,
            &["X"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::None,
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
    // pid 1 sacrosanct.
    let err = b
        .scrub_env(req(
            1,
            &["X"],
            60,
            AuthorityTier::Operator,
            ScrubSignal::None,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_process_env_scrub_backend::ProcessEnvScrubError::PidRefused { pid: 1, .. }
    ));
}
