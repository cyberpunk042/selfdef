//! SDD-077 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter. 12th application of the FsBackend pattern.

use std::time::Duration;

use selfdef_apparmor_profile_pivot_backend::{
    ApparmorProfilePivotBackend, ApparmorProfilePivotHandle, AuthorityTier, FsBackend,
    PivotProfileRequest, PivotScope,
};
use tempfile::tempdir;

fn req(
    pid: i32,
    profile: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: PivotScope,
    reason: &str,
) -> PivotProfileRequest {
    let idempotency_key = format!("{pid}:{profile}:{tier:?}:{scope:?}:{reason}");
    PivotProfileRequest {
        pid,
        target_profile: profile.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active_with_original_profile() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_original_profile(tmp.path(), "firefox").unwrap();
    let receipt = b
        .pivot_profile(req(
            4242,
            "selfdef-quarantine-strict",
            900,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "suspicious activity",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Active(_)));
    assert_eq!(receipt.original_profile, "firefox");
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_u64().unwrap(), 4242);
    assert_eq!(
        arr[0]["target_profile"].as_str().unwrap(),
        "selfdef-quarantine-strict"
    );
    assert_eq!(arr[0]["original_profile"].as_str().unwrap(), "firefox");
}

#[tokio::test]
async fn fs_backend_responder_populates_pending_with_restart_flag() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_original_profile(tmp.path(), "nginx").unwrap();
    b.pivot_profile(req(
        4242,
        "selfdef-quarantine-strict",
        900,
        AuthorityTier::Responder,
        PivotScope::Profile,
        "responder-driven",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pid"].as_u64().unwrap(), 4242);
    assert_eq!(
        arr[0]["target_profile"].as_str().unwrap(),
        "selfdef-quarantine-strict"
    );
    assert_eq!(arr[0]["original_profile"].as_str().unwrap(), "nginx");
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
    assert!(arr[0]["requires_process_restart"].as_bool().unwrap());
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::with_original_profile(tmp.path(), "nginx").unwrap();
        b.pivot_profile(req(
            1001,
            "selfdef-quarantine-strict",
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "before",
        ))
        .await
        .unwrap();
        b.pivot_profile(req(
            1002,
            "selfdef-quarantine-strict",
            900,
            AuthorityTier::Responder,
            PivotScope::Profile,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pid, 1002);
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .pivot_profile(req(
            4242,
            "selfdef-quarantine-strict",
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "t",
        ))
        .await
        .unwrap();
    let r = b.restore_profile(receipt.handle).await.unwrap();
    assert!(r.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.pivot_profile(req(
            10_000 + i,
            "selfdef-quarantine-strict",
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
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
async fn fs_backend_invalid_profile_name_rejected() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .pivot_profile(req(
            4242,
            "name with space",
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_apparmor_profile_pivot_backend::ApparmorProfilePivotError::InvalidProfileName { .. }
    ));
}

#[tokio::test]
async fn fs_backend_pid_one_sacrosanct() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .pivot_profile(req(
            1,
            "selfdef-quarantine-strict",
            60,
            AuthorityTier::Operator,
            PivotScope::Profile,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_apparmor_profile_pivot_backend::ApparmorProfilePivotError::PidSacrosanct { pid: 1, .. }
    ));
}

#[tokio::test]
async fn fs_backend_operator_overridden_unconfined_persists() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_original_profile(tmp.path(), "selfdef-quarantine-strict").unwrap();
    let receipt = b
        .pivot_profile(req(
            4242,
            "unconfined",
            60,
            AuthorityTier::OperatorOverridden,
            PivotScope::Profile,
            "forensic-capture",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ApparmorProfilePivotHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.as_array().unwrap()[0]["target_profile"].as_str().unwrap(),
        "unconfined"
    );
}
