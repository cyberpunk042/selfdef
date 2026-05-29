//! SDD-071 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter.

use std::time::Duration;

use selfdef_mount_binding_unbind_backend::{
    AuthorityTier, FsBackend, MountBindingHandle, MountBindingUnbindBackend, UnbindMountRequest,
    UnbindScope,
};
use tempfile::tempdir;

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
async fn fs_backend_persists_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .unbind_mount(req(
            "/mnt/leak",
            1500,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "container-escape",
            true,
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, MountBindingHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["mount_point"].as_str().unwrap(), "/mnt/leak");
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    b.unbind_mount(req(
        "/mnt/x",
        900,
        AuthorityTier::Responder,
        UnbindScope::Bind,
        "correlator",
        true,
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-rebinds.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["mount_point"].as_str().unwrap(), "/mnt/x");
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.unbind_mount(req(
            "/mnt/a",
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "before",
            true,
        ))
        .await
        .unwrap();
        b.unbind_mount(req(
            "/mnt/b",
            900,
            AuthorityTier::Responder,
            UnbindScope::Overlay,
            "before",
            true,
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_rebinds().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].mount_point, "/mnt/b");
}

#[tokio::test]
async fn fs_backend_rebind_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .unbind_mount(req(
            "/mnt/y",
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "t",
            true,
        ))
        .await
        .unwrap();
    let r = b.rebind_mount(receipt.handle).await.unwrap();
    assert!(r.rebound);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.unbind_mount(req(
            &format!("/mnt/x{i}"),
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "stress",
            true,
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
    assert_eq!(entries, vec!["active.json", "pending-rebinds.json"]);
}

#[tokio::test]
async fn fs_backend_validates_inputs() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .unbind_mount(req(
            "relative/path",
            60,
            AuthorityTier::Operator,
            UnbindScope::Bind,
            "x",
            true,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_mount_binding_unbind_backend::MountBindingUnbindError::InvalidRequest(_)
    ));
}
