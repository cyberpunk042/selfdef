//! SDD-076 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter. 11th application of the FsBackend pattern.

use std::time::Duration;

use selfdef_kernel_keyring_eviction_backend::{
    AuthorityTier, EvictKeyRequest, EvictionScope, FsBackend, KernelKeyringEvictionBackend,
    KernelKeyringHandle,
};
use tempfile::tempdir;

fn req(
    spec: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    scope: EvictionScope,
    reason: &str,
) -> EvictKeyRequest {
    let idempotency_key = format!("{spec}:{reason}:{tier:?}:{scope:?}");
    EvictKeyRequest {
        key_spec: spec.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        scope,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_active_with_keys_evicted() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_keys_evicted(tmp.path(), 1).unwrap();
    let receipt = b
        .evict_key(req(
            "user:krb5cc/uid=1000",
            900,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "TGT compromise",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["key_spec"].as_str().unwrap(), "user:krb5cc/uid=1000");
    assert_eq!(arr[0]["key_type"].as_str().unwrap(), "user");
    assert_eq!(arr[0]["keys_evicted"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn fs_backend_not_found_does_not_persist_to_active() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_keys_evicted(tmp.path(), 0).unwrap();
    let receipt = b
        .evict_key(req(
            "user:already-gone",
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "race",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::NotFound(_)));
    assert_eq!(receipt.keys_evicted, 0);
    assert_eq!(receipt.active_count, 0);
}

#[tokio::test]
async fn fs_backend_responder_populates_pending() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_keys_evicted(tmp.path(), 1).unwrap();
    b.evict_key(req(
        "logon:dm-crypt:luks-deadbeef",
        900,
        AuthorityTier::Responder,
        EvictionScope::Both,
        "luks-key-evict",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["key_type"].as_str().unwrap(), "logon");
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.evict_key(req(
            "user:before-1",
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "before",
        ))
        .await
        .unwrap();
        b.evict_key(req(
            "logon:before-2",
            900,
            AuthorityTier::Responder,
            EvictionScope::Both,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].key_type, "logon");
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .evict_key(req(
            "user:r",
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "t",
        ))
        .await
        .unwrap();
    let r = b.restore_key(receipt.handle).await.unwrap();
    assert!(r.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8 {
        b.evict_key(req(
            &format!("user:stress-{i}"),
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
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
async fn fs_backend_unparseable_spec_rejected() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .evict_key(req(
            "unknown_type:foo",
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_kernel_keyring_eviction_backend::KernelKeyringEvictionError::UnparseableKeySpec { .. }
    ));
}

#[tokio::test]
async fn fs_backend_hex_serial_persists() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .evict_key(req(
            "0xdeadbeef",
            60,
            AuthorityTier::Operator,
            EvictionScope::Invalidate,
            "by-serial",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, KernelKeyringHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.as_array().unwrap()[0]["key_type"].as_str().unwrap(),
        "serial"
    );
    assert_eq!(
        v.as_array().unwrap()[0]["key_spec"].as_str().unwrap(),
        "0xdeadbeef"
    );
}
