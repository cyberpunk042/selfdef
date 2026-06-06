//! SDD-078 MS5a — L1 contract test for the filesystem-backed
//! state-journal adapter. 13th application of the FsBackend pattern.

use std::time::Duration;

use selfdef_bpf_map_element_clear_backend::{
    AuthorityTier, BpfMapElementClearBackend, ClearHandle, ClearRequest, ClearScope, FsBackend,
};
use tempfile::tempdir;

fn req(
    spec: &str,
    scope: ClearScope,
    key_hex: Option<&str>,
    dur_secs: u64,
    tier: AuthorityTier,
    reason: &str,
) -> ClearRequest {
    let idempotency_key = format!("{spec}:{scope:?}:{key_hex:?}:{tier:?}:{reason}");
    ClearRequest {
        map_spec: spec.into(),
        scope,
        key_hex: key_hex.map(String::from),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_persists_element_clear() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_elements_cleared(tmp.path(), 1).unwrap();
    let receipt = b
        .clear(req(
            "/sys/fs/bpf/ip_allow_list",
            ClearScope::Element,
            Some("0a000001"),
            900,
            AuthorityTier::Operator,
            "attacker IP",
        ))
        .await
        .unwrap();
    assert!(matches!(receipt.handle, ClearHandle::Active(_)));
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("active.json must be ARRAY");
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["map_spec"].as_str().unwrap(),
        "/sys/fs/bpf/ip_allow_list"
    );
    assert_eq!(arr[0]["key_hex"].as_str().unwrap(), "0a000001");
    assert_eq!(arr[0]["elements_cleared"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn fs_backend_persists_all_scope() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_elements_cleared(tmp.path(), 42).unwrap();
    let receipt = b
        .clear(req(
            "/sys/fs/bpf/poisoned",
            ClearScope::All,
            None,
            60 * 30,
            AuthorityTier::Operator,
            "wipe poisoned map",
        ))
        .await
        .unwrap();
    assert_eq!(receipt.elements_cleared, 42);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.as_array().unwrap()[0]["scope"].as_str().unwrap(), "All");
    assert!(v.as_array().unwrap()[0]["key_hex"].is_null());
    assert_eq!(
        v.as_array().unwrap()[0]["elements_cleared"]
            .as_u64()
            .unwrap(),
        42
    );
}

#[tokio::test]
async fn fs_backend_responder_populates_pending_with_repop_flag() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::with_simulated_elements_cleared(tmp.path(), 1).unwrap();
    b.clear(req(
        "/sys/fs/bpf/ip_allow_list",
        ClearScope::Element,
        Some("0a000002"),
        600,
        AuthorityTier::Responder,
        "responder",
    ))
    .await
    .unwrap();
    let bytes = std::fs::read(tmp.path().join("pending-restores.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 600);
    assert!(
        arr[0]["requires_owning_program_repopulation"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn fs_backend_survives_reopen() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.clear(req(
            "/sys/fs/bpf/m1",
            ClearScope::Element,
            Some("00"),
            60,
            AuthorityTier::Operator,
            "before",
        ))
        .await
        .unwrap();
        b.clear(req(
            "/sys/fs/bpf/m2",
            ClearScope::Element,
            Some("01"),
            600,
            AuthorityTier::Responder,
            "before",
        ))
        .await
        .unwrap();
    }
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].map_spec, "/sys/fs/bpf/m2");
}

#[tokio::test]
async fn fs_backend_restore_removes() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let receipt = b
        .clear(req(
            "/sys/fs/bpf/r",
            ClearScope::Element,
            Some("00"),
            60,
            AuthorityTier::Operator,
            "t",
        ))
        .await
        .unwrap();
    let r = b.restore(receipt.handle).await.unwrap();
    assert!(r.cleared);
    assert_eq!(b.active_count().await, 0);
}

#[tokio::test]
async fn fs_backend_atomic_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..8u32 {
        b.clear(req(
            &format!("/sys/fs/bpf/stress-{i}"),
            ClearScope::Element,
            Some(&format!("{i:08x}")),
            60,
            AuthorityTier::Operator,
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
        .clear(req(
            "no-prefix",
            ClearScope::Element,
            Some("00"),
            60,
            AuthorityTier::Operator,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_bpf_map_element_clear_backend::BpfMapElementClearError::UnparseableMapSpec { .. }
    ));
}

#[tokio::test]
async fn fs_backend_all_scope_requires_operator() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let err = b
        .clear(req(
            "/sys/fs/bpf/x",
            ClearScope::All,
            None,
            60,
            AuthorityTier::Responder,
            "low-tier wipe",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_bpf_map_element_clear_backend::BpfMapElementClearError::AllScopeRequiresOperator { .. }
    ));
}
