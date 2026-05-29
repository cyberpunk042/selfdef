//! SDD-068 MS5a — L1 contract test for the filesystem-backed
//! production adapter. Verifies real on-disk JSON shape (the same
//! shape the 22nd-sibling textfile observer scrapes) + atomic
//! rename behaviour + survives backend reopen.

use std::time::Duration;

use selfdef_api_token_revocation_backend::{
    ApiTokenRevocationBackend, AuthorityTier, FsBackend, TokenClass, TokenClassMask,
    TokenRevocationHandle, TokenRevokeRequest,
};
use tempfile::tempdir;

fn req(
    principal: &str,
    dur_secs: u64,
    tier: AuthorityTier,
    classes: TokenClassMask,
    reason: &str,
) -> TokenRevokeRequest {
    let idempotency_key = format!("{principal}:{reason}:{tier:?}:{classes:?}");
    TokenRevokeRequest {
        principal: principal.into(),
        reason: reason.into(),
        duration: Duration::from_secs(dur_secs),
        authority: tier,
        token_classes: classes,
        idempotency_key,
    }
}

#[tokio::test]
async fn fs_backend_creates_state_dir_on_open() {
    let tmp = tempdir().unwrap();
    let state_dir = tmp.path().join("does/not/exist/yet");
    let b = FsBackend::open(&state_dir).expect("open must create the dir");
    assert!(state_dir.is_dir());
    assert_eq!(b.active_count().await, 0);
    assert_eq!(b.state_dir(), state_dir.as_path());
}

#[tokio::test]
async fn fs_backend_persists_active_to_active_json() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r = req(
        "alice",
        60 * 30,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "post-rotation",
    );
    let receipt = b.revoke_tokens(r).await.unwrap();
    assert!(matches!(receipt.handle, TokenRevocationHandle::Active(_)));
    assert_eq!(receipt.active_count, 1);
    // Verify the file shape the observer expects.
    let active_path = tmp.path().join("active.json");
    assert!(active_path.is_file());
    let bytes = std::fs::read(&active_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        parsed.is_array(),
        "active.json must be an ARRAY (observer scans with `jq length`)"
    );
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["principal"].as_str().unwrap(), "alice");
}

#[tokio::test]
async fn fs_backend_persists_responder_to_pending_restores_json() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r = req(
        "bob",
        900,
        AuthorityTier::Responder,
        TokenClassMask::Specific(vec![TokenClass::Api]),
        "correlator",
    );
    b.revoke_tokens(r).await.unwrap();
    let pending_path = tmp.path().join("pending-restores.json");
    let bytes = std::fs::read(&pending_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["principal"].as_str().unwrap(), "bob");
    assert_eq!(arr[0]["seconds_remaining"].as_u64().unwrap(), 900);
}

#[tokio::test]
async fn fs_backend_operator_does_not_populate_pending_restores() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r = req(
        "carol",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "manual",
    );
    b.revoke_tokens(r).await.unwrap();
    let pending_path = tmp.path().join("pending-restores.json");
    let bytes = std::fs::read(&pending_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn fs_backend_restore_removes_from_active_json() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r = req("dan", 60, AuthorityTier::Operator, TokenClassMask::All, "t");
    let receipt = b.revoke_tokens(r).await.unwrap();
    let restore = b.restore_tokens(receipt.handle).await.unwrap();
    assert!(restore.restored);
    assert_eq!(b.active_count().await, 0);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn fs_backend_survives_reopen_with_state_intact() {
    let tmp = tempdir().unwrap();
    {
        let b = FsBackend::open(tmp.path()).unwrap();
        b.revoke_tokens(req(
            "alice",
            60 * 30,
            AuthorityTier::Operator,
            TokenClassMask::All,
            "before-restart",
        ))
        .await
        .unwrap();
        b.revoke_tokens(req(
            "bob",
            900,
            AuthorityTier::Responder,
            TokenClassMask::All,
            "before-restart",
        ))
        .await
        .unwrap();
    } // Drop backend (simulate selfdefd restart).
    let b2 = FsBackend::open(tmp.path()).unwrap();
    assert_eq!(b2.active_count().await, 2);
    let pending = b2.pending_restores().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].principal, "bob");
}

#[tokio::test]
async fn fs_backend_validates_inputs_same_as_in_memory() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    // Empty principal.
    let err = b
        .revoke_tokens(req(
            "",
            60,
            AuthorityTier::Operator,
            TokenClassMask::All,
            "x",
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        selfdef_api_token_revocation_backend::TokenRevocationError::InvalidRequest(_)
    ));
}

#[tokio::test]
async fn fs_backend_atomic_write_leaves_no_tmpfiles() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    for i in 0..10 {
        b.revoke_tokens(req(
            &format!("user{i}"),
            60,
            AuthorityTier::Operator,
            TokenClassMask::All,
            "stress",
        ))
        .await
        .unwrap();
    }
    // After 10 atomic writes, only active.json + pending-restores.json
    // should exist — no leftover *.tmp.* files.
    let entries: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let mut sorted = entries.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["active.json", "pending-restores.json"]);
}

#[tokio::test]
async fn fs_backend_idempotent_revoke_does_not_duplicate_in_active_json() {
    let tmp = tempdir().unwrap();
    let b = FsBackend::open(tmp.path()).unwrap();
    let r1 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "t",
    );
    let r2 = req(
        "alice",
        60,
        AuthorityTier::Operator,
        TokenClassMask::All,
        "t",
    );
    let h1 = b.revoke_tokens(r1).await.unwrap().handle;
    let h2 = b.revoke_tokens(r2).await.unwrap().handle;
    assert_eq!(h1, h2);
    let bytes = std::fs::read(tmp.path().join("active.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}
