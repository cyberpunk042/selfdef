//! Destructive effector backend — unsafe forbidden (F-2026-101): a
//! future `unsafe` in a host-mutating applier must be compiler-rejected.
#![forbid(unsafe_code)]
//! SDD-069 MS1 — MFA-grant revocation backend trait + InMemoryBackend.
//!
//! Fifth IPS enforcement primitive — extends the quartet
//! (SDD-065/066/067/068) → pentet at the identity-axis. Pairs
//! with SDD-067 (shell-session) for incident-response gold:
//! kills sessions AND forces fresh MFA on next auth.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthorityTier {
    Autonomous,
    Responder,
    Operator,
    OperatorOverridden,
}

impl AuthorityTier {
    pub fn max_duration(&self) -> Duration {
        match self {
            AuthorityTier::Autonomous => Duration::from_secs(5 * 60),
            AuthorityTier::Responder => Duration::from_secs(30 * 60),
            AuthorityTier::Operator => Duration::from_secs(4 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MfaGrantSurface {
    Pam,
    Api,
    Cockpit,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MfaGrantScope {
    All,
    Specific(Vec<MfaGrantSurface>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaGrantRevokeRequest {
    pub principal: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub grant_scope: MfaGrantScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MfaGrantRevocationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaGrantRevokeReceipt {
    pub handle: MfaGrantRevocationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct MfaGrantRestoreReceipt {
    pub restored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingMfaGrantRestore {
    pub handle: MfaGrantRevocationHandle,
    pub principal: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub grant_scope: MfaGrantScope,
}

#[derive(Debug, Error)]
pub enum MfaGrantRevocationError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("authority {tier:?} max {max_secs}s exceeded by requested {requested_secs}s")]
    AuthorityInsufficient {
        tier: AuthorityTier,
        max_secs: u64,
        requested_secs: u64,
    },
    #[error("backend unreachable: {0}")]
    BackendUnreachable(String),
}

#[async_trait]
pub trait MfaGrantRevocationBackend: Send + Sync {
    async fn revoke_mfa_grants(
        &self,
        req: MfaGrantRevokeRequest,
    ) -> Result<MfaGrantRevokeReceipt, MfaGrantRevocationError>;
    async fn restore_mfa_grants(
        &self,
        handle: MfaGrantRevocationHandle,
    ) -> Result<MfaGrantRestoreReceipt, MfaGrantRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingMfaGrantRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &MfaGrantRevocationHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, MfaGrantRevocationHandle>,
    pending: HashMap<String, PendingMfaGrantRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(State::default()),
        }
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &MfaGrantRevokeRequest) -> Result<(), MfaGrantRevocationError> {
    if req.principal.trim().is_empty() {
        return Err(MfaGrantRevocationError::InvalidRequest(
            "principal must be non-empty".into(),
        ));
    }
    if req.reason.trim().is_empty() {
        return Err(MfaGrantRevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(MfaGrantRevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl MfaGrantRevocationBackend for InMemoryBackend {
    async fn revoke_mfa_grants(
        &self,
        req: MfaGrantRevokeRequest,
    ) -> Result<MfaGrantRevokeReceipt, MfaGrantRevocationError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_principal = req.principal.clone();
        let req_reason = req.reason.clone();
        let req_scope = req.grant_scope.clone();
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| MfaGrantRevocationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let MfaGrantRevocationHandle::Active(s) = &handle;
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingMfaGrantRestore {
                    handle: handle.clone(),
                    principal: req_principal,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    grant_scope: req_scope,
                },
            );
        }
        let active_count = state.active.len();
        Ok(MfaGrantRevokeReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_mfa_grants(
        &self,
        handle: MfaGrantRevocationHandle,
    ) -> Result<MfaGrantRestoreReceipt, MfaGrantRevocationError> {
        let MfaGrantRevocationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(MfaGrantRestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingMfaGrantRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMfaGrantRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &MfaGrantRevocationHandle) -> bool {
        let MfaGrantRevocationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-069 MS5a production adapter) ───────────────
//
// Same atomic-JSON pattern as SDD-068 FsBackend. Writes
// active.json + pending-restores.json under a state-dir
// (default /var/lib/selfdef/mfa-grant-revocations) which the
// 23rd-sibling textfile observer scrapes.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: MfaGrantRevocationHandle,
    principal: String,
    original_reason: String,
    original_authority: AuthorityTier,
    grant_scope: MfaGrantScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingMfaGrantRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, MfaGrantRevocationError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            MfaGrantRevocationError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
        })
    }

    fn load_active(path: &Path) -> HashMap<String, ActiveEntry> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<ActiveEntry> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|e| {
                let MfaGrantRevocationHandle::Active(k) = &e.handle;
                (k.clone(), e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingMfaGrantRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingMfaGrantRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let MfaGrantRevocationHandle::Active(k) = &p.handle;
                (k.clone(), p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), MfaGrantRevocationError> {
        let parent = target.parent().ok_or_else(|| {
            MfaGrantRevocationError::BackendUnreachable(format!(
                "target {} has no parent",
                target.display()
            ))
        })?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let tmp = parent.join(format!(
            "{}.tmp.{pid}.{nanos}",
            target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state")
        ));
        fs::write(&tmp, bytes).map_err(|e| {
            MfaGrantRevocationError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            MfaGrantRevocationError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), MfaGrantRevocationError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            MfaGrantRevocationError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingMfaGrantRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            MfaGrantRevocationError::BackendUnreachable(format!("serialize pending: {e}"))
        })?;
        Self::write_atomic(
            &self.state_dir.join("pending-restores.json"),
            &pending_bytes,
        )?;
        Ok(())
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}

#[async_trait]
impl MfaGrantRevocationBackend for FsBackend {
    async fn revoke_mfa_grants(
        &self,
        req: MfaGrantRevokeRequest,
    ) -> Result<MfaGrantRevokeReceipt, MfaGrantRevocationError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: MfaGrantRevocationHandle::Active(key.clone()),
                    principal: req.principal.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    grant_scope: req.grant_scope.clone(),
                })
                .handle
                .clone();
            if req.authority == AuthorityTier::Responder {
                let MfaGrantRevocationHandle::Active(k) = &handle;
                state.pending.insert(
                    k.clone(),
                    PendingMfaGrantRestore {
                        handle: handle.clone(),
                        principal: req.principal.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        grant_scope: req.grant_scope.clone(),
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(MfaGrantRevokeReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn restore_mfa_grants(
        &self,
        handle: MfaGrantRevocationHandle,
    ) -> Result<MfaGrantRestoreReceipt, MfaGrantRevocationError> {
        let (removed, snapshot) = {
            let MfaGrantRevocationHandle::Active(key) = &handle;
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(key);
            let removed = state.active.remove(key).is_some();
            (removed, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(MfaGrantRestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingMfaGrantRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMfaGrantRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &MfaGrantRevocationHandle) -> bool {
        let (removed, snapshot) = {
            let MfaGrantRevocationHandle::Active(key) = handle;
            let mut state = self.inner.lock().unwrap();
            let removed = state.pending.remove(key).is_some();
            (removed, state.clone())
        };
        if removed {
            let _ = self.persist(&snapshot);
        }
        removed
    }
}