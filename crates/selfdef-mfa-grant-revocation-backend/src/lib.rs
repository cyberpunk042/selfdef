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
