//! SDD-067 MS1 — session-revocation backend trait + InMemoryBackend.
//!
//! Third enforcement primitive in the SDD-065/066/067 IPS trio.
//! Same paired-enforcement-primitive 5-MS structure as the prior
//! two; see info-hub
//! `wiki/patterns/01_drafts/paired-enforcement-primitive-five-milestone-architecture.md`.
//!
//! Production adapter (LoginctlBackend) lands in MS1b under the
//! `loginctl-backend` feature flag; this crate ships the trait +
//! InMemoryBackend per the MS1-substrate decision recorded at
//! `wiki/decisions/01_drafts/in-memory-backend-as-ms1-substrate.md`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SDD-067 §4 — shorter ceilings than SDD-065/066 because
/// session-revocation directly affects the principal's ability
/// to work; long windows risk locking operator out.
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
            AuthorityTier::Autonomous => Duration::from_secs(60),
            AuthorityTier::Responder => Duration::from_secs(30 * 60),
            AuthorityTier::Operator => Duration::from_secs(4 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// Scope of the revocation — all of user's local sessions, or
/// only sessions originating from a specific source IP (useful
/// when correlator pins the attack to one IP and the user has
/// legitimate sessions from elsewhere).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationScope {
    Local,
    SourceIp(IpAddr),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub user: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: RevocationScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeReceipt {
    pub handle: RevocationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    pub restored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRestore {
    pub handle: RevocationHandle,
    pub user: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: RevocationScope,
}

#[derive(Debug, Error)]
pub enum RevocationError {
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
    #[error("user {user} is on the exclusion list — cannot revoke")]
    ExcludedUser { user: String },
}

#[async_trait]
pub trait SessionRevocationBackend: Send + Sync {
    async fn revoke_sessions(&self, req: RevokeRequest) -> Result<RevokeReceipt, RevocationError>;
    async fn restore_sessions(
        &self,
        handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError>;
    async fn pending_restores(&self) -> Vec<PendingRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &RevocationHandle) -> bool {
        false
    }
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    active: HashMap<String, RevocationHandle>,
    pending: HashMap<String, PendingRestore>,
    handle_user: HashMap<String, String>,
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

fn validate(req: &RevokeRequest) -> Result<(), RevocationError> {
    if req.user.trim().is_empty() {
        return Err(RevocationError::InvalidRequest(
            "user must be non-empty".into(),
        ));
    }
    if req.reason.trim().is_empty() {
        return Err(RevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(RevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl SessionRevocationBackend for InMemoryBackend {
    async fn revoke_sessions(&self, req: RevokeRequest) -> Result<RevokeReceipt, RevocationError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_user = req.user.clone();
        let req_reason = req.reason.clone();
        let req_scope = req.scope;
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| RevocationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let RevocationHandle::Active(s) = &handle;
        state.handle_user.insert(s.clone(), req_user.clone());
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingRestore {
                    handle: handle.clone(),
                    user: req_user,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    scope: req_scope,
                },
            );
        }
        let active_count = state.active.len();
        Ok(RevokeReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_sessions(
        &self,
        handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError> {
        let RevocationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        state.handle_user.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(RestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &RevocationHandle) -> bool {
        let RevocationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
