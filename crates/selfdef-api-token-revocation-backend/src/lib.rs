//! SDD-068 MS1 — API/web-token revocation backend trait + InMemoryBackend.
//!
//! Fourth enforcement primitive in the IPS quartet (SDD-065
//! network + SDD-066 process + SDD-067 shell-session + SDD-068
//! API-token = this crate). Same paired-enforcement-primitive
//! 5-MS structure as the prior three.
//!
//! BusEventBackend production adapter lands in MS1b under the
//! `bus-event-backend` feature flag; this crate ships the trait +
//! InMemoryBackend per the MS1-substrate decision recorded at
//! `wiki/decisions/01_drafts/in-memory-backend-as-ms1-substrate.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SDD-068 §4 — longer ceilings than SDD-067 because token
/// revocation is recoverable (operator issues new token via
/// console/cockpit), so locking-out concerns are reduced.
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
            AuthorityTier::Autonomous => Duration::from_secs(2 * 60),
            AuthorityTier::Responder => Duration::from_secs(60 * 60),
            AuthorityTier::Operator => Duration::from_secs(8 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(72 * 60 * 60),
        }
    }
}

/// Token-class taxonomy. `Other(String)` accommodates future
/// surfaces (operator-extensible) per SDD-068 open question #1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenClass {
    Api,
    Cockpit,
    Mcp,
    Other(String),
}

/// Scope of the revocation across token surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenClassMask {
    All,
    Specific(Vec<TokenClass>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRevokeRequest {
    pub principal: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub token_classes: TokenClassMask,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenRevocationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRevokeReceipt {
    pub handle: TokenRevocationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct TokenRestoreReceipt {
    pub restored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingTokenRestore {
    pub handle: TokenRevocationHandle,
    pub principal: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub token_classes: TokenClassMask,
}

#[derive(Debug, Error)]
pub enum TokenRevocationError {
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
pub trait ApiTokenRevocationBackend: Send + Sync {
    async fn revoke_tokens(
        &self,
        req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError>;
    async fn restore_tokens(
        &self,
        handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingTokenRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &TokenRevocationHandle) -> bool {
        false
    }
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    active: HashMap<String, TokenRevocationHandle>,
    pending: HashMap<String, PendingTokenRestore>,
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

fn validate(req: &TokenRevokeRequest) -> Result<(), TokenRevocationError> {
    if req.principal.trim().is_empty() {
        return Err(TokenRevocationError::InvalidRequest(
            "principal must be non-empty".into(),
        ));
    }
    if req.reason.trim().is_empty() {
        return Err(TokenRevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(TokenRevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl ApiTokenRevocationBackend for InMemoryBackend {
    async fn revoke_tokens(
        &self,
        req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_principal = req.principal.clone();
        let req_reason = req.reason.clone();
        let req_classes = req.token_classes.clone();
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| TokenRevocationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let TokenRevocationHandle::Active(s) = &handle;
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingTokenRestore {
                    handle: handle.clone(),
                    principal: req_principal,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    token_classes: req_classes,
                },
            );
        }
        let active_count = state.active.len();
        Ok(TokenRevokeReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_tokens(
        &self,
        handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError> {
        let TokenRevocationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(TokenRestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingTokenRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingTokenRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &TokenRevocationHandle) -> bool {
        let TokenRevocationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
