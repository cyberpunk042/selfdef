//! SDD-070 MS1 — network-namespace isolation backend trait + InMemoryBackend.
//!
//! Sixth IPS enforcement primitive — extends pentet (SDD-065..069)
//! → hexet at the kernel-containment axis. Pairs with SDD-066
//! (process-quarantine) and SDD-065 (block-ip) to offer operator
//! a graduated containment-choice menu.

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
            AuthorityTier::Operator => Duration::from_secs(2 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(12 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationScope {
    NetOnly,
    NetPidIpc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolatePidRequest {
    pub pid: i32,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: IsolationScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetnsIsolationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolatePidReceipt {
    pub handle: NetnsIsolationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct ReleaseReceipt {
    pub released: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingNetnsRelease {
    pub handle: NetnsIsolationHandle,
    pub pid: i32,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: IsolationScope,
}

#[derive(Debug, Error)]
pub enum NetnsIsolationError {
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
    #[error("pid {pid} already containerized — refusing isolation")]
    AlreadyContainerized { pid: i32 },
}

#[async_trait]
pub trait NetnsIsolationBackend: Send + Sync {
    async fn isolate_pid(
        &self,
        req: IsolatePidRequest,
    ) -> Result<IsolatePidReceipt, NetnsIsolationError>;
    async fn release_isolation(
        &self,
        handle: NetnsIsolationHandle,
    ) -> Result<ReleaseReceipt, NetnsIsolationError>;
    async fn pending_releases(&self) -> Vec<PendingNetnsRelease> {
        Vec::new()
    }
    async fn mark_release_decided(&self, _handle: &NetnsIsolationHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, NetnsIsolationHandle>,
    pending: HashMap<String, PendingNetnsRelease>,
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

fn validate(req: &IsolatePidRequest) -> Result<(), NetnsIsolationError> {
    if req.pid <= 0 {
        return Err(NetnsIsolationError::InvalidRequest(format!(
            "pid must be positive, got {}",
            req.pid
        )));
    }
    if req.reason.trim().is_empty() {
        return Err(NetnsIsolationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(NetnsIsolationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl NetnsIsolationBackend for InMemoryBackend {
    async fn isolate_pid(
        &self,
        req: IsolatePidRequest,
    ) -> Result<IsolatePidReceipt, NetnsIsolationError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_pid = req.pid;
        let req_reason = req.reason.clone();
        let req_scope = req.scope;
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| NetnsIsolationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let NetnsIsolationHandle::Active(s) = &handle;
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingNetnsRelease {
                    handle: handle.clone(),
                    pid: req_pid,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    scope: req_scope,
                },
            );
        }
        let active_count = state.active.len();
        Ok(IsolatePidReceipt {
            handle,
            active_count,
        })
    }

    async fn release_isolation(
        &self,
        handle: NetnsIsolationHandle,
    ) -> Result<ReleaseReceipt, NetnsIsolationError> {
        let NetnsIsolationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(ReleaseReceipt { released: removed })
    }

    async fn pending_releases(&self) -> Vec<PendingNetnsRelease> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingNetnsRelease> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_release_decided(&self, handle: &NetnsIsolationHandle) -> bool {
        let NetnsIsolationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
