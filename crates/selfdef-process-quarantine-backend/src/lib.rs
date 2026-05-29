//! SDD-066 MS1 — process-quarantine backend trait + InMemoryBackend.
//!
//! The contract: a `ProcessQuarantineBackend` accepts a
//! `FreezeRequest`, validates it against the authority+TTL matrix
//! in SDD-066 §4, then either freezes the process (returning a
//! `FreezeReceipt` with an `Active` `QuarantineHandle`) or returns
//! a typed `QuarantineError`.
//!
//! Production adapters land in MS1b under feature gates:
//! `cgroup-backend` for the Cgroupv2FreezerBackend (CAP_SYS_ADMIN);
//! `signal-backend` for the SIGSTOP fallback. This crate ships
//! the trait + `InMemoryBackend` only (hermetic; used by
//! selfdef-responder unit tests + integration substrate).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SDD-066 §4 — authority tier caps the maximum freeze duration.
/// Shorter ceilings than SDD-065 because freezing suspends work.
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
            AuthorityTier::Responder => Duration::from_secs(15 * 60),
            AuthorityTier::Operator => Duration::from_secs(60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// SDD-066 §1 — what to freeze: just the pid, or the pid's child
/// subtree (subject to the cgroup-boundary constraint per the
/// MS1b adapters).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FreezeScope {
    Process,
    Tree,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeRequest {
    pub pid: i32,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: FreezeScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuarantineHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeReceipt {
    pub handle: QuarantineHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct ReleaseReceipt {
    pub released: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRelease {
    pub handle: QuarantineHandle,
    pub pid: i32,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: FreezeScope,
}

#[derive(Debug, Error)]
pub enum QuarantineError {
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
    #[error("pid {pid} not found (process exited?)")]
    PidNotFound { pid: i32 },
}

#[async_trait]
pub trait ProcessQuarantineBackend: Send + Sync {
    async fn freeze_process(&self, req: FreezeRequest) -> Result<FreezeReceipt, QuarantineError>;
    async fn release_process(
        &self,
        handle: QuarantineHandle,
    ) -> Result<ReleaseReceipt, QuarantineError>;
    async fn pending_releases(&self) -> Vec<PendingRelease> {
        Vec::new()
    }
    async fn mark_release_decided(&self, _handle: &QuarantineHandle) -> bool {
        false
    }
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    active: HashMap<String, QuarantineHandle>, // idempotency_key → handle
    pending: HashMap<String, PendingRelease>,  // handle_str → entry
    handle_pid: HashMap<String, i32>,          // handle_str → pid
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

fn validate(req: &FreezeRequest) -> Result<(), QuarantineError> {
    if req.reason.trim().is_empty() {
        return Err(QuarantineError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    if req.pid <= 0 {
        return Err(QuarantineError::InvalidRequest(format!(
            "pid must be positive, got {}",
            req.pid
        )));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(QuarantineError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl ProcessQuarantineBackend for InMemoryBackend {
    async fn freeze_process(&self, req: FreezeRequest) -> Result<FreezeReceipt, QuarantineError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_reason = req.reason.clone();
        let req_pid = req.pid;
        let req_scope = req.scope;
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| QuarantineHandle::Active(req.idempotency_key.clone()))
            .clone();
        let QuarantineHandle::Active(s) = &handle;
        state.handle_pid.insert(s.clone(), req_pid);
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingRelease {
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
        Ok(FreezeReceipt {
            handle,
            active_count,
        })
    }

    async fn release_process(
        &self,
        handle: QuarantineHandle,
    ) -> Result<ReleaseReceipt, QuarantineError> {
        let QuarantineHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        state.handle_pid.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(ReleaseReceipt { released: removed })
    }

    async fn pending_releases(&self) -> Vec<PendingRelease> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingRelease> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_release_decided(&self, handle: &QuarantineHandle) -> bool {
        let QuarantineHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
