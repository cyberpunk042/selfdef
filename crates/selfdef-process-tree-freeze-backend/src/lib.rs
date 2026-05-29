//! SDD-072 MS1 — process-tree freeze backend trait + InMemoryBackend.
//!
//! Eighth IPS enforcement primitive — extends septet (SDD-065..071)
//! → octet at the process-graph containment axis. Pairs with
//! SDD-066 (single-pid freeze) + SDD-070 (netns-isolation) at the
//! kernel-containment family.

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
            AuthorityTier::OperatorOverridden => Duration::from_secs(8 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TreeScope {
    /// SIGSTOP root + every descendant once.
    Descendants,
    /// Strict mode: re-walk + re-stop every 100ms until the tree
    /// stabilises (no new pids for 2 consecutive sweeps).
    StrictDescendants,
    /// Children only (one level down).
    ChildrenOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeTreeRequest {
    pub root_pid: i32,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: TreeScope,
    pub include_self: bool,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessTreeHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeTreeReceipt {
    pub handle: ProcessTreeHandle,
    pub active_count: usize,
    /// Number of pids actually stopped (root + descendants).
    pub frozen_pid_count: usize,
}

#[derive(Clone, Debug)]
pub struct ThawReceipt {
    pub thawed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingTreeThaw {
    pub handle: ProcessTreeHandle,
    pub root_pid: i32,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: TreeScope,
    pub frozen_pid_count: usize,
}

#[derive(Debug, Error)]
pub enum ProcessTreeFreezeError {
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
    /// PID 1 / kernel-thread refusal — never freeze init or ksoftirqd-class.
    #[error("root pid {pid} refused: {reason}")]
    PidRefused { pid: i32, reason: String },
}

#[async_trait]
pub trait ProcessTreeFreezeBackend: Send + Sync {
    async fn freeze_tree(
        &self,
        req: FreezeTreeRequest,
    ) -> Result<FreezeTreeReceipt, ProcessTreeFreezeError>;
    async fn thaw_tree(
        &self,
        handle: ProcessTreeHandle,
    ) -> Result<ThawReceipt, ProcessTreeFreezeError>;
    async fn pending_thaws(&self) -> Vec<PendingTreeThaw> {
        Vec::new()
    }
    async fn mark_thaw_decided(&self, _handle: &ProcessTreeHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────
//
// The MS1 substrate models a tree count via the
// `simulated_frozen_pid_count` field on the InMemoryBackend itself.
// Production adapter (MS5a) will walk `/proc` and SIGSTOP for real.

#[derive(Default)]
struct State {
    active: HashMap<String, ProcessTreeHandle>,
    pending: HashMap<String, PendingTreeThaw>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test-injectable: how many pids the next freeze should report
    /// having stopped. Defaults to 1 (just the root).
    simulated_frozen_pid_count: Mutex<usize>,
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
            simulated_frozen_pid_count: Mutex::new(1),
        }
    }

    pub fn with_simulated_tree_size(size: usize) -> Self {
        let b = Self::new();
        *b.simulated_frozen_pid_count.lock().unwrap() = size;
        b
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &FreezeTreeRequest) -> Result<(), ProcessTreeFreezeError> {
    if req.root_pid <= 0 {
        return Err(ProcessTreeFreezeError::InvalidRequest(format!(
            "root_pid must be positive, got {}",
            req.root_pid
        )));
    }
    if req.root_pid == 1 {
        return Err(ProcessTreeFreezeError::PidRefused {
            pid: req.root_pid,
            reason: "pid 1 (init) is never freezable".into(),
        });
    }
    if req.reason.trim().is_empty() {
        return Err(ProcessTreeFreezeError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(ProcessTreeFreezeError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl ProcessTreeFreezeBackend for InMemoryBackend {
    async fn freeze_tree(
        &self,
        req: FreezeTreeRequest,
    ) -> Result<FreezeTreeReceipt, ProcessTreeFreezeError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_root = req.root_pid;
        let req_reason = req.reason.clone();
        let req_scope = req.scope;
        let req_duration_secs = req.duration.as_secs();
        let frozen_pid_count = *self.simulated_frozen_pid_count.lock().unwrap();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| ProcessTreeHandle::Active(req.idempotency_key.clone()))
            .clone();
        let ProcessTreeHandle::Active(s) = &handle;
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingTreeThaw {
                    handle: handle.clone(),
                    root_pid: req_root,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    scope: req_scope,
                    frozen_pid_count,
                },
            );
        }
        let active_count = state.active.len();
        Ok(FreezeTreeReceipt {
            handle,
            active_count,
            frozen_pid_count,
        })
    }

    async fn thaw_tree(
        &self,
        handle: ProcessTreeHandle,
    ) -> Result<ThawReceipt, ProcessTreeFreezeError> {
        let ProcessTreeHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(ThawReceipt { thawed: removed })
    }

    async fn pending_thaws(&self) -> Vec<PendingTreeThaw> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingTreeThaw> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_thaw_decided(&self, handle: &ProcessTreeHandle) -> bool {
        let ProcessTreeHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
