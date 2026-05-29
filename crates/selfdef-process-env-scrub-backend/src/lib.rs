//! SDD-074 MS1 — process-env scrub backend trait + InMemoryBackend.
//!
//! Tenth IPS enforcement primitive — extends nonet (SDD-065..073)
//! → dectet at the in-memory secret-residency axis. Pairs with
//! SDD-068 (token-revocation) at the credential-axis family.

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
            AuthorityTier::OperatorOverridden => Duration::from_secs(6 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScrubSignal {
    Sigusr1,
    Sigusr2,
    Sighup,
    /// Scrub only, do not signal.
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScrubEnvRequest {
    pub pid: i32,
    /// Variable names to zero in /proc/<pid>/environ. Non-empty.
    pub vars: Vec<String>,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub signal: ScrubSignal,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessEnvScrubHandle {
    Active(String),
    /// Process has no matching env-vars (race or wrong target).
    NoMatch(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScrubEnvReceipt {
    pub handle: ProcessEnvScrubHandle,
    pub active_count: usize,
    /// Number of variables actually scrubbed (may be < requested
    /// if some were not present in process environ).
    pub vars_scrubbed: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared from the active set.
    /// Note: env-scrub is destructive in process memory; restore
    /// is queue-clear + audit only.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEnvRestore {
    pub handle: ProcessEnvScrubHandle,
    pub pid: i32,
    pub vars: Vec<String>,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub signal: ScrubSignal,
    pub vars_scrubbed: usize,
}

#[derive(Debug, Error)]
pub enum ProcessEnvScrubError {
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
    /// Refusal to scrub pid 1 (init) sacrosanct gate.
    #[error("pid {pid} refused: {reason}")]
    PidRefused { pid: i32, reason: String },
}

#[async_trait]
pub trait ProcessEnvScrubBackend: Send + Sync {
    async fn scrub_env(
        &self,
        req: ScrubEnvRequest,
    ) -> Result<ScrubEnvReceipt, ProcessEnvScrubError>;
    async fn restore_env(
        &self,
        handle: ProcessEnvScrubHandle,
    ) -> Result<RestoreReceipt, ProcessEnvScrubError>;
    async fn pending_restores(&self) -> Vec<PendingEnvRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &ProcessEnvScrubHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, ProcessEnvScrubHandle>,
    pending: HashMap<String, PendingEnvRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test-injectable: simulates how many of the requested vars
    /// the target process actually had set. None ⇒ assume all
    /// requested vars matched.
    simulated_vars_matched: Mutex<Option<usize>>,
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
            simulated_vars_matched: Mutex::new(None),
        }
    }

    pub fn with_simulated_vars_matched(n: usize) -> Self {
        let b = Self::new();
        *b.simulated_vars_matched.lock().unwrap() = Some(n);
        b
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &ScrubEnvRequest) -> Result<(), ProcessEnvScrubError> {
    if req.pid <= 0 {
        return Err(ProcessEnvScrubError::InvalidRequest(format!(
            "pid must be positive, got {}",
            req.pid
        )));
    }
    if req.pid == 1 {
        return Err(ProcessEnvScrubError::PidRefused {
            pid: req.pid,
            reason: "pid 1 (init) is never env-scrubbable".into(),
        });
    }
    if req.vars.is_empty() {
        return Err(ProcessEnvScrubError::InvalidRequest(
            "vars must be non-empty".into(),
        ));
    }
    for v in &req.vars {
        if v.is_empty() {
            return Err(ProcessEnvScrubError::InvalidRequest(
                "no var name may be empty".into(),
            ));
        }
        if v.contains('=') || v.contains('\0') {
            return Err(ProcessEnvScrubError::InvalidRequest(format!(
                "var name {v:?} must not contain '=' or NUL"
            )));
        }
    }
    if req.reason.trim().is_empty() {
        return Err(ProcessEnvScrubError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(ProcessEnvScrubError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl ProcessEnvScrubBackend for InMemoryBackend {
    async fn scrub_env(
        &self,
        req: ScrubEnvRequest,
    ) -> Result<ScrubEnvReceipt, ProcessEnvScrubError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_pid = req.pid;
        let req_vars = req.vars.clone();
        let req_reason = req.reason.clone();
        let req_signal = req.signal;
        let req_duration_secs = req.duration.as_secs();
        let requested_count = req.vars.len();
        let vars_scrubbed = self
            .simulated_vars_matched
            .lock()
            .unwrap()
            .unwrap_or(requested_count);
        let mut state = self.inner.lock().unwrap();
        if vars_scrubbed == 0 {
            let handle = ProcessEnvScrubHandle::NoMatch(req.idempotency_key.clone());
            let active_count = state.active.len();
            return Ok(ScrubEnvReceipt {
                handle,
                active_count,
                vars_scrubbed: 0,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| ProcessEnvScrubHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let ProcessEnvScrubHandle::Active(s) = &handle
            && req_authority == AuthorityTier::Responder
        {
            state.pending.insert(
                s.clone(),
                PendingEnvRestore {
                    handle: handle.clone(),
                    pid: req_pid,
                    vars: req_vars,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    signal: req_signal,
                    vars_scrubbed,
                },
            );
        }
        let active_count = state.active.len();
        Ok(ScrubEnvReceipt {
            handle,
            active_count,
            vars_scrubbed,
        })
    }

    async fn restore_env(
        &self,
        handle: ProcessEnvScrubHandle,
    ) -> Result<RestoreReceipt, ProcessEnvScrubError> {
        let key = match &handle {
            ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => k.clone(),
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingEnvRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingEnvRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ProcessEnvScrubHandle) -> bool {
        let key = match handle {
            ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => k,
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}
