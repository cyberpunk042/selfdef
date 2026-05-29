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

// ─────────────── FsBackend (SDD-074 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-074. Writes atomic JSON
// snapshots of active.json + pending-restores.json under
// /var/lib/selfdef/env-scrubs so the 28th-sibling textfile
// observer can scrape them.
//
// Caveat: the actual environ-zeroing (writing zeros into
// /proc/<pid>/environ via process_vm_writev) requires exotic
// substrate and ships in a separate MS5a adapter (deferred until
// L3 nspawn substrate is available). FsBackend completes the
// observability + audit half of the SDD-074 production loop —
// MS1 trait → real on-disk state → observer → Prometheus →
// sovereign-os cockpit/alerts.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: ProcessEnvScrubHandle,
    pid: i32,
    vars: Vec<String>,
    original_reason: String,
    original_authority: AuthorityTier,
    signal: ScrubSignal,
    vars_scrubbed: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingEnvRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    /// Mirrors the InMemoryBackend test injector — when set,
    /// the next scrub_env() reports this many vars_scrubbed,
    /// otherwise assumes all requested vars matched.
    simulated_vars_matched: Mutex<Option<usize>>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, ProcessEnvScrubError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            ProcessEnvScrubError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_vars_matched: Mutex::new(None),
        })
    }

    pub fn with_simulated_vars_matched(
        state_dir: impl Into<PathBuf>,
        n: usize,
    ) -> Result<Self, ProcessEnvScrubError> {
        let b = Self::open(state_dir)?;
        *b.simulated_vars_matched.lock().unwrap() = Some(n);
        Ok(b)
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
                let k = match &e.handle {
                    ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => {
                        k.clone()
                    }
                };
                (k, e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingEnvRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingEnvRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let k = match &p.handle {
                    ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => {
                        k.clone()
                    }
                };
                (k, p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), ProcessEnvScrubError> {
        let parent = target.parent().ok_or_else(|| {
            ProcessEnvScrubError::BackendUnreachable(format!(
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
            ProcessEnvScrubError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            ProcessEnvScrubError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), ProcessEnvScrubError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            ProcessEnvScrubError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingEnvRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            ProcessEnvScrubError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl ProcessEnvScrubBackend for FsBackend {
    async fn scrub_env(
        &self,
        req: ScrubEnvRequest,
    ) -> Result<ScrubEnvReceipt, ProcessEnvScrubError> {
        validate(&req)?;
        let requested_count = req.vars.len();
        let vars_scrubbed = self
            .simulated_vars_matched
            .lock()
            .unwrap()
            .unwrap_or(requested_count);
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            if vars_scrubbed == 0 {
                // NoMatch: do not insert into active; return a Stale-equivalent handle.
                let active_count = state.active.len();
                let handle = ProcessEnvScrubHandle::NoMatch(key);
                return Ok(ScrubEnvReceipt {
                    handle,
                    active_count,
                    vars_scrubbed: 0,
                });
            }
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: ProcessEnvScrubHandle::Active(key.clone()),
                    pid: req.pid,
                    vars: req.vars.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    signal: req.signal,
                    vars_scrubbed,
                })
                .handle
                .clone();
            if let ProcessEnvScrubHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingEnvRestore {
                        handle: handle.clone(),
                        pid: req.pid,
                        vars: req.vars.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        signal: req.signal,
                        vars_scrubbed,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(ScrubEnvReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
            vars_scrubbed,
        })
    }

    async fn restore_env(
        &self,
        handle: ProcessEnvScrubHandle,
    ) -> Result<RestoreReceipt, ProcessEnvScrubError> {
        let (cleared, snapshot) = {
            let key = match &handle {
                ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => k.clone(),
            };
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let cleared = state.active.remove(&key).is_some();
            (cleared, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingEnvRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingEnvRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ProcessEnvScrubHandle) -> bool {
        let (removed, snapshot) = {
            let key = match handle {
                ProcessEnvScrubHandle::Active(k) | ProcessEnvScrubHandle::NoMatch(k) => k,
            };
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
