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
    /// pid 1 (init) is sacrosanct — freezing init via the cgroup freezer hangs
    /// the whole system (init stops reaping children and handling signals).
    /// The sibling process-tree-freeze / capability-drop / process-env-scrub /
    /// netns-isolation backends already refuse pid 1; quarantine must too.
    #[error("pid {pid} refused: {reason}")]
    PidRefused { pid: i32, reason: String },
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
    if req.pid == 1 {
        return Err(QuarantineError::PidRefused {
            pid: req.pid,
            reason: "pid 1 (init) is never freezable; freezing init hangs the host".into(),
        });
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

// ─────────────── FsBackend (SDD-066 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-066. Actual cgroup-v2 freezer
// write (echo 1 > /sys/fs/cgroup/<slice>/cgroup.freeze) requires
// exotic substrate (cgroup-v2 mounted + writable + CAP_SYS_ADMIN
// in the relevant ns); ships in a separate adapter (deferred).
// FsBackend completes the observability + audit half of the
// SDD-066 production loop for the 20th-sibling textfile observer.
//
// Closes the IPS-dectet MS5a 10/10 (state-journal layer).
// Per wiki/patterns/ms5a-state-journal-vs-enforcement-layer-separation.md.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: QuarantineHandle,
    pid: i32,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: FreezeScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingRelease>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, QuarantineError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            QuarantineError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-releases.json"));
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
                let QuarantineHandle::Active(k) = &e.handle;
                (k.clone(), e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingRelease> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingRelease> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let QuarantineHandle::Active(k) = &p.handle;
                (k.clone(), p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), QuarantineError> {
        let parent = target.parent().ok_or_else(|| {
            QuarantineError::BackendUnreachable(format!(
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
        // fsync the tempfile contents before the rename publishes them. This is
        // the durable quarantine state-journal (active + pending-release sets);
        // fs::write + fs::rename gives crash *consistency* (no torn read) but not
        // *durability* — both can return Ok with the bytes still only in the
        // page cache. A power loss right after quarantining a process could then
        // lose that entry, resurrect a stale journal, or leave a zero-length
        // file the daemon reloads as an empty quarantine set on reboot —
        // silently freeing a process that was deliberately contained (fail-open).
        {
            use std::io::Write as _;
            let mut f = fs::File::create(&tmp).map_err(|e| {
                QuarantineError::BackendUnreachable(format!("create {}: {e}", tmp.display()))
            })?;
            f.write_all(bytes).map_err(|e| {
                QuarantineError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                QuarantineError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            QuarantineError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        // fsync the parent directory so the rename's new directory entry is
        // itself durable. Best-effort: a filesystem that refuses to open or
        // fsync a directory must not fail an otherwise-good journal write.
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), QuarantineError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec)
            .map_err(|e| QuarantineError::BackendUnreachable(format!("serialize active: {e}")))?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingRelease> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec)
            .map_err(|e| QuarantineError::BackendUnreachable(format!("serialize pending: {e}")))?;
        Self::write_atomic(
            &self.state_dir.join("pending-releases.json"),
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
impl ProcessQuarantineBackend for FsBackend {
    async fn freeze_process(&self, req: FreezeRequest) -> Result<FreezeReceipt, QuarantineError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: QuarantineHandle::Active(key.clone()),
                    pid: req.pid,
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                })
                .handle
                .clone();
            let QuarantineHandle::Active(k) = &handle;
            if req.authority == AuthorityTier::Responder {
                state.pending.insert(
                    k.clone(),
                    PendingRelease {
                        handle: handle.clone(),
                        pid: req.pid,
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        scope: req.scope,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(FreezeReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn release_process(
        &self,
        handle: QuarantineHandle,
    ) -> Result<ReleaseReceipt, QuarantineError> {
        let (released, snapshot) = {
            let QuarantineHandle::Active(key) = &handle;
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(key);
            let released = state.active.remove(key).is_some();
            (released, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(ReleaseReceipt { released })
    }

    async fn pending_releases(&self) -> Vec<PendingRelease> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingRelease> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_release_decided(&self, handle: &QuarantineHandle) -> bool {
        let (removed, snapshot) = {
            let QuarantineHandle::Active(key) = handle;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn req(pid: i32) -> FreezeRequest {
        FreezeRequest {
            pid,
            reason: "containment".into(),
            duration: Duration::from_secs(60),
            authority: AuthorityTier::Operator,
            scope: FreezeScope::Process,
            idempotency_key: "k1".into(),
        }
    }

    #[test]
    fn pid_1_freeze_refused() {
        // SAFETY: pid 1 (init) is sacrosanct — freezing init via the cgroup
        // freezer hangs the whole host. The sibling process-tree-freeze and
        // other enforcement backends refuse pid 1; quarantine must too.
        assert!(matches!(
            validate(&req(1)).unwrap_err(),
            QuarantineError::PidRefused { pid: 1, .. }
        ));
    }

    #[test]
    fn nonpositive_rejected_normal_ok() {
        assert!(matches!(
            validate(&req(0)).unwrap_err(),
            QuarantineError::InvalidRequest(_)
        ));
        validate(&req(4242)).unwrap();
    }
}
