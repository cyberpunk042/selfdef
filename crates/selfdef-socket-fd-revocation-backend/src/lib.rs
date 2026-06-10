//! SDD-073 MS1 — socket-fd revocation backend trait + InMemoryBackend.
//!
//! Ninth IPS enforcement primitive — extends octet (SDD-065..072)
//! → nonet at the in-flight connection severance axis. Pairs with
//! SDD-065 (perimeter-block) + SDD-070 (netns-isolation) at the
//! network-containment family.

#![forbid(unsafe_code)]

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
            AuthorityTier::Autonomous => Duration::from_secs(2 * 60),
            AuthorityTier::Responder => Duration::from_secs(15 * 60),
            AuthorityTier::Operator => Duration::from_secs(60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(4 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketProtocol {
    Tcp,
    Unix,
    Netlink,
    Any,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeFdRequest {
    pub pid: i32,
    pub fd: i32,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub protocol: SocketProtocol,
    /// Optional inode for race-checking — if provided, the
    /// production adapter (MS5a) verifies /proc/<pid>/fdinfo/<fd>
    /// still references this inode before closing. None bypasses
    /// the check (operator says they know what they're doing).
    pub expected_inode: Option<u64>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketFdHandle {
    Active(String),
    /// Inode mismatch detected between request + execute (fd was
    /// reused); revoke was skipped, operator should re-investigate.
    Stale(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeFdReceipt {
    pub handle: SocketFdHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared from the active set.
    /// Note: socket fds are not actually reopenable — restore is
    /// purely an audit-log + queue-clear operation.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingFdRestore {
    pub handle: SocketFdHandle,
    pub pid: i32,
    pub fd: i32,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub protocol: SocketProtocol,
}

#[derive(Debug, Error)]
pub enum SocketFdRevocationError {
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
    /// Kernel < 5.10 lacks pidfd_getfd(); operator must use SDD-070.
    #[error("pidfd_getfd unsupported on this kernel — use SDD-070 netns isolation instead")]
    PidfdGetfdUnsupported,
    /// pid 1 (init) is sacrosanct — forcibly revoking init's socket fds can
    /// tear down systemd's load-bearing sockets (journal, sd_notify, socket-
    /// activation listeners), breaking host services. The sibling IPS
    /// enforcement backends (process-tree-freeze, capability-drop,
    /// process-env-scrub, netns-isolation, process-quarantine) all refuse
    /// pid 1; fd revocation must too.
    #[error("pid {pid} refused: {reason}")]
    PidRefused { pid: i32, reason: String },
}

#[async_trait]
pub trait SocketFdRevocationBackend: Send + Sync {
    async fn revoke_fd(
        &self,
        req: RevokeFdRequest,
    ) -> Result<RevokeFdReceipt, SocketFdRevocationError>;
    async fn restore_fd(
        &self,
        handle: SocketFdHandle,
    ) -> Result<RestoreReceipt, SocketFdRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingFdRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &SocketFdHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, SocketFdHandle>,
    pending: HashMap<String, PendingFdRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test-injectable: when set Some(inode), the next revoke_fd()
    /// will compare req.expected_inode against this and return a
    /// Stale handle if they differ (simulating fd reuse race).
    simulated_current_inode: Mutex<Option<u64>>,
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
            simulated_current_inode: Mutex::new(None),
        }
    }

    pub fn with_simulated_current_inode(inode: u64) -> Self {
        let b = Self::new();
        *b.simulated_current_inode.lock().unwrap() = Some(inode);
        b
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &RevokeFdRequest) -> Result<(), SocketFdRevocationError> {
    if req.pid <= 0 {
        return Err(SocketFdRevocationError::InvalidRequest(format!(
            "pid must be positive, got {}",
            req.pid
        )));
    }
    if req.pid == 1 {
        return Err(SocketFdRevocationError::PidRefused {
            pid: req.pid,
            reason: "pid 1 (init) sockets are never revocable; tearing down init's \
                     fds can break host services"
                .into(),
        });
    }
    if req.fd < 0 {
        return Err(SocketFdRevocationError::InvalidRequest(format!(
            "fd must be non-negative, got {}",
            req.fd
        )));
    }
    if req.reason.trim().is_empty() {
        return Err(SocketFdRevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(SocketFdRevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl SocketFdRevocationBackend for InMemoryBackend {
    async fn revoke_fd(
        &self,
        req: RevokeFdRequest,
    ) -> Result<RevokeFdReceipt, SocketFdRevocationError> {
        validate(&req)?;
        // Inode race-check (SDD-073 §open-q-2): if both expected and
        // simulated current inodes are present and differ, return
        // a Stale handle instead of activating.
        let stale = matches!(
            (
                req.expected_inode,
                *self.simulated_current_inode.lock().unwrap(),
            ),
            (Some(exp), Some(curr)) if exp != curr
        );
        let req_authority = req.authority;
        let req_pid = req.pid;
        let req_fd = req.fd;
        let req_reason = req.reason.clone();
        let req_protocol = req.protocol;
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        if stale {
            let handle = SocketFdHandle::Stale(req.idempotency_key.clone());
            let active_count = state.active.len();
            return Ok(RevokeFdReceipt {
                handle,
                active_count,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| SocketFdHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let SocketFdHandle::Active(s) = &handle
            && req_authority == AuthorityTier::Responder
        {
            state.pending.insert(
                s.clone(),
                PendingFdRestore {
                    handle: handle.clone(),
                    pid: req_pid,
                    fd: req_fd,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    protocol: req_protocol,
                },
            );
        }
        let active_count = state.active.len();
        Ok(RevokeFdReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_fd(
        &self,
        handle: SocketFdHandle,
    ) -> Result<RestoreReceipt, SocketFdRevocationError> {
        let key = match &handle {
            SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k.clone(),
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingFdRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingFdRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &SocketFdHandle) -> bool {
        let key = match handle {
            SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k,
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-073 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-073. The actual fd close
// (pidfd_open + pidfd_getfd + close) requires exotic substrate
// and ships in a separate adapter (deferred until L3 nspawn);
// FsBackend completes the observability + audit half of the
// production loop end-to-end.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: SocketFdHandle,
    pid: i32,
    fd: i32,
    original_reason: String,
    original_authority: AuthorityTier,
    protocol: SocketProtocol,
    expected_inode: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingFdRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    /// Same race-test injector as InMemoryBackend — set Some(inode)
    /// to make the next revoke_fd() return a Stale handle when
    /// req.expected_inode != inode.
    simulated_current_inode: Mutex<Option<u64>>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, SocketFdRevocationError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            SocketFdRevocationError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_current_inode: Mutex::new(None),
        })
    }

    pub fn with_simulated_current_inode(
        state_dir: impl Into<PathBuf>,
        inode: u64,
    ) -> Result<Self, SocketFdRevocationError> {
        let b = Self::open(state_dir)?;
        *b.simulated_current_inode.lock().unwrap() = Some(inode);
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
                    SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k.clone(),
                };
                (k, e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingFdRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingFdRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let k = match &p.handle {
                    SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k.clone(),
                };
                (k, p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), SocketFdRevocationError> {
        let parent = target.parent().ok_or_else(|| {
            SocketFdRevocationError::BackendUnreachable(format!(
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
        // fsync the tempfile contents before the rename publishes them. This
        // is a durable SDD-066 state-journal: fs::write + fs::rename gives
        // crash consistency (no torn read) but not durability — both can
        // return Ok with the bytes still only in the page cache, so a power
        // loss right after an enforcement action could lose the journal entry,
        // resurrect a stale journal, or leave a zero-length file the backend
        // reloads as an empty set on reboot, silently undoing a containment /
        // revocation (fail-open). Matches the registry / quarantine-backend fix.
        {
            use std::io::Write as _;
            let mut f = fs::File::create(&tmp).map_err(|e| {
                SocketFdRevocationError::BackendUnreachable(format!(
                    "create {}: {e}",
                    tmp.display()
                ))
            })?;
            f.write_all(bytes).map_err(|e| {
                SocketFdRevocationError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                SocketFdRevocationError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            SocketFdRevocationError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        // fsync the parent directory so the rename (the new dir entry) is
        // durable too. Best-effort.
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), SocketFdRevocationError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            SocketFdRevocationError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingFdRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            SocketFdRevocationError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl SocketFdRevocationBackend for FsBackend {
    async fn revoke_fd(
        &self,
        req: RevokeFdRequest,
    ) -> Result<RevokeFdReceipt, SocketFdRevocationError> {
        validate(&req)?;
        let stale = matches!(
            (
                req.expected_inode,
                *self.simulated_current_inode.lock().unwrap(),
            ),
            (Some(exp), Some(curr)) if exp != curr
        );
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            if stale {
                let handle = SocketFdHandle::Stale(req.idempotency_key.clone());
                let active_count = state.active.len();
                return Ok(RevokeFdReceipt {
                    handle,
                    active_count,
                });
            }
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: SocketFdHandle::Active(key.clone()),
                    pid: req.pid,
                    fd: req.fd,
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    protocol: req.protocol,
                    expected_inode: req.expected_inode,
                })
                .handle
                .clone();
            if let SocketFdHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingFdRestore {
                        handle: handle.clone(),
                        pid: req.pid,
                        fd: req.fd,
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        protocol: req.protocol,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(RevokeFdReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn restore_fd(
        &self,
        handle: SocketFdHandle,
    ) -> Result<RestoreReceipt, SocketFdRevocationError> {
        let (cleared, snapshot) = {
            let key = match &handle {
                SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k.clone(),
            };
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let cleared = state.active.remove(&key).is_some();
            (cleared, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingFdRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingFdRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &SocketFdHandle) -> bool {
        let (removed, snapshot) = {
            let key = match handle {
                SocketFdHandle::Active(k) | SocketFdHandle::Stale(k) => k,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn req(pid: i32) -> RevokeFdRequest {
        RevokeFdRequest {
            pid,
            fd: 7,
            reason: "containment".into(),
            duration: Duration::from_secs(60),
            authority: AuthorityTier::Operator,
            protocol: SocketProtocol::Tcp,
            expected_inode: None,
            idempotency_key: "k1".into(),
        }
    }

    #[test]
    fn pid_1_fd_revocation_refused() {
        // SAFETY: pid 1 (init) is sacrosanct — tearing down init's sockets can
        // break systemd's journal / sd_notify / socket-activation listeners.
        // The sibling enforcement backends all refuse pid 1; fd revocation too.
        assert!(matches!(
            validate(&req(1)).unwrap_err(),
            SocketFdRevocationError::PidRefused { pid: 1, .. }
        ));
    }

    #[test]
    fn nonpositive_and_bad_fd_rejected_normal_ok() {
        assert!(matches!(
            validate(&req(0)).unwrap_err(),
            SocketFdRevocationError::InvalidRequest(_)
        ));
        let mut bad_fd = req(4242);
        bad_fd.fd = -1;
        assert!(matches!(
            validate(&bad_fd).unwrap_err(),
            SocketFdRevocationError::InvalidRequest(_)
        ));
        validate(&req(4242)).unwrap();
    }
}
