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

// ─────────────── FsBackend (SDD-070 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-070. Actual setns(2) requires
// exotic substrate (deferred until L3 nspawn). FsBackend completes
// the observability + audit half of the production loop for the
// 24th-sibling textfile observer to scrape.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: NetnsIsolationHandle,
    pid: i32,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: IsolationScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingNetnsRelease>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, NetnsIsolationError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            NetnsIsolationError::BackendUnreachable(format!(
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
                let NetnsIsolationHandle::Active(k) = &e.handle;
                (k.clone(), e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingNetnsRelease> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingNetnsRelease> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let NetnsIsolationHandle::Active(k) = &p.handle;
                (k.clone(), p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), NetnsIsolationError> {
        let parent = target.parent().ok_or_else(|| {
            NetnsIsolationError::BackendUnreachable(format!(
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
                NetnsIsolationError::BackendUnreachable(format!("create {}: {e}", tmp.display()))
            })?;
            f.write_all(bytes).map_err(|e| {
                NetnsIsolationError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                NetnsIsolationError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            NetnsIsolationError::BackendUnreachable(format!(
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

    fn persist(&self, state: &FsState) -> Result<(), NetnsIsolationError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            NetnsIsolationError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingNetnsRelease> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            NetnsIsolationError::BackendUnreachable(format!("serialize pending: {e}"))
        })?;
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
impl NetnsIsolationBackend for FsBackend {
    async fn isolate_pid(
        &self,
        req: IsolatePidRequest,
    ) -> Result<IsolatePidReceipt, NetnsIsolationError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: NetnsIsolationHandle::Active(key.clone()),
                    pid: req.pid,
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                })
                .handle
                .clone();
            let NetnsIsolationHandle::Active(k) = &handle;
            if req.authority == AuthorityTier::Responder {
                state.pending.insert(
                    k.clone(),
                    PendingNetnsRelease {
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
        Ok(IsolatePidReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn release_isolation(
        &self,
        handle: NetnsIsolationHandle,
    ) -> Result<ReleaseReceipt, NetnsIsolationError> {
        let (released, snapshot) = {
            let NetnsIsolationHandle::Active(key) = &handle;
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(key);
            let released = state.active.remove(key).is_some();
            (released, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(ReleaseReceipt { released })
    }

    async fn pending_releases(&self) -> Vec<PendingNetnsRelease> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingNetnsRelease> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_release_decided(&self, handle: &NetnsIsolationHandle) -> bool {
        let (removed, snapshot) = {
            let NetnsIsolationHandle::Active(key) = handle;
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
