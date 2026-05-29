//! SDD-071 MS1 — mount-binding unbind backend trait + InMemoryBackend.
//!
//! Seventh IPS enforcement primitive — extends hexet (SDD-065..070)
//! → septet at the filesystem-binding axis. Pairs with SDD-066
//! (process-quarantine) + SDD-070 (netns containment) for the
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
            AuthorityTier::Responder => Duration::from_secs(20 * 60),
            AuthorityTier::Operator => Duration::from_secs(60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(6 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnbindScope {
    /// A single bind-mount target.
    Bind,
    /// The upper or lower layer of an overlayfs leaking host content.
    Overlay,
    /// Every bind-mount whose source matches the given glob/regex pattern.
    /// Operator-overridden tier only.
    AllMatching(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnbindMountRequest {
    pub mount_point: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: UnbindScope,
    /// Default true: umount -l (MS_DETACH). False = umount -f (MS_FORCE);
    /// drops live fds.
    pub lazy: bool,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MountBindingHandle {
    Active(String),
    /// Mount reappeared post-unbind (auto-remount by systemd/kubelet/etc).
    Contested(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnbindMountReceipt {
    pub handle: MountBindingHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct RebindReceipt {
    pub rebound: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingMountRebind {
    pub handle: MountBindingHandle,
    pub mount_point: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: UnbindScope,
}

#[derive(Debug, Error)]
pub enum MountBindingUnbindError {
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
    #[error("scope AllMatching requires operator-overridden tier — got {tier:?}")]
    ScopeRequiresOverride { tier: AuthorityTier },
}

#[async_trait]
pub trait MountBindingUnbindBackend: Send + Sync {
    async fn unbind_mount(
        &self,
        req: UnbindMountRequest,
    ) -> Result<UnbindMountReceipt, MountBindingUnbindError>;
    async fn rebind_mount(
        &self,
        handle: MountBindingHandle,
    ) -> Result<RebindReceipt, MountBindingUnbindError>;
    async fn pending_rebinds(&self) -> Vec<PendingMountRebind> {
        Vec::new()
    }
    async fn mark_rebind_decided(&self, _handle: &MountBindingHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, MountBindingHandle>,
    pending: HashMap<String, PendingMountRebind>,
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

fn validate(req: &UnbindMountRequest) -> Result<(), MountBindingUnbindError> {
    if req.mount_point.trim().is_empty() {
        return Err(MountBindingUnbindError::InvalidRequest(
            "mount_point must be non-empty".into(),
        ));
    }
    if !req.mount_point.starts_with('/') {
        return Err(MountBindingUnbindError::InvalidRequest(format!(
            "mount_point must be an absolute path, got {:?}",
            req.mount_point
        )));
    }
    if req.reason.trim().is_empty() {
        return Err(MountBindingUnbindError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(MountBindingUnbindError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    if matches!(req.scope, UnbindScope::AllMatching(_))
        && req.authority != AuthorityTier::OperatorOverridden
    {
        return Err(MountBindingUnbindError::ScopeRequiresOverride {
            tier: req.authority,
        });
    }
    Ok(())
}

#[async_trait]
impl MountBindingUnbindBackend for InMemoryBackend {
    async fn unbind_mount(
        &self,
        req: UnbindMountRequest,
    ) -> Result<UnbindMountReceipt, MountBindingUnbindError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_mp = req.mount_point.clone();
        let req_reason = req.reason.clone();
        let req_scope = req.scope.clone();
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| MountBindingHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let MountBindingHandle::Active(s) = &handle
            && req_authority == AuthorityTier::Responder
        {
            state.pending.insert(
                s.clone(),
                PendingMountRebind {
                    handle: handle.clone(),
                    mount_point: req_mp,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    scope: req_scope,
                },
            );
        }
        let active_count = state.active.len();
        Ok(UnbindMountReceipt {
            handle,
            active_count,
        })
    }

    async fn rebind_mount(
        &self,
        handle: MountBindingHandle,
    ) -> Result<RebindReceipt, MountBindingUnbindError> {
        let key = match &handle {
            MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k.clone(),
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let removed = state.active.remove(&key).is_some();
        Ok(RebindReceipt { rebound: removed })
    }

    async fn pending_rebinds(&self) -> Vec<PendingMountRebind> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMountRebind> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_rebind_decided(&self, handle: &MountBindingHandle) -> bool {
        let key = match handle {
            MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k,
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-071 MS5a state-journal adapter) ───────────────

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: MountBindingHandle,
    mount_point: String,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: UnbindScope,
    lazy: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingMountRebind>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, MountBindingUnbindError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            MountBindingUnbindError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-rebinds.json"));
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
                let k = match &e.handle {
                    MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k.clone(),
                };
                (k, e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingMountRebind> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingMountRebind> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let k = match &p.handle {
                    MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k.clone(),
                };
                (k, p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), MountBindingUnbindError> {
        let parent = target.parent().ok_or_else(|| {
            MountBindingUnbindError::BackendUnreachable(format!(
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
            MountBindingUnbindError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            MountBindingUnbindError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), MountBindingUnbindError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            MountBindingUnbindError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingMountRebind> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            MountBindingUnbindError::BackendUnreachable(format!("serialize pending: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("pending-rebinds.json"), &pending_bytes)?;
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
impl MountBindingUnbindBackend for FsBackend {
    async fn unbind_mount(
        &self,
        req: UnbindMountRequest,
    ) -> Result<UnbindMountReceipt, MountBindingUnbindError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: MountBindingHandle::Active(key.clone()),
                    mount_point: req.mount_point.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope.clone(),
                    lazy: req.lazy,
                })
                .handle
                .clone();
            if let MountBindingHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingMountRebind {
                        handle: handle.clone(),
                        mount_point: req.mount_point.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        scope: req.scope.clone(),
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(UnbindMountReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn rebind_mount(
        &self,
        handle: MountBindingHandle,
    ) -> Result<RebindReceipt, MountBindingUnbindError> {
        let (rebound, snapshot) = {
            let key = match &handle {
                MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k.clone(),
            };
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let rebound = state.active.remove(&key).is_some();
            (rebound, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RebindReceipt { rebound })
    }

    async fn pending_rebinds(&self) -> Vec<PendingMountRebind> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMountRebind> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_rebind_decided(&self, handle: &MountBindingHandle) -> bool {
        let (removed, snapshot) = {
            let key = match handle {
                MountBindingHandle::Active(k) | MountBindingHandle::Contested(k) => k,
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
