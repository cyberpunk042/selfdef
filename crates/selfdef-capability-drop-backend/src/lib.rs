//! SDD-075 MS1 — per-process capability-drop backend trait + InMemoryBackend.
//!
//! Eleventh IPS enforcement primitive — extends dectet (SDD-065..074)
//! → undectet at the per-process privilege-set axis. Pairs with
//! SDD-066 (single-pid freeze) + SDD-070 (netns containment) at
//! the kernel-containment family, complementing them with
//! **least-privilege graduation** — operator can dial back a
//! specific capability rather than the whole process.

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
            AuthorityTier::Autonomous => Duration::from_secs(5 * 60),
            AuthorityTier::Responder => Duration::from_secs(30 * 60),
            AuthorityTier::Operator => Duration::from_secs(4 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(8 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapScope {
    /// Drop only from bounding set (PR_CAPBSET_DROP). Effective +
    /// permitted + inheritable still hold; bounding gate prevents
    /// re-acquisition.
    BoundingOnly,
    /// Drop from effective + permitted + inheritable + bounding
    /// (full drop). Default.
    AllSets,
}

/// Known modern Linux capability set as of kernel 6.x. Includes
/// the late-added caps (CAP_BPF=39, CAP_PERFMON=38,
/// CAP_CHECKPOINT_RESTORE=40). Validator rejects names not in
/// this set; enforcement adapter (MS5a-enforcement) maps to numeric
/// and warns on missing-on-this-kernel.
const KNOWN_CAPS: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

/// Returns `Some(canonical_uppercase)` if `s` (any-case, with or
/// without `CAP_` prefix) matches a known capability. Returns
/// `None` for unknown names.
pub fn canonicalize_cap(s: &str) -> Option<&'static str> {
    let upper = s.trim().to_uppercase();
    let with_prefix = if upper.starts_with("CAP_") {
        upper
    } else {
        format!("CAP_{upper}")
    };
    KNOWN_CAPS.iter().copied().find(|k| *k == with_prefix)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DropCapsRequest {
    pub pid: i32,
    /// Capabilities to drop. Each must canonicalize to a known cap;
    /// non-empty.
    pub caps: Vec<String>,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: CapScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityDropHandle {
    Active(String),
    /// All requested caps were already absent on the target process
    /// (operator's situational awareness was stale, or process
    /// already-restricted). Receipt carries the actual count of
    /// caps that needed dropping (zero).
    Redundant(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DropCapsReceipt {
    pub handle: CapabilityDropHandle,
    pub active_count: usize,
    /// Number of caps actually dropped (may be < requested if some
    /// were already absent from the target's cap set).
    pub caps_dropped: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared. Note: capability
    /// drops are irreversible at the kernel level; restore is
    /// queue-clear + audit only. Operator must restart the process
    /// to recover the capability.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCapsRestore {
    pub handle: CapabilityDropHandle,
    pub pid: i32,
    pub caps: Vec<String>,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: CapScope,
    pub caps_dropped: usize,
}

#[derive(Debug, Error)]
pub enum CapabilityDropError {
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
    /// pid 1 (init) sacrosanct refusal.
    #[error("pid {pid} refused: {reason}")]
    PidRefused { pid: i32, reason: String },
    /// Unknown cap name in the request.
    #[error("unknown capability name: {name}")]
    UnknownCapability { name: String },
}

#[async_trait]
pub trait CapabilityDropBackend: Send + Sync {
    async fn drop_caps(&self, req: DropCapsRequest)
    -> Result<DropCapsReceipt, CapabilityDropError>;
    async fn restore_caps(
        &self,
        handle: CapabilityDropHandle,
    ) -> Result<RestoreReceipt, CapabilityDropError>;
    async fn pending_restores(&self) -> Vec<PendingCapsRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &CapabilityDropHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, CapabilityDropHandle>,
    pending: HashMap<String, PendingCapsRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test injector: simulates how many of the requested caps the
    /// target process actually held. `None` ⇒ assume all requested
    /// caps held (so caps_dropped == requested.len()).
    simulated_caps_held: Mutex<Option<usize>>,
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
            simulated_caps_held: Mutex::new(None),
        }
    }

    pub fn with_simulated_caps_held(n: usize) -> Self {
        let b = Self::new();
        *b.simulated_caps_held.lock().unwrap() = Some(n);
        b
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &DropCapsRequest) -> Result<(), CapabilityDropError> {
    if req.pid <= 0 {
        return Err(CapabilityDropError::InvalidRequest(format!(
            "pid must be positive, got {}",
            req.pid
        )));
    }
    if req.pid == 1 {
        return Err(CapabilityDropError::PidRefused {
            pid: req.pid,
            reason: "pid 1 (init) is never cap-droppable".into(),
        });
    }
    if req.caps.is_empty() {
        return Err(CapabilityDropError::InvalidRequest(
            "caps must be non-empty".into(),
        ));
    }
    for c in &req.caps {
        if canonicalize_cap(c).is_none() {
            return Err(CapabilityDropError::UnknownCapability { name: c.clone() });
        }
    }
    if req.reason.trim().is_empty() {
        return Err(CapabilityDropError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(CapabilityDropError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl CapabilityDropBackend for InMemoryBackend {
    async fn drop_caps(
        &self,
        req: DropCapsRequest,
    ) -> Result<DropCapsReceipt, CapabilityDropError> {
        validate(&req)?;
        let requested_count = req.caps.len();
        let caps_dropped = self
            .simulated_caps_held
            .lock()
            .unwrap()
            .unwrap_or(requested_count);
        let mut state = self.inner.lock().unwrap();
        if caps_dropped == 0 {
            // All requested caps were already absent.
            let handle = CapabilityDropHandle::Redundant(req.idempotency_key.clone());
            let active_count = state.active.len();
            return Ok(DropCapsReceipt {
                handle,
                active_count,
                caps_dropped: 0,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| CapabilityDropHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let CapabilityDropHandle::Active(k) = &handle
            && req.authority == AuthorityTier::Responder
        {
            state.pending.insert(
                k.clone(),
                PendingCapsRestore {
                    handle: handle.clone(),
                    pid: req.pid,
                    caps: req.caps.clone(),
                    original_authority: req.authority,
                    original_reason: req.reason.clone(),
                    seconds_remaining: req.duration.as_secs(),
                    scope: req.scope,
                    caps_dropped,
                },
            );
        }
        let active_count = state.active.len();
        Ok(DropCapsReceipt {
            handle,
            active_count,
            caps_dropped,
        })
    }

    async fn restore_caps(
        &self,
        handle: CapabilityDropHandle,
    ) -> Result<RestoreReceipt, CapabilityDropError> {
        let key = match &handle {
            CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => k.clone(),
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingCapsRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingCapsRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &CapabilityDropHandle) -> bool {
        let key = match handle {
            CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => k,
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-075 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-075. The actual prctl(PR_CAPBSET_DROP)
// requires CAP_SETPCAP substrate (deferred until L3 nspawn). FsBackend
// completes the observability + audit half of the SDD-075 production
// loop for the 29th-sibling textfile observer to scrape.
//
// Per wiki/patterns/01_drafts/ms5a-state-journal-vs-enforcement-layer-separation.md
// (info-hub PR #15) — 10th application of the pattern.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: CapabilityDropHandle,
    pid: i32,
    caps: Vec<String>,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: CapScope,
    caps_dropped: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingCapsRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    simulated_caps_held: Mutex<Option<usize>>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, CapabilityDropError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            CapabilityDropError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_caps_held: Mutex::new(None),
        })
    }

    pub fn with_simulated_caps_held(
        state_dir: impl Into<PathBuf>,
        n: usize,
    ) -> Result<Self, CapabilityDropError> {
        let b = Self::open(state_dir)?;
        *b.simulated_caps_held.lock().unwrap() = Some(n);
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
                    CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => {
                        k.clone()
                    }
                };
                (k, e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingCapsRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingCapsRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let k = match &p.handle {
                    CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => {
                        k.clone()
                    }
                };
                (k, p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), CapabilityDropError> {
        let parent = target.parent().ok_or_else(|| {
            CapabilityDropError::BackendUnreachable(format!(
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
                CapabilityDropError::BackendUnreachable(format!("create {}: {e}", tmp.display()))
            })?;
            f.write_all(bytes).map_err(|e| {
                CapabilityDropError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                CapabilityDropError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            CapabilityDropError::BackendUnreachable(format!(
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

    fn persist(&self, state: &FsState) -> Result<(), CapabilityDropError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            CapabilityDropError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingCapsRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            CapabilityDropError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl CapabilityDropBackend for FsBackend {
    async fn drop_caps(
        &self,
        req: DropCapsRequest,
    ) -> Result<DropCapsReceipt, CapabilityDropError> {
        validate(&req)?;
        let requested_count = req.caps.len();
        let caps_dropped = self
            .simulated_caps_held
            .lock()
            .unwrap()
            .unwrap_or(requested_count);
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            if caps_dropped == 0 {
                let handle = CapabilityDropHandle::Redundant(req.idempotency_key.clone());
                let active_count = state.active.len();
                return Ok(DropCapsReceipt {
                    handle,
                    active_count,
                    caps_dropped: 0,
                });
            }
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: CapabilityDropHandle::Active(key.clone()),
                    pid: req.pid,
                    caps: req.caps.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                    caps_dropped,
                })
                .handle
                .clone();
            if let CapabilityDropHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingCapsRestore {
                        handle: handle.clone(),
                        pid: req.pid,
                        caps: req.caps.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        scope: req.scope,
                        caps_dropped,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(DropCapsReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
            caps_dropped,
        })
    }

    async fn restore_caps(
        &self,
        handle: CapabilityDropHandle,
    ) -> Result<RestoreReceipt, CapabilityDropError> {
        let (cleared, snapshot) = {
            let key = match &handle {
                CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => k.clone(),
            };
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let cleared = state.active.remove(&key).is_some();
            (cleared, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingCapsRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingCapsRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &CapabilityDropHandle) -> bool {
        let (removed, snapshot) = {
            let key = match handle {
                CapabilityDropHandle::Active(k) | CapabilityDropHandle::Redundant(k) => k,
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
