//! SDD-077 MS1 — AppArmor live profile-pivot backend trait + InMemoryBackend + FsBackend.
//!
//! Thirteenth IPS enforcement primitive — extends duodectet
//! (SDD-065..076) → tridectet at the **MAC (Mandatory Access
//! Control) policy axis**. Pairs with SDD-075 (POSIX caps)
//! at the privilege-axis family: caps drop kernel-side
//! capabilities; profile pivot narrows the AppArmor profile
//! that gates path/network/cap usage within the remaining
//! capability set.

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
            AuthorityTier::OperatorOverridden => Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PivotScope {
    /// Full `aa_change_profile()` via `changeprofile <profile>\n`.
    /// Default. One-way at the kernel level.
    Profile,
    /// `aa_change_hat()` via `changehat <hat>\n` within current
    /// profile. Useful for graduated containment within sub-hats.
    Hat,
}

/// Validate an AppArmor profile or hat name against the standard
/// `^[a-zA-Z0-9_./-]{1,256}$` shape. Rejects shell metachars,
/// `\n`, and overlong names. Returns the borrowed string if ok.
pub fn validate_profile_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.len() > 256 {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-')
    {
        return None;
    }
    Some(name)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PivotProfileRequest {
    pub pid: i32,
    /// AppArmor profile (or hat, when `scope==Hat`) to pivot into.
    pub target_profile: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: PivotScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApparmorProfilePivotHandle {
    Active(String),
    /// Target profile was not loaded in the kernel
    /// (`/sys/kernel/security/apparmor/profiles`). No syscall
    /// attempted; audit records the missing profile name.
    NoTarget(String),
    /// Current profile of the target pid forbids
    /// `change_profile -> <target>` (kernel `EACCES`).
    Denied(String),
    /// Target pid died between observation and write (`ESRCH`).
    Stale(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PivotProfileReceipt {
    pub handle: ApparmorProfilePivotHandle,
    pub active_count: usize,
    /// AppArmor profile the pid was confined under BEFORE the
    /// pivot (read from `/proc/<pid>/attr/current` first). Empty
    /// string for `NoTarget`/`Stale`/`Denied` if the read failed.
    pub original_profile: String,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared. Note: AppArmor
    /// profile pivots are one-way at the kernel level — the
    /// process must be restarted under its original profile by
    /// the init system to recover.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingProfileRestore {
    pub handle: ApparmorProfilePivotHandle,
    pub pid: i32,
    pub target_profile: String,
    pub original_profile: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: PivotScope,
    /// Always `true` for SDD-077 — surfaced in cockpit so the
    /// operator knows restore is queue-clear + audit only.
    pub requires_process_restart: bool,
}

#[derive(Debug, Error)]
pub enum ApparmorProfilePivotError {
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
    /// Target profile name failed the
    /// `^[a-zA-Z0-9_./-]{1,256}$` validator.
    #[error("invalid profile name: {name}")]
    InvalidProfileName { name: String },
    /// Target pid is sacrosanct (pid 1, kernel thread, or
    /// selfdefd itself). No syscall attempted.
    #[error("pid {pid} sacrosanct: {reason}")]
    PidSacrosanct { pid: i32, reason: String },
    /// `/sys/kernel/security/apparmor/` not mounted —
    /// enforcement substrate absent.
    #[error("enforcement offline: {0}")]
    EnforcementOffline(String),
    /// Host runs SELinux, not AppArmor. SDD-077 fails-closed.
    #[error("wrong MAC backend: {0}")]
    WrongMacBackend(String),
}

#[async_trait]
pub trait ApparmorProfilePivotBackend: Send + Sync {
    async fn pivot_profile(
        &self,
        req: PivotProfileRequest,
    ) -> Result<PivotProfileReceipt, ApparmorProfilePivotError>;
    async fn restore_profile(
        &self,
        handle: ApparmorProfilePivotHandle,
    ) -> Result<RestoreReceipt, ApparmorProfilePivotError>;
    async fn pending_restores(&self) -> Vec<PendingProfileRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &ApparmorProfilePivotHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default, Clone)]
struct State {
    active: HashMap<String, ApparmorProfilePivotHandle>,
    pending: HashMap<String, PendingProfileRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test injector: simulates the pre-pivot profile value the
    /// LiveBackend would read from `/proc/<pid>/attr/current`.
    /// Default: `"unconfined"`.
    simulated_original_profile: Mutex<String>,
    /// Test injector: when set, the pivot returns this handle
    /// variant instead of `Active`. Use to simulate `NoTarget`,
    /// `Denied`, or `Stale` outcomes without a real kernel.
    forced_handle: Mutex<Option<ForcedHandleKind>>,
}

#[derive(Clone, Copy, Debug)]
enum ForcedHandleKind {
    NoTarget,
    Denied,
    Stale,
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
            simulated_original_profile: Mutex::new("unconfined".to_string()),
            forced_handle: Mutex::new(None),
        }
    }

    pub fn with_original_profile(profile: impl Into<String>) -> Self {
        let b = Self::new();
        *b.simulated_original_profile.lock().unwrap() = profile.into();
        b
    }

    pub fn force_no_target(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::NoTarget);
        self
    }
    pub fn force_denied(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::Denied);
        self
    }
    pub fn force_stale(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::Stale);
        self
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn check_sacrosanct(pid: i32) -> Result<(), ApparmorProfilePivotError> {
    if pid <= 1 {
        return Err(ApparmorProfilePivotError::PidSacrosanct {
            pid,
            reason: if pid < 0 {
                "negative pid invalid".to_string()
            } else {
                "init / kernel-thread pid".to_string()
            },
        });
    }
    Ok(())
}

fn validate(req: &PivotProfileRequest) -> Result<String, ApparmorProfilePivotError> {
    if req.reason.trim().is_empty() {
        return Err(ApparmorProfilePivotError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    check_sacrosanct(req.pid)?;
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(ApparmorProfilePivotError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    let name = validate_profile_name(&req.target_profile).ok_or_else(|| {
        ApparmorProfilePivotError::InvalidProfileName {
            name: req.target_profile.clone(),
        }
    })?;
    // Authority-tier ↔ permitted-target enforcement (D-1 / SDD §
    // "Authority tiers" table).
    let is_unconfined = name == "unconfined";
    let is_strict = name == "selfdef-quarantine-strict";
    match req.authority {
        AuthorityTier::Autonomous => {
            if name != "selfdef-observe-only" {
                return Err(ApparmorProfilePivotError::InvalidRequest(format!(
                    "Autonomous tier may only pivot into selfdef-observe-only, not {name}"
                )));
            }
        }
        AuthorityTier::Responder => {
            if name != "selfdef-observe-only" && !is_strict {
                return Err(ApparmorProfilePivotError::InvalidRequest(format!(
                    "Responder tier may only pivot into selfdef-observe-only or selfdef-quarantine-strict, not {name}"
                )));
            }
        }
        AuthorityTier::Operator => {
            if is_unconfined {
                return Err(ApparmorProfilePivotError::InvalidRequest(
                    "Operator tier cannot pivot INTO unconfined; use OperatorOverridden".into(),
                ));
            }
        }
        AuthorityTier::OperatorOverridden => {}
    }
    Ok(name.to_string())
}

#[async_trait]
impl ApparmorProfilePivotBackend for InMemoryBackend {
    async fn pivot_profile(
        &self,
        req: PivotProfileRequest,
    ) -> Result<PivotProfileReceipt, ApparmorProfilePivotError> {
        let _profile = validate(&req)?;
        let original_profile = self.simulated_original_profile.lock().unwrap().clone();
        let forced = *self.forced_handle.lock().unwrap();
        let mut state = self.inner.lock().unwrap();
        if let Some(kind) = forced {
            let handle = match kind {
                ForcedHandleKind::NoTarget => {
                    ApparmorProfilePivotHandle::NoTarget(req.idempotency_key.clone())
                }
                ForcedHandleKind::Denied => {
                    ApparmorProfilePivotHandle::Denied(req.idempotency_key.clone())
                }
                ForcedHandleKind::Stale => {
                    ApparmorProfilePivotHandle::Stale(req.idempotency_key.clone())
                }
            };
            let active_count = state.active.len();
            return Ok(PivotProfileReceipt {
                handle,
                active_count,
                original_profile,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| ApparmorProfilePivotHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let ApparmorProfilePivotHandle::Active(k) = &handle
            && req.authority == AuthorityTier::Responder
        {
            state.pending.insert(
                k.clone(),
                PendingProfileRestore {
                    handle: handle.clone(),
                    pid: req.pid,
                    target_profile: req.target_profile.clone(),
                    original_profile: original_profile.clone(),
                    original_authority: req.authority,
                    original_reason: req.reason.clone(),
                    seconds_remaining: req.duration.as_secs(),
                    scope: req.scope,
                    requires_process_restart: true,
                },
            );
        }
        let active_count = state.active.len();
        Ok(PivotProfileReceipt {
            handle,
            active_count,
            original_profile,
        })
    }

    async fn restore_profile(
        &self,
        handle: ApparmorProfilePivotHandle,
    ) -> Result<RestoreReceipt, ApparmorProfilePivotError> {
        let key = handle_key(&handle);
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingProfileRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingProfileRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ApparmorProfilePivotHandle) -> bool {
        let key = handle_key(handle);
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key).is_some()
    }
}

fn handle_key(handle: &ApparmorProfilePivotHandle) -> String {
    match handle {
        ApparmorProfilePivotHandle::Active(k)
        | ApparmorProfilePivotHandle::NoTarget(k)
        | ApparmorProfilePivotHandle::Denied(k)
        | ApparmorProfilePivotHandle::Stale(k) => k.clone(),
    }
}

// ─────────────── FsBackend (SDD-077 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-077. The actual
// aa_change_profile / aa_change_hat via /proc/<pid>/attr/current
// requires CAP_MAC_ADMIN substrate (deferred). FsBackend
// completes the observability + audit half of the SDD-077
// production loop for the 31st-sibling textfile observer.
//
// 12th application of wiki/patterns/01_drafts/
// ms5a-state-journal-vs-enforcement-layer-separation.md.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: ApparmorProfilePivotHandle,
    pid: i32,
    target_profile: String,
    original_profile: String,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: PivotScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingProfileRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    simulated_original_profile: Mutex<String>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, ApparmorProfilePivotError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            ApparmorProfilePivotError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_original_profile: Mutex::new("unconfined".to_string()),
        })
    }

    pub fn with_original_profile(
        state_dir: impl Into<PathBuf>,
        profile: impl Into<String>,
    ) -> Result<Self, ApparmorProfilePivotError> {
        let b = Self::open(state_dir)?;
        *b.simulated_original_profile.lock().unwrap() = profile.into();
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
            .map(|e| (handle_key(&e.handle), e))
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingProfileRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingProfileRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| (handle_key(&p.handle), p))
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), ApparmorProfilePivotError> {
        let parent = target.parent().ok_or_else(|| {
            ApparmorProfilePivotError::BackendUnreachable(format!(
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
                ApparmorProfilePivotError::BackendUnreachable(format!(
                    "create {}: {e}",
                    tmp.display()
                ))
            })?;
            f.write_all(bytes).map_err(|e| {
                ApparmorProfilePivotError::BackendUnreachable(format!(
                    "write {}: {e}",
                    tmp.display()
                ))
            })?;
            f.sync_all().map_err(|e| {
                ApparmorProfilePivotError::BackendUnreachable(format!(
                    "fsync {}: {e}",
                    tmp.display()
                ))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            ApparmorProfilePivotError::BackendUnreachable(format!(
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

    fn persist(&self, state: &FsState) -> Result<(), ApparmorProfilePivotError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            ApparmorProfilePivotError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingProfileRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            ApparmorProfilePivotError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl ApparmorProfilePivotBackend for FsBackend {
    async fn pivot_profile(
        &self,
        req: PivotProfileRequest,
    ) -> Result<PivotProfileReceipt, ApparmorProfilePivotError> {
        let _profile = validate(&req)?;
        let original_profile = self.simulated_original_profile.lock().unwrap().clone();
        let (handle, active_count, snapshot) = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: ApparmorProfilePivotHandle::Active(key.clone()),
                    pid: req.pid,
                    target_profile: req.target_profile.clone(),
                    original_profile: original_profile.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                })
                .handle
                .clone();
            if let ApparmorProfilePivotHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingProfileRestore {
                        handle: handle.clone(),
                        pid: req.pid,
                        target_profile: req.target_profile.clone(),
                        original_profile: original_profile.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        scope: req.scope,
                        requires_process_restart: true,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(PivotProfileReceipt {
            handle,
            active_count,
            original_profile,
        })
    }

    async fn restore_profile(
        &self,
        handle: ApparmorProfilePivotHandle,
    ) -> Result<RestoreReceipt, ApparmorProfilePivotError> {
        let (cleared, snapshot) = {
            let key = handle_key(&handle);
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let cleared = state.active.remove(&key).is_some();
            (cleared, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingProfileRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingProfileRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ApparmorProfilePivotHandle) -> bool {
        let (removed, snapshot) = {
            let key = handle_key(handle);
            let mut state = self.inner.lock().unwrap();
            let removed = state.pending.remove(&key).is_some();
            (removed, state.clone())
        };
        if removed {
            let _ = self.persist(&snapshot);
        }
        removed
    }
}
