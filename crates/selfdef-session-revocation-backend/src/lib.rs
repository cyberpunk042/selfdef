//! SDD-067 MS1 — session-revocation backend trait + InMemoryBackend.
//!
//! Third enforcement primitive in the SDD-065/066/067 IPS trio.
//! Same paired-enforcement-primitive 5-MS structure as the prior
//! two; see info-hub
//! `wiki/patterns/01_drafts/paired-enforcement-primitive-five-milestone-architecture.md`.
//!
//! Production adapter (LoginctlBackend) lands in MS1b under the
//! `loginctl-backend` feature flag; this crate ships the trait +
//! InMemoryBackend per the MS1-substrate decision recorded at
//! `wiki/decisions/01_drafts/in-memory-backend-as-ms1-substrate.md`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SDD-067 §4 — shorter ceilings than SDD-065/066 because
/// session-revocation directly affects the principal's ability
/// to work; long windows risk locking operator out.
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
            AuthorityTier::Autonomous => Duration::from_secs(60),
            AuthorityTier::Responder => Duration::from_secs(30 * 60),
            AuthorityTier::Operator => Duration::from_secs(4 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// Scope of the revocation — all of user's local sessions, or
/// only sessions originating from a specific source IP (useful
/// when correlator pins the attack to one IP and the user has
/// legitimate sessions from elsewhere).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationScope {
    Local,
    SourceIp(IpAddr),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub user: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: RevocationScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeReceipt {
    pub handle: RevocationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    pub restored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRestore {
    pub handle: RevocationHandle,
    pub user: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: RevocationScope,
}

#[derive(Debug, Error)]
pub enum RevocationError {
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
    #[error("user {user} is on the exclusion list — cannot revoke")]
    ExcludedUser { user: String },
}

#[async_trait]
pub trait SessionRevocationBackend: Send + Sync {
    async fn revoke_sessions(&self, req: RevokeRequest) -> Result<RevokeReceipt, RevocationError>;
    async fn restore_sessions(
        &self,
        handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError>;
    async fn pending_restores(&self) -> Vec<PendingRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &RevocationHandle) -> bool {
        false
    }
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    active: HashMap<String, RevocationHandle>,
    pending: HashMap<String, PendingRestore>,
    handle_user: HashMap<String, String>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Users whose sessions must NEVER be revoked — the self-lockout guard.
    /// `revoke_sessions` refuses these with [`RevocationError::ExcludedUser`].
    /// Populate with the operator account, the daemon's own service user, and
    /// any break-glass admin, so an attacker-crafted event naming one of them
    /// can't lock the responder (or the operator) out of the very host under
    /// attack. Empty by default — the daemon wires the deployment's set.
    excluded_users: std::collections::HashSet<String>,
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
            excluded_users: std::collections::HashSet::new(),
        }
    }

    /// Set the never-revoke exclusion list (self-lockout guard). Chainable.
    #[must_use]
    pub fn with_excluded_users(
        mut self,
        users: impl IntoIterator<Item = String>,
    ) -> Self {
        self.excluded_users = users.into_iter().collect();
        self
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &RevokeRequest) -> Result<(), RevocationError> {
    if req.user.trim().is_empty() {
        return Err(RevocationError::InvalidRequest(
            "user must be non-empty".into(),
        ));
    }
    if req.reason.trim().is_empty() {
        return Err(RevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(RevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl SessionRevocationBackend for InMemoryBackend {
    async fn revoke_sessions(&self, req: RevokeRequest) -> Result<RevokeReceipt, RevocationError> {
        validate(&req)?;
        // Self-lockout guard: never revoke a protected principal (operator /
        // daemon service user / break-glass admin). An attacker-crafted event
        // naming such a user must not be able to lock the responder — or the
        // operator — out of the host under attack.
        if self.excluded_users.contains(&req.user) {
            return Err(RevocationError::ExcludedUser { user: req.user });
        }
        let req_authority = req.authority;
        let req_user = req.user.clone();
        let req_reason = req.reason.clone();
        let req_scope = req.scope;
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| RevocationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let RevocationHandle::Active(s) = &handle;
        state.handle_user.insert(s.clone(), req_user.clone());
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingRestore {
                    handle: handle.clone(),
                    user: req_user,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    scope: req_scope,
                },
            );
        }
        let active_count = state.active.len();
        Ok(RevokeReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_sessions(
        &self,
        handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError> {
        let RevocationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        state.handle_user.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(RestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &RevocationHandle) -> bool {
        let RevocationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-067 MS5a production adapter) ───────────────
//
// Same atomic-JSON pattern as SDD-068/069 FsBackend. Writes
// active.json + pending-restores.json under a state-dir
// (default /var/lib/selfdef/revocations) which the 21st-sibling
// textfile observer scrapes.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: RevocationHandle,
    user: String,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: RevocationScope,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, RevocationError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            RevocationError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
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
                let RevocationHandle::Active(k) = &e.handle;
                (k.clone(), e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let RevocationHandle::Active(k) = &p.handle;
                (k.clone(), p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), RevocationError> {
        let parent = target.parent().ok_or_else(|| {
            RevocationError::BackendUnreachable(format!(
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
                RevocationError::BackendUnreachable(format!("create {}: {e}", tmp.display()))
            })?;
            f.write_all(bytes).map_err(|e| {
                RevocationError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                RevocationError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            RevocationError::BackendUnreachable(format!(
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

    fn persist(&self, state: &FsState) -> Result<(), RevocationError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec)
            .map_err(|e| RevocationError::BackendUnreachable(format!("serialize active: {e}")))?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec)
            .map_err(|e| RevocationError::BackendUnreachable(format!("serialize pending: {e}")))?;
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
impl SessionRevocationBackend for FsBackend {
    async fn revoke_sessions(&self, req: RevokeRequest) -> Result<RevokeReceipt, RevocationError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: RevocationHandle::Active(key.clone()),
                    user: req.user.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                })
                .handle
                .clone();
            if req.authority == AuthorityTier::Responder {
                let RevocationHandle::Active(k) = &handle;
                state.pending.insert(
                    k.clone(),
                    PendingRestore {
                        handle: handle.clone(),
                        user: req.user.clone(),
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
        Ok(RevokeReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn restore_sessions(
        &self,
        handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError> {
        let (removed, snapshot) = {
            let RevocationHandle::Active(key) = &handle;
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(key);
            let removed = state.active.remove(key).is_some();
            (removed, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &RevocationHandle) -> bool {
        let (removed, snapshot) = {
            let RevocationHandle::Active(key) = handle;
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
