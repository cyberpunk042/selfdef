//! SDD-068 MS1 — API/web-token revocation backend trait + InMemoryBackend.
//!
//! Fourth enforcement primitive in the IPS quartet (SDD-065
//! network + SDD-066 process + SDD-067 shell-session + SDD-068
//! API-token = this crate). Same paired-enforcement-primitive
//! 5-MS structure as the prior three.
//!
//! BusEventBackend production adapter lands in MS1b under the
//! `bus-event-backend` feature flag; this crate ships the trait +
//! InMemoryBackend per the MS1-substrate decision recorded at
//! `wiki/decisions/01_drafts/in-memory-backend-as-ms1-substrate.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SDD-068 §4 — longer ceilings than SDD-067 because token
/// revocation is recoverable (operator issues new token via
/// console/cockpit), so locking-out concerns are reduced.
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
            AuthorityTier::Responder => Duration::from_secs(60 * 60),
            AuthorityTier::Operator => Duration::from_secs(8 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(72 * 60 * 60),
        }
    }
}

/// Token-class taxonomy. `Other(String)` accommodates future
/// surfaces (operator-extensible) per SDD-068 open question #1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenClass {
    Api,
    Cockpit,
    Mcp,
    Other(String),
}

/// Scope of the revocation across token surfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenClassMask {
    All,
    Specific(Vec<TokenClass>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRevokeRequest {
    pub principal: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub token_classes: TokenClassMask,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenRevocationHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRevokeReceipt {
    pub handle: TokenRevocationHandle,
    pub active_count: usize,
}

#[derive(Clone, Debug)]
pub struct TokenRestoreReceipt {
    pub restored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingTokenRestore {
    pub handle: TokenRevocationHandle,
    pub principal: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub token_classes: TokenClassMask,
}

#[derive(Debug, Error)]
pub enum TokenRevocationError {
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
}

#[async_trait]
pub trait ApiTokenRevocationBackend: Send + Sync {
    async fn revoke_tokens(
        &self,
        req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError>;
    async fn restore_tokens(
        &self,
        handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingTokenRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &TokenRevocationHandle) -> bool {
        false
    }
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    active: HashMap<String, TokenRevocationHandle>,
    pending: HashMap<String, PendingTokenRestore>,
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

fn validate(req: &TokenRevokeRequest) -> Result<(), TokenRevocationError> {
    if req.principal.trim().is_empty() {
        return Err(TokenRevocationError::InvalidRequest(
            "principal must be non-empty".into(),
        ));
    }
    if req.reason.trim().is_empty() {
        return Err(TokenRevocationError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(TokenRevocationError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    Ok(())
}

#[async_trait]
impl ApiTokenRevocationBackend for InMemoryBackend {
    async fn revoke_tokens(
        &self,
        req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError> {
        validate(&req)?;
        let req_authority = req.authority;
        let req_principal = req.principal.clone();
        let req_reason = req.reason.clone();
        let req_classes = req.token_classes.clone();
        let req_duration_secs = req.duration.as_secs();
        let mut state = self.inner.lock().unwrap();
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| TokenRevocationHandle::Active(req.idempotency_key.clone()))
            .clone();
        let TokenRevocationHandle::Active(s) = &handle;
        if req_authority == AuthorityTier::Responder {
            state.pending.insert(
                s.clone(),
                PendingTokenRestore {
                    handle: handle.clone(),
                    principal: req_principal,
                    original_authority: req_authority,
                    original_reason: req_reason,
                    seconds_remaining: req_duration_secs,
                    token_classes: req_classes,
                },
            );
        }
        let active_count = state.active.len();
        Ok(TokenRevokeReceipt {
            handle,
            active_count,
        })
    }

    async fn restore_tokens(
        &self,
        handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError> {
        let TokenRevocationHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key);
        let removed = state.active.remove(key).is_some();
        Ok(TokenRestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingTokenRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingTokenRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &TokenRevocationHandle) -> bool {
        let TokenRevocationHandle::Active(key) = handle;
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-068 MS5a production adapter) ───────────────
//
// Filesystem-backed production adapter. Writes atomic JSON snapshots
// of active.json + pending-restores.json under a state-dir, so the
// 22nd-sibling textfile observer
// (packaging/scripts/selfdef-token-revocations-textfile.sh) can scrape
// them and emit Prometheus gauges.
//
// Atomicity: each write goes to a sibling tempfile in the same
// directory, then `rename(tmp, target)` — POSIX-atomic within a
// filesystem, so the observer never reads a partial write.
//
// Pure std::fs — no exotic syscalls, no kernel-version dependency.
// Works in any container or bare-metal environment with write
// access to the state directory.

use std::fs;
use std::path::{Path, PathBuf};

/// On-disk representation of an active token-revocation handle.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: TokenRevocationHandle,
    principal: String,
    original_reason: String,
    original_authority: AuthorityTier,
    token_classes: TokenClassMask,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingTokenRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
}

impl FsBackend {
    /// Opens or initialises an FsBackend rooted at `state_dir`.
    /// Creates the directory if absent. Loads existing JSON if
    /// present; silently re-initialises to empty if either file
    /// is malformed (operator-recoverable: rm + restart).
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, TokenRevocationError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            TokenRevocationError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active_path = state_dir.join("active.json");
        let pending_path = state_dir.join("pending-restores.json");
        let active = Self::load_active(&active_path);
        let pending = Self::load_pending(&pending_path);
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
        })
    }

    fn load_active(path: &Path) -> HashMap<String, ActiveEntry> {
        // Disk layout for active.json is an ARRAY of ActiveEntry
        // (matching the observer's `jq length` scan + persist()'s
        // serialize_pretty(Vec) call). Convert to the internal
        // HashMap keyed by handle.
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
                let TokenRevocationHandle::Active(k) = &e.handle;
                (k.clone(), e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingTokenRestore> {
        // Same shape as load_active — array on disk, HashMap in memory.
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingTokenRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let TokenRevocationHandle::Active(k) = &p.handle;
                (k.clone(), p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), TokenRevocationError> {
        // mktemp in same directory so rename(2) is atomic.
        let parent = target.parent().ok_or_else(|| {
            TokenRevocationError::BackendUnreachable(format!(
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
        // loss right after a token revocation could lose the journal entry,
        // resurrect a stale journal, or leave a zero-length file the backend
        // reloads as an empty set on reboot, silently un-revoking a token
        // (fail-open). Matches the registry / quarantine-backend fix.
        {
            use std::io::Write as _;
            let mut f = fs::File::create(&tmp).map_err(|e| {
                TokenRevocationError::BackendUnreachable(format!("create {}: {e}", tmp.display()))
            })?;
            f.write_all(bytes).map_err(|e| {
                TokenRevocationError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
            })?;
            f.sync_all().map_err(|e| {
                TokenRevocationError::BackendUnreachable(format!("fsync {}: {e}", tmp.display()))
            })?;
        }
        fs::rename(&tmp, target).map_err(|e| {
            // Best-effort cleanup of the tempfile on rename failure.
            let _ = fs::remove_file(&tmp);
            TokenRevocationError::BackendUnreachable(format!(
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

    fn persist(&self, state: &FsState) -> Result<(), TokenRevocationError> {
        // active.json is also an ARRAY for the observer's jq scan.
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            TokenRevocationError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;

        let pending_vec: Vec<&PendingTokenRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            TokenRevocationError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl ApiTokenRevocationBackend for FsBackend {
    async fn revoke_tokens(
        &self,
        req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError> {
        validate(&req)?;
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: TokenRevocationHandle::Active(key.clone()),
                    principal: req.principal.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    token_classes: req.token_classes.clone(),
                })
                .handle
                .clone();
            if req.authority == AuthorityTier::Responder {
                let TokenRevocationHandle::Active(k) = &handle;
                state.pending.insert(
                    k.clone(),
                    PendingTokenRestore {
                        handle: handle.clone(),
                        principal: req.principal.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        token_classes: req.token_classes.clone(),
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(TokenRevokeReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
        })
    }

    async fn restore_tokens(
        &self,
        handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError> {
        let (removed, snapshot) = {
            let TokenRevocationHandle::Active(key) = &handle;
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(key);
            let removed = state.active.remove(key).is_some();
            (removed, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(TokenRestoreReceipt { restored: removed })
    }

    async fn pending_restores(&self) -> Vec<PendingTokenRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingTokenRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &TokenRevocationHandle) -> bool {
        let (removed, snapshot) = {
            let TokenRevocationHandle::Active(key) = handle;
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
