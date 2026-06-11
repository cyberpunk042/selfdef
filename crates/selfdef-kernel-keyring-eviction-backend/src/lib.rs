//! Destructive effector backend — unsafe forbidden (F-2026-101): a
//! future `unsafe` in a host-mutating applier must be compiler-rejected.
#![forbid(unsafe_code)]
//! SDD-076 MS1 — kernel-keyring eviction backend trait + InMemoryBackend.
//!
//! Twelfth IPS enforcement primitive — extends undectet
//! (SDD-065..075) → duodectet at the **kernel-keyring axis**.
//! Pairs with SDD-068 (API/web token revoke) + SDD-069 (MFA
//! grant) + SDD-074 (in-memory env scrub) + SDD-075 (POSIX
//! caps) at the credential-axis family.

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
pub enum EvictionScope {
    /// `keyctl_invalidate` — marks key dead; in-flight refs still
    /// valid, new lookups fail with EKEYREVOKED. Default.
    Invalidate,
    /// `keyctl_unlink` — removes the key from one keyring. If it's
    /// in other keyrings or held by other refs, still alive there.
    Unlink,
    /// Both invalidate AND unlink from the default keyring.
    Both,
}

/// Known kernel key types — the validator accepts these as the
/// type prefix in `<type>:<desc>` key-spec syntax. Empty type
/// prefix is rejected (must be `<type>:<desc>` or `0x<serial>`).
const KNOWN_TYPES: &[&str] = &[
    "user",         // user-defined keys (krb5cc, ssh-agent-fwd)
    "logon",        // login-only keys (dm-crypt master)
    "keyring",      // a keyring itself (e.g. _uid.1000)
    "big_key",      // payloads > page size, encrypted in swap
    "asymmetric",   // public/private keypairs (in-kernel TLS)
    "trusted",      // TPM-rooted keys
    "encrypted",    // master-key-encrypted blobs
    "rxrpc",        // AFS rxrpc tokens
    "rxrpc_s",      // AFS server keys
    "dns_resolver", // DNS resolution cache
    "id_resolver",  // NFSv4 id_resolver
    "cifs.idmap",   // CIFS identity mapping
    "cifs.spnego",  // CIFS SPNEGO tokens
];

/// Parse key-spec into (type, desc). Returns `Some(("serial",
/// "0x<hex>"))` for numeric serials, `Some((type, desc))` for
/// `<type>:<desc>`, `None` for malformed.
pub fn parse_key_spec(spec: &str) -> Option<(&str, &str)> {
    let trimmed = spec.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(("serial", trimmed));
        }
        return None;
    }
    let (ty, desc) = trimmed.split_once(':')?;
    if ty.is_empty() || desc.is_empty() {
        return None;
    }
    if !KNOWN_TYPES.contains(&ty) {
        return None;
    }
    Some((ty, desc))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvictKeyRequest {
    /// Key spec: `0x<hex>` numeric serial OR `<type>:<desc>`.
    pub key_spec: String,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub scope: EvictionScope,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KernelKeyringHandle {
    Active(String),
    /// Target key was not in the kernel keyring at evict-time (race
    /// or stale spec). Receipt's keys_evicted is 0; not counted
    /// as active.
    NotFound(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvictKeyReceipt {
    pub handle: KernelKeyringHandle,
    pub active_count: usize,
    /// Number of underlying kernel-keyring entries actually
    /// invalidated/unlinked. Most evictions are exactly 1 (one
    /// key); Both-scope can be 2 if the key was both invalidated
    /// AND removed from its default keyring.
    pub keys_evicted: usize,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared. Note: kernel-
    /// keyring evictions are irreversible — the operator must
    /// re-acquire the key via the upstream auth flow.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingKeyRestore {
    pub handle: KernelKeyringHandle,
    pub key_spec: String,
    pub key_type: String,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub scope: EvictionScope,
    pub keys_evicted: usize,
}

#[derive(Debug, Error)]
pub enum KernelKeyringEvictionError {
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
    /// Key-spec didn't parse — neither `0x<hex>` serial nor
    /// `<type>:<desc>` with known type.
    #[error("unparseable key spec: {spec}")]
    UnparseableKeySpec { spec: String },
}

#[async_trait]
pub trait KernelKeyringEvictionBackend: Send + Sync {
    async fn evict_key(
        &self,
        req: EvictKeyRequest,
    ) -> Result<EvictKeyReceipt, KernelKeyringEvictionError>;
    async fn restore_key(
        &self,
        handle: KernelKeyringHandle,
    ) -> Result<RestoreReceipt, KernelKeyringEvictionError>;
    async fn pending_restores(&self) -> Vec<PendingKeyRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &KernelKeyringHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default)]
struct State {
    active: HashMap<String, KernelKeyringHandle>,
    pending: HashMap<String, PendingKeyRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test injector: simulates how many underlying keys the
    /// evict_key call actually invalidated. `None` ⇒ default 1.
    /// `Some(0)` simulates the NotFound case.
    simulated_keys_evicted: Mutex<Option<usize>>,
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
            simulated_keys_evicted: Mutex::new(None),
        }
    }

    pub fn with_simulated_keys_evicted(n: usize) -> Self {
        let b = Self::new();
        *b.simulated_keys_evicted.lock().unwrap() = Some(n);
        b
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &EvictKeyRequest) -> Result<(String, String), KernelKeyringEvictionError> {
    if req.reason.trim().is_empty() {
        return Err(KernelKeyringEvictionError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(KernelKeyringEvictionError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    let (ty, desc) = parse_key_spec(&req.key_spec).ok_or_else(|| {
        KernelKeyringEvictionError::UnparseableKeySpec {
            spec: req.key_spec.clone(),
        }
    })?;
    Ok((ty.to_string(), desc.to_string()))
}

#[async_trait]
impl KernelKeyringEvictionBackend for InMemoryBackend {
    async fn evict_key(
        &self,
        req: EvictKeyRequest,
    ) -> Result<EvictKeyReceipt, KernelKeyringEvictionError> {
        let (ty, _desc) = validate(&req)?;
        let keys_evicted = self.simulated_keys_evicted.lock().unwrap().unwrap_or(1);
        let mut state = self.inner.lock().unwrap();
        if keys_evicted == 0 {
            let handle = KernelKeyringHandle::NotFound(req.idempotency_key.clone());
            let active_count = state.active.len();
            return Ok(EvictKeyReceipt {
                handle,
                active_count,
                keys_evicted: 0,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| KernelKeyringHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let KernelKeyringHandle::Active(k) = &handle
            && req.authority == AuthorityTier::Responder
        {
            state.pending.insert(
                k.clone(),
                PendingKeyRestore {
                    handle: handle.clone(),
                    key_spec: req.key_spec.clone(),
                    key_type: ty.clone(),
                    original_authority: req.authority,
                    original_reason: req.reason.clone(),
                    seconds_remaining: req.duration.as_secs(),
                    scope: req.scope,
                    keys_evicted,
                },
            );
        }
        let active_count = state.active.len();
        Ok(EvictKeyReceipt {
            handle,
            active_count,
            keys_evicted,
        })
    }

    async fn restore_key(
        &self,
        handle: KernelKeyringHandle,
    ) -> Result<RestoreReceipt, KernelKeyringEvictionError> {
        let key = match &handle {
            KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k.clone(),
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingKeyRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingKeyRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &KernelKeyringHandle) -> bool {
        let key = match handle {
            KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k,
        };
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(key).is_some()
    }
}

// ─────────────── FsBackend (SDD-076 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-076. The actual `keyctl_invalidate`
// requires `CAP_SYS_ADMIN` substrate for keyrings outside the
// caller's session (deferred). FsBackend completes the observability
// + audit half of the SDD-076 production loop for the 30th-sibling
// textfile observer.
//
// 11th application of wiki/patterns/01_drafts/
// ms5a-state-journal-vs-enforcement-layer-separation.md.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: KernelKeyringHandle,
    key_spec: String,
    key_type: String,
    original_reason: String,
    original_authority: AuthorityTier,
    scope: EvictionScope,
    keys_evicted: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingKeyRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    simulated_keys_evicted: Mutex<Option<usize>>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, KernelKeyringEvictionError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            KernelKeyringEvictionError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_keys_evicted: Mutex::new(None),
        })
    }

    pub fn with_simulated_keys_evicted(
        state_dir: impl Into<PathBuf>,
        n: usize,
    ) -> Result<Self, KernelKeyringEvictionError> {
        let b = Self::open(state_dir)?;
        *b.simulated_keys_evicted.lock().unwrap() = Some(n);
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
                    KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k.clone(),
                };
                (k, e)
            })
            .collect()
    }

    fn load_pending(path: &Path) -> HashMap<String, PendingKeyRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingKeyRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| {
                let k = match &p.handle {
                    KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k.clone(),
                };
                (k, p)
            })
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), KernelKeyringEvictionError> {
        let parent = target.parent().ok_or_else(|| {
            KernelKeyringEvictionError::BackendUnreachable(format!(
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
            KernelKeyringEvictionError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            KernelKeyringEvictionError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), KernelKeyringEvictionError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            KernelKeyringEvictionError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingKeyRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            KernelKeyringEvictionError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl KernelKeyringEvictionBackend for FsBackend {
    async fn evict_key(
        &self,
        req: EvictKeyRequest,
    ) -> Result<EvictKeyReceipt, KernelKeyringEvictionError> {
        let (ty, _desc) = validate(&req)?;
        let keys_evicted = self.simulated_keys_evicted.lock().unwrap().unwrap_or(1);
        let snapshot = {
            let mut state = self.inner.lock().unwrap();
            if keys_evicted == 0 {
                let handle = KernelKeyringHandle::NotFound(req.idempotency_key.clone());
                let active_count = state.active.len();
                return Ok(EvictKeyReceipt {
                    handle,
                    active_count,
                    keys_evicted: 0,
                });
            }
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: KernelKeyringHandle::Active(key.clone()),
                    key_spec: req.key_spec.clone(),
                    key_type: ty.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    scope: req.scope,
                    keys_evicted,
                })
                .handle
                .clone();
            if let KernelKeyringHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingKeyRestore {
                        handle: handle.clone(),
                        key_spec: req.key_spec.clone(),
                        key_type: ty,
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        scope: req.scope,
                        keys_evicted,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot.2)?;
        Ok(EvictKeyReceipt {
            handle: snapshot.0,
            active_count: snapshot.1,
            keys_evicted,
        })
    }

    async fn restore_key(
        &self,
        handle: KernelKeyringHandle,
    ) -> Result<RestoreReceipt, KernelKeyringEvictionError> {
        let (cleared, snapshot) = {
            let key = match &handle {
                KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k.clone(),
            };
            let mut state = self.inner.lock().unwrap();
            state.pending.remove(&key);
            let cleared = state.active.remove(&key).is_some();
            (cleared, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingKeyRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingKeyRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &KernelKeyringHandle) -> bool {
        let (removed, snapshot) = {
            let key = match handle {
                KernelKeyringHandle::Active(k) | KernelKeyringHandle::NotFound(k) => k,
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