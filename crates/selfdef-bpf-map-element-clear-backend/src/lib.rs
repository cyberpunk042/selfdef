//! SDD-078 MS1 — eBPF map element clear backend trait + InMemoryBackend + FsBackend.
//!
//! Fourteenth IPS enforcement primitive — extends tridectet
//! (SDD-065..077) → quattuordectet at the **eBPF map state
//! axis**. Pairs with SDD-076 (kernel-keyring eviction) at
//! the kernel-state-eviction family: SDD-076 evicts cached
//! credentials via keyctl; SDD-078 evicts BPF map state via
//! the bpf() syscall. Different syscall surface, different
//! state-store semantics, different attacker-leverage models.

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
pub enum ClearScope {
    /// BPF_MAP_DELETE_ELEM for a single key. `--key <hex>` required.
    Element,
    /// Iterate via BPF_MAP_GET_NEXT_KEY + BPF_MAP_DELETE_ELEM for
    /// every element. Operator+ tier only (D-10). 1M-iteration cap.
    All,
}

/// Resolved kind of `<map-spec>`. The CLI parses the raw string into
/// one of these; the backend stores both for audit.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MapSpecKind {
    /// `/sys/fs/bpf/<name>` — most stable across reboots.
    Path,
    /// `id:<u32>` — volatile across kernel reboots; matches
    /// `bpftool map list` ID column.
    Id,
    /// `name:<map-name>` — the map's in-program name; ambiguous
    /// if multiple maps share the name.
    Name,
}

/// Parse a `<map-spec>` string into (kind, value). Returns `None`
/// for malformed input.
pub fn parse_map_spec(spec: &str) -> Option<(MapSpecKind, &str)> {
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix("id:") {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some((MapSpecKind::Id, rest));
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("name:") {
        if !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Some((MapSpecKind::Name, rest));
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("/sys/fs/bpf/") {
        if !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '.' || c == '-')
        {
            return Some((MapSpecKind::Path, trimmed));
        }
        return None;
    }
    None
}

/// Validate hex-bytes key encoding. Returns the decoded byte length
/// (for key_size matching) or `None` if malformed (odd-length, non-
/// hex chars, empty).
pub fn parse_key_hex(key: &str) -> Option<usize> {
    let trimmed = key.trim();
    if trimmed.is_empty() || trimmed.len() % 2 != 0 {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.len() / 2)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearRequest {
    pub map_spec: String,
    pub scope: ClearScope,
    /// Hex-bytes key. `Some` required for `ClearScope::Element`,
    /// must be `None` for `ClearScope::All`.
    pub key_hex: Option<String>,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClearHandle {
    Active(String),
    /// map_spec didn't resolve to a loaded BPF map.
    MapNotFound(String),
    /// `name:<x>` resolved to >1 map.
    AmbiguousName(String),
    /// `--key` byte length ≠ map's key_size.
    KeySizeMismatch(String),
    /// Element-scope clear but key wasn't in the map (race or
    /// stale spec; not an error, audit only).
    KeyNotFound(String),
    /// Kernel returned EPERM/EACCES (map_flags forbid delete, or
    /// selfdef lacks CAP_BPF/CAP_SYS_ADMIN).
    BpfMapAccessDenied(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearReceipt {
    pub handle: ClearHandle,
    pub active_count: usize,
    /// Number of underlying BPF map elements actually deleted.
    /// 1 for Element-scope on a hit; 0 for KeyNotFound; N for
    /// All-scope (bounded by 1M).
    pub elements_cleared: usize,
    pub map_spec_kind: MapSpecKind,
}

#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    /// True if the handle was found + cleared. Note: BPF map element
    /// clears are one-way — selfdef did not snapshot prior values;
    /// the owning BPF program's control plane must re-add elements.
    pub cleared: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingMapRestore {
    pub handle: ClearHandle,
    pub map_spec: String,
    pub map_spec_kind: MapSpecKind,
    pub scope: ClearScope,
    pub key_hex: Option<String>,
    pub original_authority: AuthorityTier,
    pub original_reason: String,
    pub seconds_remaining: u64,
    pub elements_cleared: usize,
    /// Always `true` for SDD-078 — surfaced in cockpit so the
    /// operator knows restore is queue-clear + audit only; the
    /// owning BPF program's control plane must re-populate.
    pub requires_owning_program_repopulation: bool,
}

#[derive(Debug, Error)]
pub enum BpfMapElementClearError {
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
    /// `<map-spec>` failed the parse_map_spec validator.
    #[error("unparseable map spec: {spec}")]
    UnparseableMapSpec { spec: String },
    /// `--key <hex>` failed the parse_key_hex validator.
    #[error("invalid key hex: {key}")]
    InvalidKeyHex { key: String },
    /// `ClearScope::Element` but `key_hex` is None.
    #[error("element-scope clear requires --key")]
    ElementScopeRequiresKey,
    /// `ClearScope::All` but `key_hex` is Some.
    #[error("all-scope clear forbids --key (specify keyed element-scope instead)")]
    AllScopeForbidsKey,
    /// Authority tier insufficient for `ClearScope::All`.
    #[error("scope All requires Operator+ tier; got {tier:?} (D-10)")]
    AllScopeRequiresOperator { tier: AuthorityTier },
    /// /sys/fs/bpf/ not mounted — enforcement substrate absent.
    #[error("enforcement offline: {0}")]
    EnforcementOffline(String),
}

#[async_trait]
pub trait BpfMapElementClearBackend: Send + Sync {
    async fn clear(&self, req: ClearRequest) -> Result<ClearReceipt, BpfMapElementClearError>;
    async fn restore(&self, handle: ClearHandle)
    -> Result<RestoreReceipt, BpfMapElementClearError>;
    async fn pending_restores(&self) -> Vec<PendingMapRestore> {
        Vec::new()
    }
    async fn mark_restore_decided(&self, _handle: &ClearHandle) -> bool {
        false
    }
}

// ─────────────── InMemoryBackend ───────────────

#[derive(Default, Clone)]
struct State {
    active: HashMap<String, ClearHandle>,
    pending: HashMap<String, PendingMapRestore>,
}

pub struct InMemoryBackend {
    inner: Mutex<State>,
    /// Test injector: simulates how many BPF map elements were
    /// actually deleted. `None` → default: 1 for Element scope,
    /// 0 for All scope (no elements present).
    simulated_elements_cleared: Mutex<Option<usize>>,
    forced_handle: Mutex<Option<ForcedHandleKind>>,
}

#[derive(Clone, Copy, Debug)]
enum ForcedHandleKind {
    MapNotFound,
    AmbiguousName,
    KeySizeMismatch,
    KeyNotFound,
    BpfMapAccessDenied,
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
            simulated_elements_cleared: Mutex::new(None),
            forced_handle: Mutex::new(None),
        }
    }

    pub fn with_simulated_elements_cleared(n: usize) -> Self {
        let b = Self::new();
        *b.simulated_elements_cleared.lock().unwrap() = Some(n);
        b
    }

    pub fn force_map_not_found(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::MapNotFound);
        self
    }
    pub fn force_ambiguous_name(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::AmbiguousName);
        self
    }
    pub fn force_key_size_mismatch(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::KeySizeMismatch);
        self
    }
    pub fn force_key_not_found(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::KeyNotFound);
        self
    }
    pub fn force_access_denied(self) -> Self {
        *self.forced_handle.lock().unwrap() = Some(ForcedHandleKind::BpfMapAccessDenied);
        self
    }

    pub async fn active_count(&self) -> usize {
        self.inner.lock().unwrap().active.len()
    }
}

fn validate(req: &ClearRequest) -> Result<MapSpecKind, BpfMapElementClearError> {
    if req.reason.trim().is_empty() {
        return Err(BpfMapElementClearError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(BpfMapElementClearError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    let (kind, _val) = parse_map_spec(&req.map_spec).ok_or_else(|| {
        BpfMapElementClearError::UnparseableMapSpec {
            spec: req.map_spec.clone(),
        }
    })?;
    match req.scope {
        ClearScope::Element => {
            let key = req
                .key_hex
                .as_ref()
                .ok_or(BpfMapElementClearError::ElementScopeRequiresKey)?;
            if parse_key_hex(key).is_none() {
                return Err(BpfMapElementClearError::InvalidKeyHex { key: key.clone() });
            }
        }
        ClearScope::All => {
            if req.key_hex.is_some() {
                return Err(BpfMapElementClearError::AllScopeForbidsKey);
            }
            if !matches!(
                req.authority,
                AuthorityTier::Operator | AuthorityTier::OperatorOverridden
            ) {
                return Err(BpfMapElementClearError::AllScopeRequiresOperator {
                    tier: req.authority,
                });
            }
        }
    }
    Ok(kind)
}

#[async_trait]
impl BpfMapElementClearBackend for InMemoryBackend {
    async fn clear(&self, req: ClearRequest) -> Result<ClearReceipt, BpfMapElementClearError> {
        let kind = validate(&req)?;
        let forced = *self.forced_handle.lock().unwrap();
        let default_cleared = match req.scope {
            ClearScope::Element => 1,
            ClearScope::All => 0,
        };
        let elements_cleared = self
            .simulated_elements_cleared
            .lock()
            .unwrap()
            .unwrap_or(default_cleared);
        let mut state = self.inner.lock().unwrap();
        if let Some(fkind) = forced {
            let handle = match fkind {
                ForcedHandleKind::MapNotFound => {
                    ClearHandle::MapNotFound(req.idempotency_key.clone())
                }
                ForcedHandleKind::AmbiguousName => {
                    ClearHandle::AmbiguousName(req.idempotency_key.clone())
                }
                ForcedHandleKind::KeySizeMismatch => {
                    ClearHandle::KeySizeMismatch(req.idempotency_key.clone())
                }
                ForcedHandleKind::KeyNotFound => {
                    ClearHandle::KeyNotFound(req.idempotency_key.clone())
                }
                ForcedHandleKind::BpfMapAccessDenied => {
                    ClearHandle::BpfMapAccessDenied(req.idempotency_key.clone())
                }
            };
            let active_count = state.active.len();
            return Ok(ClearReceipt {
                handle,
                active_count,
                elements_cleared: 0,
                map_spec_kind: kind,
            });
        }
        let handle = state
            .active
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| ClearHandle::Active(req.idempotency_key.clone()))
            .clone();
        if let ClearHandle::Active(k) = &handle
            && req.authority == AuthorityTier::Responder
        {
            state.pending.insert(
                k.clone(),
                PendingMapRestore {
                    handle: handle.clone(),
                    map_spec: req.map_spec.clone(),
                    map_spec_kind: kind.clone(),
                    scope: req.scope,
                    key_hex: req.key_hex.clone(),
                    original_authority: req.authority,
                    original_reason: req.reason.clone(),
                    seconds_remaining: req.duration.as_secs(),
                    elements_cleared,
                    requires_owning_program_repopulation: true,
                },
            );
        }
        let active_count = state.active.len();
        Ok(ClearReceipt {
            handle,
            active_count,
            elements_cleared,
            map_spec_kind: kind,
        })
    }

    async fn restore(
        &self,
        handle: ClearHandle,
    ) -> Result<RestoreReceipt, BpfMapElementClearError> {
        let key = handle_key(&handle);
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key);
        let cleared = state.active.remove(&key).is_some();
        Ok(RestoreReceipt { cleared })
    }

    async fn pending_restores(&self) -> Vec<PendingMapRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMapRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ClearHandle) -> bool {
        let key = handle_key(handle);
        let mut state = self.inner.lock().unwrap();
        state.pending.remove(&key).is_some()
    }
}

fn handle_key(handle: &ClearHandle) -> String {
    match handle {
        ClearHandle::Active(k)
        | ClearHandle::MapNotFound(k)
        | ClearHandle::AmbiguousName(k)
        | ClearHandle::KeySizeMismatch(k)
        | ClearHandle::KeyNotFound(k)
        | ClearHandle::BpfMapAccessDenied(k) => k.clone(),
    }
}

// ─────────────── FsBackend (SDD-078 MS5a state-journal adapter) ───────────────
//
// State-journaling layer for SDD-078. The actual bpf() syscalls
// (BPF_MAP_DELETE_ELEM / BPF_MAP_GET_NEXT_KEY / BPF_OBJ_GET /
// BPF_MAP_GET_FD_BY_ID) require CAP_BPF / CAP_SYS_ADMIN substrate
// (deferred). FsBackend completes the observability + audit half
// of the SDD-078 production loop for the 32nd-sibling textfile
// observer.
//
// 13th application of wiki/patterns/01_drafts/
// ms5a-state-journal-vs-enforcement-layer-separation.md.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveEntry {
    handle: ClearHandle,
    map_spec: String,
    map_spec_kind: MapSpecKind,
    scope: ClearScope,
    key_hex: Option<String>,
    original_reason: String,
    original_authority: AuthorityTier,
    elements_cleared: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FsState {
    #[serde(default)]
    active: HashMap<String, ActiveEntry>,
    #[serde(default)]
    pending: HashMap<String, PendingMapRestore>,
}

pub struct FsBackend {
    state_dir: PathBuf,
    inner: Mutex<FsState>,
    simulated_elements_cleared: Mutex<Option<usize>>,
}

impl FsBackend {
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, BpfMapElementClearError> {
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir).map_err(|e| {
            BpfMapElementClearError::BackendUnreachable(format!(
                "create_dir_all {}: {e}",
                state_dir.display()
            ))
        })?;
        let active = Self::load_active(&state_dir.join("active.json"));
        let pending = Self::load_pending(&state_dir.join("pending-restores.json"));
        Ok(Self {
            state_dir,
            inner: Mutex::new(FsState { active, pending }),
            simulated_elements_cleared: Mutex::new(None),
        })
    }

    pub fn with_simulated_elements_cleared(
        state_dir: impl Into<PathBuf>,
        n: usize,
    ) -> Result<Self, BpfMapElementClearError> {
        let b = Self::open(state_dir)?;
        *b.simulated_elements_cleared.lock().unwrap() = Some(n);
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

    fn load_pending(path: &Path) -> HashMap<String, PendingMapRestore> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => return HashMap::new(),
        };
        let vec: Vec<PendingMapRestore> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return HashMap::new(),
        };
        vec.into_iter()
            .map(|p| (handle_key(&p.handle), p))
            .collect()
    }

    fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), BpfMapElementClearError> {
        let parent = target.parent().ok_or_else(|| {
            BpfMapElementClearError::BackendUnreachable(format!(
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
            BpfMapElementClearError::BackendUnreachable(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            BpfMapElementClearError::BackendUnreachable(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                target.display()
            ))
        })?;
        Ok(())
    }

    fn persist(&self, state: &FsState) -> Result<(), BpfMapElementClearError> {
        let active_vec: Vec<&ActiveEntry> = state.active.values().collect();
        let active_bytes = serde_json::to_vec_pretty(&active_vec).map_err(|e| {
            BpfMapElementClearError::BackendUnreachable(format!("serialize active: {e}"))
        })?;
        Self::write_atomic(&self.state_dir.join("active.json"), &active_bytes)?;
        let pending_vec: Vec<&PendingMapRestore> = state.pending.values().collect();
        let pending_bytes = serde_json::to_vec_pretty(&pending_vec).map_err(|e| {
            BpfMapElementClearError::BackendUnreachable(format!("serialize pending: {e}"))
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
impl BpfMapElementClearBackend for FsBackend {
    async fn clear(&self, req: ClearRequest) -> Result<ClearReceipt, BpfMapElementClearError> {
        let kind = validate(&req)?;
        let default_cleared = match req.scope {
            ClearScope::Element => 1,
            ClearScope::All => 0,
        };
        let elements_cleared = self
            .simulated_elements_cleared
            .lock()
            .unwrap()
            .unwrap_or(default_cleared);
        let (handle, active_count, snapshot) = {
            let mut state = self.inner.lock().unwrap();
            let key = req.idempotency_key.clone();
            let handle = state
                .active
                .entry(key.clone())
                .or_insert(ActiveEntry {
                    handle: ClearHandle::Active(key.clone()),
                    map_spec: req.map_spec.clone(),
                    map_spec_kind: kind.clone(),
                    scope: req.scope,
                    key_hex: req.key_hex.clone(),
                    original_reason: req.reason.clone(),
                    original_authority: req.authority,
                    elements_cleared,
                })
                .handle
                .clone();
            if let ClearHandle::Active(k) = &handle
                && req.authority == AuthorityTier::Responder
            {
                state.pending.insert(
                    k.clone(),
                    PendingMapRestore {
                        handle: handle.clone(),
                        map_spec: req.map_spec.clone(),
                        map_spec_kind: kind.clone(),
                        scope: req.scope,
                        key_hex: req.key_hex.clone(),
                        original_authority: req.authority,
                        original_reason: req.reason.clone(),
                        seconds_remaining: req.duration.as_secs(),
                        elements_cleared,
                        requires_owning_program_repopulation: true,
                    },
                );
            }
            let active_count = state.active.len();
            (handle, active_count, state.clone())
        };
        self.persist(&snapshot)?;
        Ok(ClearReceipt {
            handle,
            active_count,
            elements_cleared,
            map_spec_kind: kind,
        })
    }

    async fn restore(
        &self,
        handle: ClearHandle,
    ) -> Result<RestoreReceipt, BpfMapElementClearError> {
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

    async fn pending_restores(&self) -> Vec<PendingMapRestore> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<PendingMapRestore> = state.pending.values().cloned().collect();
        out.sort_by_key(|p| p.seconds_remaining);
        out
    }

    async fn mark_restore_decided(&self, handle: &ClearHandle) -> bool {
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
