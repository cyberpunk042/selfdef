//! SDD-073 MS1 — socket-fd revocation backend trait + InMemoryBackend.
//!
//! Ninth IPS enforcement primitive — extends octet (SDD-065..072)
//! → nonet at the in-flight connection severance axis. Pairs with
//! SDD-065 (perimeter-block) + SDD-070 (netns-isolation) at the
//! network-containment family.

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
