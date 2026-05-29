//! SDD-065 MS1 — IP-block backend trait + in-memory test impl.
//!
//! The contract: a `BlockSetBackend` accepts a `BlockIpRequest`,
//! validates it against the authority/duration matrix in SDD-065
//! §4, then either persists the block (returning a `BlockReceipt`
//! with an active `BlockHandle`) or returns a typed `BackendError`.
//!
//! The default production backend (nftables-set adapter) is
//! gated behind a `nftables-backend` feature in MS1b. This crate
//! ships the trait + `InMemoryBackend` (hermetic, used by
//! selfdef-responder unit tests).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Authority tier — caps the maximum allowed block duration.
/// See SDD-065 §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthorityTier {
    /// selfdefd burst-response, no operator confirmation.
    Autonomous,
    /// Correlator/responder chain.
    Responder,
    /// CLI-initiated by operator.
    Operator,
    /// Extended-duration tier requiring --confirm-extended.
    OperatorOverridden,
}

impl AuthorityTier {
    /// Maximum block duration permitted for this tier.
    pub fn max_duration(&self) -> Duration {
        match self {
            AuthorityTier::Autonomous => Duration::from_secs(5 * 60),
            AuthorityTier::Responder => Duration::from_secs(60 * 60),
            AuthorityTier::Operator => Duration::from_secs(24 * 60 * 60),
            AuthorityTier::OperatorOverridden => Duration::from_secs(720 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockIpRequest {
    pub addr: IpAddr,
    pub reason: String,
    pub duration: Duration,
    pub authority: AuthorityTier,
    pub idempotency_key: String,
}

/// Opaque handle identifying an active block. Stable across
/// idempotent re-blocks of the same {addr, reason, tier}.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockHandle {
    Active(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockReceipt {
    pub handle: BlockHandle,
    pub scope_v4_count: usize,
    pub scope_v6_count: usize,
}

#[derive(Clone, Debug)]
pub struct UnblockReceipt {
    pub released: bool,
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("authority {tier:?} max {max_secs}s exceeded by requested {requested_secs}s")]
    AuthorityInsufficient {
        tier: AuthorityTier,
        max_secs: u64,
        requested_secs: u64,
    },
    #[error("ipv6 link-local address refused: {0}")]
    LinkLocalRefused(Ipv6Addr),
    #[error("backend unreachable: {0}")]
    BackendUnreachable(String),
}

#[async_trait]
pub trait BlockSetBackend: Send + Sync {
    async fn block_ip(&self, req: BlockIpRequest) -> Result<BlockReceipt, BackendError>;
    async fn unblock_ip(&self, handle: BlockHandle) -> Result<UnblockReceipt, BackendError>;
}

// ───────────────────────── In-memory backend ─────────────────────────

#[derive(Default)]
struct State {
    v4: HashMap<String, BlockHandle>, // idempotency_key → handle
    v6: HashMap<String, BlockHandle>,
    handle_addr: HashMap<String, IpAddr>, // handle string → addr
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

    pub async fn active_v4_count(&self) -> usize {
        self.inner.lock().unwrap().v4.len()
    }

    pub async fn active_v6_count(&self) -> usize {
        self.inner.lock().unwrap().v6.len()
    }
}

fn validate(req: &BlockIpRequest) -> Result<(), BackendError> {
    if req.reason.trim().is_empty() {
        return Err(BackendError::InvalidRequest(
            "reason must be non-empty".into(),
        ));
    }
    let max = req.authority.max_duration();
    if req.duration > max {
        return Err(BackendError::AuthorityInsufficient {
            tier: req.authority,
            max_secs: max.as_secs(),
            requested_secs: req.duration.as_secs(),
        });
    }
    if let IpAddr::V6(v6) = req.addr {
        // fe80::/10 — link-local, never block.
        let octets = v6.octets();
        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
            return Err(BackendError::LinkLocalRefused(v6));
        }
    }
    Ok(())
}

#[async_trait]
impl BlockSetBackend for InMemoryBackend {
    async fn block_ip(&self, req: BlockIpRequest) -> Result<BlockReceipt, BackendError> {
        validate(&req)?;
        let mut state = self.inner.lock().unwrap();
        let (set, other_count) = match req.addr {
            IpAddr::V4(_) => (&mut state.v4, 0),
            IpAddr::V6(_) => (&mut state.v6, 0),
        };
        let handle = set
            .entry(req.idempotency_key.clone())
            .or_insert_with(|| BlockHandle::Active(req.idempotency_key.clone()))
            .clone();
        let _ = other_count;
        let BlockHandle::Active(s) = &handle;
        state.handle_addr.insert(s.clone(), req.addr);
        let scope_v4_count = state.v4.len();
        let scope_v6_count = state.v6.len();
        Ok(BlockReceipt {
            handle,
            scope_v4_count,
            scope_v6_count,
        })
    }

    async fn unblock_ip(&self, handle: BlockHandle) -> Result<UnblockReceipt, BackendError> {
        let BlockHandle::Active(key) = &handle;
        let mut state = self.inner.lock().unwrap();
        let addr = state.handle_addr.remove(key);
        let removed = match addr {
            Some(IpAddr::V4(_)) => state.v4.remove(key).is_some(),
            Some(IpAddr::V6(_)) => state.v6.remove(key).is_some(),
            None => false,
        };
        Ok(UnblockReceipt { released: removed })
    }
}
