//! `selfdef-exclusive-lock-policy` — named-resource lease lock.
//!
//! `acquire(resource_id, owner, ts, max_hold_ms)`:
//!   * resource free → `Acquired { lease_id }`.
//!   * held by other & not expired → `HeldByOther { owner,
//!     held_until_ms }`.
//!   * held by `owner` (or other's expired) → `SelfReacquired
//!     { lease_id }`.
//!
//! `release(resource_id, lease_id)` returns Released / UnknownLease
//! / WrongLease.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    /// Lease id.
    pub lease_id: u64,
    /// Owner.
    pub owner: String,
    /// Acquired at.
    pub acquired_at_ms: u64,
    /// Max-hold.
    pub max_hold_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExclusiveLockPolicy {
    /// Schema version.
    pub schema_version: String,
    /// resource_id → lease.
    pub leases: BTreeMap<String, Lease>,
    /// Next lease id.
    pub next_id: u64,
}

/// Acquire verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AcquireVerdict {
    /// New lease granted.
    Acquired {
        /// id.
        lease_id: u64,
    },
    /// Same owner reacquired — same lease id.
    SelfReacquired {
        /// id.
        lease_id: u64,
    },
    /// Held by another owner whose lease is still live.
    HeldByOther {
        /// owner.
        owner: String,
        /// when it expires.
        held_until_ms: u64,
    },
}

/// Release verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReleaseVerdict {
    /// Released.
    Released,
    /// Resource is currently locked but the lease id doesn't match.
    WrongLease,
    /// Resource isn't locked.
    UnknownLease,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LockError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty resource id.
    #[error("resource id empty")]
    EmptyResource,
    /// Empty owner.
    #[error("owner empty")]
    EmptyOwner,
}

impl ExclusiveLockPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            leases: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Acquire.
    pub fn acquire(&mut self, resource_id: &str, owner: &str, now_ms: u64, max_hold_ms: u64) -> Result<AcquireVerdict, LockError> {
        if resource_id.is_empty() { return Err(LockError::EmptyResource); }
        if owner.is_empty() { return Err(LockError::EmptyOwner); }
        let existing = self.leases.get(resource_id).cloned();
        match existing {
            Some(lease) => {
                let expires = lease.acquired_at_ms.saturating_add(lease.max_hold_ms);
                if lease.owner == owner {
                    // Refresh the existing lease in place.
                    let updated = Lease {
                        lease_id: lease.lease_id,
                        owner: owner.into(),
                        acquired_at_ms: now_ms,
                        max_hold_ms,
                    };
                    self.leases.insert(resource_id.into(), updated);
                    Ok(AcquireVerdict::SelfReacquired { lease_id: lease.lease_id })
                } else if now_ms >= expires {
                    // Other owner's lease expired — we take over.
                    let lease_id = self.next_id;
                    self.next_id = self.next_id.wrapping_add(1);
                    self.leases.insert(resource_id.into(), Lease {
                        lease_id,
                        owner: owner.into(),
                        acquired_at_ms: now_ms,
                        max_hold_ms,
                    });
                    Ok(AcquireVerdict::Acquired { lease_id })
                } else {
                    Ok(AcquireVerdict::HeldByOther { owner: lease.owner, held_until_ms: expires })
                }
            }
            None => {
                let lease_id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.leases.insert(resource_id.into(), Lease {
                    lease_id,
                    owner: owner.into(),
                    acquired_at_ms: now_ms,
                    max_hold_ms,
                });
                Ok(AcquireVerdict::Acquired { lease_id })
            }
        }
    }

    /// Release.
    pub fn release(&mut self, resource_id: &str, lease_id: u64) -> ReleaseVerdict {
        let lease = match self.leases.get(resource_id) {
            Some(l) => l,
            None => return ReleaseVerdict::UnknownLease,
        };
        if lease.lease_id != lease_id {
            return ReleaseVerdict::WrongLease;
        }
        self.leases.remove(resource_id);
        ReleaseVerdict::Released
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LockError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LockError::SchemaMismatch); }
        for (id, l) in &self.leases {
            if id.is_empty() { return Err(LockError::EmptyResource); }
            if l.owner.is_empty() { return Err(LockError::EmptyOwner); }
        }
        Ok(())
    }
}

impl Default for ExclusiveLockPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_free() {
        let mut l = ExclusiveLockPolicy::new();
        match l.acquire("r", "alice", 0, 1000).unwrap() {
            AcquireVerdict::Acquired { lease_id } => assert!(lease_id > 0),
            _ => panic!(),
        }
    }

    #[test]
    fn self_reacquire_same_id() {
        let mut l = ExclusiveLockPolicy::new();
        let id1 = match l.acquire("r", "alice", 0, 1000).unwrap() {
            AcquireVerdict::Acquired { lease_id } => lease_id,
            _ => unreachable!(),
        };
        match l.acquire("r", "alice", 100, 1000).unwrap() {
            AcquireVerdict::SelfReacquired { lease_id } => assert_eq!(lease_id, id1),
            _ => panic!(),
        }
    }

    #[test]
    fn held_by_other() {
        let mut l = ExclusiveLockPolicy::new();
        l.acquire("r", "alice", 0, 1000).unwrap();
        match l.acquire("r", "bob", 100, 1000).unwrap() {
            AcquireVerdict::HeldByOther { owner, held_until_ms } => {
                assert_eq!(owner, "alice");
                assert_eq!(held_until_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn expired_takeover() {
        let mut l = ExclusiveLockPolicy::new();
        l.acquire("r", "alice", 0, 1000).unwrap();
        // Long after alice's lease expires, bob takes over.
        assert!(matches!(l.acquire("r", "bob", 5000, 1000).unwrap(), AcquireVerdict::Acquired { .. }));
    }

    #[test]
    fn release_correct_lease() {
        let mut l = ExclusiveLockPolicy::new();
        let id = match l.acquire("r", "alice", 0, 1000).unwrap() {
            AcquireVerdict::Acquired { lease_id } => lease_id,
            _ => unreachable!(),
        };
        assert_eq!(l.release("r", id), ReleaseVerdict::Released);
        assert_eq!(l.release("r", id), ReleaseVerdict::UnknownLease);
    }

    #[test]
    fn release_wrong_lease() {
        let mut l = ExclusiveLockPolicy::new();
        l.acquire("r", "alice", 0, 1000).unwrap();
        assert_eq!(l.release("r", 999), ReleaseVerdict::WrongLease);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut l = ExclusiveLockPolicy::new();
        assert!(matches!(l.acquire("", "o", 0, 1).unwrap_err(), LockError::EmptyResource));
        assert!(matches!(l.acquire("r", "", 0, 1).unwrap_err(), LockError::EmptyOwner));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ExclusiveLockPolicy::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LockError::SchemaMismatch));
    }

    #[test]
    fn lock_serde_roundtrip() {
        let mut l = ExclusiveLockPolicy::new();
        l.acquire("r", "alice", 0, 1000).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ExclusiveLockPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
