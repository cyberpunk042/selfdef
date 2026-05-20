//! `selfdef-named-lock` — by-key exclusive locks.
//!
//! acquire(key, owner, now, ttl_ms) grants iff key is free OR
//! the existing lock has expired. release(key, owner) releases
//! only if owner matches. held(key, now) returns Some(owner) if
//! valid. expire(now) sweeps stale entries.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Lock entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hold {
    /// Owner.
    pub owner: String,
    /// Expiry ts ms.
    pub expires_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamedLock {
    /// Schema version.
    pub schema_version: String,
    /// key → hold.
    pub holds: BTreeMap<String, Hold>,
    /// Acquires.
    pub acquires: u64,
    /// Releases.
    pub releases: u64,
    /// Expires.
    pub expires: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LockError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("owner empty")]
    EmptyOwner,
    /// Zero ttl.
    #[error("ttl_ms must be >= 1")]
    ZeroTtl,
    /// Held by other.
    #[error("held by other: {0}")]
    HeldByOther(String),
    /// Owner mismatch.
    #[error("owner mismatch on release")]
    OwnerMismatch,
    /// Not held.
    #[error("not held")]
    NotHeld,
}

impl NamedLock {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            holds: BTreeMap::new(),
            acquires: 0,
            releases: 0,
            expires: 0,
        }
    }

    /// Acquire.
    pub fn acquire(&mut self, key: &str, owner: &str, now_ms: u64, ttl_ms: u64) -> Result<(), LockError> {
        if key.is_empty() { return Err(LockError::EmptyKey); }
        if owner.is_empty() { return Err(LockError::EmptyOwner); }
        if ttl_ms == 0 { return Err(LockError::ZeroTtl); }
        if let Some(h) = self.holds.get(key) {
            if h.expires_at_ms > now_ms && h.owner != owner {
                return Err(LockError::HeldByOther(h.owner.clone()));
            }
        }
        self.holds.insert(key.into(), Hold {
            owner: owner.into(),
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        });
        self.acquires = self.acquires.saturating_add(1);
        Ok(())
    }

    /// Release.
    pub fn release(&mut self, key: &str, owner: &str) -> Result<(), LockError> {
        let h = self.holds.get(key).ok_or(LockError::NotHeld)?;
        if h.owner != owner { return Err(LockError::OwnerMismatch); }
        self.holds.remove(key);
        self.releases = self.releases.saturating_add(1);
        Ok(())
    }

    /// Held by (None if free or expired).
    pub fn held(&self, key: &str, now_ms: u64) -> Option<&str> {
        let h = self.holds.get(key)?;
        if h.expires_at_ms > now_ms { Some(h.owner.as_str()) } else { None }
    }

    /// Sweep expired entries; return count removed.
    pub fn expire(&mut self, now_ms: u64) -> u32 {
        let stale: Vec<String> = self.holds.iter()
            .filter(|(_, h)| h.expires_at_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let n = stale.len() as u32;
        for k in stale { self.holds.remove(&k); }
        self.expires = self.expires.saturating_add(n as u64);
        n
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LockError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LockError::SchemaMismatch); }
        for (k, h) in &self.holds {
            if k.is_empty() { return Err(LockError::EmptyKey); }
            if h.owner.is_empty() { return Err(LockError::EmptyOwner); }
        }
        Ok(())
    }
}

impl Default for NamedLock {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release() {
        let mut l = NamedLock::new();
        l.acquire("r", "owner1", 0, 1000).unwrap();
        assert_eq!(l.held("r", 500), Some("owner1"));
        l.release("r", "owner1").unwrap();
        assert!(l.held("r", 500).is_none());
    }

    #[test]
    fn held_by_other_rejected() {
        let mut l = NamedLock::new();
        l.acquire("r", "owner1", 0, 1000).unwrap();
        assert!(matches!(l.acquire("r", "owner2", 500, 1000).unwrap_err(), LockError::HeldByOther(_)));
    }

    #[test]
    fn expired_lock_can_be_taken() {
        let mut l = NamedLock::new();
        l.acquire("r", "owner1", 0, 100).unwrap();
        l.acquire("r", "owner2", 200, 1000).unwrap();
        assert_eq!(l.held("r", 250), Some("owner2"));
    }

    #[test]
    fn same_owner_renews() {
        let mut l = NamedLock::new();
        l.acquire("r", "owner1", 0, 100).unwrap();
        l.acquire("r", "owner1", 50, 1000).unwrap();
        assert_eq!(l.held("r", 500), Some("owner1"));
    }

    #[test]
    fn owner_mismatch_release_rejected() {
        let mut l = NamedLock::new();
        l.acquire("r", "owner1", 0, 1000).unwrap();
        assert!(matches!(l.release("r", "owner2").unwrap_err(), LockError::OwnerMismatch));
    }

    #[test]
    fn release_not_held_rejected() {
        let mut l = NamedLock::new();
        assert!(matches!(l.release("r", "x").unwrap_err(), LockError::NotHeld));
    }

    #[test]
    fn expire_sweeps() {
        let mut l = NamedLock::new();
        l.acquire("a", "o", 0, 100).unwrap();
        l.acquire("b", "o", 0, 1000).unwrap();
        assert_eq!(l.expire(500), 1);
        assert!(l.holds.contains_key("b"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut l = NamedLock::new();
        assert!(matches!(l.acquire("", "o", 0, 1).unwrap_err(), LockError::EmptyKey));
        assert!(matches!(l.acquire("k", "", 0, 1).unwrap_err(), LockError::EmptyOwner));
        assert!(matches!(l.acquire("k", "o", 0, 0).unwrap_err(), LockError::ZeroTtl));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = NamedLock::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LockError::SchemaMismatch));
    }

    #[test]
    fn lock_serde_roundtrip() {
        let mut l = NamedLock::new();
        l.acquire("r", "o", 0, 1000).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: NamedLock = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
