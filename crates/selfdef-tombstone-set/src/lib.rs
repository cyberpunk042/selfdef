//! `selfdef-tombstone-set` — soft-delete marker set with grace TTL.
//!
//! mark(id, now) records a tombstone for id; is_tombstoned(id, now)
//! true iff a non-expired tombstone exists. compact(now) prunes
//! expired tombstones. Grace TTL ensures distributed replicas see
//! the delete before the record's "absence" is reused by an
//! insert with the same id (which is the classic resurrection bug
//! a tombstone prevents).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TombstoneSet {
    /// Schema version.
    pub schema_version: String,
    /// Grace TTL ms.
    pub grace_ttl_ms: u64,
    /// id → expires_at_ms.
    pub tombs: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TombError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero TTL.
    #[error("grace_ttl_ms must be >= 1")]
    ZeroTtl,
    /// Empty.
    #[error("id empty")]
    EmptyId,
}

impl TombstoneSet {
    /// New.
    pub fn new(grace_ttl_ms: u64) -> Result<Self, TombError> {
        if grace_ttl_ms == 0 {
            return Err(TombError::ZeroTtl);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            grace_ttl_ms,
            tombs: BTreeMap::new(),
        })
    }

    /// Mark id as tombstoned.
    pub fn mark(&mut self, id: &str, now_ms: u64) -> Result<(), TombError> {
        if id.is_empty() {
            return Err(TombError::EmptyId);
        }
        let exp = now_ms.saturating_add(self.grace_ttl_ms);
        self.tombs.insert(id.into(), exp);
        Ok(())
    }

    /// True iff id has a live (non-expired) tombstone.
    pub fn is_tombstoned(&self, id: &str, now_ms: u64) -> bool {
        match self.tombs.get(id) {
            Some(&exp) => exp > now_ms,
            None => false,
        }
    }

    /// Drop expired tombstones.
    pub fn compact(&mut self, now_ms: u64) {
        self.tombs.retain(|_, &mut exp| exp > now_ms);
    }

    /// Live tombstone count.
    pub fn len(&self, now_ms: u64) -> usize {
        self.tombs.values().filter(|&&exp| exp > now_ms).count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TombError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TombError::SchemaMismatch);
        }
        if self.grace_ttl_ms == 0 {
            return Err(TombError::ZeroTtl);
        }
        for k in self.tombs.keys() {
            if k.is_empty() {
                return Err(TombError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_check() {
        let mut s = TombstoneSet::new(1000).unwrap();
        s.mark("a", 0).unwrap();
        assert!(s.is_tombstoned("a", 500));
    }

    #[test]
    fn expires_after_grace() {
        let mut s = TombstoneSet::new(1000).unwrap();
        s.mark("a", 0).unwrap();
        assert!(!s.is_tombstoned("a", 2000));
    }

    #[test]
    fn re_mark_extends_expiry() {
        let mut s = TombstoneSet::new(1000).unwrap();
        s.mark("a", 0).unwrap();
        s.mark("a", 500).unwrap();
        // Now expires at 1500; check at 1200.
        assert!(s.is_tombstoned("a", 1200));
    }

    #[test]
    fn compact_drops_expired() {
        let mut s = TombstoneSet::new(1000).unwrap();
        s.mark("a", 0).unwrap();
        s.mark("b", 0).unwrap();
        s.compact(2000);
        assert!(s.tombs.is_empty());
    }

    #[test]
    fn unknown_not_tombstoned() {
        let s = TombstoneSet::new(1000).unwrap();
        assert!(!s.is_tombstoned("nope", 0));
    }

    #[test]
    fn empty_id_rejected() {
        let mut s = TombstoneSet::new(1000).unwrap();
        assert!(matches!(s.mark("", 0).unwrap_err(), TombError::EmptyId));
    }

    #[test]
    fn zero_ttl_rejected() {
        assert!(matches!(
            TombstoneSet::new(0).unwrap_err(),
            TombError::ZeroTtl
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = TombstoneSet::new(100).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            TombError::SchemaMismatch
        ));
    }

    #[test]
    fn tomb_serde_roundtrip() {
        let mut s = TombstoneSet::new(500).unwrap();
        s.mark("a", 10).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: TombstoneSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
