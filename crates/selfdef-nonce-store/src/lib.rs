//! `selfdef-nonce-store` — single-use nonce with TTL.
//!
//! observe(nonce, now_ms) is the single primitive: returns Accept
//! if the nonce is unknown (and inserts it with expiry now+ttl), or
//! Replay if already seen and not yet expired. tick(now_ms) drops
//! expired entries. Suitable for HMAC/signature replay defense in
//! the IPS audit/admission path.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Observation outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Accepted (new).
    Accept,
    /// Rejected (replay).
    Replay,
}

/// Store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceStore {
    /// Schema version.
    pub schema_version: String,
    /// TTL ms.
    pub ttl_ms: u64,
    /// nonce → expires_at_ms.
    pub seen: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum NonceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero TTL.
    #[error("ttl_ms must be >= 1")]
    ZeroTtl,
    /// Empty.
    #[error("nonce empty")]
    EmptyNonce,
}

impl NonceStore {
    /// New.
    pub fn new(ttl_ms: u64) -> Result<Self, NonceError> {
        if ttl_ms == 0 { return Err(NonceError::ZeroTtl); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            ttl_ms,
            seen: BTreeMap::new(),
        })
    }

    /// Observe a nonce.
    pub fn observe(&mut self, nonce: &str, now_ms: u64) -> Result<Outcome, NonceError> {
        if nonce.is_empty() { return Err(NonceError::EmptyNonce); }
        // Drop expired *for this nonce* lazily.
        if let Some(&exp) = self.seen.get(nonce) {
            if exp > now_ms {
                return Ok(Outcome::Replay);
            } else {
                self.seen.remove(nonce);
            }
        }
        self.seen.insert(nonce.into(), now_ms.saturating_add(self.ttl_ms));
        Ok(Outcome::Accept)
    }

    /// Drop all expired entries.
    pub fn tick(&mut self, now_ms: u64) {
        self.seen.retain(|_, &mut exp| exp > now_ms);
    }

    /// Count of live entries (not pruned).
    pub fn live(&self, now_ms: u64) -> usize {
        self.seen.values().filter(|&&exp| exp > now_ms).count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), NonceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(NonceError::SchemaMismatch); }
        if self.ttl_ms == 0 { return Err(NonceError::ZeroTtl); }
        for k in self.seen.keys() {
            if k.is_empty() { return Err(NonceError::EmptyNonce); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observe_accepts() {
        let mut s = NonceStore::new(1000).unwrap();
        assert_eq!(s.observe("n1", 0).unwrap(), Outcome::Accept);
    }

    #[test]
    fn replay_detected_within_ttl() {
        let mut s = NonceStore::new(1000).unwrap();
        s.observe("n1", 0).unwrap();
        assert_eq!(s.observe("n1", 500).unwrap(), Outcome::Replay);
    }

    #[test]
    fn replay_window_closes_after_ttl() {
        let mut s = NonceStore::new(1000).unwrap();
        s.observe("n1", 0).unwrap();
        // After expiry, the nonce can be re-accepted.
        assert_eq!(s.observe("n1", 2000).unwrap(), Outcome::Accept);
    }

    #[test]
    fn tick_drops_expired() {
        let mut s = NonceStore::new(1000).unwrap();
        s.observe("a", 0).unwrap();
        s.observe("b", 0).unwrap();
        s.tick(2000);
        assert_eq!(s.live(2000), 0);
        assert!(s.seen.is_empty());
    }

    #[test]
    fn empty_nonce_rejected() {
        let mut s = NonceStore::new(1000).unwrap();
        assert!(matches!(s.observe("", 0).unwrap_err(), NonceError::EmptyNonce));
    }

    #[test]
    fn zero_ttl_rejected() {
        assert!(matches!(NonceStore::new(0).unwrap_err(), NonceError::ZeroTtl));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = NonceStore::new(1000).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), NonceError::SchemaMismatch));
    }

    #[test]
    fn nonce_serde_roundtrip() {
        let mut s = NonceStore::new(500).unwrap();
        s.observe("a", 10).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: NonceStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
