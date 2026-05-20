//! `selfdef-idempotency-key-store` — idempotency keys + responses.
//!
//! Entry{key, request_fingerprint, response_status, response_body,
//! expires_at_ms}. begin(key, fp, now, ttl) returns Outcome::New if
//! not present (caller proceeds), Outcome::ReplayMatch if present
//! and fp matches (caller returns stored response), Outcome::Conflict
//! if present with different fp (caller rejects). commit(key, status,
//! body) records the response. compact prunes expired.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Stored entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Request fingerprint.
    pub request_fingerprint: String,
    /// Response status.
    pub response_status: u16,
    /// Response body.
    pub response_body: String,
    /// Whether the response has been committed.
    pub committed: bool,
    /// Expires ts ms.
    pub expires_at_ms: u64,
}

/// Outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Outcome {
    /// New (proceed).
    New,
    /// Already begun, same fingerprint, not yet committed.
    InProgress,
    /// Already committed, replay the response.
    Replay {
        /// Status.
        status: u16,
        /// Body.
        body: String,
    },
    /// Fingerprint mismatch.
    Conflict,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdempotencyKeyStore {
    /// Schema version.
    pub schema_version: String,
    /// TTL ms.
    pub ttl_ms: u64,
    /// key → entry.
    pub entries: BTreeMap<String, Entry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IdemError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero ttl.
    #[error("ttl_ms must be >= 1")]
    ZeroTtl,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Unknown.
    #[error("key not found: {0}")]
    NotFound(String),
}

impl IdempotencyKeyStore {
    /// New.
    pub fn new(ttl_ms: u64) -> Result<Self, IdemError> {
        if ttl_ms == 0 { return Err(IdemError::ZeroTtl); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            ttl_ms,
            entries: BTreeMap::new(),
        })
    }

    /// Begin (or replay) for key+fp at now_ms.
    pub fn begin(&mut self, key: &str, fingerprint: &str, now_ms: u64) -> Result<Outcome, IdemError> {
        if key.is_empty() { return Err(IdemError::EmptyKey); }
        // Expire stale entries lazily.
        if let Some(e) = self.entries.get(key) {
            if e.expires_at_ms <= now_ms { self.entries.remove(key); }
        }
        match self.entries.get(key) {
            None => {
                self.entries.insert(key.into(), Entry {
                    request_fingerprint: fingerprint.into(),
                    response_status: 0,
                    response_body: String::new(),
                    committed: false,
                    expires_at_ms: now_ms.saturating_add(self.ttl_ms),
                });
                Ok(Outcome::New)
            }
            Some(e) => {
                if e.request_fingerprint != fingerprint {
                    return Ok(Outcome::Conflict);
                }
                if e.committed {
                    Ok(Outcome::Replay {
                        status: e.response_status,
                        body: e.response_body.clone(),
                    })
                } else {
                    Ok(Outcome::InProgress)
                }
            }
        }
    }

    /// Commit a response for key.
    pub fn commit(&mut self, key: &str, status: u16, body: &str) -> Result<(), IdemError> {
        let e = self.entries.get_mut(key).ok_or_else(|| IdemError::NotFound(key.into()))?;
        e.response_status = status;
        e.response_body = body.into();
        e.committed = true;
        Ok(())
    }

    /// Drop expired entries.
    pub fn compact(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| e.expires_at_ms > now_ms);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IdemError> {
        if self.schema_version != SCHEMA_VERSION { return Err(IdemError::SchemaMismatch); }
        if self.ttl_ms == 0 { return Err(IdemError::ZeroTtl); }
        for k in self.entries.keys() {
            if k.is_empty() { return Err(IdemError::EmptyKey); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_begin_is_new() {
        let mut s = IdempotencyKeyStore::new(60_000).unwrap();
        assert!(matches!(s.begin("k1", "fp", 0).unwrap(), Outcome::New));
    }

    #[test]
    fn second_begin_same_fp_in_progress() {
        let mut s = IdempotencyKeyStore::new(60_000).unwrap();
        s.begin("k1", "fp", 0).unwrap();
        assert!(matches!(s.begin("k1", "fp", 100).unwrap(), Outcome::InProgress));
    }

    #[test]
    fn after_commit_replays_response() {
        let mut s = IdempotencyKeyStore::new(60_000).unwrap();
        s.begin("k1", "fp", 0).unwrap();
        s.commit("k1", 200, "ok").unwrap();
        match s.begin("k1", "fp", 100).unwrap() {
            Outcome::Replay { status, body } => {
                assert_eq!(status, 200);
                assert_eq!(body, "ok");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn different_fp_conflict() {
        let mut s = IdempotencyKeyStore::new(60_000).unwrap();
        s.begin("k1", "fp1", 0).unwrap();
        assert_eq!(s.begin("k1", "fp2", 100).unwrap(), Outcome::Conflict);
    }

    #[test]
    fn expired_treated_as_new() {
        let mut s = IdempotencyKeyStore::new(1000).unwrap();
        s.begin("k1", "fp", 0).unwrap();
        // After ttl elapses, begin treats it as a fresh request.
        assert!(matches!(s.begin("k1", "fp", 2000).unwrap(), Outcome::New));
    }

    #[test]
    fn empty_key_rejected() {
        let mut s = IdempotencyKeyStore::new(1000).unwrap();
        assert!(matches!(s.begin("", "fp", 0).unwrap_err(), IdemError::EmptyKey));
    }

    #[test]
    fn commit_unknown_rejected() {
        let mut s = IdempotencyKeyStore::new(1000).unwrap();
        assert!(matches!(s.commit("nope", 200, "x").unwrap_err(), IdemError::NotFound(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = IdempotencyKeyStore::new(1000).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), IdemError::SchemaMismatch));
    }

    #[test]
    fn idem_serde_roundtrip() {
        let mut s = IdempotencyKeyStore::new(1000).unwrap();
        s.begin("k1", "fp", 0).unwrap();
        s.commit("k1", 200, "ok").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: IdempotencyKeyStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
