//! `selfdef-stale-set` — keys flagged stale-pending-refresh.
//!
//! State machine per key:
//!   absent → flag(now) → Pending{since}
//!   Pending → start_refresh(now) → Refreshing{started}
//!   Refreshing → confirm(now) → absent (key is fresh again)
//!   Refreshing → fail(err)    → Pending (revert to flagged)
//! is_stale(key) true iff Pending or Refreshing.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-key state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase", content = "since_ms")]
pub enum Stale {
    /// Flagged but no refresh in flight.
    Pending(u64),
    /// Refresh in flight.
    Refreshing(u64),
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaleSet {
    /// Schema version.
    pub schema_version: String,
    /// key → state.
    pub stale: BTreeMap<String, Stale>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StaleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Unknown.
    #[error("unknown key: {0}")]
    Unknown(String),
    /// Invalid phase.
    #[error("invalid phase for operation")]
    InvalidPhase,
}

impl StaleSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            stale: BTreeMap::new(),
        }
    }

    /// Flag.
    pub fn flag(&mut self, key: &str, now_ms: u64) -> Result<(), StaleError> {
        if key.is_empty() {
            return Err(StaleError::EmptyKey);
        }
        self.stale
            .entry(key.into())
            .or_insert(Stale::Pending(now_ms));
        Ok(())
    }

    /// Begin refresh.
    pub fn start_refresh(&mut self, key: &str, now_ms: u64) -> Result<(), StaleError> {
        let s = self
            .stale
            .get_mut(key)
            .ok_or_else(|| StaleError::Unknown(key.into()))?;
        match s {
            Stale::Pending(_) => {
                *s = Stale::Refreshing(now_ms);
                Ok(())
            }
            _ => Err(StaleError::InvalidPhase),
        }
    }

    /// Confirm refresh succeeded — clears the key.
    pub fn confirm(&mut self, key: &str) -> Result<(), StaleError> {
        match self.stale.get(key) {
            Some(Stale::Refreshing(_)) => {
                self.stale.remove(key);
                Ok(())
            }
            Some(_) => Err(StaleError::InvalidPhase),
            None => Err(StaleError::Unknown(key.into())),
        }
    }

    /// Refresh failed — revert to Pending (carries the original since).
    pub fn fail(&mut self, key: &str, now_ms: u64) -> Result<(), StaleError> {
        let s = self
            .stale
            .get_mut(key)
            .ok_or_else(|| StaleError::Unknown(key.into()))?;
        match s {
            Stale::Refreshing(_) => {
                *s = Stale::Pending(now_ms);
                Ok(())
            }
            _ => Err(StaleError::InvalidPhase),
        }
    }

    /// Is key stale (Pending OR Refreshing)?
    pub fn is_stale(&self, key: &str) -> bool {
        self.stale.contains_key(key)
    }

    /// Pending-only count (queue depth for refresh scheduler).
    pub fn pending_count(&self) -> usize {
        self.stale
            .values()
            .filter(|s| matches!(s, Stale::Pending(_)))
            .count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StaleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StaleError::SchemaMismatch);
        }
        for k in self.stale.keys() {
            if k.is_empty() {
                return Err(StaleError::EmptyKey);
            }
        }
        Ok(())
    }
}

impl Default for StaleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_makes_stale() {
        let mut s = StaleSet::new();
        s.flag("a", 100).unwrap();
        assert!(s.is_stale("a"));
        assert_eq!(s.pending_count(), 1);
    }

    #[test]
    fn refresh_confirm_clears() {
        let mut s = StaleSet::new();
        s.flag("a", 0).unwrap();
        s.start_refresh("a", 100).unwrap();
        s.confirm("a").unwrap();
        assert!(!s.is_stale("a"));
    }

    #[test]
    fn fail_reverts_to_pending() {
        let mut s = StaleSet::new();
        s.flag("a", 0).unwrap();
        s.start_refresh("a", 100).unwrap();
        s.fail("a", 200).unwrap();
        assert!(matches!(s.stale.get("a"), Some(Stale::Pending(_))));
    }

    #[test]
    fn double_flag_idempotent_since_preserved() {
        let mut s = StaleSet::new();
        s.flag("a", 100).unwrap();
        s.flag("a", 500).unwrap();
        assert!(matches!(s.stale.get("a"), Some(Stale::Pending(100))));
    }

    #[test]
    fn confirm_when_pending_rejected() {
        let mut s = StaleSet::new();
        s.flag("a", 0).unwrap();
        assert!(matches!(
            s.confirm("a").unwrap_err(),
            StaleError::InvalidPhase
        ));
    }

    #[test]
    fn unknown_key_rejected() {
        let mut s = StaleSet::new();
        assert!(matches!(
            s.start_refresh("nope", 0).unwrap_err(),
            StaleError::Unknown(_)
        ));
    }

    #[test]
    fn empty_key_rejected() {
        let mut s = StaleSet::new();
        assert!(matches!(s.flag("", 0).unwrap_err(), StaleError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = StaleSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            StaleError::SchemaMismatch
        ));
    }

    #[test]
    fn stale_serde_roundtrip() {
        let mut s = StaleSet::new();
        s.flag("a", 0).unwrap();
        s.start_refresh("a", 10).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: StaleSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
