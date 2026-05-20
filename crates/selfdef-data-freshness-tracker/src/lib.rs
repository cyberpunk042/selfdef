//! `selfdef-data-freshness-tracker` — per-key freshness.
//!
//! Per key, last_updated_ms. age = now - last_updated. Bands:
//! < fresh_ms = Fresh, < stale_ms = Stale, else Expired. No entry
//! → Unknown.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Freshness band.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    /// Fresh.
    Fresh,
    /// Stale.
    Stale,
    /// Expired.
    Expired,
    /// Unknown (no record).
    Unknown,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataFreshnessTracker {
    /// Schema version.
    pub schema_version: String,
    /// Fresh band upper.
    pub fresh_ms: u64,
    /// Stale band upper.
    pub stale_ms: u64,
    /// key → last_updated_ms.
    pub updated: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FreshnessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Bad bounds.
    #[error("fresh ({f}) >= stale ({s})")]
    BadBounds {
        /// f.
        f: u64,
        /// s.
        s: u64,
    },
}

impl DataFreshnessTracker {
    /// New.
    pub fn new(fresh_ms: u64, stale_ms: u64) -> Result<Self, FreshnessError> {
        if fresh_ms >= stale_ms { return Err(FreshnessError::BadBounds { f: fresh_ms, s: stale_ms }); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            fresh_ms,
            stale_ms,
            updated: BTreeMap::new(),
        })
    }

    /// Record update.
    pub fn update(&mut self, key: &str, ts_ms: u64) -> Result<(), FreshnessError> {
        if key.is_empty() { return Err(FreshnessError::EmptyKey); }
        self.updated.insert(key.into(), ts_ms);
        Ok(())
    }

    /// Check freshness.
    pub fn check(&self, key: &str, now_ms: u64) -> Freshness {
        let Some(last) = self.updated.get(key) else { return Freshness::Unknown; };
        let age = now_ms.saturating_sub(*last);
        if age < self.fresh_ms { Freshness::Fresh }
        else if age < self.stale_ms { Freshness::Stale }
        else { Freshness::Expired }
    }

    /// Remove.
    pub fn forget(&mut self, key: &str) -> bool {
        self.updated.remove(key).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FreshnessError::SchemaMismatch); }
        if self.fresh_ms >= self.stale_ms { return Err(FreshnessError::BadBounds { f: self.fresh_ms, s: self.stale_ms }); }
        for k in self.updated.keys() {
            if k.is_empty() { return Err(FreshnessError::EmptyKey); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_under_fresh_ms() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 0).unwrap();
        assert_eq!(t.check("k", 500), Freshness::Fresh);
    }

    #[test]
    fn stale_in_band() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 0).unwrap();
        assert_eq!(t.check("k", 2000), Freshness::Stale);
    }

    #[test]
    fn expired_past_stale() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 0).unwrap();
        assert_eq!(t.check("k", 10_000), Freshness::Expired);
    }

    #[test]
    fn unknown_when_no_record() {
        let t = DataFreshnessTracker::new(1000, 5000).unwrap();
        assert_eq!(t.check("k", 0), Freshness::Unknown);
    }

    #[test]
    fn update_resets_age() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 0).unwrap();
        t.update("k", 4000).unwrap();
        assert_eq!(t.check("k", 4500), Freshness::Fresh);
    }

    #[test]
    fn forget_makes_unknown() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 0).unwrap();
        t.forget("k");
        assert_eq!(t.check("k", 0), Freshness::Unknown);
    }

    #[test]
    fn bad_bounds_rejected() {
        assert!(matches!(DataFreshnessTracker::new(5000, 1000).unwrap_err(), FreshnessError::BadBounds { .. }));
    }

    #[test]
    fn empty_key_rejected() {
        let mut t = DataFreshnessTracker::new(1, 2).unwrap();
        assert!(matches!(t.update("", 0).unwrap_err(), FreshnessError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = DataFreshnessTracker::new(1, 2).unwrap();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), FreshnessError::SchemaMismatch));
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut t = DataFreshnessTracker::new(1000, 5000).unwrap();
        t.update("k", 100).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: DataFreshnessTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
