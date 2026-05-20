//! `selfdef-tiered-retention-policy` — hot/warm/cold tiers.
//!
//! Each item ages: 0..hot_ms = Hot, hot_ms..warm_ms = Warm,
//! warm_ms..cold_ms = Cold, >= cold_ms = Expired (purge candidate).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Hot.
    Hot,
    /// Warm.
    Warm,
    /// Cold.
    Cold,
    /// Expired.
    Expired,
}

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TieredRetentionPolicy {
    /// Schema version marker.
    pub schema_version_marker: u32,
    /// Hot upper bound (ms).
    pub hot_ms: u64,
    /// Warm upper bound (ms).
    pub warm_ms: u64,
    /// Cold upper bound (ms).
    pub cold_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RetentionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad bounds.
    #[error("must satisfy hot ({h}) <= warm ({w}) <= cold ({c})")]
    BadBounds {
        /// hot.
        h: u64,
        /// warm.
        w: u64,
        /// cold.
        c: u64,
    },
}

impl TieredRetentionPolicy {
    /// New.
    pub fn new(hot_ms: u64, warm_ms: u64, cold_ms: u64) -> Result<Self, RetentionError> {
        if !(hot_ms <= warm_ms && warm_ms <= cold_ms) {
            return Err(RetentionError::BadBounds { h: hot_ms, w: warm_ms, c: cold_ms });
        }
        Ok(Self {
            schema_version_marker: 1,
            hot_ms,
            warm_ms,
            cold_ms,
        })
    }

    /// Classify an item's tier given its age.
    pub fn classify(&self, age_ms: u64) -> Tier {
        if age_ms < self.hot_ms { Tier::Hot }
        else if age_ms < self.warm_ms { Tier::Warm }
        else if age_ms < self.cold_ms { Tier::Cold }
        else { Tier::Expired }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version_marker != 1 { return Err(RetentionError::SchemaMismatch); }
        if !(self.hot_ms <= self.warm_ms && self.warm_ms <= self.cold_ms) {
            return Err(RetentionError::BadBounds {
                h: self.hot_ms,
                w: self.warm_ms,
                c: self.cold_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_each_tier() {
        let p = TieredRetentionPolicy::new(1000, 5000, 10000).unwrap();
        assert_eq!(p.classify(500), Tier::Hot);
        assert_eq!(p.classify(2000), Tier::Warm);
        assert_eq!(p.classify(7000), Tier::Cold);
        assert_eq!(p.classify(15000), Tier::Expired);
    }

    #[test]
    fn boundary_belongs_upper() {
        let p = TieredRetentionPolicy::new(1000, 5000, 10000).unwrap();
        assert_eq!(p.classify(1000), Tier::Warm);
        assert_eq!(p.classify(5000), Tier::Cold);
        assert_eq!(p.classify(10000), Tier::Expired);
    }

    #[test]
    fn bad_bounds_rejected() {
        assert!(matches!(TieredRetentionPolicy::new(5000, 1000, 10000).unwrap_err(), RetentionError::BadBounds { .. }));
        assert!(matches!(TieredRetentionPolicy::new(1000, 5000, 4000).unwrap_err(), RetentionError::BadBounds { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TieredRetentionPolicy::new(1, 2, 3).unwrap();
        p.schema_version_marker = 99;
        assert!(matches!(p.validate().unwrap_err(), RetentionError::SchemaMismatch));
    }

    #[test]
    fn retention_serde_roundtrip() {
        let p = TieredRetentionPolicy::new(1000, 5000, 10000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: TieredRetentionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
