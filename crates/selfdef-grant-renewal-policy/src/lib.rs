//! `selfdef-grant-renewal-policy` — IPS-side gate over grant renewal.
//!
//! Renewal is only allowed if:
//! - Grant still has `min_remaining_seconds` left (default 60s).
//! - Renewal `delta_seconds` ≤ `max_delta_seconds` (default 86_400s).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Renewal policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRenewalPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Minimum remaining seconds the grant must still have to be renewable.
    pub min_remaining_seconds: u32,
    /// Maximum renewal delta seconds.
    pub max_delta_seconds: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RenewalError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Below min_remaining.
    #[error("remaining {remaining}s < min {min}s")]
    BelowMinRemaining {
        /// remaining.
        remaining: u32,
        /// min.
        min: u32,
    },
    /// Delta too big.
    #[error("delta {delta}s > max {max}s")]
    DeltaTooLarge {
        /// delta.
        delta: u32,
        /// max.
        max: u32,
    },
    /// Delta 0.
    #[error("delta zero")]
    DeltaZero,
}

impl GrantRenewalPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            min_remaining_seconds: 60,
            max_delta_seconds: 86_400,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RenewalError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RenewalError::SchemaMismatch);
        }
        Ok(())
    }

    /// Authorize a renewal.
    pub fn authorize(
        &self,
        remaining_seconds: u32,
        delta_seconds: u32,
    ) -> Result<(), RenewalError> {
        if delta_seconds == 0 {
            return Err(RenewalError::DeltaZero);
        }
        if remaining_seconds < self.min_remaining_seconds {
            return Err(RenewalError::BelowMinRemaining {
                remaining: remaining_seconds,
                min: self.min_remaining_seconds,
            });
        }
        if delta_seconds > self.max_delta_seconds {
            return Err(RenewalError::DeltaTooLarge {
                delta: delta_seconds,
                max: self.max_delta_seconds,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        GrantRenewalPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn renewal_within_limits_ok() {
        let p = GrantRenewalPolicy::canonical();
        p.authorize(120, 60).unwrap();
    }

    #[test]
    fn below_min_remaining_rejected() {
        let p = GrantRenewalPolicy::canonical();
        assert!(matches!(p.authorize(30, 60).unwrap_err(), RenewalError::BelowMinRemaining { .. }));
    }

    #[test]
    fn delta_too_large_rejected() {
        let p = GrantRenewalPolicy::canonical();
        assert!(matches!(p.authorize(120, 100_000).unwrap_err(), RenewalError::DeltaTooLarge { .. }));
    }

    #[test]
    fn delta_zero_rejected() {
        let p = GrantRenewalPolicy::canonical();
        assert!(matches!(p.authorize(120, 0).unwrap_err(), RenewalError::DeltaZero));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = GrantRenewalPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), RenewalError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = GrantRenewalPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: GrantRenewalPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
