//! `selfdef-substrate-network-clock-policy` — clock-skew gate.
//!
//! Local clock vs authoritative-NTP reading. drift = abs(local -
//! authoritative). decide(drift_seconds) returns Ok / Warn / Reject.
//! Catches winder-back attempts.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClockDecision {
    /// Drift within warn_seconds.
    Ok,
    /// Drift between warn_seconds and reject_seconds.
    Warn,
    /// Drift beyond reject_seconds.
    Reject,
    /// No authoritative reading available.
    NoAuthority,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateNetworkClockPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Drift considered Warn at-or-above (seconds).
    pub warn_seconds: u32,
    /// Drift considered Reject at-or-above (seconds).
    pub reject_seconds: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ClockError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad thresholds.
    #[error("warn_seconds {warn} >= reject_seconds {reject}")]
    BadThresholds {
        /// warn.
        warn: u32,
        /// reject.
        reject: u32,
    },
}

impl SubstrateNetworkClockPolicy {
    /// Canonical: Warn at 5s, Reject at 60s.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            warn_seconds: 5,
            reject_seconds: 60,
        }
    }

    /// Decide with authoritative drift.
    pub fn decide(&self, drift_seconds: Option<u32>) -> ClockDecision {
        match drift_seconds {
            None => ClockDecision::NoAuthority,
            Some(d) if d >= self.reject_seconds => ClockDecision::Reject,
            Some(d) if d >= self.warn_seconds => ClockDecision::Warn,
            Some(_) => ClockDecision::Ok,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ClockError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ClockError::SchemaMismatch);
        }
        if self.warn_seconds >= self.reject_seconds {
            return Err(ClockError::BadThresholds {
                warn: self.warn_seconds,
                reject: self.reject_seconds,
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
        SubstrateNetworkClockPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn no_authority_reported() {
        let p = SubstrateNetworkClockPolicy::canonical();
        assert_eq!(p.decide(None), ClockDecision::NoAuthority);
    }

    #[test]
    fn low_drift_ok() {
        let p = SubstrateNetworkClockPolicy::canonical();
        assert_eq!(p.decide(Some(2)), ClockDecision::Ok);
    }

    #[test]
    fn medium_drift_warn() {
        let p = SubstrateNetworkClockPolicy::canonical();
        assert_eq!(p.decide(Some(5)), ClockDecision::Warn);
        assert_eq!(p.decide(Some(30)), ClockDecision::Warn);
    }

    #[test]
    fn high_drift_reject() {
        let p = SubstrateNetworkClockPolicy::canonical();
        assert_eq!(p.decide(Some(60)), ClockDecision::Reject);
        assert_eq!(p.decide(Some(3600)), ClockDecision::Reject);
    }

    #[test]
    fn bad_thresholds_rejected() {
        let mut p = SubstrateNetworkClockPolicy::canonical();
        p.warn_seconds = 100;
        assert!(matches!(p.validate().unwrap_err(), ClockError::BadThresholds { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateNetworkClockPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ClockError::SchemaMismatch));
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(serde_json::to_string(&ClockDecision::NoAuthority).unwrap(), "\"no-authority\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SubstrateNetworkClockPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateNetworkClockPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
