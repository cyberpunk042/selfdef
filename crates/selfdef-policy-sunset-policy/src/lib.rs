//! `selfdef-policy-sunset-policy` — temporary-rule sunset.
//!
//! Each policy can declare `(sunset_at_ms, warn_window_ms)`.
//! `classify(policy_id, now)` returns:
//!   * `Active` — now < sunset_at - warn_window_ms.
//!   * `Warning { remaining_ms }` — within the warn window.
//!   * `Expired` — now ≥ sunset_at.
//!   * `Unknown` — policy not registered.
//!
//! `rotate(now)` removes + returns Expired policies so the audit log
//! can record each sunset.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One sunset entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SunsetEntry {
    /// Sunset ts ms.
    pub sunset_at_ms: u64,
    /// Warn window (ms before sunset).
    pub warn_window_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySunsetPolicy {
    /// Schema version.
    pub schema_version: String,
    /// policy_id → entry.
    pub entries: BTreeMap<String, SunsetEntry>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SunsetVerdict {
    /// Still active and outside the warning window.
    Active,
    /// Inside the warning window.
    Warning {
        /// ms until sunset.
        remaining_ms: u64,
    },
    /// At or past sunset.
    Expired,
    /// No record.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SunsetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyId,
}

impl PolicySunsetPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        policy_id: &str,
        sunset_at_ms: u64,
        warn_window_ms: u64,
    ) -> Result<(), SunsetError> {
        if policy_id.is_empty() {
            return Err(SunsetError::EmptyId);
        }
        self.entries.insert(
            policy_id.into(),
            SunsetEntry {
                sunset_at_ms,
                warn_window_ms,
            },
        );
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, policy_id: &str, now_ms: u64) -> SunsetVerdict {
        let e = match self.entries.get(policy_id).copied() {
            Some(e) => e,
            None => return SunsetVerdict::Unknown,
        };
        if now_ms >= e.sunset_at_ms {
            return SunsetVerdict::Expired;
        }
        let warn_start = e.sunset_at_ms.saturating_sub(e.warn_window_ms);
        if now_ms >= warn_start {
            SunsetVerdict::Warning {
                remaining_ms: e.sunset_at_ms - now_ms,
            }
        } else {
            SunsetVerdict::Active
        }
    }

    /// Rotate. Returns the expired entries (removed from the map).
    pub fn rotate(&mut self, now_ms: u64) -> Vec<(String, SunsetEntry)> {
        let expired: Vec<(String, SunsetEntry)> = self
            .entries
            .iter()
            .filter(|(_, e)| now_ms >= e.sunset_at_ms)
            .map(|(k, e)| (k.clone(), *e))
            .collect();
        for (k, _) in &expired {
            self.entries.remove(k);
        }
        expired
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SunsetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SunsetError::SchemaMismatch);
        }
        for k in self.entries.keys() {
            if k.is_empty() {
                return Err(SunsetError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for PolicySunsetPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_when_outside_warn() {
        let mut p = PolicySunsetPolicy::new();
        p.register("rule-1", 10_000, 1_000).unwrap();
        assert_eq!(p.classify("rule-1", 5_000), SunsetVerdict::Active);
    }

    #[test]
    fn warning_when_inside_warn_window() {
        let mut p = PolicySunsetPolicy::new();
        p.register("rule-1", 10_000, 2_000).unwrap();
        let v = p.classify("rule-1", 9_000);
        assert_eq!(
            v,
            SunsetVerdict::Warning {
                remaining_ms: 1_000
            }
        );
    }

    #[test]
    fn expired_at_or_past() {
        let mut p = PolicySunsetPolicy::new();
        p.register("rule-1", 10_000, 0).unwrap();
        assert_eq!(p.classify("rule-1", 10_000), SunsetVerdict::Expired);
        assert_eq!(p.classify("rule-1", 99_999), SunsetVerdict::Expired);
    }

    #[test]
    fn unknown_policy() {
        let p = PolicySunsetPolicy::new();
        assert_eq!(p.classify("nope", 0), SunsetVerdict::Unknown);
    }

    #[test]
    fn rotate_returns_and_removes_expired() {
        let mut p = PolicySunsetPolicy::new();
        p.register("a", 10_000, 0).unwrap();
        p.register("b", 100_000, 0).unwrap();
        let removed = p.rotate(50_000);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, "a");
        assert!(p.entries.contains_key("b"));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PolicySunsetPolicy::new();
        assert!(matches!(
            p.register("", 0, 0).unwrap_err(),
            SunsetError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicySunsetPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            SunsetError::SchemaMismatch
        ));
    }

    #[test]
    fn sunset_serde_roundtrip() {
        let mut p = PolicySunsetPolicy::new();
        p.register("a", 10_000, 1_000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicySunsetPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
