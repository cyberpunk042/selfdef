//! `selfdef-session-lifetime-policy` — per-Profile session lifetime gate.
//!
//! Each Profile carries `max_age_ms` (absolute lifetime) and
//! `max_idle_ms` (gap since last interaction). `classify(profile,
//! age, idle)` returns Active / IdleExpired{idle_cap} /
//! AgeExpired{age_cap} / Unconfigured. AgeExpired takes precedence
//! when both caps are exceeded.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Per-profile lifetime caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileLifetime {
    /// Absolute lifetime cap (ms).
    pub max_age_ms: u64,
    /// Idle gap cap (ms).
    pub max_idle_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionLifetimePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile caps.
    pub profiles: BTreeMap<Profile, ProfileLifetime>,
}

/// Classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LifetimeVerdict {
    /// Active.
    Active,
    /// Idle gap exceeded.
    IdleExpired {
        /// idle cap ms.
        idle_cap_ms: u64,
    },
    /// Age cap exceeded (takes precedence over idle).
    AgeExpired {
        /// age cap ms.
        age_cap_ms: u64,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LifetimeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SessionLifetimePolicy {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        let h: u64 = 60 * 60 * 1000;
        let m: u64 = 60 * 1000;
        p.insert(
            Profile::Private,
            ProfileLifetime {
                max_age_ms: h,
                max_idle_ms: 5 * m,
            },
        );
        p.insert(
            Profile::Fast,
            ProfileLifetime {
                max_age_ms: 4 * h,
                max_idle_ms: 15 * m,
            },
        );
        p.insert(
            Profile::Careful,
            ProfileLifetime {
                max_age_ms: h,
                max_idle_ms: 10 * m,
            },
        );
        p.insert(
            Profile::Autonomous,
            ProfileLifetime {
                max_age_ms: 8 * h,
                max_idle_ms: 30 * m,
            },
        );
        p.insert(
            Profile::Experimental,
            ProfileLifetime {
                max_age_ms: 16 * h,
                max_idle_ms: 60 * m,
            },
        );
        p.insert(
            Profile::Production,
            ProfileLifetime {
                max_age_ms: 2 * h,
                max_idle_ms: 10 * m,
            },
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, age_ms: u64, idle_ms: u64) -> LifetimeVerdict {
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return LifetimeVerdict::Unconfigured,
        };
        if age_ms >= cfg.max_age_ms {
            return LifetimeVerdict::AgeExpired {
                age_cap_ms: cfg.max_age_ms,
            };
        }
        if idle_ms >= cfg.max_idle_ms {
            return LifetimeVerdict::IdleExpired {
                idle_cap_ms: cfg.max_idle_ms,
            };
        }
        LifetimeVerdict::Active
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LifetimeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LifetimeError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SessionLifetimePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn active_under_caps() {
        let p = SessionLifetimePolicy::canonical();
        assert_eq!(
            p.classify(Profile::Fast, 1000, 1000),
            LifetimeVerdict::Active
        );
    }

    #[test]
    fn idle_expired() {
        let p = SessionLifetimePolicy::canonical();
        // Fast idle cap 15m = 900_000 ms.
        let v = p.classify(Profile::Fast, 1_000_000, 900_001);
        assert_eq!(
            v,
            LifetimeVerdict::IdleExpired {
                idle_cap_ms: 900_000
            }
        );
    }

    #[test]
    fn age_expired() {
        let p = SessionLifetimePolicy::canonical();
        // Fast age cap 4h = 14_400_000.
        let v = p.classify(Profile::Fast, 14_400_001, 0);
        assert_eq!(
            v,
            LifetimeVerdict::AgeExpired {
                age_cap_ms: 14_400_000
            }
        );
    }

    #[test]
    fn age_precedence_over_idle() {
        let p = SessionLifetimePolicy::canonical();
        // Both caps exceeded; AgeExpired should win.
        let v = p.classify(Profile::Fast, 99_999_999, 99_999_999);
        assert!(matches!(v, LifetimeVerdict::AgeExpired { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut p = SessionLifetimePolicy::canonical();
        p.profiles.clear();
        assert_eq!(
            p.classify(Profile::Fast, 0, 0),
            LifetimeVerdict::Unconfigured
        );
    }

    #[test]
    fn experimental_long_session() {
        let p = SessionLifetimePolicy::canonical();
        let h = 60 * 60 * 1000;
        // 12 hours; Experimental cap is 16h.
        assert_eq!(
            p.classify(Profile::Experimental, 12 * h, 0),
            LifetimeVerdict::Active
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SessionLifetimePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            LifetimeError::SchemaMismatch
        ));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SessionLifetimePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SessionLifetimePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
