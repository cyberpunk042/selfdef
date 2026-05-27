//! `selfdef-fact-recall-cache-policy` — per-FactClass cache TTL.
//!
//! 5 FactClasses with their own ttl_seconds + may_serve_stale.
//! decide(class, age, allow_stale) returns Hit / Stale / Miss.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Fact class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactClass {
    /// Stable (rarely changes; e.g., laws of physics).
    Stable,
    /// Slow-evolving (e.g., country capitals).
    SlowEvolving,
    /// Volatile (stock prices, exchange rates).
    Volatile,
    /// Operator-owned (operator's name, etc.).
    Operator,
    /// Computed (derived from other facts).
    Computed,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheVerdict {
    /// Fresh.
    Hit,
    /// Stale but may be served (allow_stale + class.may_serve_stale).
    Stale,
    /// Miss — must re-fetch.
    Miss,
}

/// Per-class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassConfig {
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// May serve stale on allow_stale hint?
    pub may_serve_stale: bool,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FactRecallCachePolicy {
    /// Schema version.
    pub schema_version: String,
    /// stable.
    pub stable: ClassConfig,
    /// slow-evolving.
    pub slow_evolving: ClassConfig,
    /// volatile.
    pub volatile: ClassConfig,
    /// operator.
    pub operator: ClassConfig,
    /// computed.
    pub computed: ClassConfig,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// TTL zero.
    #[error("class {0:?} ttl_seconds zero")]
    TtlZero(FactClass),
}

impl FactRecallCachePolicy {
    /// Canonical:
    /// * Stable: 90d, may serve stale.
    /// * SlowEvolving: 7d, may serve stale.
    /// * Volatile: 30s, no stale.
    /// * Operator: 365d, no stale (must always be fresh from operator authority).
    /// * Computed: 1h, may serve stale.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            stable: ClassConfig {
                ttl_seconds: 90 * 86400,
                may_serve_stale: true,
            },
            slow_evolving: ClassConfig {
                ttl_seconds: 7 * 86400,
                may_serve_stale: true,
            },
            volatile: ClassConfig {
                ttl_seconds: 30,
                may_serve_stale: false,
            },
            operator: ClassConfig {
                ttl_seconds: 365 * 86400,
                may_serve_stale: false,
            },
            computed: ClassConfig {
                ttl_seconds: 3600,
                may_serve_stale: true,
            },
        }
    }

    /// Config for a class.
    pub fn config(&self, c: FactClass) -> ClassConfig {
        match c {
            FactClass::Stable => self.stable,
            FactClass::SlowEvolving => self.slow_evolving,
            FactClass::Volatile => self.volatile,
            FactClass::Operator => self.operator,
            FactClass::Computed => self.computed,
        }
    }

    /// Decide.
    pub fn decide(&self, class: FactClass, age_seconds: u64, allow_stale: bool) -> CacheVerdict {
        let cfg = self.config(class);
        if age_seconds <= cfg.ttl_seconds {
            return CacheVerdict::Hit;
        }
        if allow_stale && cfg.may_serve_stale {
            return CacheVerdict::Stale;
        }
        CacheVerdict::Miss
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CacheError::SchemaMismatch);
        }
        for (c, cfg) in [
            (FactClass::Stable, self.stable),
            (FactClass::SlowEvolving, self.slow_evolving),
            (FactClass::Volatile, self.volatile),
            (FactClass::Operator, self.operator),
            (FactClass::Computed, self.computed),
        ] {
            if cfg.ttl_seconds == 0 {
                return Err(CacheError::TtlZero(c));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        FactRecallCachePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn fresh_within_ttl_hit() {
        let p = FactRecallCachePolicy::canonical();
        assert_eq!(p.decide(FactClass::Volatile, 10, false), CacheVerdict::Hit);
    }

    #[test]
    fn volatile_after_ttl_miss_no_stale() {
        let p = FactRecallCachePolicy::canonical();
        // Volatile may_serve_stale = false.
        assert_eq!(p.decide(FactClass::Volatile, 100, true), CacheVerdict::Miss);
    }

    #[test]
    fn stable_serves_stale_when_allowed() {
        let p = FactRecallCachePolicy::canonical();
        assert_eq!(
            p.decide(FactClass::Stable, 999 * 86400, true),
            CacheVerdict::Stale
        );
    }

    #[test]
    fn stable_miss_when_stale_disallowed() {
        let p = FactRecallCachePolicy::canonical();
        assert_eq!(
            p.decide(FactClass::Stable, 999 * 86400, false),
            CacheVerdict::Miss
        );
    }

    #[test]
    fn operator_never_stale() {
        let p = FactRecallCachePolicy::canonical();
        // Operator may_serve_stale=false.
        assert_eq!(
            p.decide(FactClass::Operator, 10_000 * 86400, true),
            CacheVerdict::Miss
        );
    }

    #[test]
    fn ttl_zero_rejected() {
        let mut p = FactRecallCachePolicy::canonical();
        p.volatile.ttl_seconds = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            CacheError::TtlZero(FactClass::Volatile)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = FactRecallCachePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            CacheError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&FactClass::SlowEvolving).unwrap(),
            "\"slow-evolving\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = FactRecallCachePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: FactRecallCachePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
