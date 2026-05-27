//! `selfdef-fault-injector` — deterministic fault decisions.
//!
//! Per-tag rules: rate_bp 0..=10000 (10000 = always inject).
//! decide(tag, attempt_id) hashes (tag, attempt_id, seed) via
//! FNV-1a-64 to a number in 0..10000 and returns Inject iff
//! < rate_bp. Counts per tag tracked. Pure deterministic.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Rule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Rate in basis points (10000 = always).
    pub rate_bp: u32,
    /// Times inject decision returned.
    pub injects: u64,
    /// Times skip decision returned.
    pub skips: u64,
}

/// Decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Inject the fault.
    Inject,
    /// Skip.
    Skip,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultInjector {
    /// Schema version.
    pub schema_version: String,
    /// Per-tag rules.
    pub rules: BTreeMap<String, Rule>,
    /// PRNG seed.
    pub seed: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum InjectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tag.
    #[error("tag empty")]
    EmptyTag,
    /// Bad rate.
    #[error("rate_bp must be 0..=10000")]
    BadRate,
    /// Zero seed.
    #[error("seed must be != 0")]
    ZeroSeed,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl FaultInjector {
    /// New with seed.
    pub fn new(seed: u64) -> Result<Self, InjectorError> {
        if seed == 0 {
            return Err(InjectorError::ZeroSeed);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            rules: BTreeMap::new(),
            seed,
        })
    }

    /// Set rate for a tag.
    pub fn set_rate(&mut self, tag: &str, rate_bp: u32) -> Result<(), InjectorError> {
        if tag.is_empty() {
            return Err(InjectorError::EmptyTag);
        }
        if rate_bp > 10000 {
            return Err(InjectorError::BadRate);
        }
        let entry = self.rules.entry(tag.into()).or_insert(Rule {
            rate_bp,
            injects: 0,
            skips: 0,
        });
        entry.rate_bp = rate_bp;
        Ok(())
    }

    /// Decide whether to inject for (tag, attempt_id).
    pub fn decide(&mut self, tag: &str, attempt_id: &str) -> Result<Decision, InjectorError> {
        if tag.is_empty() {
            return Err(InjectorError::EmptyTag);
        }
        // If no rule, treat as 0 bp (no inject).
        let rule = match self.rules.get_mut(tag) {
            Some(r) => r,
            None => return Ok(Decision::Skip),
        };
        if rule.rate_bp == 0 {
            rule.skips = rule.skips.saturating_add(1);
            return Ok(Decision::Skip);
        }
        if rule.rate_bp >= 10000 {
            rule.injects = rule.injects.saturating_add(1);
            return Ok(Decision::Inject);
        }
        let mut buf = Vec::with_capacity(tag.len() + attempt_id.len() + 16);
        buf.extend_from_slice(tag.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(attempt_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.seed.to_be_bytes());
        let h = fnv1a_64(&buf);
        let n = (h % 10_000) as u32;
        let decision = if n < rule.rate_bp {
            Decision::Inject
        } else {
            Decision::Skip
        };
        match decision {
            Decision::Inject => rule.injects = rule.injects.saturating_add(1),
            Decision::Skip => rule.skips = rule.skips.saturating_add(1),
        }
        Ok(decision)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), InjectorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(InjectorError::SchemaMismatch);
        }
        if self.seed == 0 {
            return Err(InjectorError::ZeroSeed);
        }
        for (k, r) in &self.rules {
            if k.is_empty() {
                return Err(InjectorError::EmptyTag);
            }
            if r.rate_bp > 10000 {
                return Err(InjectorError::BadRate);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rule_skips() {
        let mut f = FaultInjector::new(42).unwrap();
        assert_eq!(f.decide("unknown", "a").unwrap(), Decision::Skip);
    }

    #[test]
    fn rate_zero_always_skip() {
        let mut f = FaultInjector::new(42).unwrap();
        f.set_rate("t", 0).unwrap();
        for i in 0..20 {
            assert_eq!(f.decide("t", &i.to_string()).unwrap(), Decision::Skip);
        }
    }

    #[test]
    fn rate_10000_always_inject() {
        let mut f = FaultInjector::new(42).unwrap();
        f.set_rate("t", 10000).unwrap();
        for i in 0..20 {
            assert_eq!(f.decide("t", &i.to_string()).unwrap(), Decision::Inject);
        }
    }

    #[test]
    fn rate_50pct_close_to_half_over_many() {
        let mut f = FaultInjector::new(42).unwrap();
        f.set_rate("t", 5000).unwrap();
        let mut injected = 0u64;
        for i in 0..2000 {
            if f.decide("t", &i.to_string()).unwrap() == Decision::Inject {
                injected += 1;
            }
        }
        // Expect ~1000 injects ±15%.
        assert!((800..=1200).contains(&injected), "got {}", injected);
    }

    #[test]
    fn deterministic_same_seed() {
        let mut f1 = FaultInjector::new(7).unwrap();
        f1.set_rate("t", 5000).unwrap();
        let mut f2 = FaultInjector::new(7).unwrap();
        f2.set_rate("t", 5000).unwrap();
        for i in 0..50 {
            assert_eq!(
                f1.decide("t", &i.to_string()).unwrap(),
                f2.decide("t", &i.to_string()).unwrap()
            );
        }
    }

    #[test]
    fn different_seed_diverges() {
        let mut f1 = FaultInjector::new(7).unwrap();
        f1.set_rate("t", 5000).unwrap();
        let mut f2 = FaultInjector::new(8).unwrap();
        f2.set_rate("t", 5000).unwrap();
        let mut diff = 0;
        for i in 0..100 {
            if f1.decide("t", &i.to_string()).unwrap() != f2.decide("t", &i.to_string()).unwrap() {
                diff += 1;
            }
        }
        assert!(diff > 20, "diff={}", diff);
    }

    #[test]
    fn bad_inputs_rejected() {
        let mut f = FaultInjector::new(7).unwrap();
        assert!(matches!(
            f.set_rate("", 100).unwrap_err(),
            InjectorError::EmptyTag
        ));
        assert!(matches!(
            f.set_rate("t", 10001).unwrap_err(),
            InjectorError::BadRate
        ));
        assert!(matches!(
            FaultInjector::new(0).unwrap_err(),
            InjectorError::ZeroSeed
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = FaultInjector::new(7).unwrap();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            InjectorError::SchemaMismatch
        ));
    }

    #[test]
    fn injector_serde_roundtrip() {
        let mut f = FaultInjector::new(7).unwrap();
        f.set_rate("t", 3000).unwrap();
        f.decide("t", "a").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: FaultInjector = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
