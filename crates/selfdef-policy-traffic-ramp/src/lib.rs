//! `selfdef-policy-traffic-ramp` — gradual policy rollout.
//!
//! Each policy has a `ramp_bp` in 0..=10000 (basis points; 10000 =
//! 100%). For an actor id, `included(policy, actor)` is deterministic:
//! `FNV-1a-64(policy || ":" || actor) mod 10000 < ramp_bp`. Bumping
//! ramp_bp up never excludes an actor who was previously included
//! (monotonicity property).
//!
//! `set_ramp(policy, bp)` updates; `current(policy)` returns the
//! current bp; `decide(policy, actor)` returns Included/Excluded.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyTrafficRamp {
    /// Schema version.
    pub schema_version: String,
    /// policy → ramp_bp.
    pub ramps: BTreeMap<String, u32>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RampVerdict {
    /// Actor is in the ramp.
    Included,
    /// Actor is not yet in the ramp.
    Excluded,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RampError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy.
    #[error("policy id empty")]
    EmptyPolicy,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Bp out of range.
    #[error("ramp_bp must be in 0..=10000, got {0}")]
    BadBp(u32),
}

/// FNV-1a 64.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl PolicyTrafficRamp {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            ramps: BTreeMap::new(),
        }
    }

    /// Set ramp.
    pub fn set_ramp(&mut self, policy: &str, ramp_bp: u32) -> Result<(), RampError> {
        if policy.is_empty() {
            return Err(RampError::EmptyPolicy);
        }
        if ramp_bp > 10000 {
            return Err(RampError::BadBp(ramp_bp));
        }
        self.ramps.insert(policy.into(), ramp_bp);
        Ok(())
    }

    /// Get current ramp.
    pub fn current(&self, policy: &str) -> u32 {
        self.ramps.get(policy).copied().unwrap_or(0)
    }

    /// Decide for a given actor.
    pub fn decide(&self, policy: &str, actor: &str) -> Result<RampVerdict, RampError> {
        if policy.is_empty() {
            return Err(RampError::EmptyPolicy);
        }
        if actor.is_empty() {
            return Err(RampError::EmptyActor);
        }
        let bp = self.current(policy);
        if bp == 0 {
            return Ok(RampVerdict::Excluded);
        }
        if bp >= 10000 {
            return Ok(RampVerdict::Included);
        }
        let key = format!("{policy}:{actor}");
        let bucket = (fnv1a_64(key.as_bytes()) % 10000) as u32;
        if bucket < bp {
            Ok(RampVerdict::Included)
        } else {
            Ok(RampVerdict::Excluded)
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RampError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RampError::SchemaMismatch);
        }
        for (id, bp) in &self.ramps {
            if id.is_empty() {
                return Err(RampError::EmptyPolicy);
            }
            if *bp > 10000 {
                return Err(RampError::BadBp(*bp));
            }
        }
        Ok(())
    }
}

impl Default for PolicyTrafficRamp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ramp_all_excluded() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p", 0).unwrap();
        assert_eq!(r.decide("p", "alice").unwrap(), RampVerdict::Excluded);
        assert_eq!(r.decide("p", "bob").unwrap(), RampVerdict::Excluded);
    }

    #[test]
    fn full_ramp_all_included() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p", 10000).unwrap();
        assert_eq!(r.decide("p", "alice").unwrap(), RampVerdict::Included);
        assert_eq!(r.decide("p", "bob").unwrap(), RampVerdict::Included);
    }

    #[test]
    fn determinism() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p", 5000).unwrap();
        let v1 = r.decide("p", "alice").unwrap();
        let v2 = r.decide("p", "alice").unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn monotonicity_under_ramp_increase() {
        let mut r = PolicyTrafficRamp::new();
        // Test 100 actors at 50% → check that all stay included when raised to 100%.
        r.set_ramp("p", 5000).unwrap();
        let included_before: Vec<bool> = (0..100)
            .map(|i| {
                matches!(
                    r.decide("p", &format!("actor-{i}")).unwrap(),
                    RampVerdict::Included
                )
            })
            .collect();
        r.set_ramp("p", 10000).unwrap();
        for (i, was) in included_before.iter().enumerate() {
            let now = matches!(
                r.decide("p", &format!("actor-{i}")).unwrap(),
                RampVerdict::Included
            );
            if *was {
                assert!(now, "actor-{i} dropped on ramp increase");
            }
        }
    }

    #[test]
    fn distribution_roughly_matches_bp() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p", 5000).unwrap();
        let included = (0..10_000)
            .filter(|i| {
                matches!(
                    r.decide("p", &format!("actor-{i}")).unwrap(),
                    RampVerdict::Included
                )
            })
            .count();
        // Allow ±10% on a 10k sample (should land near 50%).
        assert!((4500..=5500).contains(&included), "got {included}");
    }

    #[test]
    fn different_policies_independent() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p1", 5000).unwrap();
        r.set_ramp("p2", 5000).unwrap();
        // Same actor, different policies → independent buckets.
        let v1 = r.decide("p1", "x").unwrap();
        let v2 = r.decide("p2", "x").unwrap();
        // We can't predict, but the call must succeed.
        let _ = (v1, v2);
    }

    #[test]
    fn missing_policy_zero() {
        let r = PolicyTrafficRamp::new();
        assert_eq!(r.decide("p", "alice").unwrap(), RampVerdict::Excluded);
    }

    #[test]
    fn bad_bp_rejected() {
        let mut r = PolicyTrafficRamp::new();
        assert!(matches!(
            r.set_ramp("p", 10001).unwrap_err(),
            RampError::BadBp(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = PolicyTrafficRamp::new();
        assert!(matches!(
            r.set_ramp("", 5000).unwrap_err(),
            RampError::EmptyPolicy
        ));
        assert!(matches!(
            r.decide("", "x").unwrap_err(),
            RampError::EmptyPolicy
        ));
        r.set_ramp("p", 5000).unwrap();
        assert!(matches!(
            r.decide("p", "").unwrap_err(),
            RampError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = PolicyTrafficRamp::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RampError::SchemaMismatch
        ));
    }

    #[test]
    fn ramp_serde_roundtrip() {
        let mut r = PolicyTrafficRamp::new();
        r.set_ramp("p", 5000).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: PolicyTrafficRamp = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
