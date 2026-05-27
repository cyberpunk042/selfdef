//! `selfdef-config-personalization-bounds` — per-(Profile, knob) guard.
//!
//! Each knob is declared with a `Bound` per Profile. `check(profile,
//! knob_id, value)` returns:
//!   * `Ok` — value inside the bound.
//!   * `OutOfBound { bound, observed }` — value outside.
//!   * `UnknownKnob` — no bound declared for (profile, knob).
//!   * `UnknownProfile` — Profile has no declarations.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

/// Allowed bound kinds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Bound {
    /// Integer must be in [min, max].
    IntRange {
        /// min inclusive.
        min: i64,
        /// max inclusive.
        max: i64,
    },
    /// Value must be one of `allowed`.
    EnumOf {
        /// allowed set (string-typed for transport).
        allowed: BTreeSet<String>,
    },
    /// Boolean (either value accepted).
    BoolEither,
    /// String length ≤ max chars.
    StrLenAtMost {
        /// max chars.
        max: u32,
    },
}

/// Knob-typed value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Value {
    /// Integer.
    Int {
        /// value.
        v: i64,
    },
    /// String.
    Str {
        /// value.
        v: String,
    },
    /// Bool.
    Bool {
        /// value.
        v: bool,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigPersonalizationBounds {
    /// Schema version.
    pub schema_version: String,
    /// profile → knob → bound.
    pub bounds: BTreeMap<Profile, BTreeMap<String, Bound>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CheckVerdict {
    /// Within bound.
    Ok,
    /// Out of bound.
    OutOfBound {
        /// the bound.
        bound: Bound,
        /// the observed value.
        observed: Value,
    },
    /// Knob not declared.
    UnknownKnob,
    /// Profile not declared.
    UnknownProfile,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BoundsError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty knob id.
    #[error("knob id empty")]
    EmptyId,
    /// Bad bound.
    #[error("bound min > max")]
    BadBound,
}

impl ConfigPersonalizationBounds {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            bounds: BTreeMap::new(),
        }
    }

    /// Set a bound.
    pub fn set(
        &mut self,
        profile: Profile,
        knob_id: &str,
        bound: Bound,
    ) -> Result<(), BoundsError> {
        if knob_id.is_empty() {
            return Err(BoundsError::EmptyId);
        }
        if let Bound::IntRange { min, max } = &bound {
            if min > max {
                return Err(BoundsError::BadBound);
            }
        }
        self.bounds
            .entry(profile)
            .or_default()
            .insert(knob_id.into(), bound);
        Ok(())
    }

    /// Check.
    pub fn check(&self, profile: Profile, knob_id: &str, value: &Value) -> CheckVerdict {
        let map = match self.bounds.get(&profile) {
            Some(m) => m,
            None => return CheckVerdict::UnknownProfile,
        };
        let b = match map.get(knob_id) {
            Some(b) => b.clone(),
            None => return CheckVerdict::UnknownKnob,
        };
        if Self::passes(&b, value) {
            CheckVerdict::Ok
        } else {
            CheckVerdict::OutOfBound {
                bound: b,
                observed: value.clone(),
            }
        }
    }

    fn passes(b: &Bound, v: &Value) -> bool {
        match (b, v) {
            (Bound::IntRange { min, max }, Value::Int { v }) => v >= min && v <= max,
            (Bound::EnumOf { allowed }, Value::Str { v }) => allowed.contains(v),
            (Bound::BoolEither, Value::Bool { .. }) => true,
            (Bound::StrLenAtMost { max }, Value::Str { v }) => (v.chars().count() as u32) <= *max,
            _ => false, // type mismatch counts as out-of-bound.
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BoundsError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BoundsError::SchemaMismatch);
        }
        for map in self.bounds.values() {
            for (k, b) in map {
                if k.is_empty() {
                    return Err(BoundsError::EmptyId);
                }
                if let Bound::IntRange { min, max } = b {
                    if min > max {
                        return Err(BoundsError::BadBound);
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for ConfigPersonalizationBounds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_in_range_ok() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "n", Bound::IntRange { min: 0, max: 10 })
            .unwrap();
        assert_eq!(
            c.check(Profile::Fast, "n", &Value::Int { v: 5 }),
            CheckVerdict::Ok
        );
    }

    #[test]
    fn int_out_of_range() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "n", Bound::IntRange { min: 0, max: 10 })
            .unwrap();
        assert!(matches!(
            c.check(Profile::Fast, "n", &Value::Int { v: 99 }),
            CheckVerdict::OutOfBound { .. }
        ));
    }

    #[test]
    fn enum_ok_and_denied() {
        let mut c = ConfigPersonalizationBounds::new();
        let mut allowed = BTreeSet::new();
        allowed.insert("on".into());
        allowed.insert("off".into());
        c.set(Profile::Fast, "mode", Bound::EnumOf { allowed })
            .unwrap();
        assert_eq!(
            c.check(Profile::Fast, "mode", &Value::Str { v: "on".into() }),
            CheckVerdict::Ok
        );
        assert!(matches!(
            c.check(Profile::Fast, "mode", &Value::Str { v: "wat".into() }),
            CheckVerdict::OutOfBound { .. }
        ));
    }

    #[test]
    fn bool_either() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "flag", Bound::BoolEither).unwrap();
        assert_eq!(
            c.check(Profile::Fast, "flag", &Value::Bool { v: true }),
            CheckVerdict::Ok
        );
        assert_eq!(
            c.check(Profile::Fast, "flag", &Value::Bool { v: false }),
            CheckVerdict::Ok
        );
    }

    #[test]
    fn str_len_at_most() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "label", Bound::StrLenAtMost { max: 3 })
            .unwrap();
        assert_eq!(
            c.check(Profile::Fast, "label", &Value::Str { v: "ab".into() }),
            CheckVerdict::Ok
        );
        assert!(matches!(
            c.check(Profile::Fast, "label", &Value::Str { v: "abcd".into() }),
            CheckVerdict::OutOfBound { .. }
        ));
    }

    #[test]
    fn type_mismatch_is_out_of_bound() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "n", Bound::IntRange { min: 0, max: 10 })
            .unwrap();
        assert!(matches!(
            c.check(Profile::Fast, "n", &Value::Str { v: "x".into() }),
            CheckVerdict::OutOfBound { .. }
        ));
    }

    #[test]
    fn unknown_knob_and_profile() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "n", Bound::IntRange { min: 0, max: 10 })
            .unwrap();
        assert_eq!(
            c.check(Profile::Fast, "missing", &Value::Int { v: 0 }),
            CheckVerdict::UnknownKnob
        );
        assert_eq!(
            c.check(Profile::Production, "n", &Value::Int { v: 0 }),
            CheckVerdict::UnknownProfile
        );
    }

    #[test]
    fn bad_bound_rejected() {
        let mut c = ConfigPersonalizationBounds::new();
        assert!(matches!(
            c.set(Profile::Fast, "n", Bound::IntRange { min: 10, max: 1 })
                .unwrap_err(),
            BoundsError::BadBound
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut c = ConfigPersonalizationBounds::new();
        assert!(matches!(
            c.set(Profile::Fast, "", Bound::BoolEither).unwrap_err(),
            BoundsError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ConfigPersonalizationBounds::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            BoundsError::SchemaMismatch
        ));
    }

    #[test]
    fn bounds_serde_roundtrip() {
        let mut c = ConfigPersonalizationBounds::new();
        c.set(Profile::Fast, "n", Bound::IntRange { min: 0, max: 10 })
            .unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: ConfigPersonalizationBounds = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
