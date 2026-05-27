//! `selfdef-threshold-set` — named monotonic thresholds.
//!
//! Threshold{name, value} stored sorted by value ascending.
//! classify(value) returns the latest band whose threshold
//! <= value; below first → default_band; empty → default_band.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Threshold band.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Threshold {
    /// Band name.
    pub name: String,
    /// Lower bound (inclusive); higher than this triggers the band.
    pub value: i64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThresholdSet {
    /// Schema version.
    pub schema_version: String,
    /// Sorted by value asc.
    pub thresholds: Vec<Threshold>,
    /// Default band (when value < first threshold or empty).
    pub default_band: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ThresholdError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("default_band empty")]
    EmptyDefault,
    /// Duplicate.
    #[error("duplicate name: {0}")]
    DuplicateName(String),
    /// Bad order.
    #[error("thresholds must be strictly increasing by value")]
    NotStrictlyIncreasing,
}

impl ThresholdSet {
    /// New.
    pub fn new(default_band: &str) -> Result<Self, ThresholdError> {
        if default_band.is_empty() {
            return Err(ThresholdError::EmptyDefault);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            thresholds: Vec::new(),
            default_band: default_band.into(),
        })
    }

    /// Add threshold (inserts sorted; rejects duplicate value).
    pub fn add(&mut self, name: &str, value: i64) -> Result<(), ThresholdError> {
        if name.is_empty() {
            return Err(ThresholdError::EmptyName);
        }
        if self.thresholds.iter().any(|t| t.name == name) {
            return Err(ThresholdError::DuplicateName(name.into()));
        }
        let pos = self.thresholds.binary_search_by_key(&value, |t| t.value);
        if pos.is_ok() {
            return Err(ThresholdError::NotStrictlyIncreasing);
        }
        let pos = pos.unwrap_err();
        self.thresholds.insert(
            pos,
            Threshold {
                name: name.into(),
                value,
            },
        );
        Ok(())
    }

    /// Classify value.
    pub fn classify(&self, value: i64) -> &str {
        let mut band: &str = &self.default_band;
        for t in &self.thresholds {
            if t.value <= value {
                band = t.name.as_str();
            } else {
                break;
            }
        }
        band
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ThresholdError::SchemaMismatch);
        }
        if self.default_band.is_empty() {
            return Err(ThresholdError::EmptyDefault);
        }
        for t in &self.thresholds {
            if t.name.is_empty() {
                return Err(ThresholdError::EmptyName);
            }
        }
        for w in self.thresholds.windows(2) {
            if w[0].value >= w[1].value {
                return Err(ThresholdError::NotStrictlyIncreasing);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> ThresholdSet {
        let mut s = ThresholdSet::new("low").unwrap();
        s.add("medium", 25).unwrap();
        s.add("high", 75).unwrap();
        s.add("critical", 95).unwrap();
        s
    }

    #[test]
    fn classify_bands() {
        let s = set();
        assert_eq!(s.classify(10), "low");
        assert_eq!(s.classify(25), "medium");
        assert_eq!(s.classify(50), "medium");
        assert_eq!(s.classify(80), "high");
        assert_eq!(s.classify(100), "critical");
    }

    #[test]
    fn empty_set_uses_default() {
        let s = ThresholdSet::new("low").unwrap();
        assert_eq!(s.classify(999), "low");
    }

    #[test]
    fn out_of_order_insert() {
        let mut s = ThresholdSet::new("low").unwrap();
        s.add("c", 100).unwrap();
        s.add("a", 25).unwrap();
        s.add("b", 50).unwrap();
        // Should be sorted by value.
        let names: Vec<&str> = s.thresholds.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn duplicate_value_rejected() {
        let mut s = ThresholdSet::new("low").unwrap();
        s.add("a", 50).unwrap();
        assert!(matches!(
            s.add("b", 50).unwrap_err(),
            ThresholdError::NotStrictlyIncreasing
        ));
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut s = ThresholdSet::new("low").unwrap();
        s.add("a", 50).unwrap();
        assert!(matches!(
            s.add("a", 60).unwrap_err(),
            ThresholdError::DuplicateName(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = ThresholdSet::new("low").unwrap();
        assert!(matches!(
            s.add("", 1).unwrap_err(),
            ThresholdError::EmptyName
        ));
        assert!(matches!(
            ThresholdSet::new("").unwrap_err(),
            ThresholdError::EmptyDefault
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = set();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            ThresholdError::SchemaMismatch
        ));
    }

    #[test]
    fn set_serde_roundtrip() {
        let s = set();
        let j = serde_json::to_string(&s).unwrap();
        let back: ThresholdSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
