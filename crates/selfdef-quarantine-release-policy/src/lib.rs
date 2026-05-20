//! `selfdef-quarantine-release-policy` — gate for quarantine releases.
//!
//! `classify(reviewed_by_count, age_ms, has_operator_signoff)` returns:
//!   * `Releasable` — all three gates met.
//!   * `NeedsMoreReviewers { have, need }` — under min_reviewers.
//!   * `TooFresh { age_ms, need_min_age_ms }` — under min_age_ms.
//!   * `NeedsOperator` — operator signoff still required.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineReleasePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Minimum reviewer count to release.
    pub min_reviewers: u32,
    /// Minimum age (ms) before release is even considered.
    pub min_age_ms: u64,
    /// Whether operator sign-off is required.
    pub require_operator: bool,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReleaseVerdict {
    /// All gates met.
    Releasable,
    /// Not enough distinct reviewers.
    NeedsMoreReviewers {
        /// have.
        have: u32,
        /// need.
        need: u32,
    },
    /// Too young.
    TooFresh {
        /// age.
        age_ms: u64,
        /// need.
        need_min_age_ms: u64,
    },
    /// Needs operator signoff.
    NeedsOperator,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReleaseError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl QuarantineReleasePolicy {
    /// New.
    pub fn new(min_reviewers: u32, min_age_ms: u64, require_operator: bool) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            min_reviewers,
            min_age_ms,
            require_operator,
        }
    }

    /// Classify.
    pub fn classify(&self, reviewed_by_count: u32, age_ms: u64, has_operator_signoff: bool) -> ReleaseVerdict {
        if reviewed_by_count < self.min_reviewers {
            return ReleaseVerdict::NeedsMoreReviewers {
                have: reviewed_by_count,
                need: self.min_reviewers,
            };
        }
        if age_ms < self.min_age_ms {
            return ReleaseVerdict::TooFresh {
                age_ms,
                need_min_age_ms: self.min_age_ms,
            };
        }
        if self.require_operator && !has_operator_signoff {
            return ReleaseVerdict::NeedsOperator;
        }
        ReleaseVerdict::Releasable
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ReleaseError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_met_releasable() {
        let p = QuarantineReleasePolicy::new(2, 60_000, true);
        assert_eq!(p.classify(3, 120_000, true), ReleaseVerdict::Releasable);
    }

    #[test]
    fn needs_more_reviewers() {
        let p = QuarantineReleasePolicy::new(3, 0, false);
        assert_eq!(p.classify(1, 0, false), ReleaseVerdict::NeedsMoreReviewers { have: 1, need: 3 });
    }

    #[test]
    fn too_fresh() {
        let p = QuarantineReleasePolicy::new(0, 60_000, false);
        assert_eq!(p.classify(0, 30_000, false), ReleaseVerdict::TooFresh { age_ms: 30_000, need_min_age_ms: 60_000 });
    }

    #[test]
    fn needs_operator() {
        let p = QuarantineReleasePolicy::new(0, 0, true);
        assert_eq!(p.classify(0, 0, false), ReleaseVerdict::NeedsOperator);
        assert_eq!(p.classify(0, 0, true), ReleaseVerdict::Releasable);
    }

    #[test]
    fn order_reviewers_first() {
        // Under both reviewer count and min_age — reviewers come first.
        let p = QuarantineReleasePolicy::new(3, 60_000, false);
        assert!(matches!(p.classify(0, 0, false), ReleaseVerdict::NeedsMoreReviewers { .. }));
    }

    #[test]
    fn order_age_second() {
        // Reviewers met, age not.
        let p = QuarantineReleasePolicy::new(1, 60_000, true);
        assert!(matches!(p.classify(2, 0, true), ReleaseVerdict::TooFresh { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = QuarantineReleasePolicy::new(0, 0, false);
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ReleaseError::SchemaMismatch));
    }

    #[test]
    fn release_serde_roundtrip() {
        let p = QuarantineReleasePolicy::new(2, 1000, true);
        let j = serde_json::to_string(&p).unwrap();
        let back: QuarantineReleasePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
