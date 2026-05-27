//! `selfdef-grant-batch-policy` — multi-grant approval gate.
//!
//! Batch admission: count must be ≤ max_per_batch, and no grant in
//! the batch may exceed max_radius_in_batch. Returns Allow or a
//! typed BatchDenial.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Blast radius (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlastRadius {
    /// LocalEphemeral.
    LocalEphemeral,
    /// LocalPersistent.
    LocalPersistent,
    /// CrossSession.
    CrossSession,
    /// CrossMachine.
    CrossMachine,
    /// Public.
    Public,
}

/// One grant entry in the batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantEntry {
    /// Stable id.
    pub id: String,
    /// Blast radius of the grant.
    pub radius: BlastRadius,
}

/// Batch decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BatchDecision {
    /// Allow.
    Allow,
    /// Too many grants in batch.
    TooMany {
        /// observed.
        observed: u32,
        /// cap.
        cap: u32,
    },
    /// Radius exceeded.
    RadiusExceeded {
        /// offending id.
        id: String,
        /// observed.
        observed: BlastRadius,
        /// cap.
        cap: BlastRadius,
    },
    /// Empty batch.
    EmptyBatch,
    /// Duplicate id in batch.
    DuplicateId {
        /// id.
        id: String,
    },
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantBatchPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Max distinct grants per batch.
    pub max_per_batch: u32,
    /// Max BlastRadius any single grant may carry in a batch.
    pub max_radius_in_batch: BlastRadius,
}

/// Errors (construction-time).
#[derive(Debug, Error)]
pub enum BatchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_per_batch zero.
    #[error("max_per_batch is zero")]
    MaxZero,
}

impl GrantBatchPolicy {
    /// Canonical: max 8 grants per batch; max radius CrossSession.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_per_batch: 8,
            max_radius_in_batch: BlastRadius::CrossSession,
        }
    }

    /// Decide.
    pub fn decide(&self, batch: &[GrantEntry]) -> BatchDecision {
        if batch.is_empty() {
            return BatchDecision::EmptyBatch;
        }
        if (batch.len() as u32) > self.max_per_batch {
            return BatchDecision::TooMany {
                observed: batch.len() as u32,
                cap: self.max_per_batch,
            };
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for g in batch {
            if !seen.insert(g.id.as_str()) {
                return BatchDecision::DuplicateId { id: g.id.clone() };
            }
            if g.radius > self.max_radius_in_batch {
                return BatchDecision::RadiusExceeded {
                    id: g.id.clone(),
                    observed: g.radius,
                    cap: self.max_radius_in_batch,
                };
            }
        }
        BatchDecision::Allow
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BatchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BatchError::SchemaMismatch);
        }
        if self.max_per_batch == 0 {
            return Err(BatchError::MaxZero);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(id: &str, r: BlastRadius) -> GrantEntry {
        GrantEntry {
            id: id.into(),
            radius: r,
        }
    }

    #[test]
    fn canonical_validates() {
        GrantBatchPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn empty_batch_rejected() {
        let p = GrantBatchPolicy::canonical();
        assert!(matches!(p.decide(&[]), BatchDecision::EmptyBatch));
    }

    #[test]
    fn small_batch_allows() {
        let p = GrantBatchPolicy::canonical();
        let r = p.decide(&[g("a", BlastRadius::LocalPersistent)]);
        assert!(matches!(r, BatchDecision::Allow));
    }

    #[test]
    fn too_many_rejected() {
        let p = GrantBatchPolicy::canonical();
        let entries: Vec<GrantEntry> = (0..10)
            .map(|i| g(&format!("g{i}"), BlastRadius::LocalEphemeral))
            .collect();
        assert!(matches!(p.decide(&entries), BatchDecision::TooMany { .. }));
    }

    #[test]
    fn radius_exceeded_rejected() {
        let p = GrantBatchPolicy::canonical();
        let r = p.decide(&[
            g("safe", BlastRadius::LocalPersistent),
            g("public", BlastRadius::Public),
        ]);
        match r {
            BatchDecision::RadiusExceeded { id, .. } => assert_eq!(id, "public"),
            _ => panic!(),
        }
    }

    #[test]
    fn radius_at_cap_allowed() {
        let p = GrantBatchPolicy::canonical();
        let r = p.decide(&[g("a", BlastRadius::CrossSession)]);
        assert!(matches!(r, BatchDecision::Allow));
    }

    #[test]
    fn duplicate_id_rejected() {
        let p = GrantBatchPolicy::canonical();
        let r = p.decide(&[
            g("dup", BlastRadius::LocalEphemeral),
            g("dup", BlastRadius::LocalEphemeral),
        ]);
        assert!(matches!(r, BatchDecision::DuplicateId { .. }));
    }

    #[test]
    fn max_per_batch_zero_rejected() {
        let mut p = GrantBatchPolicy::canonical();
        p.max_per_batch = 0;
        assert!(matches!(p.validate().unwrap_err(), BatchError::MaxZero));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = GrantBatchPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            BatchError::SchemaMismatch
        ));
    }

    #[test]
    fn decision_serde_kebab() {
        let d = BatchDecision::EmptyBatch;
        assert!(
            serde_json::to_string(&d)
                .unwrap()
                .contains("\"kind\":\"empty-batch\"")
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = GrantBatchPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: GrantBatchPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
