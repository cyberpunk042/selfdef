//! `selfdef-policy-mutation-record` — append-only mutation ledger.
//!
//! Each mutation records `(policy_id, mutation_id, proposed_by,
//! witnessed_by, applied_by, ts)`. Records are immutable once
//! written. `fetch(mutation_id)` returns Option<Record>.
//! `for_policy(policy_id)` lists every mutation for a policy.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One mutation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Mutation id.
    pub mutation_id: String,
    /// Policy id.
    pub policy_id: String,
    /// Proposer.
    pub proposed_by: String,
    /// Witnesses.
    pub witnessed_by: Vec<String>,
    /// Applier.
    pub applied_by: String,
    /// When applied.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMutationRecord {
    /// Schema version.
    pub schema_version: String,
    /// mutation_id → record.
    pub records: BTreeMap<String, Record>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RecordError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty mutation id.
    #[error("mutation id empty")]
    EmptyMutationId,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyPolicyId,
    /// Empty proposer.
    #[error("proposed_by empty")]
    EmptyProposer,
    /// Empty applier.
    #[error("applied_by empty")]
    EmptyApplier,
    /// Empty witness.
    #[error("witness empty")]
    EmptyWitness,
    /// Duplicate.
    #[error("duplicate mutation: {0}")]
    Duplicate(String),
}

impl PolicyMutationRecord {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            records: BTreeMap::new(),
        }
    }

    /// Record a mutation.
    pub fn record(&mut self, r: Record) -> Result<(), RecordError> {
        if r.mutation_id.is_empty() {
            return Err(RecordError::EmptyMutationId);
        }
        if r.policy_id.is_empty() {
            return Err(RecordError::EmptyPolicyId);
        }
        if r.proposed_by.is_empty() {
            return Err(RecordError::EmptyProposer);
        }
        if r.applied_by.is_empty() {
            return Err(RecordError::EmptyApplier);
        }
        for w in &r.witnessed_by {
            if w.is_empty() {
                return Err(RecordError::EmptyWitness);
            }
        }
        if self.records.contains_key(&r.mutation_id) {
            return Err(RecordError::Duplicate(r.mutation_id));
        }
        self.records.insert(r.mutation_id.clone(), r);
        Ok(())
    }

    /// Fetch.
    pub fn fetch(&self, mutation_id: &str) -> Option<&Record> {
        self.records.get(mutation_id)
    }

    /// Records for a policy.
    pub fn for_policy(&self, policy_id: &str) -> Vec<Record> {
        self.records
            .values()
            .filter(|r| r.policy_id == policy_id)
            .cloned()
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RecordError::SchemaMismatch);
        }
        for r in self.records.values() {
            if r.mutation_id.is_empty() {
                return Err(RecordError::EmptyMutationId);
            }
            if r.policy_id.is_empty() {
                return Err(RecordError::EmptyPolicyId);
            }
            if r.proposed_by.is_empty() {
                return Err(RecordError::EmptyProposer);
            }
            if r.applied_by.is_empty() {
                return Err(RecordError::EmptyApplier);
            }
            for w in &r.witnessed_by {
                if w.is_empty() {
                    return Err(RecordError::EmptyWitness);
                }
            }
        }
        Ok(())
    }
}

impl Default for PolicyMutationRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, policy: &str) -> Record {
        Record {
            mutation_id: id.into(),
            policy_id: policy.into(),
            proposed_by: "alice".into(),
            witnessed_by: vec!["bob".into(), "carol".into()],
            applied_by: "alice".into(),
            ts_ms: 100,
        }
    }

    #[test]
    fn record_and_fetch() {
        let mut r = PolicyMutationRecord::new();
        r.record(rec("m1", "p1")).unwrap();
        assert!(r.fetch("m1").is_some());
    }

    #[test]
    fn duplicate_rejected() {
        let mut r = PolicyMutationRecord::new();
        r.record(rec("m1", "p1")).unwrap();
        assert!(matches!(
            r.record(rec("m1", "p1")).unwrap_err(),
            RecordError::Duplicate(_)
        ));
    }

    #[test]
    fn for_policy_filters() {
        let mut r = PolicyMutationRecord::new();
        r.record(rec("m1", "p1")).unwrap();
        r.record(rec("m2", "p1")).unwrap();
        r.record(rec("m3", "p2")).unwrap();
        assert_eq!(r.for_policy("p1").len(), 2);
    }

    #[test]
    fn empty_fields_rejected() {
        let mut r = PolicyMutationRecord::new();
        let mut bad = rec("m1", "p1");
        bad.mutation_id = "".into();
        assert!(matches!(
            r.record(bad).unwrap_err(),
            RecordError::EmptyMutationId
        ));
        let mut bad2 = rec("m1", "p1");
        bad2.witnessed_by = vec!["".into()];
        assert!(matches!(
            r.record(bad2).unwrap_err(),
            RecordError::EmptyWitness
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = PolicyMutationRecord::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RecordError::SchemaMismatch
        ));
    }

    #[test]
    fn record_serde_roundtrip() {
        let mut r = PolicyMutationRecord::new();
        r.record(rec("m1", "p1")).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: PolicyMutationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
