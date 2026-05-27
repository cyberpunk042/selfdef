//! `selfdef-action-witness-policy` — N-distinct-witness gate.
//!
//! Per-BlastRadius minimum witness count. submit_witness adds a
//! (witness_id, action_id) pair (deduplicated). admit returns Allow
//! when distinct-witness count ≥ required, else Pending{required, observed}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Blast radius (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Per-radius required witness count.
pub fn default_required(r: BlastRadius) -> u32 {
    match r {
        BlastRadius::LocalEphemeral => 0,
        BlastRadius::LocalPersistent => 0,
        BlastRadius::CrossSession => 1,
        BlastRadius::CrossMachine => 2,
        BlastRadius::Public => 3,
    }
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WitnessVerdict {
    /// Enough witnesses.
    Allow,
    /// Pending more witnesses.
    Pending {
        /// required.
        required: u32,
        /// observed.
        observed: u32,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionWitnessPolicy {
    /// Schema version.
    pub schema_version: String,
    /// action_id → set of witness ids (BTreeMap → Vec for sorted-set semantic).
    pub witnesses: BTreeMap<String, Vec<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WitnessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("empty id")]
    EmptyId,
}

impl ActionWitnessPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            witnesses: BTreeMap::new(),
        }
    }

    /// Submit a distinct witness (idempotent).
    pub fn submit_witness(
        &mut self,
        action_id: &str,
        witness_id: &str,
    ) -> Result<(), WitnessError> {
        if action_id.is_empty() || witness_id.is_empty() {
            return Err(WitnessError::EmptyId);
        }
        let entry = self.witnesses.entry(action_id.into()).or_default();
        if !entry.iter().any(|w| w == witness_id) {
            entry.push(witness_id.into());
            entry.sort();
        }
        Ok(())
    }

    /// Distinct witness count for action.
    pub fn count(&self, action_id: &str) -> u32 {
        self.witnesses
            .get(action_id)
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }

    /// Decide.
    pub fn admit(&self, action_id: &str, radius: BlastRadius) -> WitnessVerdict {
        let required = default_required(radius);
        let observed = self.count(action_id);
        if observed >= required {
            WitnessVerdict::Allow
        } else {
            WitnessVerdict::Pending { required, observed }
        }
    }

    /// Clear witnesses for an action.
    pub fn clear(&mut self, action_id: &str) {
        self.witnesses.remove(action_id);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WitnessError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WitnessError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for ActionWitnessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_no_witnesses_needed() {
        let p = ActionWitnessPolicy::new();
        assert!(matches!(
            p.admit("a", BlastRadius::LocalEphemeral),
            WitnessVerdict::Allow
        ));
    }

    #[test]
    fn cross_session_needs_one() {
        let mut p = ActionWitnessPolicy::new();
        let v = p.admit("a", BlastRadius::CrossSession);
        assert!(matches!(
            v,
            WitnessVerdict::Pending {
                required: 1,
                observed: 0
            }
        ));
        p.submit_witness("a", "w1").unwrap();
        assert!(matches!(
            p.admit("a", BlastRadius::CrossSession),
            WitnessVerdict::Allow
        ));
    }

    #[test]
    fn public_needs_three_distinct() {
        let mut p = ActionWitnessPolicy::new();
        p.submit_witness("a", "w1").unwrap();
        p.submit_witness("a", "w1").unwrap(); // dup
        assert!(matches!(
            p.admit("a", BlastRadius::Public),
            WitnessVerdict::Pending { observed: 1, .. }
        ));
        p.submit_witness("a", "w2").unwrap();
        p.submit_witness("a", "w3").unwrap();
        assert!(matches!(
            p.admit("a", BlastRadius::Public),
            WitnessVerdict::Allow
        ));
    }

    #[test]
    fn count_zero_for_unknown() {
        let p = ActionWitnessPolicy::new();
        assert_eq!(p.count("ghost"), 0);
    }

    #[test]
    fn clear_removes_witnesses() {
        let mut p = ActionWitnessPolicy::new();
        p.submit_witness("a", "w1").unwrap();
        p.clear("a");
        assert_eq!(p.count("a"), 0);
    }

    #[test]
    fn empty_ids_rejected() {
        let mut p = ActionWitnessPolicy::new();
        assert!(matches!(
            p.submit_witness("", "w").unwrap_err(),
            WitnessError::EmptyId
        ));
        assert!(matches!(
            p.submit_witness("a", "").unwrap_err(),
            WitnessError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActionWitnessPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            WitnessError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        let v = WitnessVerdict::Allow;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"allow\"")
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ActionWitnessPolicy::new();
        p.submit_witness("a", "w1").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActionWitnessPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
