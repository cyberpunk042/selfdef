//! `selfdef-policy-decision-batcher` — batched decision emit.
//!
//! Accumulates validated `PolicyDecision`s; when `MAX_BATCH` is reached
//! (or `flush` is called) emits a single `DecisionBatch` envelope with
//! FNV-1a hash of the concatenated trace_ids.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::PolicyDecision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Maximum batch size.
pub const MAX_BATCH: usize = 128;

/// FNV-1a 64-bit.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One emitted batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionBatch {
    /// Schema version.
    pub schema_version: String,
    /// Decisions.
    pub decisions: Vec<PolicyDecision>,
    /// FNV-1a hex of trace_ids concatenated by '|'.
    pub batch_hash: String,
    /// ISO-8601 UTC.
    pub emitted_at: String,
}

/// Batcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecisionBatcher {
    /// Schema version.
    pub schema_version: String,
    /// Pending decisions (not yet emitted).
    pub pending: Vec<PolicyDecision>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BatcherError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Pending decision invalid.
    #[error("invalid decision: {0}")]
    InvalidDecision(String),
    /// Batch full.
    #[error("batch full ({MAX_BATCH} max)")]
    Full,
    /// Empty on flush.
    #[error("empty batch on flush")]
    Empty,
}

fn batch_hash(decisions: &[PolicyDecision]) -> String {
    let s: String = decisions.iter().map(|d| d.trace_id.as_str()).collect::<Vec<_>>().join("|");
    format!("0x{:016x}", fnv1a_64(s.as_bytes()))
}

impl PolicyDecisionBatcher {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pending: Vec::new(),
        }
    }

    /// Push a decision after validating it.
    pub fn push(&mut self, d: PolicyDecision) -> Result<(), BatcherError> {
        d.validate().map_err(|e| BatcherError::InvalidDecision(e.to_string()))?;
        if self.pending.len() >= MAX_BATCH {
            return Err(BatcherError::Full);
        }
        self.pending.push(d);
        Ok(())
    }

    /// Whether the batch is at MAX_BATCH.
    pub fn is_full(&self) -> bool { self.pending.len() >= MAX_BATCH }

    /// Flush the pending decisions into a `DecisionBatch`. Clears pending.
    pub fn flush(&mut self, emitted_at: &str) -> Result<DecisionBatch, BatcherError> {
        if self.pending.is_empty() { return Err(BatcherError::Empty); }
        let decisions = std::mem::take(&mut self.pending);
        let hash = batch_hash(&decisions);
        Ok(DecisionBatch {
            schema_version: SCHEMA_VERSION.into(),
            decisions,
            batch_hash: hash,
            emitted_at: emitted_at.into(),
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BatcherError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BatcherError::SchemaMismatch);
        }
        Ok(())
    }
}

impl DecisionBatch {
    /// Validate (recompute hash).
    pub fn validate(&self) -> Result<(), BatcherError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BatcherError::SchemaMismatch);
        }
        if self.decisions.is_empty() { return Err(BatcherError::Empty); }
        let recomputed = batch_hash(&self.decisions);
        if recomputed != self.batch_hash {
            return Err(BatcherError::InvalidDecision(format!(
                "batch_hash mismatch: stored={}, recomputed={recomputed}",
                self.batch_hash
            )));
        }
        Ok(())
    }
}

impl Default for PolicyDecisionBatcher {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, Outcome, RiskClass, SideEffectClass, UserApprovalState};

    fn d(trace: &str) -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "op".into(),
            action: "fs.read".into(),
            resource: "/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::ReadOnly,
            user_approval: UserApprovalState::NotRequired,
            outcome: Outcome::Allow,
            reason: "ok".into(),
            trace_id: trace.into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn empty_batcher_validates() {
        PolicyDecisionBatcher::new().validate().unwrap();
    }

    #[test]
    fn push_and_flush() {
        let mut b = PolicyDecisionBatcher::new();
        b.push(d("tr-1")).unwrap();
        b.push(d("tr-2")).unwrap();
        let batch = b.flush("2026-05-19T03:00:00Z").unwrap();
        assert_eq!(batch.decisions.len(), 2);
        batch.validate().unwrap();
        assert!(b.pending.is_empty());
    }

    #[test]
    fn full_caught() {
        let mut b = PolicyDecisionBatcher::new();
        for i in 0..MAX_BATCH {
            b.push(d(&format!("tr-{i}"))).unwrap();
        }
        assert!(b.is_full());
        assert!(matches!(b.push(d("overflow")).unwrap_err(), BatcherError::Full));
    }

    #[test]
    fn flush_empty_rejected() {
        let mut b = PolicyDecisionBatcher::new();
        assert!(matches!(b.flush("t").unwrap_err(), BatcherError::Empty));
    }

    #[test]
    fn invalid_decision_rejected_on_push() {
        let mut b = PolicyDecisionBatcher::new();
        let mut bad = d("tr-1");
        bad.subject = String::new();
        assert!(matches!(b.push(bad).unwrap_err(), BatcherError::InvalidDecision(_)));
    }

    #[test]
    fn tampered_hash_caught() {
        let mut b = PolicyDecisionBatcher::new();
        b.push(d("tr-1")).unwrap();
        let mut batch = b.flush("t").unwrap();
        batch.batch_hash = "0xdeadbeefdeadbeef".into();
        assert!(matches!(batch.validate().unwrap_err(), BatcherError::InvalidDecision(_)));
    }

    #[test]
    fn deterministic_hash() {
        let mut a = PolicyDecisionBatcher::new();
        a.push(d("tr-1")).unwrap();
        a.push(d("tr-2")).unwrap();
        let ba = a.flush("t").unwrap();
        let mut b = PolicyDecisionBatcher::new();
        b.push(d("tr-1")).unwrap();
        b.push(d("tr-2")).unwrap();
        let bb = b.flush("t").unwrap();
        assert_eq!(ba.batch_hash, bb.batch_hash);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = PolicyDecisionBatcher::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BatcherError::SchemaMismatch));
    }

    #[test]
    fn batcher_serde_roundtrip() {
        let mut b = PolicyDecisionBatcher::new();
        b.push(d("tr-1")).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: PolicyDecisionBatcher = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
