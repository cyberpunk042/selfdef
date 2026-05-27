//! `selfdef-vote-tally` — weighted vote tally.
//!
//! Per voter: weight + cast (Approve/Reject/Abstain). cast()
//! records (replaces prior). result returns Result{approve, reject,
//! abstain, decision: Approve/Reject/Pending}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Vote.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Vote {
    /// Approve.
    Approve,
    /// Reject.
    Reject,
    /// Abstain.
    Abstain,
}

/// Voter.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Voter {
    /// Weight.
    pub weight: u32,
    /// Cast vote (None = not yet voted).
    pub cast: Option<Vote>,
}

/// Decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Approved.
    Approved,
    /// Rejected.
    Rejected,
    /// Still pending.
    Pending,
}

/// Tally result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tally {
    /// Approve weight.
    pub approve: u64,
    /// Reject weight.
    pub reject: u64,
    /// Abstain weight.
    pub abstain: u64,
    /// Cast count.
    pub cast: u32,
    /// Total voters.
    pub total: u32,
    /// Decision.
    pub decision: Decision,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteTally {
    /// Schema version.
    pub schema_version: String,
    /// Approve threshold in basis points (10000 = 100% of approve+reject).
    pub approve_threshold_bp: u32,
    /// voter id → voter.
    pub voters: BTreeMap<String, Voter>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum VoteError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("voter id empty")]
    EmptyVoter,
    /// Zero weight.
    #[error("weight must be >= 1")]
    ZeroWeight,
    /// Bad threshold.
    #[error("threshold must be 1..=10000")]
    BadThreshold,
    /// Duplicate.
    #[error("duplicate voter: {0}")]
    DuplicateVoter(String),
    /// Unknown.
    #[error("unknown voter: {0}")]
    UnknownVoter(String),
}

impl VoteTally {
    /// New.
    pub fn new(approve_threshold_bp: u32) -> Result<Self, VoteError> {
        if approve_threshold_bp == 0 || approve_threshold_bp > 10000 {
            return Err(VoteError::BadThreshold);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            approve_threshold_bp,
            voters: BTreeMap::new(),
        })
    }

    /// Register voter.
    pub fn register(&mut self, voter: &str, weight: u32) -> Result<(), VoteError> {
        if voter.is_empty() {
            return Err(VoteError::EmptyVoter);
        }
        if weight == 0 {
            return Err(VoteError::ZeroWeight);
        }
        if self.voters.contains_key(voter) {
            return Err(VoteError::DuplicateVoter(voter.into()));
        }
        self.voters
            .insert(voter.into(), Voter { weight, cast: None });
        Ok(())
    }

    /// Cast vote (replaces prior).
    pub fn cast(&mut self, voter: &str, vote: Vote) -> Result<(), VoteError> {
        let v = self
            .voters
            .get_mut(voter)
            .ok_or_else(|| VoteError::UnknownVoter(voter.into()))?;
        v.cast = Some(vote);
        Ok(())
    }

    /// Tally.
    pub fn tally(&self) -> Tally {
        let mut approve = 0u64;
        let mut reject = 0u64;
        let mut abstain = 0u64;
        let mut cast = 0u32;
        for v in self.voters.values() {
            match v.cast {
                None => {}
                Some(Vote::Approve) => {
                    approve = approve.saturating_add(v.weight as u64);
                    cast += 1;
                }
                Some(Vote::Reject) => {
                    reject = reject.saturating_add(v.weight as u64);
                    cast += 1;
                }
                Some(Vote::Abstain) => {
                    abstain = abstain.saturating_add(v.weight as u64);
                    cast += 1;
                }
            }
        }
        let total = self.voters.len() as u32;
        let participating = approve + reject;
        let decision = if participating == 0 {
            Decision::Pending
        } else {
            // approve / (approve + reject) × 10000 >= threshold → Approved.
            let approve_bp = (approve.saturating_mul(10_000)) / participating;
            if cast == total {
                if approve_bp >= self.approve_threshold_bp as u64 {
                    Decision::Approved
                } else {
                    Decision::Rejected
                }
            } else {
                // Not everyone has cast yet; decisive if approve already at threshold
                // OR reject share guarantees rejection no matter how remaining votes fall.
                let remaining_weight: u64 = self
                    .voters
                    .values()
                    .filter(|v| v.cast.is_none())
                    .map(|v| v.weight as u64)
                    .sum();
                // Best-case approve if all remaining vote approve:
                let best_approve = approve + remaining_weight;
                let best_part = best_approve + reject;
                let best_approve_bp = if best_part == 0 {
                    10000
                } else {
                    (best_approve * 10000) / best_part
                };
                // Worst-case approve_bp (no remaining ever approves):
                let worst_approve_bp = if participating == 0 { 0 } else { approve_bp };
                if worst_approve_bp >= self.approve_threshold_bp as u64 {
                    Decision::Approved
                } else if best_approve_bp < self.approve_threshold_bp as u64 {
                    Decision::Rejected
                } else {
                    Decision::Pending
                }
            }
        };
        Tally {
            approve,
            reject,
            abstain,
            cast,
            total,
            decision,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), VoteError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VoteError::SchemaMismatch);
        }
        if self.approve_threshold_bp == 0 || self.approve_threshold_bp > 10000 {
            return Err(VoteError::BadThreshold);
        }
        for (k, v) in &self.voters {
            if k.is_empty() {
                return Err(VoteError::EmptyVoter);
            }
            if v.weight == 0 {
                return Err(VoteError::ZeroWeight);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_at_majority() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        t.register("b", 1).unwrap();
        t.register("c", 1).unwrap();
        t.cast("a", Vote::Approve).unwrap();
        t.cast("b", Vote::Approve).unwrap();
        t.cast("c", Vote::Reject).unwrap();
        assert_eq!(t.tally().decision, Decision::Approved);
    }

    #[test]
    fn rejected_below_threshold() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        t.register("b", 1).unwrap();
        t.cast("a", Vote::Approve).unwrap();
        t.cast("b", Vote::Reject).unwrap();
        assert_eq!(t.tally().decision, Decision::Rejected);
    }

    #[test]
    fn pending_when_no_votes() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        assert_eq!(t.tally().decision, Decision::Pending);
    }

    #[test]
    fn weighted_vote() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("heavy", 10).unwrap();
        t.register("light", 1).unwrap();
        t.cast("heavy", Vote::Approve).unwrap();
        t.cast("light", Vote::Reject).unwrap();
        // 10/11 = 9090 bp >= 5001 → Approved.
        assert_eq!(t.tally().decision, Decision::Approved);
    }

    #[test]
    fn decisive_early_approve() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("heavy", 10).unwrap();
        t.register("light", 1).unwrap();
        t.cast("heavy", Vote::Approve).unwrap();
        // worst-case approve = 10/(10+0) = 10000 bp >= 5001 (no rejects).
        // Wait — participating = 10 only, so approve_bp = 10000. Decisive Approved.
        assert_eq!(t.tally().decision, Decision::Approved);
    }

    #[test]
    fn cast_replaces() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        t.cast("a", Vote::Approve).unwrap();
        t.cast("a", Vote::Reject).unwrap();
        assert_eq!(t.tally().reject, 1);
    }

    #[test]
    fn duplicate_voter_rejected() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        assert!(matches!(
            t.register("a", 1).unwrap_err(),
            VoteError::DuplicateVoter(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = VoteTally::new(5001).unwrap();
        assert!(matches!(
            t.register("", 1).unwrap_err(),
            VoteError::EmptyVoter
        ));
        assert!(matches!(
            t.register("a", 0).unwrap_err(),
            VoteError::ZeroWeight
        ));
    }

    #[test]
    fn bad_threshold_rejected() {
        assert!(matches!(
            VoteTally::new(0).unwrap_err(),
            VoteError::BadThreshold
        ));
        assert!(matches!(
            VoteTally::new(10001).unwrap_err(),
            VoteError::BadThreshold
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = VoteTally::new(5001).unwrap();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            VoteError::SchemaMismatch
        ));
    }

    #[test]
    fn vote_serde_roundtrip() {
        let mut t = VoteTally::new(5001).unwrap();
        t.register("a", 1).unwrap();
        t.cast("a", Vote::Approve).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: VoteTally = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
