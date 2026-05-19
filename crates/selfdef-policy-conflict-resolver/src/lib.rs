//! `selfdef-policy-conflict-resolver` — multi-policy decision merge.
//!
//! When N policies vote on the same action, this resolver collapses
//! them under deny-overrides semantics with the order:
//! `Deny > Ask > Sandbox > Allow`. Ties broken by source priority
//! (lower number = higher priority). Output records the winning
//! source so the audit trail explains the verdict.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-policy decision (mirrors the canonical 4-outcome IPS taxonomy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Allow outright.
    Allow,
    /// Allow only in sandbox.
    Sandbox,
    /// Defer to operator approval.
    Ask,
    /// Deny outright.
    Deny,
}

impl Decision {
    /// Strictness rank — higher = more restrictive. Deny=4, Ask=3,
    /// Sandbox=2, Allow=1.
    pub fn rank(self) -> u8 {
        match self {
            Decision::Deny => 4,
            Decision::Ask => 3,
            Decision::Sandbox => 2,
            Decision::Allow => 1,
        }
    }
}

/// One policy vote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyVote {
    /// Source policy id.
    pub source: String,
    /// Source priority (lower = higher priority for tie-break).
    pub priority: u32,
    /// Decision.
    pub decision: Decision,
    /// Optional reason (≤ 200 chars).
    pub reason: String,
}

/// Result of the merge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictResolution {
    /// Schema version.
    pub schema_version: String,
    /// Winning decision.
    pub decision: Decision,
    /// Winning source id.
    pub winning_source: String,
    /// All votes considered, in arrival order.
    pub votes: Vec<PolicyVote>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ConflictError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// No votes.
    #[error("no votes to resolve")]
    NoVotes,
    /// Empty source id.
    #[error("vote source empty")]
    EmptySource,
    /// Reason too long.
    #[error("vote {0} reason length {1} > 200")]
    ReasonTooLong(String, usize),
}

/// Resolver (stateless).
#[derive(Debug, Clone, Default)]
pub struct PolicyConflictResolver;

impl PolicyConflictResolver {
    /// Resolve a non-empty set of votes.
    pub fn resolve(votes: Vec<PolicyVote>) -> Result<ConflictResolution, ConflictError> {
        if votes.is_empty() {
            return Err(ConflictError::NoVotes);
        }
        for v in &votes {
            if v.source.is_empty() {
                return Err(ConflictError::EmptySource);
            }
            let n = v.reason.chars().count();
            if n > 200 {
                return Err(ConflictError::ReasonTooLong(v.source.clone(), n));
            }
        }
        // Pick highest rank; tie-break by lowest priority number; then by arrival order.
        let mut idx_best = 0usize;
        for i in 1..votes.len() {
            let cur = &votes[idx_best];
            let cand = &votes[i];
            if cand.decision.rank() > cur.decision.rank()
                || (cand.decision.rank() == cur.decision.rank() && cand.priority < cur.priority)
            {
                idx_best = i;
            }
        }
        Ok(ConflictResolution {
            schema_version: SCHEMA_VERSION.into(),
            decision: votes[idx_best].decision,
            winning_source: votes[idx_best].source.clone(),
            votes,
        })
    }
}

impl ConflictResolution {
    /// Validate.
    pub fn validate(&self) -> Result<(), ConflictError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConflictError::SchemaMismatch);
        }
        if self.votes.is_empty() {
            return Err(ConflictError::NoVotes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(source: &str, priority: u32, d: Decision) -> PolicyVote {
        PolicyVote {
            source: source.into(),
            priority,
            decision: d,
            reason: String::new(),
        }
    }

    #[test]
    fn empty_rejected() {
        assert!(matches!(
            PolicyConflictResolver::resolve(vec![]).unwrap_err(),
            ConflictError::NoVotes
        ));
    }

    #[test]
    fn single_vote_wins() {
        let r = PolicyConflictResolver::resolve(vec![v("p", 0, Decision::Allow)]).unwrap();
        assert_eq!(r.decision, Decision::Allow);
        assert_eq!(r.winning_source, "p");
    }

    #[test]
    fn deny_overrides_allow() {
        let r = PolicyConflictResolver::resolve(vec![
            v("a", 0, Decision::Allow),
            v("b", 1, Decision::Deny),
        ]).unwrap();
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.winning_source, "b");
    }

    #[test]
    fn ask_overrides_allow_and_sandbox() {
        let r = PolicyConflictResolver::resolve(vec![
            v("a", 0, Decision::Allow),
            v("b", 1, Decision::Sandbox),
            v("c", 2, Decision::Ask),
        ]).unwrap();
        assert_eq!(r.decision, Decision::Ask);
        assert_eq!(r.winning_source, "c");
    }

    #[test]
    fn deny_overrides_ask() {
        let r = PolicyConflictResolver::resolve(vec![
            v("ask", 0, Decision::Ask),
            v("deny", 5, Decision::Deny),
        ]).unwrap();
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.winning_source, "deny");
    }

    #[test]
    fn sandbox_overrides_allow() {
        let r = PolicyConflictResolver::resolve(vec![
            v("a", 0, Decision::Allow),
            v("b", 1, Decision::Sandbox),
        ]).unwrap();
        assert_eq!(r.decision, Decision::Sandbox);
    }

    #[test]
    fn tie_breaks_on_priority() {
        let r = PolicyConflictResolver::resolve(vec![
            v("low-prio", 10, Decision::Deny),
            v("high-prio", 1, Decision::Deny),
        ]).unwrap();
        assert_eq!(r.winning_source, "high-prio");
    }

    #[test]
    fn empty_source_rejected() {
        assert!(matches!(
            PolicyConflictResolver::resolve(vec![v("", 0, Decision::Allow)]).unwrap_err(),
            ConflictError::EmptySource
        ));
    }

    #[test]
    fn reason_too_long_rejected() {
        let mut vote = v("p", 0, Decision::Allow);
        vote.reason = "x".repeat(201);
        assert!(matches!(
            PolicyConflictResolver::resolve(vec![vote]).unwrap_err(),
            ConflictError::ReasonTooLong(_, 201)
        ));
    }

    #[test]
    fn all_allow_returns_allow() {
        let r = PolicyConflictResolver::resolve(vec![
            v("a", 0, Decision::Allow),
            v("b", 1, Decision::Allow),
            v("c", 2, Decision::Allow),
        ]).unwrap();
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn votes_preserved_in_order() {
        let r = PolicyConflictResolver::resolve(vec![
            v("first", 0, Decision::Allow),
            v("second", 1, Decision::Ask),
            v("third", 2, Decision::Sandbox),
        ]).unwrap();
        assert_eq!(r.votes[0].source, "first");
        assert_eq!(r.votes[1].source, "second");
        assert_eq!(r.votes[2].source, "third");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = PolicyConflictResolver::resolve(vec![v("p", 0, Decision::Allow)]).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), ConflictError::SchemaMismatch));
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(serde_json::to_string(&Decision::Sandbox).unwrap(), "\"sandbox\"");
        assert_eq!(serde_json::to_string(&Decision::Ask).unwrap(), "\"ask\"");
    }

    #[test]
    fn rank_order_correct() {
        assert!(Decision::Deny.rank() > Decision::Ask.rank());
        assert!(Decision::Ask.rank() > Decision::Sandbox.rank());
        assert!(Decision::Sandbox.rank() > Decision::Allow.rank());
    }

    #[test]
    fn resolution_serde_roundtrip() {
        let r = PolicyConflictResolver::resolve(vec![
            v("a", 0, Decision::Allow),
            v("b", 1, Decision::Deny),
        ]).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ConflictResolution = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
