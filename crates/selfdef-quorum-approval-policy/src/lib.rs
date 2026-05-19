//! `selfdef-quorum-approval-policy` — N-of-M operator approval.
//!
//! High-risk actions are gated on accumulated approvals from
//! distinct operators. Duplicate approvals from the same operator
//! do not double-count. A single explicit veto vacates the entire
//! pool — the request must be re-initiated.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One operator's vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vote {
    /// Approve.
    Approve,
    /// Veto (cancels the pool).
    Veto,
}

/// Gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuorumDecision {
    /// Quorum met → action clears.
    Cleared,
    /// Pool open, more approvals needed.
    Pending,
    /// Pool vacated by veto → action denied.
    Vetoed,
}

/// One recorded vote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ballot {
    /// Operator id.
    pub operator_id: String,
    /// Vote.
    pub vote: Vote,
    /// ISO-8601 UTC timestamp.
    pub at: String,
}

/// Quorum-approval policy for one pending action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumPool {
    /// Schema version.
    pub schema_version: String,
    /// Action being gated (free-form id).
    pub action_id: String,
    /// Required approvals (N).
    pub required: u32,
    /// Authorized operator ids (M); only these may vote.
    pub authorized: Vec<String>,
    /// Recorded ballots (order = arrival).
    pub ballots: Vec<Ballot>,
    /// Has a veto landed?
    pub vetoed: bool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuorumError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty action id.
    #[error("action_id empty")]
    EmptyActionId,
    /// Required > authorized count.
    #[error("required {required} > authorized {authorized}")]
    RequiredExceedsAuthorized {
        /// required.
        required: u32,
        /// authorized.
        authorized: usize,
    },
    /// Required must be > 0.
    #[error("required is zero")]
    RequiredZero,
    /// Empty operator id.
    #[error("operator_id empty")]
    EmptyOperatorId,
    /// Duplicate operator id in authorized list.
    #[error("duplicate authorized operator id: {0}")]
    DuplicateAuthorized(String),
    /// Voter not in authorized list.
    #[error("voter {0} not authorized")]
    NotAuthorized(String),
    /// Pool already vetoed.
    #[error("pool already vetoed")]
    AlreadyVetoed,
    /// Pool already cleared (quorum met) — no more votes.
    #[error("pool already cleared")]
    AlreadyCleared,
}

impl QuorumPool {
    /// New pool. `authorized` must contain `required` or more distinct ids.
    pub fn new(action_id: &str, required: u32, authorized: Vec<String>) -> Result<Self, QuorumError> {
        if action_id.is_empty() {
            return Err(QuorumError::EmptyActionId);
        }
        if required == 0 {
            return Err(QuorumError::RequiredZero);
        }
        check_authorized(&authorized)?;
        if (required as usize) > authorized.len() {
            return Err(QuorumError::RequiredExceedsAuthorized {
                required,
                authorized: authorized.len(),
            });
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            action_id: action_id.into(),
            required,
            authorized,
            ballots: Vec::new(),
            vetoed: false,
        })
    }

    /// Cast a vote. Duplicate approvals from the same operator are a
    /// no-op (idempotent). A veto from any authorized operator vacates
    /// the pool.
    pub fn cast(&mut self, operator_id: &str, vote: Vote, at: &str) -> Result<QuorumDecision, QuorumError> {
        if operator_id.is_empty() {
            return Err(QuorumError::EmptyOperatorId);
        }
        if self.vetoed {
            return Err(QuorumError::AlreadyVetoed);
        }
        if matches!(self.decide(), QuorumDecision::Cleared) {
            return Err(QuorumError::AlreadyCleared);
        }
        if !self.authorized.iter().any(|a| a == operator_id) {
            return Err(QuorumError::NotAuthorized(operator_id.into()));
        }
        match vote {
            Vote::Veto => {
                self.vetoed = true;
                self.ballots.push(Ballot {
                    operator_id: operator_id.into(),
                    vote,
                    at: at.into(),
                });
            }
            Vote::Approve => {
                // Idempotent: only record first Approve from this operator.
                let already = self.ballots.iter().any(|b| b.operator_id == operator_id && b.vote == Vote::Approve);
                if !already {
                    self.ballots.push(Ballot {
                        operator_id: operator_id.into(),
                        vote,
                        at: at.into(),
                    });
                }
            }
        }
        Ok(self.decide())
    }

    /// Count distinct approving operators.
    pub fn approvals(&self) -> u32 {
        use std::collections::HashSet;
        let mut s: HashSet<&str> = HashSet::new();
        for b in &self.ballots {
            if b.vote == Vote::Approve {
                s.insert(b.operator_id.as_str());
            }
        }
        s.len() as u32
    }

    /// Compute decision.
    pub fn decide(&self) -> QuorumDecision {
        if self.vetoed {
            return QuorumDecision::Vetoed;
        }
        if self.approvals() >= self.required {
            QuorumDecision::Cleared
        } else {
            QuorumDecision::Pending
        }
    }

    /// Reset pool (clears ballots + veto). action_id, required, authorized preserved.
    pub fn reset(&mut self) {
        self.ballots.clear();
        self.vetoed = false;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuorumError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QuorumError::SchemaMismatch);
        }
        if self.action_id.is_empty() {
            return Err(QuorumError::EmptyActionId);
        }
        if self.required == 0 {
            return Err(QuorumError::RequiredZero);
        }
        check_authorized(&self.authorized)?;
        if (self.required as usize) > self.authorized.len() {
            return Err(QuorumError::RequiredExceedsAuthorized {
                required: self.required,
                authorized: self.authorized.len(),
            });
        }
        Ok(())
    }
}

fn check_authorized(authorized: &[String]) -> Result<(), QuorumError> {
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    for a in authorized {
        if a.is_empty() {
            return Err(QuorumError::EmptyOperatorId);
        }
        if !seen.insert(a.as_str()) {
            return Err(QuorumError::DuplicateAuthorized(a.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn empty_action_rejected() {
        assert!(matches!(
            QuorumPool::new("", 1, auth(&["a"])).unwrap_err(),
            QuorumError::EmptyActionId
        ));
    }

    #[test]
    fn required_zero_rejected() {
        assert!(matches!(
            QuorumPool::new("act", 0, auth(&["a"])).unwrap_err(),
            QuorumError::RequiredZero
        ));
    }

    #[test]
    fn required_exceeds_authorized_rejected() {
        assert!(matches!(
            QuorumPool::new("act", 3, auth(&["a", "b"])).unwrap_err(),
            QuorumError::RequiredExceedsAuthorized { .. }
        ));
    }

    #[test]
    fn duplicate_authorized_rejected() {
        assert!(matches!(
            QuorumPool::new("act", 1, auth(&["a", "a"])).unwrap_err(),
            QuorumError::DuplicateAuthorized(_)
        ));
    }

    #[test]
    fn pending_until_quorum() {
        let mut p = QuorumPool::new("act", 2, auth(&["a", "b", "c"])).unwrap();
        assert_eq!(p.cast("a", Vote::Approve, "t1").unwrap(), QuorumDecision::Pending);
        assert_eq!(p.cast("b", Vote::Approve, "t2").unwrap(), QuorumDecision::Cleared);
    }

    #[test]
    fn duplicate_approve_idempotent() {
        let mut p = QuorumPool::new("act", 2, auth(&["a", "b", "c"])).unwrap();
        p.cast("a", Vote::Approve, "t1").unwrap();
        p.cast("a", Vote::Approve, "t2").unwrap();
        p.cast("a", Vote::Approve, "t3").unwrap();
        assert_eq!(p.approvals(), 1);
        assert_eq!(p.decide(), QuorumDecision::Pending);
    }

    #[test]
    fn veto_vacates_pool() {
        let mut p = QuorumPool::new("act", 2, auth(&["a", "b", "c"])).unwrap();
        p.cast("a", Vote::Approve, "t1").unwrap();
        assert_eq!(p.cast("c", Vote::Veto, "t2").unwrap(), QuorumDecision::Vetoed);
        assert!(p.vetoed);
    }

    #[test]
    fn unauthorized_voter_rejected() {
        let mut p = QuorumPool::new("act", 1, auth(&["a"])).unwrap();
        assert!(matches!(p.cast("z", Vote::Approve, "t").unwrap_err(), QuorumError::NotAuthorized(_)));
    }

    #[test]
    fn vote_after_veto_rejected() {
        let mut p = QuorumPool::new("act", 1, auth(&["a", "b"])).unwrap();
        p.cast("a", Vote::Veto, "t").unwrap();
        assert!(matches!(p.cast("b", Vote::Approve, "t").unwrap_err(), QuorumError::AlreadyVetoed));
    }

    #[test]
    fn vote_after_cleared_rejected() {
        let mut p = QuorumPool::new("act", 1, auth(&["a", "b"])).unwrap();
        p.cast("a", Vote::Approve, "t").unwrap();
        assert!(matches!(p.cast("b", Vote::Approve, "t").unwrap_err(), QuorumError::AlreadyCleared));
    }

    #[test]
    fn reset_clears_state() {
        let mut p = QuorumPool::new("act", 2, auth(&["a", "b"])).unwrap();
        p.cast("a", Vote::Veto, "t").unwrap();
        p.reset();
        assert!(!p.vetoed);
        assert_eq!(p.approvals(), 0);
        assert_eq!(p.decide(), QuorumDecision::Pending);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = QuorumPool::new("act", 1, auth(&["a"])).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), QuorumError::SchemaMismatch));
    }

    #[test]
    fn vote_serde_kebab() {
        assert_eq!(serde_json::to_string(&Vote::Approve).unwrap(), "\"approve\"");
        assert_eq!(serde_json::to_string(&Vote::Veto).unwrap(), "\"veto\"");
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(serde_json::to_string(&QuorumDecision::Cleared).unwrap(), "\"cleared\"");
        assert_eq!(serde_json::to_string(&QuorumDecision::Pending).unwrap(), "\"pending\"");
        assert_eq!(serde_json::to_string(&QuorumDecision::Vetoed).unwrap(), "\"vetoed\"");
    }

    #[test]
    fn pool_serde_roundtrip() {
        let mut p = QuorumPool::new("act", 2, auth(&["a", "b"])).unwrap();
        p.cast("a", Vote::Approve, "t").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: QuorumPool = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
