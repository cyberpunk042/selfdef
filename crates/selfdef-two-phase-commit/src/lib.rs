//! `selfdef-two-phase-commit` — 2PC coordinator.
//!
//! Phase{Init/Preparing/Prepared/Committing/Committed/Aborting/
//! Aborted}. register adds participants. vote(participant,
//! outcome) records a Yes/No. When all have voted Yes, transition
//! Prepared and decide() commits; any No transitions Aborting +
//! decide() aborts. Decision is recorded; further votes rejected.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Init (registering participants).
    Init,
    /// Preparing (some have voted).
    Preparing,
    /// All voted Yes; ready to commit.
    Prepared,
    /// Committed.
    Committed,
    /// At least one No vote.
    Aborting,
    /// Aborted.
    Aborted,
}

/// Vote.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Vote {
    /// Yes.
    Yes,
    /// No.
    No,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TwoPhaseCommit {
    /// Schema version.
    pub schema_version: String,
    /// Phase.
    pub phase: Phase,
    /// participant id → vote (None = pending).
    pub participants: BTreeMap<String, Option<Vote>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CommitError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("participant id empty")]
    EmptyParticipant,
    /// Duplicate.
    #[error("duplicate participant: {0}")]
    DuplicateParticipant(String),
    /// Unknown.
    #[error("unknown participant: {0}")]
    UnknownParticipant(String),
    /// Bad state.
    #[error("invalid phase for operation")]
    InvalidPhase,
    /// No participants.
    #[error("no participants")]
    NoParticipants,
}

impl TwoPhaseCommit {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            phase: Phase::Init,
            participants: BTreeMap::new(),
        }
    }

    /// Register a participant.
    pub fn register(&mut self, id: &str) -> Result<(), CommitError> {
        if id.is_empty() { return Err(CommitError::EmptyParticipant); }
        if self.phase != Phase::Init {
            return Err(CommitError::InvalidPhase);
        }
        if self.participants.contains_key(id) {
            return Err(CommitError::DuplicateParticipant(id.into()));
        }
        self.participants.insert(id.into(), None);
        Ok(())
    }

    /// Record a vote.
    pub fn vote(&mut self, id: &str, v: Vote) -> Result<Phase, CommitError> {
        if self.phase == Phase::Committed || self.phase == Phase::Aborted {
            return Err(CommitError::InvalidPhase);
        }
        let slot = self.participants.get_mut(id).ok_or_else(|| CommitError::UnknownParticipant(id.into()))?;
        *slot = Some(v);
        // Recompute phase.
        let any_no = self.participants.values().any(|x| *x == Some(Vote::No));
        let all_yes = self.participants.values().all(|x| *x == Some(Vote::Yes));
        let some_voted = self.participants.values().any(|x| x.is_some());
        self.phase = if any_no {
            Phase::Aborting
        } else if all_yes && !self.participants.is_empty() {
            Phase::Prepared
        } else if some_voted {
            Phase::Preparing
        } else {
            Phase::Init
        };
        Ok(self.phase)
    }

    /// Finalize: Prepared→Committed; Aborting→Aborted. Others error.
    pub fn decide(&mut self) -> Result<Phase, CommitError> {
        if self.participants.is_empty() {
            return Err(CommitError::NoParticipants);
        }
        self.phase = match self.phase {
            Phase::Prepared => Phase::Committed,
            Phase::Aborting => Phase::Aborted,
            _ => return Err(CommitError::InvalidPhase),
        };
        Ok(self.phase)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CommitError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CommitError::SchemaMismatch); }
        for k in self.participants.keys() {
            if k.is_empty() { return Err(CommitError::EmptyParticipant); }
        }
        Ok(())
    }
}

impl Default for TwoPhaseCommit {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_commits() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.register("b").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        assert_eq!(t.phase, Phase::Preparing);
        t.vote("b", Vote::Yes).unwrap();
        assert_eq!(t.phase, Phase::Prepared);
        assert_eq!(t.decide().unwrap(), Phase::Committed);
    }

    #[test]
    fn any_no_aborts() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.register("b").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        t.vote("b", Vote::No).unwrap();
        assert_eq!(t.phase, Phase::Aborting);
        assert_eq!(t.decide().unwrap(), Phase::Aborted);
    }

    #[test]
    fn register_after_voting_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        assert!(matches!(t.register("b").unwrap_err(), CommitError::InvalidPhase));
    }

    #[test]
    fn vote_after_decide_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        t.decide().unwrap();
        assert!(matches!(t.vote("a", Vote::No).unwrap_err(), CommitError::InvalidPhase));
    }

    #[test]
    fn decide_without_prepared_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        assert!(matches!(t.decide().unwrap_err(), CommitError::InvalidPhase));
    }

    #[test]
    fn duplicate_participant_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        assert!(matches!(t.register("a").unwrap_err(), CommitError::DuplicateParticipant(_)));
    }

    #[test]
    fn unknown_vote_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        assert!(matches!(t.vote("nope", Vote::Yes).unwrap_err(), CommitError::UnknownParticipant(_)));
    }

    #[test]
    fn vote_revision_to_no_aborts() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.register("b").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        t.vote("b", Vote::Yes).unwrap();
        // Revise b's vote before decide.
        t.vote("b", Vote::No).unwrap();
        assert_eq!(t.phase, Phase::Aborting);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = TwoPhaseCommit::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), CommitError::SchemaMismatch));
    }

    #[test]
    fn tpc_serde_roundtrip() {
        let mut t = TwoPhaseCommit::new();
        t.register("a").unwrap();
        t.vote("a", Vote::Yes).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: TwoPhaseCommit = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
