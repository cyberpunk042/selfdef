//! `selfdef-approval-flow` — multi-stage approval workflow.
//!
//! Stage{name, required (set of approver ids), got (set
//! collected)}. Phase{Pending/Approved/Rejected}. approve(
//! approver) records approval at the active stage; once all
//! required approvers signed off, advance to next stage.
//! After last stage → Approved. reject(reason) → Rejected.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Stage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stage {
    /// Name.
    pub name: String,
    /// Required approver ids.
    pub required: BTreeSet<String>,
    /// Approvers who have signed off.
    pub got: BTreeSet<String>,
}

/// Phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "phase", content = "reason")]
pub enum Phase {
    /// Pending at stage index.
    Pending,
    /// Approved.
    Approved,
    /// Rejected with reason.
    Rejected(String),
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalFlow {
    /// Schema version.
    pub schema_version: String,
    /// Stages in order.
    pub stages: Vec<Stage>,
    /// Active stage index (only meaningful in Pending).
    pub current: usize,
    /// Phase.
    pub phase: Phase,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FlowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("approver empty")]
    EmptyApprover,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
    /// No stages.
    #[error("no stages")]
    NoStages,
    /// Not pending.
    #[error("not pending")]
    NotPending,
    /// Unknown approver.
    #[error("approver not required at active stage: {0}")]
    NotRequiredApprover(String),
    /// Already approved.
    #[error("approver already approved: {0}")]
    AlreadyApproved(String),
}

impl ApprovalFlow {
    /// New (Pending at stage 0).
    pub fn new(stages: Vec<(String, Vec<String>)>) -> Result<Self, FlowError> {
        if stages.is_empty() {
            return Err(FlowError::NoStages);
        }
        let mut s_vec: Vec<Stage> = Vec::with_capacity(stages.len());
        for (name, required) in stages {
            if name.is_empty() {
                return Err(FlowError::EmptyName);
            }
            for r in &required {
                if r.is_empty() {
                    return Err(FlowError::EmptyApprover);
                }
            }
            s_vec.push(Stage {
                name,
                required: required.into_iter().collect(),
                got: BTreeSet::new(),
            });
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            stages: s_vec,
            current: 0,
            phase: Phase::Pending,
        })
    }

    /// Approve at active stage.
    pub fn approve(&mut self, approver: &str) -> Result<Phase, FlowError> {
        if approver.is_empty() {
            return Err(FlowError::EmptyApprover);
        }
        if self.phase != Phase::Pending {
            return Err(FlowError::NotPending);
        }
        let stage = self
            .stages
            .get_mut(self.current)
            .ok_or(FlowError::NotPending)?;
        if !stage.required.contains(approver) {
            return Err(FlowError::NotRequiredApprover(approver.into()));
        }
        if !stage.got.insert(approver.into()) {
            return Err(FlowError::AlreadyApproved(approver.into()));
        }
        // Advance if complete.
        if stage.got == stage.required {
            self.current += 1;
            if self.current >= self.stages.len() {
                self.phase = Phase::Approved;
            }
        }
        Ok(self.phase.clone())
    }

    /// Reject (one-way).
    pub fn reject(&mut self, reason: &str) -> Result<(), FlowError> {
        if reason.is_empty() {
            return Err(FlowError::EmptyReason);
        }
        if self.phase != Phase::Pending {
            return Err(FlowError::NotPending);
        }
        self.phase = Phase::Rejected(reason.into());
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FlowError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FlowError::SchemaMismatch);
        }
        if self.stages.is_empty() {
            return Err(FlowError::NoStages);
        }
        for s in &self.stages {
            if s.name.is_empty() {
                return Err(FlowError::EmptyName);
            }
            for r in &s.required {
                if r.is_empty() {
                    return Err(FlowError::EmptyApprover);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> ApprovalFlow {
        ApprovalFlow::new(vec![
            ("manager".into(), vec!["alice".into()]),
            ("security".into(), vec!["bob".into(), "carol".into()]),
        ])
        .unwrap()
    }

    #[test]
    fn approve_advances_stages() {
        let mut f = flow();
        assert_eq!(f.approve("alice").unwrap(), Phase::Pending);
        assert_eq!(f.current, 1);
        f.approve("bob").unwrap();
        assert_eq!(f.current, 1);
        let p = f.approve("carol").unwrap();
        assert_eq!(p, Phase::Approved);
    }

    #[test]
    fn reject_marks_rejected() {
        let mut f = flow();
        f.reject("too risky").unwrap();
        match f.phase {
            Phase::Rejected(r) => assert_eq!(r, "too risky"),
            _ => panic!("expected rejected"),
        }
    }

    #[test]
    fn non_required_rejected() {
        let mut f = flow();
        assert!(matches!(
            f.approve("bob").unwrap_err(),
            FlowError::NotRequiredApprover(_)
        ));
    }

    #[test]
    fn duplicate_approval_rejected() {
        let mut f = flow();
        f.approve("alice").unwrap();
        // Now at security stage.
        f.approve("bob").unwrap();
        assert!(matches!(
            f.approve("bob").unwrap_err(),
            FlowError::AlreadyApproved(_)
        ));
    }

    #[test]
    fn approve_after_done_rejected() {
        let mut f = flow();
        f.approve("alice").unwrap();
        f.approve("bob").unwrap();
        f.approve("carol").unwrap();
        assert!(matches!(
            f.approve("alice").unwrap_err(),
            FlowError::NotPending
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let r = ApprovalFlow::new(vec![]);
        assert!(matches!(r.unwrap_err(), FlowError::NoStages));
        let r = ApprovalFlow::new(vec![("".into(), vec!["a".into()])]);
        assert!(matches!(r.unwrap_err(), FlowError::EmptyName));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = flow();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            FlowError::SchemaMismatch
        ));
    }

    #[test]
    fn flow_serde_roundtrip() {
        let mut f = flow();
        f.approve("alice").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: ApprovalFlow = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
