//! `selfdef-doctrine-citation` — every decision must cite a doctrine.
//!
//! Maps (Outcome × SideEffectClass) to the set of doctrines from
//! `selfdef-doctrinal-preservation` that govern the decision. The daemon
//! attaches the resulting citation list to each `PolicyDecision` it emits;
//! the audit log records the citations alongside the decision payload.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_doctrinal_preservation::{DoctrineRegistry, DoctrineTag};
use selfdef_policy_decision::{Outcome, PolicyDecision, SideEffectClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Citation envelope attached to a decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CitationSet {
    /// Schema version.
    pub schema_version: String,
    /// trace_id linking to the originating decision.
    pub trace_id: String,
    /// Cited doctrines (must be non-empty when emitted).
    pub tags: Vec<DoctrineTag>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CitationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty citation list — every decision must cite ≥1 doctrine.
    #[error("citation set empty for trace {0}")]
    Empty(String),
    /// Cited a doctrine that is not in the registry.
    #[error("cited doctrine {0:?} not present in registry")]
    Unknown(DoctrineTag),
    /// Trace_id mismatch with the decision.
    #[error("trace_id mismatch: citation={citation} decision={decision}")]
    TraceMismatch {
        /// Citation's trace_id.
        citation: String,
        /// Decision's trace_id.
        decision: String,
    },
}

/// Compute the canonical citation set for a decision.
///
/// Rules:
/// - Every decision cites `EveryActionObservable` (MS033 F03842) +
///   `TraceAtDecision` (MS033 F03942).
/// - `Outcome::Ask` cites `AuthorityFollowsEvidence` (MS040 R09362).
/// - `SideEffectClass::Persistent` cites `CommitIsDurableChange` (MS041 R09601).
/// - `SideEffectClass::FsWrite | NetworkEgress | Process` cite
///   `VmProposesHostCommits` + `VmNeverMutates` (MS034).
/// - `Outcome::Sandbox` cites `ExplicitExchange` (MS037 E0371).
pub fn cite(decision: &PolicyDecision) -> CitationSet {
    let mut tags = vec![
        DoctrineTag::EveryActionObservable,
        DoctrineTag::TraceAtDecision,
    ];

    if decision.outcome == Outcome::Ask {
        tags.push(DoctrineTag::AuthorityFollowsEvidence);
    }
    if decision.side_effect_class == SideEffectClass::Persistent {
        tags.push(DoctrineTag::CommitIsDurableChange);
    }
    if matches!(
        decision.side_effect_class,
        SideEffectClass::FsWrite | SideEffectClass::NetworkEgress | SideEffectClass::Process
    ) {
        tags.push(DoctrineTag::VmProposesHostCommits);
        tags.push(DoctrineTag::VmNeverMutates);
    }
    if decision.outcome == Outcome::Sandbox {
        tags.push(DoctrineTag::ExplicitExchange);
    }

    // Dedup while preserving order.
    let mut seen = std::collections::HashSet::new();
    tags.retain(|t| seen.insert(*t));

    CitationSet {
        schema_version: SCHEMA_VERSION.into(),
        trace_id: decision.trace_id.clone(),
        tags,
    }
}

impl CitationSet {
    /// Validate against the decision + registry.
    pub fn validate(
        &self,
        decision: &PolicyDecision,
        registry: &DoctrineRegistry,
    ) -> Result<(), CitationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CitationError::SchemaMismatch);
        }
        if self.tags.is_empty() {
            return Err(CitationError::Empty(self.trace_id.clone()));
        }
        if self.trace_id != decision.trace_id {
            return Err(CitationError::TraceMismatch {
                citation: self.trace_id.clone(),
                decision: decision.trace_id.clone(),
            });
        }
        for t in &self.tags {
            if !registry.records.iter().any(|r| r.tag == *t) {
                return Err(CitationError::Unknown(*t));
            }
        }
        Ok(())
    }

    /// True if a specific doctrine is cited.
    pub fn cites(&self, tag: DoctrineTag) -> bool {
        self.tags.contains(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, RiskClass, UserApprovalState};

    fn d_base(outcome: Outcome, sec: SideEffectClass) -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "op".into(),
            action: "fs.write".into(),
            resource: "/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: sec,
            user_approval: UserApprovalState::NotRequired,
            outcome,
            reason: "ok".into(),
            trace_id: "tr-1".into(),
            signature: "ms003".into(),
        }
    }

    fn reg() -> DoctrineRegistry {
        DoctrineRegistry::canonical()
    }

    #[test]
    fn baseline_two_doctrines_always_cited() {
        let d = d_base(Outcome::Allow, SideEffectClass::ReadOnly);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::EveryActionObservable));
        assert!(c.cites(DoctrineTag::TraceAtDecision));
        assert_eq!(c.tags.len(), 2);
        c.validate(&d, &reg()).unwrap();
    }

    #[test]
    fn ask_adds_authority_follows_evidence() {
        let d = d_base(Outcome::Ask, SideEffectClass::ReadOnly);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::AuthorityFollowsEvidence));
    }

    #[test]
    fn persistent_adds_commit_doctrine() {
        let d = d_base(Outcome::Allow, SideEffectClass::Persistent);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::CommitIsDurableChange));
    }

    #[test]
    fn fs_write_adds_vm_proposes_doctrines() {
        let d = d_base(Outcome::Allow, SideEffectClass::FsWrite);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::VmProposesHostCommits));
        assert!(c.cites(DoctrineTag::VmNeverMutates));
    }

    #[test]
    fn network_egress_adds_vm_proposes_doctrines() {
        let d = d_base(Outcome::Allow, SideEffectClass::NetworkEgress);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::VmProposesHostCommits));
    }

    #[test]
    fn process_adds_vm_proposes_doctrines() {
        let d = d_base(Outcome::Allow, SideEffectClass::Process);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::VmNeverMutates));
    }

    #[test]
    fn sandbox_outcome_adds_explicit_exchange() {
        let d = d_base(Outcome::Sandbox, SideEffectClass::FsWrite);
        let c = cite(&d);
        assert!(c.cites(DoctrineTag::ExplicitExchange));
    }

    #[test]
    fn dedup_preserves_order_and_no_duplicates() {
        let d = d_base(Outcome::Ask, SideEffectClass::FsWrite);
        let c = cite(&d);
        // 2 baseline + Ask + 2 vm-proposes/mutates = 5 distinct
        assert_eq!(c.tags.len(), 5);
        use std::collections::HashSet;
        let s: HashSet<_> = c.tags.iter().collect();
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn empty_citation_rejected() {
        let d = d_base(Outcome::Allow, SideEffectClass::ReadOnly);
        let mut c = cite(&d);
        c.tags.clear();
        assert!(matches!(
            c.validate(&d, &reg()).unwrap_err(),
            CitationError::Empty(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let d = d_base(Outcome::Allow, SideEffectClass::ReadOnly);
        let mut c = cite(&d);
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate(&d, &reg()).unwrap_err(),
            CitationError::SchemaMismatch
        ));
    }

    #[test]
    fn trace_mismatch_caught() {
        let d = d_base(Outcome::Allow, SideEffectClass::ReadOnly);
        let mut c = cite(&d);
        c.trace_id = "tr-2".into();
        match c.validate(&d, &reg()).unwrap_err() {
            CitationError::TraceMismatch { citation, decision } => {
                assert_eq!(citation, "tr-2");
                assert_eq!(decision, "tr-1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn citation_serde_roundtrip() {
        let d = d_base(Outcome::Ask, SideEffectClass::FsWrite);
        let c = cite(&d);
        let j = serde_json::to_string(&c).unwrap();
        let back: CitationSet = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
