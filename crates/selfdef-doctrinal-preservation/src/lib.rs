//! `selfdef-doctrinal-preservation` — composite verbatim doctrine registry.
//!
//! Aggregates every doctrine string from the IPS-side crates into one
//! tamper-checkable snapshot. Per operator standing direction
//! ("you cannot invent crap") + multiple verbatim preservation
//! requirements (R10297 / R10298 / MS040 R09362 / MS041 R09601 / etc.)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_cli_mirror::DOCTRINE_FULLSTACK_AT_THE_EDGES;
use selfdef_commit_authority::DOCTRINE_COMMIT_IS_DURABLE_CHANGE;
use selfdef_communication_boundary::{DOCTRINE_VM_NEVER_MUTATES, DOCTRINE_VM_PROPOSES_HOST_COMMITS};
use selfdef_filesystem_boundary::{DOCTRINE_EXPLICIT_EXCHANGE, DOCTRINE_VM_WRITES_PROPOSALS};
use selfdef_policy_decision::{DOCTRINE_EVERY_ACTION_OBSERVABLE, DOCTRINE_TRACE_AT_DECISION};
use selfdef_profile_authority_gate::DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE;
use selfdef_tui_mirror::DOCTRINE_NO_VANITY_GRAPHS;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine tag enumerates every canonical doctrine string this crate aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctrineTag {
    /// MS043 R10297 — "Fullstack at the edges" (CLI).
    FullstackAtTheEdges,
    /// MS043 R10298 — "A dashboard should not show vanity graphs" (TUI).
    NoVanityGraphs,
    /// MS040 R09362 — "Authority follows evidence".
    AuthorityFollowsEvidence,
    /// MS041 R09601 — "A commit is any durable change".
    CommitIsDurableChange,
    /// MS033 F03842 — "Every action becomes observable and governed".
    EveryActionObservable,
    /// MS033 F03942 — "Trace is emitted when the action is decided, not after".
    TraceAtDecision,
    /// MS034 E0346 — "Never let the VM directly mutate host truth".
    VmNeverMutates,
    /// MS034 E0347 — "The VM proposes. Host commits."
    VmProposesHostCommits,
    /// MS037 E0371 — "Use explicit exchange directories".
    ExplicitExchange,
    /// MS037 E0373 — "VM writes proposals, not final state".
    VmWritesProposals,
}

impl DoctrineTag {
    /// Verbatim string for this tag.
    pub fn verbatim(self) -> &'static str {
        match self {
            DoctrineTag::FullstackAtTheEdges => DOCTRINE_FULLSTACK_AT_THE_EDGES,
            DoctrineTag::NoVanityGraphs => DOCTRINE_NO_VANITY_GRAPHS,
            DoctrineTag::AuthorityFollowsEvidence => DOCTRINE_AUTHORITY_FOLLOWS_EVIDENCE,
            DoctrineTag::CommitIsDurableChange => DOCTRINE_COMMIT_IS_DURABLE_CHANGE,
            DoctrineTag::EveryActionObservable => DOCTRINE_EVERY_ACTION_OBSERVABLE,
            DoctrineTag::TraceAtDecision => DOCTRINE_TRACE_AT_DECISION,
            DoctrineTag::VmNeverMutates => DOCTRINE_VM_NEVER_MUTATES,
            DoctrineTag::VmProposesHostCommits => DOCTRINE_VM_PROPOSES_HOST_COMMITS,
            DoctrineTag::ExplicitExchange => DOCTRINE_EXPLICIT_EXCHANGE,
            DoctrineTag::VmWritesProposals => DOCTRINE_VM_WRITES_PROPOSALS,
        }
    }
    /// Provenance string ("MS<NN> + R<RID>") for audit traceability.
    pub fn provenance(self) -> &'static str {
        match self {
            DoctrineTag::FullstackAtTheEdges => "MS043 R10297",
            DoctrineTag::NoVanityGraphs => "MS043 R10298",
            DoctrineTag::AuthorityFollowsEvidence => "MS040 R09362",
            DoctrineTag::CommitIsDurableChange => "MS041 R09601",
            DoctrineTag::EveryActionObservable => "MS033 F03842",
            DoctrineTag::TraceAtDecision => "MS033 F03942",
            DoctrineTag::VmNeverMutates => "MS034 E0346",
            DoctrineTag::VmProposesHostCommits => "MS034 E0347",
            DoctrineTag::ExplicitExchange => "MS037 E0371",
            DoctrineTag::VmWritesProposals => "MS037 E0373",
        }
    }
    /// Iterate every canonical tag.
    pub fn all() -> [DoctrineTag; 10] {
        [
            DoctrineTag::FullstackAtTheEdges, DoctrineTag::NoVanityGraphs,
            DoctrineTag::AuthorityFollowsEvidence, DoctrineTag::CommitIsDurableChange,
            DoctrineTag::EveryActionObservable, DoctrineTag::TraceAtDecision,
            DoctrineTag::VmNeverMutates, DoctrineTag::VmProposesHostCommits,
            DoctrineTag::ExplicitExchange, DoctrineTag::VmWritesProposals,
        ]
    }
}

/// One doctrine record (tag + verbatim text + provenance).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctrineRecord {
    /// Tag.
    pub tag: DoctrineTag,
    /// Verbatim text.
    pub text: String,
    /// Provenance (MS / R-row reference).
    pub provenance: String,
}

/// Registry composite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctrineRegistry {
    /// Schema version.
    pub schema_version: String,
    /// Captured at.
    pub captured_at: String,
    /// All 10 doctrine records.
    pub records: Vec<DoctrineRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DoctrineError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Wrong record count.
    #[error("record count {0} != 10")]
    CountInvalid(usize),
    /// Tag missing.
    #[error("required tag missing: {0:?}")]
    TagMissing(DoctrineTag),
    /// Verbatim text tampered.
    #[error("verbatim text tampered for {tag:?}: expected verbatim, got {actual:?}")]
    TextTampered {
        /// Tag.
        tag: DoctrineTag,
        /// Observed (tampered) text.
        actual: String,
    },
}

impl DoctrineRegistry {
    /// Build canonical registry from this binary's compile-time constants.
    pub fn canonical() -> Self {
        let records = DoctrineTag::all().into_iter().map(|t| DoctrineRecord {
            tag: t,
            text: t.verbatim().into(),
            provenance: t.provenance().into(),
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            records,
        }
    }

    /// Validate every record's text against this binary's compile-time constants.
    pub fn validate(&self) -> Result<(), DoctrineError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DoctrineError::SchemaMismatch);
        }
        if self.records.len() != 10 {
            return Err(DoctrineError::CountInvalid(self.records.len()));
        }
        for tag in DoctrineTag::all() {
            let rec = self.records.iter().find(|r| r.tag == tag)
                .ok_or(DoctrineError::TagMissing(tag))?;
            let expected = tag.verbatim();
            if rec.text != expected {
                return Err(DoctrineError::TextTampered {
                    tag,
                    actual: rec.text.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_doctrines_canonical() {
        assert_eq!(DoctrineTag::all().len(), 10);
    }

    #[test]
    fn canonical_registry_validates() {
        DoctrineRegistry::canonical().validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = DoctrineRegistry::canonical();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), DoctrineError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_rejected() {
        let mut r = DoctrineRegistry::canonical();
        r.records.pop();
        assert!(matches!(r.validate().unwrap_err(), DoctrineError::CountInvalid(9)));
    }

    #[test]
    fn text_tamper_caught() {
        let mut r = DoctrineRegistry::canonical();
        r.records[0].text = "tampered".into();
        match r.validate().unwrap_err() {
            DoctrineError::TextTampered { tag, actual } => {
                // The actual order matches DoctrineTag::all() — first is FullstackAtTheEdges
                assert_eq!(tag, DoctrineTag::FullstackAtTheEdges);
                assert_eq!(actual, "tampered");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn provenance_strings_present() {
        for tag in DoctrineTag::all() {
            let p = tag.provenance();
            assert!(p.starts_with("MS"), "tag {tag:?} provenance {p}");
        }
    }

    #[test]
    fn verbatim_strings_non_empty() {
        for tag in DoctrineTag::all() {
            let v = tag.verbatim();
            assert!(!v.is_empty(), "tag {tag:?} text empty");
        }
    }

    #[test]
    fn doctrine_tag_serde_kebab() {
        assert_eq!(serde_json::to_string(&DoctrineTag::AuthorityFollowsEvidence).unwrap(), "\"authority-follows-evidence\"");
        assert_eq!(serde_json::to_string(&DoctrineTag::CommitIsDurableChange).unwrap(), "\"commit-is-durable-change\"");
        assert_eq!(serde_json::to_string(&DoctrineTag::TraceAtDecision).unwrap(), "\"trace-at-decision\"");
    }

    #[test]
    fn registry_serde_roundtrip() {
        let r = DoctrineRegistry::canonical();
        let j = serde_json::to_string(&r).unwrap();
        let back: DoctrineRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
