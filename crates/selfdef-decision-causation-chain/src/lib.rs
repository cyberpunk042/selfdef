//! `selfdef-decision-causation-chain` — record decision lineage.
//!
//! `record(decision_id, summary, ts_ms, caused_by[])` adds a node
//! and links it back to each cause. Each cause must already exist
//! (or the call fails) — this enforces "no orphan ancestors". A
//! decision may have many causes (DAG, not a tree) and many
//! consequences. Cycles are prevented at insert: adding a cause
//! that would create a cycle returns `WouldCycle`.
//!
//! `ancestors(id, max_depth)` returns the set of upstream decisions
//! up to `max_depth` hops; `descendants(id, max_depth)` likewise
//! downstream.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One decision node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// Id.
    pub id: String,
    /// Operator-readable summary.
    pub summary: String,
    /// Recorded ts.
    pub ts_ms: u64,
    /// Causes (upstream decisions that contributed).
    pub caused_by: BTreeSet<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionCausationChain {
    /// Schema version.
    pub schema_version: String,
    /// id → decision.
    pub decisions: BTreeMap<String, Decision>,
    /// Reverse index: cause → consequences.
    pub consequences: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CausationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Empty summary.
    #[error("summary empty")]
    EmptySummary,
    /// Duplicate.
    #[error("duplicate decision: {0}")]
    DuplicateId(String),
    /// Unknown cause.
    #[error("unknown cause: {0}")]
    UnknownCause(String),
    /// Self-cause.
    #[error("decision cannot be its own cause: {0}")]
    SelfCause(String),
    /// Would create a cycle.
    #[error("adding cause {cause} for {decision} would create a cycle")]
    WouldCycle {
        /// decision.
        decision: String,
        /// cause.
        cause: String,
    },
}

impl DecisionCausationChain {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            decisions: BTreeMap::new(),
            consequences: BTreeMap::new(),
        }
    }

    /// Record.
    pub fn record(
        &mut self,
        id: &str,
        summary: &str,
        ts_ms: u64,
        caused_by: &[&str],
    ) -> Result<(), CausationError> {
        if id.is_empty() {
            return Err(CausationError::EmptyId);
        }
        if summary.is_empty() {
            return Err(CausationError::EmptySummary);
        }
        if self.decisions.contains_key(id) {
            return Err(CausationError::DuplicateId(id.into()));
        }
        for c in caused_by {
            if c == &id {
                return Err(CausationError::SelfCause(id.into()));
            }
            if !self.decisions.contains_key(*c) {
                return Err(CausationError::UnknownCause((*c).into()));
            }
        }
        // Because each cause already exists and we're adding a new
        // leaf with no descendants yet, there's no way to create a
        // cycle. (We still validate via `add_cause` if added later.)
        let mut set = BTreeSet::new();
        for c in caused_by {
            set.insert((*c).into());
        }
        self.decisions.insert(
            id.into(),
            Decision {
                id: id.into(),
                summary: summary.into(),
                ts_ms,
                caused_by: set,
            },
        );
        for c in caused_by {
            self.consequences
                .entry((*c).into())
                .or_default()
                .insert(id.into());
        }
        Ok(())
    }

    /// Add a cause relationship after recording (validates no cycle).
    pub fn add_cause(&mut self, decision: &str, cause: &str) -> Result<(), CausationError> {
        if decision == cause {
            return Err(CausationError::SelfCause(decision.into()));
        }
        if !self.decisions.contains_key(cause) {
            return Err(CausationError::UnknownCause(cause.into()));
        }
        if !self.decisions.contains_key(decision) {
            return Err(CausationError::UnknownCause(decision.into()));
        }
        // If `decision` is already an ancestor of `cause`, adding
        // cause→decision would loop.
        if self.is_ancestor(decision, cause) {
            return Err(CausationError::WouldCycle {
                decision: decision.into(),
                cause: cause.into(),
            });
        }
        self.decisions
            .get_mut(decision)
            .unwrap()
            .caused_by
            .insert(cause.into());
        self.consequences
            .entry(cause.into())
            .or_default()
            .insert(decision.into());
        Ok(())
    }

    /// Is `candidate_ancestor` reachable upstream from `start`?
    fn is_ancestor(&self, candidate_ancestor: &str, start: &str) -> bool {
        let mut q: VecDeque<String> = VecDeque::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        q.push_back(start.into());
        seen.insert(start.into());
        while let Some(n) = q.pop_front() {
            if n == candidate_ancestor {
                return true;
            }
            if let Some(d) = self.decisions.get(&n) {
                for c in &d.caused_by {
                    if seen.insert(c.clone()) {
                        q.push_back(c.clone());
                    }
                }
            }
        }
        false
    }

    /// Ancestors up to depth.
    pub fn ancestors(&self, id: &str, max_depth: u32) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut frontier: Vec<String> = vec![id.into()];
        for _ in 0..max_depth {
            let mut next: Vec<String> = Vec::new();
            for n in &frontier {
                if let Some(d) = self.decisions.get(n) {
                    for c in &d.caused_by {
                        if out.insert(c.clone()) {
                            next.push(c.clone());
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        out
    }

    /// Descendants up to depth.
    pub fn descendants(&self, id: &str, max_depth: u32) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut frontier: Vec<String> = vec![id.into()];
        for _ in 0..max_depth {
            let mut next: Vec<String> = Vec::new();
            for n in &frontier {
                if let Some(kids) = self.consequences.get(n) {
                    for k in kids {
                        if out.insert(k.clone()) {
                            next.push(k.clone());
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        out
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CausationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CausationError::SchemaMismatch);
        }
        for (id, d) in &self.decisions {
            if id.is_empty() {
                return Err(CausationError::EmptyId);
            }
            if d.summary.is_empty() {
                return Err(CausationError::EmptySummary);
            }
            for c in &d.caused_by {
                if !self.decisions.contains_key(c) {
                    return Err(CausationError::UnknownCause(c.clone()));
                }
            }
        }
        Ok(())
    }
}

impl Default for DecisionCausationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_with_no_causes() {
        let mut c = DecisionCausationChain::new();
        c.record("d1", "first", 0, &[]).unwrap();
        assert!(c.ancestors("d1", 10).is_empty());
    }

    #[test]
    fn record_with_causes() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "root", 0, &[]).unwrap();
        c.record("b", "follows a", 1, &["a"]).unwrap();
        assert!(c.ancestors("b", 10).contains("a"));
        assert!(c.descendants("a", 10).contains("b"));
    }

    #[test]
    fn unknown_cause_rejected() {
        let mut c = DecisionCausationChain::new();
        assert!(matches!(
            c.record("b", "x", 0, &["nope"]).unwrap_err(),
            CausationError::UnknownCause(_)
        ));
    }

    #[test]
    fn self_cause_rejected() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "x", 0, &[]).unwrap();
        // record() catches it because the cause is the same id (it won't even be in decisions yet, but we check before insertion).
        let mut c2 = DecisionCausationChain::new();
        c2.record("a", "x", 0, &[]).unwrap();
        assert!(matches!(
            c2.add_cause("a", "a").unwrap_err(),
            CausationError::SelfCause(_)
        ));
    }

    #[test]
    fn add_cause_cycle_rejected() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "x", 0, &[]).unwrap();
        c.record("b", "x", 1, &["a"]).unwrap();
        c.record("c", "x", 2, &["b"]).unwrap();
        // a → b → c. Adding c as cause of a creates a→c→b→a.
        assert!(matches!(
            c.add_cause("a", "c").unwrap_err(),
            CausationError::WouldCycle { .. }
        ));
    }

    #[test]
    fn ancestors_respects_depth() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "x", 0, &[]).unwrap();
        c.record("b", "x", 0, &["a"]).unwrap();
        c.record("c", "x", 0, &["b"]).unwrap();
        // c's ancestors at depth 1 = {b} only.
        let one = c.ancestors("c", 1);
        assert!(one.contains("b"));
        assert!(!one.contains("a"));
        let two = c.ancestors("c", 2);
        assert!(two.contains("a"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "x", 0, &[]).unwrap();
        assert!(matches!(
            c.record("a", "x", 0, &[]).unwrap_err(),
            CausationError::DuplicateId(_)
        ));
    }

    #[test]
    fn dag_branch_and_merge() {
        let mut c = DecisionCausationChain::new();
        c.record("root", "x", 0, &[]).unwrap();
        c.record("a", "x", 0, &["root"]).unwrap();
        c.record("b", "x", 0, &["root"]).unwrap();
        // c merges a and b.
        c.record("merge", "x", 0, &["a", "b"]).unwrap();
        let anc = c.ancestors("merge", 10);
        assert!(anc.contains("a"));
        assert!(anc.contains("b"));
        assert!(anc.contains("root"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut c = DecisionCausationChain::new();
        assert!(matches!(
            c.record("", "x", 0, &[]).unwrap_err(),
            CausationError::EmptyId
        ));
        assert!(matches!(
            c.record("a", "", 0, &[]).unwrap_err(),
            CausationError::EmptySummary
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = DecisionCausationChain::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CausationError::SchemaMismatch
        ));
    }

    #[test]
    fn causation_serde_roundtrip() {
        let mut c = DecisionCausationChain::new();
        c.record("a", "x", 0, &[]).unwrap();
        c.record("b", "y", 1, &["a"]).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: DecisionCausationChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
