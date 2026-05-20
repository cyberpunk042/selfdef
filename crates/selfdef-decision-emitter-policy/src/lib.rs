//! `selfdef-decision-emitter-policy` — per-decision-kind sink routing.
//!
//! Each decision_kind maps to a `BTreeSet<Sink>` of subscribers.
//! `set(kind, sinks)` configures; `emitted_to(kind)` returns the
//! subscribed sinks; `add_sink(kind, sink)` / `remove_sink(kind,
//! sink)` for finer control.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sink {
    /// Audit ledger.
    Audit,
    /// Trace span exporter.
    Trace,
    /// Operator-facing notifier.
    Operator,
    /// Mirror sync target.
    Mirror,
    /// External webhook.
    External,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionEmitterPolicy {
    /// Schema version.
    pub schema_version: String,
    /// decision_kind → sinks.
    pub routes: BTreeMap<String, BTreeSet<Sink>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EmitterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty kind.
    #[error("decision_kind empty")]
    EmptyKind,
}

impl DecisionEmitterPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            routes: BTreeMap::new(),
        }
    }

    /// Set sinks for a kind (replaces existing).
    pub fn set(&mut self, decision_kind: &str, sinks: BTreeSet<Sink>) -> Result<(), EmitterError> {
        if decision_kind.is_empty() { return Err(EmitterError::EmptyKind); }
        self.routes.insert(decision_kind.into(), sinks);
        Ok(())
    }

    /// Add a sink to a kind.
    pub fn add_sink(&mut self, decision_kind: &str, sink: Sink) -> Result<(), EmitterError> {
        if decision_kind.is_empty() { return Err(EmitterError::EmptyKind); }
        self.routes.entry(decision_kind.into()).or_default().insert(sink);
        Ok(())
    }

    /// Remove a sink from a kind.
    pub fn remove_sink(&mut self, decision_kind: &str, sink: Sink) -> bool {
        if let Some(set) = self.routes.get_mut(decision_kind) {
            let r = set.remove(&sink);
            if set.is_empty() { self.routes.remove(decision_kind); }
            return r;
        }
        false
    }

    /// Sinks for a kind.
    pub fn emitted_to(&self, decision_kind: &str) -> Vec<Sink> {
        self.routes.get(decision_kind)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EmitterError> {
        if self.schema_version != SCHEMA_VERSION { return Err(EmitterError::SchemaMismatch); }
        for k in self.routes.keys() {
            if k.is_empty() { return Err(EmitterError::EmptyKind); }
        }
        Ok(())
    }
}

impl Default for DecisionEmitterPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_query() {
        let mut p = DecisionEmitterPolicy::new();
        let s: BTreeSet<Sink> = [Sink::Audit, Sink::Trace].into_iter().collect();
        p.set("policy.update", s).unwrap();
        let sinks = p.emitted_to("policy.update");
        assert!(sinks.contains(&Sink::Audit));
        assert!(sinks.contains(&Sink::Trace));
    }

    #[test]
    fn add_then_remove() {
        let mut p = DecisionEmitterPolicy::new();
        p.add_sink("policy.update", Sink::Audit).unwrap();
        p.add_sink("policy.update", Sink::Mirror).unwrap();
        assert!(p.remove_sink("policy.update", Sink::Mirror));
        assert_eq!(p.emitted_to("policy.update"), vec![Sink::Audit]);
    }

    #[test]
    fn remove_unknown_false() {
        let mut p = DecisionEmitterPolicy::new();
        assert!(!p.remove_sink("policy.update", Sink::Audit));
    }

    #[test]
    fn empty_kind_rejected() {
        let mut p = DecisionEmitterPolicy::new();
        assert!(matches!(p.set("", BTreeSet::new()).unwrap_err(), EmitterError::EmptyKind));
    }

    #[test]
    fn unknown_kind_no_sinks() {
        let p = DecisionEmitterPolicy::new();
        assert!(p.emitted_to("nope").is_empty());
    }

    #[test]
    fn empty_set_auto_prunes_via_remove() {
        let mut p = DecisionEmitterPolicy::new();
        p.add_sink("k", Sink::Audit).unwrap();
        p.remove_sink("k", Sink::Audit);
        assert!(!p.routes.contains_key("k"));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = DecisionEmitterPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), EmitterError::SchemaMismatch));
    }

    #[test]
    fn emitter_serde_roundtrip() {
        let mut p = DecisionEmitterPolicy::new();
        p.add_sink("k", Sink::Audit).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: DecisionEmitterPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
