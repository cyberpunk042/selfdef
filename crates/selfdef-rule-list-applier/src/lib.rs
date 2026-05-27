//! `selfdef-rule-list-applier` — ordered allow/deny rules.
//!
//! Rule{id, effect, key_exact OR key_prefix}. evaluate(key)
//! walks rules in order; first rule that matches by exact or
//! prefix wins. If none matches, returns `default`. Match
//! counts tracked per rule.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Effect.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// Match kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum Match {
    /// Exact key.
    Exact(String),
    /// Prefix.
    Prefix(String),
}

/// Rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Id.
    pub id: String,
    /// Effect.
    pub effect: Effect,
    /// Match.
    pub match_: Match,
    /// Match counter.
    pub matches: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleListApplier {
    /// Schema version.
    pub schema_version: String,
    /// Ordered rules.
    pub rules: Vec<Rule>,
    /// Default effect when no rule matches.
    pub default_effect: Effect,
    /// Default-applied counter.
    pub defaults_applied: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RuleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("rule id empty")]
    EmptyId,
    /// Empty.
    #[error("match value empty")]
    EmptyMatch,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

impl RuleListApplier {
    /// New.
    pub fn new(default_effect: Effect) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rules: Vec::new(),
            default_effect,
            defaults_applied: 0,
        }
    }

    /// Append rule (insertion order = priority).
    pub fn append(&mut self, id: &str, effect: Effect, match_: Match) -> Result<(), RuleError> {
        if id.is_empty() {
            return Err(RuleError::EmptyId);
        }
        match &match_ {
            Match::Exact(v) | Match::Prefix(v) => {
                if v.is_empty() {
                    return Err(RuleError::EmptyMatch);
                }
            }
        }
        if self.rules.iter().any(|r| r.id == id) {
            return Err(RuleError::DuplicateId(id.into()));
        }
        self.rules.push(Rule {
            id: id.into(),
            effect,
            match_,
            matches: 0,
        });
        Ok(())
    }

    /// Evaluate; returns Effect (counters mutated).
    pub fn evaluate(&mut self, key: &str) -> Effect {
        for r in self.rules.iter_mut() {
            let hit = match &r.match_ {
                Match::Exact(v) => key == v,
                Match::Prefix(v) => key.starts_with(v.as_str()),
            };
            if hit {
                r.matches = r.matches.saturating_add(1);
                return r.effect;
            }
        }
        self.defaults_applied = self.defaults_applied.saturating_add(1);
        self.default_effect
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RuleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RuleError::SchemaMismatch);
        }
        for r in &self.rules {
            if r.id.is_empty() {
                return Err(RuleError::EmptyId);
            }
            match &r.match_ {
                Match::Exact(v) | Match::Prefix(v) => {
                    if v.is_empty() {
                        return Err(RuleError::EmptyMatch);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rules_uses_default() {
        let mut a = RuleListApplier::new(Effect::Deny);
        assert_eq!(a.evaluate("anything"), Effect::Deny);
        assert_eq!(a.defaults_applied, 1);
    }

    #[test]
    fn exact_match_wins() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.append("r1", Effect::Allow, Match::Exact("/etc/passwd".into()))
            .unwrap();
        assert_eq!(a.evaluate("/etc/passwd"), Effect::Allow);
        assert_eq!(a.evaluate("/etc/shadow"), Effect::Deny);
    }

    #[test]
    fn prefix_match() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.append("r1", Effect::Allow, Match::Prefix("/var/log/".into()))
            .unwrap();
        assert_eq!(a.evaluate("/var/log/messages"), Effect::Allow);
        assert_eq!(a.evaluate("/var/log/auth.log"), Effect::Allow);
        assert_eq!(a.evaluate("/etc/passwd"), Effect::Deny);
    }

    #[test]
    fn first_match_wins() {
        let mut a = RuleListApplier::new(Effect::Allow);
        a.append(
            "deny-secret",
            Effect::Deny,
            Match::Prefix("/etc/secret".into()),
        )
        .unwrap();
        a.append("allow-etc", Effect::Allow, Match::Prefix("/etc/".into()))
            .unwrap();
        assert_eq!(a.evaluate("/etc/secret/db.key"), Effect::Deny);
        assert_eq!(a.evaluate("/etc/passwd"), Effect::Allow);
    }

    #[test]
    fn match_counter_increments() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.append("r1", Effect::Allow, Match::Exact("k".into()))
            .unwrap();
        a.evaluate("k");
        a.evaluate("k");
        assert_eq!(a.rules[0].matches, 2);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.append("r1", Effect::Allow, Match::Exact("a".into()))
            .unwrap();
        assert!(matches!(
            a.append("r1", Effect::Deny, Match::Exact("b".into()))
                .unwrap_err(),
            RuleError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut a = RuleListApplier::new(Effect::Deny);
        assert!(matches!(
            a.append("", Effect::Allow, Match::Exact("a".into()))
                .unwrap_err(),
            RuleError::EmptyId
        ));
        assert!(matches!(
            a.append("r", Effect::Allow, Match::Exact("".into()))
                .unwrap_err(),
            RuleError::EmptyMatch
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.schema_version = "9.9.9".into();
        assert!(matches!(
            a.validate().unwrap_err(),
            RuleError::SchemaMismatch
        ));
    }

    #[test]
    fn applier_serde_roundtrip() {
        let mut a = RuleListApplier::new(Effect::Deny);
        a.append("r1", Effect::Allow, Match::Prefix("/var/".into()))
            .unwrap();
        a.evaluate("/var/log");
        let j = serde_json::to_string(&a).unwrap();
        let back: RuleListApplier = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
