//! `selfdef-decision-redo-budget` — per-session redo caps.
//!
//! Counts redos per ReDoClass. request decrements remaining if any.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Redo class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReDoClass {
    /// Same decision re-run.
    Same,
    /// Adjacent (next-step or previous-step in the same plan).
    Adjacent,
    /// Cross-plan re-run.
    Cross,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRedoBudget {
    /// Schema version.
    pub schema_version: String,
    /// Same cap.
    pub same_cap: u32,
    /// Adjacent cap.
    pub adjacent_cap: u32,
    /// Cross cap.
    pub cross_cap: u32,
    /// Same used.
    pub same_used: u32,
    /// Adjacent used.
    pub adjacent_used: u32,
    /// Cross used.
    pub cross_used: u32,
}

/// Decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReDoVerdict {
    /// Allowed; carries remaining.
    Allow {
        /// remaining.
        remaining: u32,
    },
    /// Denied (budget exhausted).
    Denied {
        /// cap.
        cap: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl DecisionRedoBudget {
    /// Canonical: Same 5, Adjacent 3, Cross 1.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            same_cap: 5, adjacent_cap: 3, cross_cap: 1,
            same_used: 0, adjacent_used: 0, cross_used: 0,
        }
    }

    /// Cap for class.
    pub fn cap(&self, class: ReDoClass) -> u32 {
        match class {
            ReDoClass::Same => self.same_cap,
            ReDoClass::Adjacent => self.adjacent_cap,
            ReDoClass::Cross => self.cross_cap,
        }
    }

    /// Used for class.
    pub fn used(&self, class: ReDoClass) -> u32 {
        match class {
            ReDoClass::Same => self.same_used,
            ReDoClass::Adjacent => self.adjacent_used,
            ReDoClass::Cross => self.cross_used,
        }
    }

    /// Request a redo (decrements remaining).
    pub fn request(&mut self, class: ReDoClass) -> ReDoVerdict {
        let cap = self.cap(class);
        let used = self.used(class);
        if used >= cap {
            return ReDoVerdict::Denied { cap };
        }
        match class {
            ReDoClass::Same => self.same_used += 1,
            ReDoClass::Adjacent => self.adjacent_used += 1,
            ReDoClass::Cross => self.cross_used += 1,
        }
        ReDoVerdict::Allow { remaining: cap - self.used(class) }
    }

    /// Reset counters (new session).
    pub fn reset(&mut self) {
        self.same_used = 0;
        self.adjacent_used = 0;
        self.cross_used = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        DecisionRedoBudget::canonical().validate().unwrap();
    }

    #[test]
    fn first_request_allowed() {
        let mut b = DecisionRedoBudget::canonical();
        let v = b.request(ReDoClass::Same);
        match v {
            ReDoVerdict::Allow { remaining } => assert_eq!(remaining, 4),
            _ => panic!(),
        }
    }

    #[test]
    fn cap_exhausts() {
        let mut b = DecisionRedoBudget::canonical();
        for _ in 0..5 { b.request(ReDoClass::Same); }
        assert!(matches!(b.request(ReDoClass::Same), ReDoVerdict::Denied { .. }));
    }

    #[test]
    fn cross_smallest_cap() {
        let mut b = DecisionRedoBudget::canonical();
        b.request(ReDoClass::Cross);
        assert!(matches!(b.request(ReDoClass::Cross), ReDoVerdict::Denied { .. }));
    }

    #[test]
    fn classes_independent() {
        let mut b = DecisionRedoBudget::canonical();
        b.request(ReDoClass::Cross);
        // Same still has budget.
        assert!(matches!(b.request(ReDoClass::Same), ReDoVerdict::Allow { .. }));
    }

    #[test]
    fn reset_clears() {
        let mut b = DecisionRedoBudget::canonical();
        b.request(ReDoClass::Same);
        b.reset();
        assert_eq!(b.same_used, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = DecisionRedoBudget::canonical();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BudgetError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ReDoClass::Adjacent).unwrap(), "\"adjacent\"");
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = DecisionRedoBudget::canonical();
        b.request(ReDoClass::Same);
        let j = serde_json::to_string(&b).unwrap();
        let back: DecisionRedoBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
