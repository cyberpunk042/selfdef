//! `selfdef-decision-watchdog` — per-decision wall-time watchdog.
//!
//! register(id, class, started_at) tracks a decision. tick(now)
//! returns a list of timed-out ids whose elapsed exceeds the class
//! budget. complete(id) drops it from the pending set.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    /// Fast (read-only).
    Fast,
    /// Standard (mutating).
    Standard,
    /// Slow (cross-boundary, expensive).
    Slow,
}

/// One in-flight decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InFlight {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: DecisionClass,
    /// Started at unix seconds.
    pub started_at: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionWatchdog {
    /// Schema version.
    pub schema_version: String,
    /// Fast budget seconds.
    pub fast_budget_seconds: u64,
    /// Standard budget seconds.
    pub standard_budget_seconds: u64,
    /// Slow budget seconds.
    pub slow_budget_seconds: u64,
    /// In-flight decisions.
    pub in_flight: Vec<InFlight>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WatchdogError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Budget zero.
    #[error("budget {0:?} is zero")]
    BudgetZero(DecisionClass),
    /// Empty id.
    #[error("decision id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
    /// Unknown id.
    #[error("unknown id: {0}")]
    Unknown(String),
}

impl DecisionWatchdog {
    /// Canonical: Fast 5s, Standard 30s, Slow 300s.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            fast_budget_seconds: 5,
            standard_budget_seconds: 30,
            slow_budget_seconds: 300,
            in_flight: Vec::new(),
        }
    }

    /// Budget for a class.
    pub fn budget(&self, class: DecisionClass) -> u64 {
        match class {
            DecisionClass::Fast => self.fast_budget_seconds,
            DecisionClass::Standard => self.standard_budget_seconds,
            DecisionClass::Slow => self.slow_budget_seconds,
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        id: &str,
        class: DecisionClass,
        started_at: u64,
    ) -> Result<(), WatchdogError> {
        if id.is_empty() {
            return Err(WatchdogError::EmptyId);
        }
        if self.in_flight.iter().any(|x| x.id == id) {
            return Err(WatchdogError::DuplicateId(id.into()));
        }
        self.in_flight.push(InFlight {
            id: id.into(),
            class,
            started_at,
        });
        Ok(())
    }

    /// Complete (drop from in-flight).
    pub fn complete(&mut self, id: &str) -> Result<(), WatchdogError> {
        let pos = self
            .in_flight
            .iter()
            .position(|x| x.id == id)
            .ok_or_else(|| WatchdogError::Unknown(id.into()))?;
        self.in_flight.remove(pos);
        Ok(())
    }

    /// Tick — returns timed-out ids.
    pub fn tick(&self, now: u64) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for f in &self.in_flight {
            let budget = self.budget(f.class);
            let elapsed = now.saturating_sub(f.started_at);
            if elapsed > budget {
                out.push(f.id.clone());
            }
        }
        out
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WatchdogError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WatchdogError::SchemaMismatch);
        }
        for (c, b) in [
            (DecisionClass::Fast, self.fast_budget_seconds),
            (DecisionClass::Standard, self.standard_budget_seconds),
            (DecisionClass::Slow, self.slow_budget_seconds),
        ] {
            if b == 0 {
                return Err(WatchdogError::BudgetZero(c));
            }
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for f in &self.in_flight {
            if f.id.is_empty() {
                return Err(WatchdogError::EmptyId);
            }
            if !seen.insert(f.id.as_str()) {
                return Err(WatchdogError::DuplicateId(f.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        DecisionWatchdog::canonical().validate().unwrap();
    }

    #[test]
    fn register_complete() {
        let mut w = DecisionWatchdog::canonical();
        w.register("d1", DecisionClass::Fast, 100).unwrap();
        w.complete("d1").unwrap();
        assert!(w.in_flight.is_empty());
    }

    #[test]
    fn tick_no_timeouts_when_under_budget() {
        let mut w = DecisionWatchdog::canonical();
        w.register("d1", DecisionClass::Fast, 100).unwrap();
        assert!(w.tick(102).is_empty());
    }

    #[test]
    fn tick_reports_fast_timeout() {
        let mut w = DecisionWatchdog::canonical();
        w.register("d1", DecisionClass::Fast, 100).unwrap();
        // Fast budget = 5s; tick at 110.
        let timeouts = w.tick(110);
        assert_eq!(timeouts, vec!["d1"]);
    }

    #[test]
    fn slow_budget_higher() {
        let mut w = DecisionWatchdog::canonical();
        w.register("slow", DecisionClass::Slow, 100).unwrap();
        // Slow budget = 300s; at +200s still ok.
        assert!(w.tick(300).is_empty());
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut w = DecisionWatchdog::canonical();
        w.register("d1", DecisionClass::Fast, 100).unwrap();
        assert!(matches!(
            w.register("d1", DecisionClass::Slow, 200).unwrap_err(),
            WatchdogError::DuplicateId(_)
        ));
    }

    #[test]
    fn complete_unknown_rejected() {
        let mut w = DecisionWatchdog::canonical();
        assert!(matches!(
            w.complete("none").unwrap_err(),
            WatchdogError::Unknown(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut w = DecisionWatchdog::canonical();
        assert!(matches!(
            w.register("", DecisionClass::Fast, 100).unwrap_err(),
            WatchdogError::EmptyId
        ));
    }

    #[test]
    fn budget_zero_rejected_on_validate() {
        let mut w = DecisionWatchdog::canonical();
        w.fast_budget_seconds = 0;
        assert!(matches!(
            w.validate().unwrap_err(),
            WatchdogError::BudgetZero(DecisionClass::Fast)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = DecisionWatchdog::canonical();
        w.schema_version = "9.9.9".into();
        assert!(matches!(
            w.validate().unwrap_err(),
            WatchdogError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&DecisionClass::Standard).unwrap(),
            "\"standard\""
        );
    }

    #[test]
    fn watchdog_serde_roundtrip() {
        let mut w = DecisionWatchdog::canonical();
        w.register("d1", DecisionClass::Fast, 100).unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let back: DecisionWatchdog = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
