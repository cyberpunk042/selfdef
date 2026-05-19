//! `selfdef-collector-budget-guard` — per-collector EPS budget enforcement.
//!
//! Each of the 7 IPS collectors (from `selfdef-collector-source-taxonomy`)
//! carries a hard EPS ceiling and a soft warning threshold. The guard
//! evaluates a sampled EPS reading against those thresholds and returns a
//! `BudgetVerdict` the daemon uses to decide quarantine / warn / proceed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_collector_source_taxonomy::CollectorKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Verdict for one collector's sampled EPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetVerdict {
    /// Under both warn + hard ceiling.
    Within,
    /// Above warn but below hard.
    Warn,
    /// Above hard ceiling — quarantine.
    Quarantine,
}

/// Per-collector budget envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorBudget {
    /// Which collector.
    pub kind: CollectorKind,
    /// Warn at this EPS.
    pub warn_eps: u32,
    /// Quarantine at this EPS (must be > warn_eps).
    pub hard_eps: u32,
}

/// Budget registry — exactly 7 entries, one per CollectorKind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetRegistry {
    /// Schema version.
    pub schema_version: String,
    /// 7 budgets.
    pub budgets: Vec<CollectorBudget>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 7.
    #[error("budget count {0} != 7 canonical")]
    CountInvalid(usize),
    /// Missing required collector.
    #[error("missing budget for collector: {0:?}")]
    Missing(CollectorKind),
    /// warn >= hard.
    #[error("invalid thresholds for {kind:?}: warn {warn_eps} >= hard {hard_eps}")]
    ThresholdsInverted {
        /// Collector.
        kind: CollectorKind,
        /// Warn EPS.
        warn_eps: u32,
        /// Hard EPS.
        hard_eps: u32,
    },
}

impl CollectorBudget {
    /// Evaluate a sampled EPS reading against this budget.
    pub fn evaluate(&self, eps: u32) -> BudgetVerdict {
        if eps >= self.hard_eps {
            BudgetVerdict::Quarantine
        } else if eps >= self.warn_eps {
            BudgetVerdict::Warn
        } else {
            BudgetVerdict::Within
        }
    }
}

impl BudgetRegistry {
    /// Canonical defaults — operator-tuned per-collector EPS ceilings.
    /// auditd and journald are high-volume; canary is bounded test traffic;
    /// ebpf and tetragon scale with kernel probe count; eventstream and
    /// suricata are network-facing.
    pub fn canonical() -> Self {
        let budgets = vec![
            CollectorBudget { kind: CollectorKind::Auditd,       warn_eps:  8_000, hard_eps: 20_000 },
            CollectorBudget { kind: CollectorKind::Canary,       warn_eps:    100, hard_eps:    500 },
            CollectorBudget { kind: CollectorKind::Ebpf,         warn_eps: 12_000, hard_eps: 40_000 },
            CollectorBudget { kind: CollectorKind::EventStream,  warn_eps:  4_000, hard_eps: 10_000 },
            CollectorBudget { kind: CollectorKind::Journald,     warn_eps:  6_000, hard_eps: 15_000 },
            CollectorBudget { kind: CollectorKind::Suricata,     warn_eps:  3_000, hard_eps:  8_000 },
            CollectorBudget { kind: CollectorKind::Tetragon,     warn_eps: 10_000, hard_eps: 30_000 },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            budgets,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        if self.budgets.len() != 7 {
            return Err(BudgetError::CountInvalid(self.budgets.len()));
        }
        let required = [
            CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
            CollectorKind::EventStream, CollectorKind::Journald,
            CollectorKind::Suricata, CollectorKind::Tetragon,
        ];
        for k in required {
            if !self.budgets.iter().any(|b| b.kind == k) {
                return Err(BudgetError::Missing(k));
            }
        }
        for b in &self.budgets {
            if b.warn_eps >= b.hard_eps {
                return Err(BudgetError::ThresholdsInverted {
                    kind: b.kind,
                    warn_eps: b.warn_eps,
                    hard_eps: b.hard_eps,
                });
            }
        }
        Ok(())
    }

    /// Lookup budget by collector kind.
    pub fn get(&self, kind: CollectorKind) -> Option<&CollectorBudget> {
        self.budgets.iter().find(|b| b.kind == kind)
    }

    /// Evaluate a sample for one collector. Returns Quarantine if no budget exists.
    pub fn evaluate(&self, kind: CollectorKind, eps: u32) -> BudgetVerdict {
        match self.get(kind) {
            Some(b) => b.evaluate(eps),
            None => BudgetVerdict::Quarantine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        BudgetRegistry::canonical().validate().unwrap();
    }

    #[test]
    fn seven_budgets_present() {
        let r = BudgetRegistry::canonical();
        assert_eq!(r.budgets.len(), 7);
        for k in [CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
                  CollectorKind::EventStream, CollectorKind::Journald,
                  CollectorKind::Suricata, CollectorKind::Tetragon] {
            assert!(r.get(k).is_some(), "missing budget for {k:?}");
        }
    }

    #[test]
    fn within_below_warn() {
        let r = BudgetRegistry::canonical();
        assert_eq!(r.evaluate(CollectorKind::Auditd, 1_000), BudgetVerdict::Within);
    }

    #[test]
    fn warn_between_thresholds() {
        let r = BudgetRegistry::canonical();
        // auditd: warn 8_000, hard 20_000
        assert_eq!(r.evaluate(CollectorKind::Auditd, 10_000), BudgetVerdict::Warn);
    }

    #[test]
    fn quarantine_above_hard() {
        let r = BudgetRegistry::canonical();
        assert_eq!(r.evaluate(CollectorKind::Auditd, 25_000), BudgetVerdict::Quarantine);
    }

    #[test]
    fn warn_inclusive_at_threshold() {
        let r = BudgetRegistry::canonical();
        // exactly at warn → Warn (>=)
        assert_eq!(r.evaluate(CollectorKind::Canary, 100), BudgetVerdict::Warn);
        // exactly at hard → Quarantine
        assert_eq!(r.evaluate(CollectorKind::Canary, 500), BudgetVerdict::Quarantine);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = BudgetRegistry::canonical();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), BudgetError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut r = BudgetRegistry::canonical();
        r.budgets.pop();
        assert!(matches!(r.validate().unwrap_err(), BudgetError::CountInvalid(6)));
    }

    #[test]
    fn thresholds_inverted_caught() {
        let mut r = BudgetRegistry::canonical();
        r.budgets[0].warn_eps = 30_000; // > hard_eps 20_000
        match r.validate().unwrap_err() {
            BudgetError::ThresholdsInverted { kind, warn_eps, hard_eps } => {
                assert_eq!(kind, CollectorKind::Auditd);
                assert_eq!(warn_eps, 30_000);
                assert_eq!(hard_eps, 20_000);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn verdict_serde_kebab() {
        assert_eq!(serde_json::to_string(&BudgetVerdict::Within).unwrap(), "\"within\"");
        assert_eq!(serde_json::to_string(&BudgetVerdict::Quarantine).unwrap(), "\"quarantine\"");
    }

    #[test]
    fn registry_serde_roundtrip() {
        let r = BudgetRegistry::canonical();
        let j = serde_json::to_string(&r).unwrap();
        let back: BudgetRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
