//! `selfdef-dispatch-fanout-budget` — per-subscriber bus rate cap.
//!
//! Each `Subscriber` (from the bus registry) declares an events/sec
//! ceiling. `evaluate(subscriber, eps)` returns `FanoutVerdict`:
//! `Within` / `Throttle` / `Drop`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_bus_subscriber_registry::Subscriber;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Verdict for a sampled EPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutVerdict {
    /// Within ceiling.
    Within,
    /// Above warn, below hard — throttle producer.
    Throttle,
    /// Above hard — drop excess.
    Drop,
}

/// Per-subscriber budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FanoutBudget {
    /// Subscriber.
    pub subscriber: Subscriber,
    /// Warn at this EPS.
    pub warn_eps: u32,
    /// Drop at this EPS.
    pub hard_eps: u32,
}

/// Registry envelope — 9 budgets (one per subscriber).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FanoutRegistry {
    /// Schema version.
    pub schema_version: String,
    /// 9 budgets.
    pub budgets: Vec<FanoutBudget>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FanoutError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 9.
    #[error("budget count {0} != 9 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing subscriber: {0:?}")]
    Missing(Subscriber),
    /// warn >= hard.
    #[error("thresholds inverted for {sub:?}: warn {warn} >= hard {hard}")]
    Inverted {
        /// sub.
        sub: Subscriber,
        /// warn.
        warn: u32,
        /// hard.
        hard: u32,
    },
}

const REQUIRED: [Subscriber; 9] = [
    Subscriber::AuditLog, Subscriber::Quarantine, Subscriber::Notifier,
    Subscriber::EvidenceLedger, Subscriber::HistorySink, Subscriber::PolicyBus,
    Subscriber::TrustScore, Subscriber::ProfileAuthority, Subscriber::DashboardManifest,
];

impl FanoutBudget {
    /// Evaluate an EPS reading.
    pub fn evaluate(&self, eps: u32) -> FanoutVerdict {
        if eps >= self.hard_eps { FanoutVerdict::Drop }
        else if eps >= self.warn_eps { FanoutVerdict::Throttle }
        else { FanoutVerdict::Within }
    }
}

impl FanoutRegistry {
    /// Canonical operator-tuned defaults.
    pub fn canonical() -> Self {
        let budgets = vec![
            FanoutBudget { subscriber: Subscriber::AuditLog,          warn_eps: 50_000, hard_eps: 100_000 },
            FanoutBudget { subscriber: Subscriber::Quarantine,        warn_eps:  1_000, hard_eps:   5_000 },
            FanoutBudget { subscriber: Subscriber::Notifier,          warn_eps:    500, hard_eps:   2_000 },
            FanoutBudget { subscriber: Subscriber::EvidenceLedger,    warn_eps: 30_000, hard_eps:  80_000 },
            FanoutBudget { subscriber: Subscriber::HistorySink,       warn_eps: 50_000, hard_eps: 100_000 },
            FanoutBudget { subscriber: Subscriber::PolicyBus,         warn_eps: 20_000, hard_eps:  50_000 },
            FanoutBudget { subscriber: Subscriber::TrustScore,        warn_eps:  5_000, hard_eps:  15_000 },
            FanoutBudget { subscriber: Subscriber::ProfileAuthority,  warn_eps:    100, hard_eps:   1_000 },
            FanoutBudget { subscriber: Subscriber::DashboardManifest, warn_eps: 10_000, hard_eps:  30_000 },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            budgets,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FanoutError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FanoutError::SchemaMismatch);
        }
        if self.budgets.len() != 9 {
            return Err(FanoutError::CountInvalid(self.budgets.len()));
        }
        for s in REQUIRED {
            if !self.budgets.iter().any(|b| b.subscriber == s) {
                return Err(FanoutError::Missing(s));
            }
        }
        for b in &self.budgets {
            if b.warn_eps >= b.hard_eps {
                return Err(FanoutError::Inverted {
                    sub: b.subscriber, warn: b.warn_eps, hard: b.hard_eps,
                });
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: Subscriber) -> Option<&FanoutBudget> {
        self.budgets.iter().find(|b| b.subscriber == s)
    }

    /// Evaluate for one subscriber.
    pub fn evaluate(&self, s: Subscriber, eps: u32) -> FanoutVerdict {
        match self.get(s) {
            Some(b) => b.evaluate(eps),
            None => FanoutVerdict::Drop, // unknown subscriber → drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        FanoutRegistry::canonical().validate().unwrap();
    }

    #[test]
    fn nine_budgets_present() {
        let r = FanoutRegistry::canonical();
        for s in REQUIRED {
            assert!(r.get(s).is_some(), "missing {s:?}");
        }
    }

    #[test]
    fn within_below_warn() {
        let r = FanoutRegistry::canonical();
        assert_eq!(r.evaluate(Subscriber::AuditLog, 1_000), FanoutVerdict::Within);
    }

    #[test]
    fn throttle_between() {
        let r = FanoutRegistry::canonical();
        // AuditLog warn 50k, hard 100k → 70k = throttle
        assert_eq!(r.evaluate(Subscriber::AuditLog, 70_000), FanoutVerdict::Throttle);
    }

    #[test]
    fn drop_above_hard() {
        let r = FanoutRegistry::canonical();
        assert_eq!(r.evaluate(Subscriber::AuditLog, 200_000), FanoutVerdict::Drop);
    }

    #[test]
    fn notifier_has_low_caps() {
        let r = FanoutRegistry::canonical();
        // Notifier warn 500, hard 2_000
        assert_eq!(r.evaluate(Subscriber::Notifier, 1_500), FanoutVerdict::Throttle);
        assert_eq!(r.evaluate(Subscriber::Notifier, 3_000), FanoutVerdict::Drop);
    }

    #[test]
    fn thresholds_inverted_caught() {
        let mut r = FanoutRegistry::canonical();
        r.budgets[0].warn_eps = 999_999;
        match r.validate().unwrap_err() {
            FanoutError::Inverted { sub, .. } => assert_eq!(sub, r.budgets[0].subscriber),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = FanoutRegistry::canonical();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), FanoutError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut r = FanoutRegistry::canonical();
        r.budgets.pop();
        assert!(matches!(r.validate().unwrap_err(), FanoutError::CountInvalid(8)));
    }

    #[test]
    fn verdict_serde_kebab() {
        assert_eq!(serde_json::to_string(&FanoutVerdict::Within).unwrap(), "\"within\"");
        assert_eq!(serde_json::to_string(&FanoutVerdict::Throttle).unwrap(), "\"throttle\"");
        assert_eq!(serde_json::to_string(&FanoutVerdict::Drop).unwrap(), "\"drop\"");
    }

    #[test]
    fn registry_serde_roundtrip() {
        let r = FanoutRegistry::canonical();
        let j = serde_json::to_string(&r).unwrap();
        let back: FanoutRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
