//! `selfdef-eval-bench-recorder` — would-outcome vs actual recorder.
//!
//! `record_eval(suite_id, scenario_id, would_outcome, actual_outcome,
//! ts)` records one agreement sample. `report(suite_id)` aggregates
//! across all scenarios in the suite.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One eval sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalSample {
    /// scenario id.
    pub scenario_id: String,
    /// outcome the candidate said.
    pub would_outcome: String,
    /// outcome the live policy said.
    pub actual_outcome: String,
    /// when recorded.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalBenchRecorder {
    /// Schema version.
    pub schema_version: String,
    /// suite_id → samples.
    pub by_suite: BTreeMap<String, Vec<EvalSample>>,
}

/// Report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgreementReport {
    /// Total samples.
    pub total: u32,
    /// Number that agreed.
    pub agreed: u32,
    /// Disagreement % × 100.
    pub disagreed_pct_x100: u32,
    /// Up to 16 disagreement examples for the UI.
    pub disagreement_samples: Vec<EvalSample>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BenchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty suite id.
    #[error("suite id empty")]
    EmptySuite,
    /// Empty scenario id.
    #[error("scenario id empty")]
    EmptyScenario,
    /// Empty outcome.
    #[error("outcome empty")]
    EmptyOutcome,
}

impl EvalBenchRecorder {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_suite: BTreeMap::new(),
        }
    }

    /// Record a sample.
    pub fn record_eval(
        &mut self,
        suite_id: &str,
        scenario_id: &str,
        would_outcome: &str,
        actual_outcome: &str,
        ts_ms: u64,
    ) -> Result<(), BenchError> {
        if suite_id.is_empty() {
            return Err(BenchError::EmptySuite);
        }
        if scenario_id.is_empty() {
            return Err(BenchError::EmptyScenario);
        }
        if would_outcome.is_empty() || actual_outcome.is_empty() {
            return Err(BenchError::EmptyOutcome);
        }
        self.by_suite
            .entry(suite_id.into())
            .or_default()
            .push(EvalSample {
                scenario_id: scenario_id.into(),
                would_outcome: would_outcome.into(),
                actual_outcome: actual_outcome.into(),
                ts_ms,
            });
        Ok(())
    }

    /// Aggregate report.
    pub fn report(&self, suite_id: &str) -> AgreementReport {
        let samples = match self.by_suite.get(suite_id) {
            Some(s) => s,
            None => {
                return AgreementReport {
                    total: 0,
                    agreed: 0,
                    disagreed_pct_x100: 0,
                    disagreement_samples: vec![],
                };
            }
        };
        let total = samples.len() as u32;
        let agreed = samples
            .iter()
            .filter(|s| s.would_outcome == s.actual_outcome)
            .count() as u32;
        let disagreed = total - agreed;
        let disagreed_pct_x100 = if total == 0 {
            0
        } else {
            ((disagreed as u64) * 10_000 / total as u64) as u32
        };
        let disagreement_samples: Vec<EvalSample> = samples
            .iter()
            .filter(|s| s.would_outcome != s.actual_outcome)
            .take(16)
            .cloned()
            .collect();
        AgreementReport {
            total,
            agreed,
            disagreed_pct_x100,
            disagreement_samples,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BenchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BenchError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for EvalBenchRecorder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report() {
        let b = EvalBenchRecorder::new();
        let r = b.report("nope");
        assert_eq!(r.total, 0);
    }

    #[test]
    fn full_agreement() {
        let mut b = EvalBenchRecorder::new();
        b.record_eval("s", "a", "Allow", "Allow", 0).unwrap();
        b.record_eval("s", "b", "Deny", "Deny", 0).unwrap();
        let r = b.report("s");
        assert_eq!(r.total, 2);
        assert_eq!(r.agreed, 2);
        assert_eq!(r.disagreed_pct_x100, 0);
    }

    #[test]
    fn partial_disagreement() {
        let mut b = EvalBenchRecorder::new();
        b.record_eval("s", "a", "Allow", "Allow", 0).unwrap();
        b.record_eval("s", "b", "Allow", "Deny", 0).unwrap();
        b.record_eval("s", "c", "Deny", "Allow", 0).unwrap();
        b.record_eval("s", "d", "Allow", "Allow", 0).unwrap();
        let r = b.report("s");
        assert_eq!(r.total, 4);
        assert_eq!(r.agreed, 2);
        // 2/4 = 50% → 5000 in x100 of percent (= 50.00%).
        assert_eq!(r.disagreed_pct_x100, 5000);
        assert_eq!(r.disagreement_samples.len(), 2);
    }

    #[test]
    fn disagreement_capped_at_16() {
        let mut b = EvalBenchRecorder::new();
        for i in 0..20 {
            b.record_eval("s", &format!("s{i}"), "Allow", "Deny", 0)
                .unwrap();
        }
        let r = b.report("s");
        assert_eq!(r.disagreement_samples.len(), 16);
    }

    #[test]
    fn empty_fields_rejected() {
        let mut b = EvalBenchRecorder::new();
        assert!(matches!(
            b.record_eval("", "a", "x", "x", 0).unwrap_err(),
            BenchError::EmptySuite
        ));
        assert!(matches!(
            b.record_eval("s", "", "x", "x", 0).unwrap_err(),
            BenchError::EmptyScenario
        ));
        assert!(matches!(
            b.record_eval("s", "a", "", "x", 0).unwrap_err(),
            BenchError::EmptyOutcome
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = EvalBenchRecorder::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BenchError::SchemaMismatch
        ));
    }

    #[test]
    fn bench_serde_roundtrip() {
        let mut b = EvalBenchRecorder::new();
        b.record_eval("s", "a", "Allow", "Allow", 0).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: EvalBenchRecorder = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
