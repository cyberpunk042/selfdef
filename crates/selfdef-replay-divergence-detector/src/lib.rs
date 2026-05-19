//! `selfdef-replay-divergence-detector` — replay vs recorded compare.
//!
//! Each recorded step has (tool_id, decision, output_hash,
//! elapsed_ms_max). Replaying produces the same triple. compare()
//! walks both step lists; first index where any axis differs yields
//! a typed Divergence.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One step observation (recorded or replayed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    /// Tool id.
    pub tool_id: String,
    /// IPS decision text.
    pub decision: String,
    /// Hash of the tool output.
    pub output_hash: String,
    /// Elapsed ms (for timing checks).
    pub elapsed_ms: u32,
}

/// Divergence cause.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DivergenceCause {
    /// IPS decision changed between record and replay.
    DecisionChanged {
        /// recorded.
        recorded: String,
        /// observed.
        observed: String,
    },
    /// Output hash differed.
    OutputDiffered {
        /// recorded.
        recorded: String,
        /// observed.
        observed: String,
    },
    /// Tool missing in replay.
    ToolMissing {
        /// recorded tool id.
        recorded_tool: String,
    },
    /// Replay had more steps than recorded.
    UnexpectedExtraStep,
    /// Replay shorter than recorded.
    ReplayShorter,
    /// Replay took > 2x the recorded elapsed_ms.
    TimingExceeded {
        /// recorded.
        recorded_ms: u32,
        /// observed.
        observed_ms: u32,
    },
}

/// Divergence report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Divergence {
    /// Schema version.
    pub schema_version: String,
    /// 0-based step index.
    pub step_index: usize,
    /// Cause.
    pub cause: DivergenceCause,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DivergenceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Stateless detector.
#[derive(Debug, Clone, Default)]
pub struct ReplayDivergenceDetector;

impl ReplayDivergenceDetector {
    /// Compare. Returns None when in lockstep.
    pub fn compare(recorded: &[Step], observed: &[Step]) -> Option<Divergence> {
        let n = recorded.len().min(observed.len());
        for i in 0..n {
            let r = &recorded[i];
            let o = &observed[i];
            if r.tool_id != o.tool_id {
                return Some(Divergence {
                    schema_version: SCHEMA_VERSION.into(),
                    step_index: i,
                    cause: DivergenceCause::ToolMissing {
                        recorded_tool: r.tool_id.clone(),
                    },
                });
            }
            if r.decision != o.decision {
                return Some(Divergence {
                    schema_version: SCHEMA_VERSION.into(),
                    step_index: i,
                    cause: DivergenceCause::DecisionChanged {
                        recorded: r.decision.clone(),
                        observed: o.decision.clone(),
                    },
                });
            }
            if !r.output_hash.eq_ignore_ascii_case(&o.output_hash) {
                return Some(Divergence {
                    schema_version: SCHEMA_VERSION.into(),
                    step_index: i,
                    cause: DivergenceCause::OutputDiffered {
                        recorded: r.output_hash.clone(),
                        observed: o.output_hash.clone(),
                    },
                });
            }
            if o.elapsed_ms > r.elapsed_ms.saturating_mul(2) {
                return Some(Divergence {
                    schema_version: SCHEMA_VERSION.into(),
                    step_index: i,
                    cause: DivergenceCause::TimingExceeded {
                        recorded_ms: r.elapsed_ms,
                        observed_ms: o.elapsed_ms,
                    },
                });
            }
        }
        if observed.len() > recorded.len() {
            return Some(Divergence {
                schema_version: SCHEMA_VERSION.into(),
                step_index: recorded.len(),
                cause: DivergenceCause::UnexpectedExtraStep,
            });
        }
        if observed.len() < recorded.len() {
            return Some(Divergence {
                schema_version: SCHEMA_VERSION.into(),
                step_index: observed.len(),
                cause: DivergenceCause::ReplayShorter,
            });
        }
        None
    }
}

impl Divergence {
    /// Validate.
    pub fn validate(&self) -> Result<(), DivergenceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DivergenceError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(tool: &str, dec: &str, hash: &str, ms: u32) -> Step {
        Step {
            tool_id: tool.into(),
            decision: dec.into(),
            output_hash: hash.into(),
            elapsed_ms: ms,
        }
    }

    #[test]
    fn identical_no_divergence() {
        let r = vec![step("git", "allow", "abc", 100), step("ls", "allow", "def", 50)];
        let o = r.clone();
        assert!(ReplayDivergenceDetector::compare(&r, &o).is_none());
    }

    #[test]
    fn decision_changed_at_index() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "deny", "abc", 100)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert_eq!(d.step_index, 0);
        assert!(matches!(d.cause, DivergenceCause::DecisionChanged { .. }));
    }

    #[test]
    fn output_differed() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "allow", "xxx", 100)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert!(matches!(d.cause, DivergenceCause::OutputDiffered { .. }));
    }

    #[test]
    fn output_hash_case_insensitive() {
        let r = vec![step("git", "allow", "ABC", 100)];
        let o = vec![step("git", "allow", "abc", 100)];
        assert!(ReplayDivergenceDetector::compare(&r, &o).is_none());
    }

    #[test]
    fn tool_missing_at_index() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("ls", "allow", "abc", 100)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert!(matches!(d.cause, DivergenceCause::ToolMissing { .. }));
    }

    #[test]
    fn unexpected_extra_step() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![
            step("git", "allow", "abc", 100),
            step("ls", "allow", "def", 50),
        ];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert_eq!(d.step_index, 1);
        assert!(matches!(d.cause, DivergenceCause::UnexpectedExtraStep));
    }

    #[test]
    fn replay_shorter() {
        let r = vec![
            step("git", "allow", "abc", 100),
            step("ls", "allow", "def", 50),
        ];
        let o = vec![step("git", "allow", "abc", 100)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert_eq!(d.step_index, 1);
        assert!(matches!(d.cause, DivergenceCause::ReplayShorter));
    }

    #[test]
    fn timing_exceeded_when_more_than_double() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "allow", "abc", 250)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        assert!(matches!(d.cause, DivergenceCause::TimingExceeded { .. }));
    }

    #[test]
    fn timing_under_double_ok() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "allow", "abc", 150)];
        assert!(ReplayDivergenceDetector::compare(&r, &o).is_none());
    }

    #[test]
    fn empty_pair_no_divergence() {
        assert!(ReplayDivergenceDetector::compare(&[], &[]).is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "deny", "abc", 100)];
        let mut d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DivergenceError::SchemaMismatch));
    }

    #[test]
    fn cause_serde_kebab() {
        let c = DivergenceCause::UnexpectedExtraStep;
        let j = serde_json::to_string(&c).unwrap();
        assert!(j.contains("\"kind\":\"unexpected-extra-step\""));
    }

    #[test]
    fn divergence_serde_roundtrip() {
        let r = vec![step("git", "allow", "abc", 100)];
        let o = vec![step("git", "deny", "abc", 100)];
        let d = ReplayDivergenceDetector::compare(&r, &o).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: Divergence = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
