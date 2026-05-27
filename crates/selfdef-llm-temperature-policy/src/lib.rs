//! `selfdef-llm-temperature-policy` — temperature range per mode.
//!
//! Each ExecutionMode declares (min, max). admit(mode, t) returns
//! Allow when t in [min,max], Denied otherwise. clamp clips into
//! range. Production/Replay enforce 0.0..=0.0 (greedy decode).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    /// Plan.
    Plan,
    /// DryRun.
    DryRun,
    /// Shadow.
    Shadow,
    /// Sandbox.
    Sandbox,
    /// Execute.
    Execute,
    /// Replay.
    Replay,
    /// Debug.
    Debug,
}

/// Per-mode temp range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct TempRange {
    /// Minimum (inclusive).
    pub min: f32,
    /// Maximum (inclusive).
    pub max: f32,
}

/// Admit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Admitted.
    Allow,
    /// Denied.
    Denied,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmTemperaturePolicy {
    /// Schema version.
    pub schema_version: String,
    /// plan.
    pub plan: TempRange,
    /// dry-run.
    pub dry_run: TempRange,
    /// shadow.
    pub shadow: TempRange,
    /// sandbox.
    pub sandbox: TempRange,
    /// execute.
    pub execute: TempRange,
    /// replay.
    pub replay: TempRange,
    /// debug.
    pub debug: TempRange,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TempError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad range.
    #[error("mode {0:?} range invalid (min {1} > max {2}, or NaN)")]
    BadRange(ExecutionMode, f32, f32),
}

impl LlmTemperaturePolicy {
    /// Canonical: Plan 0..1, DryRun 0..0.7, Shadow 0..0.5,
    /// Sandbox 0..0.8, Execute 0..0.3, Replay 0..0, Debug 0..1.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            plan: TempRange { min: 0.0, max: 1.0 },
            dry_run: TempRange { min: 0.0, max: 0.7 },
            shadow: TempRange { min: 0.0, max: 0.5 },
            sandbox: TempRange { min: 0.0, max: 0.8 },
            execute: TempRange { min: 0.0, max: 0.3 },
            replay: TempRange { min: 0.0, max: 0.0 },
            debug: TempRange { min: 0.0, max: 1.0 },
        }
    }

    /// Range for mode.
    pub fn range(&self, mode: ExecutionMode) -> TempRange {
        match mode {
            ExecutionMode::Plan => self.plan,
            ExecutionMode::DryRun => self.dry_run,
            ExecutionMode::Shadow => self.shadow,
            ExecutionMode::Sandbox => self.sandbox,
            ExecutionMode::Execute => self.execute,
            ExecutionMode::Replay => self.replay,
            ExecutionMode::Debug => self.debug,
        }
    }

    /// Admit.
    pub fn admit(&self, mode: ExecutionMode, t: f32) -> AdmitDecision {
        if t.is_nan() {
            return AdmitDecision::Denied;
        }
        let r = self.range(mode);
        if t >= r.min && t <= r.max {
            AdmitDecision::Allow
        } else {
            AdmitDecision::Denied
        }
    }

    /// Clamp into range.
    pub fn clamp(&self, mode: ExecutionMode, t: f32) -> f32 {
        let r = self.range(mode);
        if t.is_nan() {
            return r.min;
        }
        t.clamp(r.min, r.max)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TempError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TempError::SchemaMismatch);
        }
        for (m, r) in [
            (ExecutionMode::Plan, self.plan),
            (ExecutionMode::DryRun, self.dry_run),
            (ExecutionMode::Shadow, self.shadow),
            (ExecutionMode::Sandbox, self.sandbox),
            (ExecutionMode::Execute, self.execute),
            (ExecutionMode::Replay, self.replay),
            (ExecutionMode::Debug, self.debug),
        ] {
            if r.min.is_nan() || r.max.is_nan() || r.min > r.max {
                return Err(TempError::BadRange(m, r.min, r.max));
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
        LlmTemperaturePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn plan_allows_high_temp() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.admit(ExecutionMode::Plan, 0.9), AdmitDecision::Allow);
    }

    #[test]
    fn execute_rejects_high_temp() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.admit(ExecutionMode::Execute, 0.9), AdmitDecision::Denied);
    }

    #[test]
    fn replay_only_zero() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.admit(ExecutionMode::Replay, 0.0), AdmitDecision::Allow);
        assert_eq!(p.admit(ExecutionMode::Replay, 0.1), AdmitDecision::Denied);
    }

    #[test]
    fn clamp_clips_into_range() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.clamp(ExecutionMode::Execute, 0.9), 0.3);
        assert_eq!(p.clamp(ExecutionMode::Plan, 1.5), 1.0);
    }

    #[test]
    fn clamp_nan_returns_min() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.clamp(ExecutionMode::Plan, f32::NAN), 0.0);
    }

    #[test]
    fn nan_denied() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(
            p.admit(ExecutionMode::Plan, f32::NAN),
            AdmitDecision::Denied
        );
    }

    #[test]
    fn negative_denied() {
        let p = LlmTemperaturePolicy::canonical();
        assert_eq!(p.admit(ExecutionMode::Plan, -0.1), AdmitDecision::Denied);
    }

    #[test]
    fn bad_range_rejected() {
        let mut p = LlmTemperaturePolicy::canonical();
        p.execute = TempRange { min: 0.5, max: 0.1 };
        assert!(matches!(
            p.validate().unwrap_err(),
            TempError::BadRange(ExecutionMode::Execute, _, _)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = LlmTemperaturePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            TempError::SchemaMismatch
        ));
    }

    #[test]
    fn mode_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ExecutionMode::DryRun).unwrap(),
            "\"dry-run\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutionMode::Replay).unwrap(),
            "\"replay\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = LlmTemperaturePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: LlmTemperaturePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
