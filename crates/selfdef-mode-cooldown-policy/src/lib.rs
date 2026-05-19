//! `selfdef-mode-cooldown-policy` — per-mode minimum dwell time.
//!
//! Each `ExecutionMode` declares a minimum dwell time (seconds) the
//! daemon enforces before allowing a transition out. Prevents flapping.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_execution_mode_policy::ExecutionMode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-mode cooldown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeCooldown {
    /// Mode.
    pub mode: ExecutionMode,
    /// Minimum dwell seconds.
    pub dwell_seconds: u32,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeCooldownPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 7 cooldowns.
    pub cooldowns: Vec<ModeCooldown>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CooldownError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 7.
    #[error("cooldown count {0} != 7 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing mode: {0:?}")]
    Missing(ExecutionMode),
    /// Transition blocked.
    #[error("mode {mode:?} cooldown not elapsed: {elapsed_seconds}s < {required_seconds}s")]
    CooldownNotElapsed {
        /// mode.
        mode: ExecutionMode,
        /// elapsed.
        elapsed_seconds: u32,
        /// required.
        required_seconds: u32,
    },
}

impl ModeCooldownPolicy {
    /// Canonical defaults — Execute longest cooldown, Plan shortest.
    pub fn canonical() -> Self {
        let cooldowns = vec![
            ModeCooldown { mode: ExecutionMode::Plan,    dwell_seconds:  5 },
            ModeCooldown { mode: ExecutionMode::DryRun,  dwell_seconds: 10 },
            ModeCooldown { mode: ExecutionMode::Shadow,  dwell_seconds: 10 },
            ModeCooldown { mode: ExecutionMode::Sandbox, dwell_seconds: 30 },
            ModeCooldown { mode: ExecutionMode::Execute, dwell_seconds: 60 },
            ModeCooldown { mode: ExecutionMode::Replay,  dwell_seconds:  0 }, // can exit anytime
            ModeCooldown { mode: ExecutionMode::Debug,   dwell_seconds: 15 },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cooldowns,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CooldownError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CooldownError::SchemaMismatch);
        }
        if self.cooldowns.len() != 7 {
            return Err(CooldownError::CountInvalid(self.cooldowns.len()));
        }
        for m in ExecutionMode::ALL {
            if !self.cooldowns.iter().any(|c| c.mode == m) {
                return Err(CooldownError::Missing(m));
            }
        }
        Ok(())
    }

    /// Lookup dwell seconds.
    pub fn dwell(&self, mode: ExecutionMode) -> u32 {
        self.cooldowns.iter().find(|c| c.mode == mode).map(|c| c.dwell_seconds).unwrap_or(0)
    }

    /// Authorize exit from `mode` after `elapsed_seconds`.
    pub fn permit_exit(&self, mode: ExecutionMode, elapsed_seconds: u32) -> Result<(), CooldownError> {
        let required = self.dwell(mode);
        if elapsed_seconds < required {
            return Err(CooldownError::CooldownNotElapsed {
                mode, elapsed_seconds, required_seconds: required,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ModeCooldownPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn all_modes_present() {
        let p = ModeCooldownPolicy::canonical();
        for m in ExecutionMode::ALL { assert!(p.cooldowns.iter().any(|c| c.mode == m)); }
    }

    #[test]
    fn execute_longest_cooldown() {
        let p = ModeCooldownPolicy::canonical();
        let exec = p.dwell(ExecutionMode::Execute);
        for m in ExecutionMode::ALL {
            assert!(p.dwell(m) <= exec, "{m:?} dwell {} > execute {}", p.dwell(m), exec);
        }
    }

    #[test]
    fn replay_no_cooldown() {
        let p = ModeCooldownPolicy::canonical();
        assert_eq!(p.dwell(ExecutionMode::Replay), 0);
        p.permit_exit(ExecutionMode::Replay, 0).unwrap();
    }

    #[test]
    fn permit_exit_blocks_before_dwell() {
        let p = ModeCooldownPolicy::canonical();
        // Execute cooldown 60s → 30s elapsed should block.
        assert!(matches!(
            p.permit_exit(ExecutionMode::Execute, 30).unwrap_err(),
            CooldownError::CooldownNotElapsed { .. }
        ));
        // 60s should pass.
        p.permit_exit(ExecutionMode::Execute, 60).unwrap();
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = ModeCooldownPolicy::canonical();
        p.cooldowns.pop();
        assert!(matches!(p.validate().unwrap_err(), CooldownError::CountInvalid(6)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ModeCooldownPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), CooldownError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ModeCooldownPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: ModeCooldownPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
