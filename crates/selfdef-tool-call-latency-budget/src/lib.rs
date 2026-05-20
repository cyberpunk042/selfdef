//! `selfdef-tool-call-latency-budget` — per-Profile per-call wall-clock budget.
//!
//! Each Profile carries (soft_ms, hard_ms). start() records start_ts;
//! poll() returns OnTime / SoftExpired / HardExpired against elapsed.
//! finish() clears the entry. Distinct from the task-level deadline
//! extension policy — this is the single-tool-call lane.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Per-Profile budget.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileLatency {
    /// Soft expiry ms.
    pub soft_ms: u64,
    /// Hard expiry ms.
    pub hard_ms: u64,
}

/// One in-flight call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallEntry {
    /// id.
    pub id: u64,
    /// profile.
    pub profile: Profile,
    /// tool label.
    pub tool: String,
    /// start ts ms.
    pub start_ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallLatencyBudget {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile budgets.
    pub profiles: BTreeMap<Profile, ProfileLatency>,
    /// Calls in flight.
    pub calls: Vec<CallEntry>,
}

/// Poll verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PollVerdict {
    /// Under soft budget.
    OnTime {
        /// elapsed.
        elapsed_ms: u64,
    },
    /// Past soft, under hard.
    SoftExpired {
        /// elapsed.
        elapsed_ms: u64,
        /// soft.
        soft_ms: u64,
    },
    /// Past hard.
    HardExpired {
        /// elapsed.
        elapsed_ms: u64,
        /// hard.
        hard_ms: u64,
    },
    /// Profile unconfigured.
    Unconfigured,
    /// Unknown call id.
    UnknownCall,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LatencyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown call id.
    #[error("unknown call id: {0}")]
    UnknownCall(u64),
    /// Bad thresholds.
    #[error("soft_ms {0} > hard_ms {1}")]
    BadThresholds(u64, u64),
}

impl ToolCallLatencyBudget {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(Profile::Private,      ProfileLatency { soft_ms: 5_000,  hard_ms: 15_000 });
        p.insert(Profile::Fast,         ProfileLatency { soft_ms: 10_000, hard_ms: 30_000 });
        p.insert(Profile::Careful,      ProfileLatency { soft_ms: 30_000, hard_ms: 90_000 });
        p.insert(Profile::Autonomous,   ProfileLatency { soft_ms: 30_000, hard_ms: 120_000 });
        p.insert(Profile::Experimental, ProfileLatency { soft_ms: 60_000, hard_ms: 300_000 });
        p.insert(Profile::Production,   ProfileLatency { soft_ms: 15_000, hard_ms: 60_000 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
            calls: Vec::new(),
        }
    }

    /// Start a call.
    pub fn start(&mut self, id: u64, profile: Profile, tool: &str, start_ts_ms: u64) {
        self.calls.push(CallEntry { id, profile, tool: tool.into(), start_ts_ms });
    }

    /// Poll.
    pub fn poll(&self, id: u64, now_ms: u64) -> PollVerdict {
        let c = match self.calls.iter().find(|c| c.id == id) {
            Some(c) => c,
            None => return PollVerdict::UnknownCall,
        };
        let cfg = match self.profiles.get(&c.profile) {
            Some(c) => *c,
            None => return PollVerdict::Unconfigured,
        };
        let elapsed_ms = now_ms.saturating_sub(c.start_ts_ms);
        if elapsed_ms >= cfg.hard_ms {
            PollVerdict::HardExpired { elapsed_ms, hard_ms: cfg.hard_ms }
        } else if elapsed_ms >= cfg.soft_ms {
            PollVerdict::SoftExpired { elapsed_ms, soft_ms: cfg.soft_ms }
        } else {
            PollVerdict::OnTime { elapsed_ms }
        }
    }

    /// Finish.
    pub fn finish(&mut self, id: u64) -> Result<(), LatencyError> {
        let pos = self.calls.iter().position(|c| c.id == id)
            .ok_or(LatencyError::UnknownCall(id))?;
        self.calls.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LatencyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LatencyError::SchemaMismatch);
        }
        for cfg in self.profiles.values() {
            if cfg.soft_ms > cfg.hard_ms {
                return Err(LatencyError::BadThresholds(cfg.soft_ms, cfg.hard_ms));
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
        ToolCallLatencyBudget::canonical().validate().unwrap();
    }

    #[test]
    fn on_time() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        assert!(matches!(b.poll(1, 1000), PollVerdict::OnTime { .. }));
    }

    #[test]
    fn soft_expired() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        // Fast soft 10s.
        assert!(matches!(b.poll(1, 15_000), PollVerdict::SoftExpired { .. }));
    }

    #[test]
    fn hard_expired() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        // Fast hard 30s.
        assert!(matches!(b.poll(1, 35_000), PollVerdict::HardExpired { .. }));
    }

    #[test]
    fn unknown_call() {
        let b = ToolCallLatencyBudget::canonical();
        assert_eq!(b.poll(999, 0), PollVerdict::UnknownCall);
    }

    #[test]
    fn unconfigured_profile() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        b.profiles.clear();
        assert_eq!(b.poll(1, 1), PollVerdict::Unconfigured);
    }

    #[test]
    fn finish_removes() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        b.finish(1).unwrap();
        assert!(matches!(b.finish(1).unwrap_err(), LatencyError::UnknownCall(_)));
    }

    #[test]
    fn bad_thresholds_rejected() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.profiles.insert(Profile::Fast, ProfileLatency { soft_ms: 1000, hard_ms: 100 });
        assert!(matches!(b.validate().unwrap_err(), LatencyError::BadThresholds(_, _)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), LatencyError::SchemaMismatch));
    }

    #[test]
    fn latency_serde_roundtrip() {
        let mut b = ToolCallLatencyBudget::canonical();
        b.start(1, Profile::Fast, "fetch", 0);
        let j = serde_json::to_string(&b).unwrap();
        let back: ToolCallLatencyBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
