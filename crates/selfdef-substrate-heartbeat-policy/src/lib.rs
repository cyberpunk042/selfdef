//! `selfdef-substrate-heartbeat-policy` — component-liveness watchdog.
//!
//! `register(component_id, deadline_ms)` registers a heartbeat
//! contract. `beat(component_id, ts)` records the latest heartbeat
//! (monotonic). `check(component_id, now)` returns Live{age} when
//! the gap is under the deadline, Stale{age, deadline} when over,
//! Unknown when never beat. `stale_set(now)` lists all stale ids.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-component entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    /// Deadline (ms since last beat).
    pub deadline_ms: u64,
    /// Last beat ts.
    pub last_beat_ms: Option<u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateHeartbeatPolicy {
    /// Schema version.
    pub schema_version: String,
    /// component_id → entry.
    pub components: BTreeMap<String, Component>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HeartbeatVerdict {
    /// Live.
    Live {
        /// age since last beat.
        age_ms: u64,
    },
    /// Stale.
    Stale {
        /// age.
        age_ms: u64,
        /// deadline.
        deadline_ms: u64,
    },
    /// Never beat.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HeartbeatError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty component id.
    #[error("component id empty")]
    EmptyId,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl SubstrateHeartbeatPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            components: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, component_id: &str, deadline_ms: u64) -> Result<(), HeartbeatError> {
        if component_id.is_empty() {
            return Err(HeartbeatError::EmptyId);
        }
        // Preserve any existing last_beat across re-register.
        let prev = self.components.get(component_id).copied();
        self.components.insert(
            component_id.into(),
            Component {
                deadline_ms,
                last_beat_ms: prev.and_then(|p| p.last_beat_ms),
            },
        );
        Ok(())
    }

    /// Heartbeat.
    pub fn beat(&mut self, component_id: &str, ts_ms: u64) -> Result<(), HeartbeatError> {
        if component_id.is_empty() {
            return Err(HeartbeatError::EmptyId);
        }
        let entry = self
            .components
            .entry(component_id.into())
            .or_insert(Component {
                deadline_ms: 60_000,
                last_beat_ms: None,
            });
        if let Some(prev) = entry.last_beat_ms {
            if ts_ms < prev {
                return Err(HeartbeatError::NonMonotonic { prev, new: ts_ms });
            }
        }
        entry.last_beat_ms = Some(ts_ms);
        Ok(())
    }

    /// Check.
    pub fn check(&self, component_id: &str, now_ms: u64) -> HeartbeatVerdict {
        let e = match self.components.get(component_id) {
            Some(e) => *e,
            None => return HeartbeatVerdict::Unknown,
        };
        match e.last_beat_ms {
            None => HeartbeatVerdict::Unknown,
            Some(t) => {
                let age = now_ms.saturating_sub(t);
                if age > e.deadline_ms {
                    HeartbeatVerdict::Stale {
                        age_ms: age,
                        deadline_ms: e.deadline_ms,
                    }
                } else {
                    HeartbeatVerdict::Live { age_ms: age }
                }
            }
        }
    }

    /// All stale ids at now_ms.
    pub fn stale_set(&self, now_ms: u64) -> Vec<String> {
        self.components
            .iter()
            .filter(|(_, e)| {
                matches!(
                    e.last_beat_ms
                        .map(|t| now_ms.saturating_sub(t) > e.deadline_ms),
                    Some(true)
                )
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HeartbeatError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HeartbeatError::SchemaMismatch);
        }
        for k in self.components.keys() {
            if k.is_empty() {
                return Err(HeartbeatError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for SubstrateHeartbeatPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_until_beat() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("worker", 1000).unwrap();
        assert_eq!(p.check("worker", 0), HeartbeatVerdict::Unknown);
    }

    #[test]
    fn live_when_within_deadline() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("worker", 1000).unwrap();
        p.beat("worker", 100).unwrap();
        let v = p.check("worker", 500);
        assert_eq!(v, HeartbeatVerdict::Live { age_ms: 400 });
    }

    #[test]
    fn stale_past_deadline() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("worker", 1000).unwrap();
        p.beat("worker", 0).unwrap();
        let v = p.check("worker", 5000);
        assert_eq!(
            v,
            HeartbeatVerdict::Stale {
                age_ms: 5000,
                deadline_ms: 1000
            }
        );
    }

    #[test]
    fn beat_preserved_across_re_register() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("worker", 1000).unwrap();
        p.beat("worker", 100).unwrap();
        // Tighten the deadline.
        p.register("worker", 100).unwrap();
        // 200 ms later — age 100, deadline 100 — Live (boundary).
        assert!(matches!(
            p.check("worker", 200),
            HeartbeatVerdict::Live { .. }
        ));
    }

    #[test]
    fn stale_set_reports() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("alive", 10_000).unwrap();
        p.beat("alive", 0).unwrap();
        p.register("dead", 10).unwrap();
        p.beat("dead", 0).unwrap();
        let s = p.stale_set(5_000);
        assert!(s.contains(&"dead".to_string()));
        assert!(!s.contains(&"alive".to_string()));
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("w", 1000).unwrap();
        p.beat("w", 200).unwrap();
        assert!(matches!(
            p.beat("w", 100).unwrap_err(),
            HeartbeatError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = SubstrateHeartbeatPolicy::new();
        assert!(matches!(
            p.register("", 1000).unwrap_err(),
            HeartbeatError::EmptyId
        ));
        assert!(matches!(
            p.beat("", 0).unwrap_err(),
            HeartbeatError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            HeartbeatError::SchemaMismatch
        ));
    }

    #[test]
    fn heartbeat_serde_roundtrip() {
        let mut p = SubstrateHeartbeatPolicy::new();
        p.register("w", 1000).unwrap();
        p.beat("w", 100).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateHeartbeatPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
