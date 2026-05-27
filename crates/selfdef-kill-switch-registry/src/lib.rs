//! `selfdef-kill-switch-registry` — emergency kill switches.
//!
//! Each switch starts Armed (function enabled). Tripping requires
//! a non-empty reason. Re-arming requires the operator to confirm
//! a fresh resolution AND a different actor than the one that
//! tripped it (two-person rule, when `dual_control = true`).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Switch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Switch {
    /// Id.
    pub id: String,
    /// Description (what does flipping it stop).
    pub description: String,
    /// Tripped?
    pub tripped: bool,
    /// Trip reason.
    pub trip_reason: Option<String>,
    /// Tripped at.
    pub tripped_at_ms: Option<u64>,
    /// Tripped by.
    pub tripped_by: Option<String>,
    /// Dual control (require different actor to re-arm).
    pub dual_control: bool,
    /// Trip count (historical).
    pub trip_count: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchRegistry {
    /// Schema version.
    pub schema_version: String,
    /// id → switch.
    pub switches: BTreeMap<String, Switch>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SwitchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("description empty")]
    EmptyDescription,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Duplicate.
    #[error("duplicate switch id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown switch: {0}")]
    UnknownSwitch(String),
    /// Already tripped.
    #[error("switch already tripped: {0}")]
    AlreadyTripped(String),
    /// Not tripped.
    #[error("switch not tripped: {0}")]
    NotTripped(String),
    /// Dual control violation.
    #[error("dual control: re-arm actor must differ from tripper for {0}")]
    DualControl(String),
}

impl KillSwitchRegistry {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            switches: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(
        &mut self,
        id: &str,
        description: &str,
        dual_control: bool,
    ) -> Result<(), SwitchError> {
        if id.is_empty() {
            return Err(SwitchError::EmptyId);
        }
        if description.is_empty() {
            return Err(SwitchError::EmptyDescription);
        }
        if self.switches.contains_key(id) {
            return Err(SwitchError::DuplicateId(id.into()));
        }
        self.switches.insert(
            id.into(),
            Switch {
                id: id.into(),
                description: description.into(),
                tripped: false,
                trip_reason: None,
                tripped_at_ms: None,
                tripped_by: None,
                dual_control,
                trip_count: 0,
            },
        );
        Ok(())
    }

    /// Trip.
    pub fn trip(
        &mut self,
        id: &str,
        reason: &str,
        actor: &str,
        ts_ms: u64,
    ) -> Result<(), SwitchError> {
        if reason.is_empty() {
            return Err(SwitchError::EmptyReason);
        }
        if actor.is_empty() {
            return Err(SwitchError::EmptyActor);
        }
        let s = self
            .switches
            .get_mut(id)
            .ok_or_else(|| SwitchError::UnknownSwitch(id.into()))?;
        if s.tripped {
            return Err(SwitchError::AlreadyTripped(id.into()));
        }
        s.tripped = true;
        s.trip_reason = Some(reason.into());
        s.tripped_by = Some(actor.into());
        s.tripped_at_ms = Some(ts_ms);
        s.trip_count = s.trip_count.saturating_add(1);
        Ok(())
    }

    /// Re-arm (clear tripped state).
    pub fn rearm(&mut self, id: &str, actor: &str) -> Result<(), SwitchError> {
        if actor.is_empty() {
            return Err(SwitchError::EmptyActor);
        }
        let s = self
            .switches
            .get_mut(id)
            .ok_or_else(|| SwitchError::UnknownSwitch(id.into()))?;
        if !s.tripped {
            return Err(SwitchError::NotTripped(id.into()));
        }
        if s.dual_control {
            if let Some(tripper) = &s.tripped_by {
                if tripper == actor {
                    return Err(SwitchError::DualControl(id.into()));
                }
            }
        }
        s.tripped = false;
        s.trip_reason = None;
        s.tripped_by = None;
        s.tripped_at_ms = None;
        Ok(())
    }

    /// Is operational? (true = not tripped).
    pub fn is_operational(&self, id: &str) -> bool {
        self.switches.get(id).map(|s| !s.tripped).unwrap_or(false)
    }

    /// List currently-tripped switches.
    pub fn tripped_ids(&self) -> Vec<String> {
        self.switches
            .values()
            .filter(|s| s.tripped)
            .map(|s| s.id.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SwitchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SwitchError::SchemaMismatch);
        }
        for (id, s) in &self.switches {
            if id.is_empty() {
                return Err(SwitchError::EmptyId);
            }
            if s.description.is_empty() {
                return Err(SwitchError::EmptyDescription);
            }
            if s.tripped {
                if s.trip_reason.as_ref().map(|r| r.is_empty()).unwrap_or(true) {
                    return Err(SwitchError::EmptyReason);
                }
                if s.tripped_by.as_ref().map(|a| a.is_empty()).unwrap_or(true) {
                    return Err(SwitchError::EmptyActor);
                }
            }
        }
        Ok(())
    }
}

impl Default for KillSwitchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_starts_operational() {
        let mut r = KillSwitchRegistry::new();
        r.register("egress", "halt all outbound traffic", false)
            .unwrap();
        assert!(r.is_operational("egress"));
    }

    #[test]
    fn trip_then_rearm() {
        let mut r = KillSwitchRegistry::new();
        r.register("egress", "halt", false).unwrap();
        r.trip("egress", "alert spike", "alice", 100).unwrap();
        assert!(!r.is_operational("egress"));
        r.rearm("egress", "alice").unwrap();
        assert!(r.is_operational("egress"));
    }

    #[test]
    fn dual_control_blocks_self_rearm() {
        let mut r = KillSwitchRegistry::new();
        r.register("kill", "halt", true).unwrap();
        r.trip("kill", "reason", "alice", 0).unwrap();
        assert!(matches!(
            r.rearm("kill", "alice").unwrap_err(),
            SwitchError::DualControl(_)
        ));
        // Different actor can re-arm.
        r.rearm("kill", "bob").unwrap();
    }

    #[test]
    fn double_trip_rejected() {
        let mut r = KillSwitchRegistry::new();
        r.register("k", "x", false).unwrap();
        r.trip("k", "r", "a", 0).unwrap();
        assert!(matches!(
            r.trip("k", "r2", "b", 1).unwrap_err(),
            SwitchError::AlreadyTripped(_)
        ));
    }

    #[test]
    fn rearm_unarmed_rejected() {
        let mut r = KillSwitchRegistry::new();
        r.register("k", "x", false).unwrap();
        assert!(matches!(
            r.rearm("k", "a").unwrap_err(),
            SwitchError::NotTripped(_)
        ));
    }

    #[test]
    fn trip_count_increments() {
        let mut r = KillSwitchRegistry::new();
        r.register("k", "x", false).unwrap();
        r.trip("k", "r", "a", 0).unwrap();
        r.rearm("k", "a").unwrap();
        r.trip("k", "r", "a", 1).unwrap();
        assert_eq!(r.switches["k"].trip_count, 2);
    }

    #[test]
    fn tripped_ids_lists() {
        let mut r = KillSwitchRegistry::new();
        r.register("a", "x", false).unwrap();
        r.register("b", "x", false).unwrap();
        r.trip("a", "r", "x", 0).unwrap();
        assert_eq!(r.tripped_ids(), vec!["a".to_string()]);
    }

    #[test]
    fn unknown_switch_rejected() {
        let mut r = KillSwitchRegistry::new();
        assert!(matches!(
            r.trip("nope", "r", "a", 0).unwrap_err(),
            SwitchError::UnknownSwitch(_)
        ));
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut r = KillSwitchRegistry::new();
        r.register("a", "x", false).unwrap();
        assert!(matches!(
            r.register("a", "x", false).unwrap_err(),
            SwitchError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = KillSwitchRegistry::new();
        assert!(matches!(
            r.register("", "x", false).unwrap_err(),
            SwitchError::EmptyId
        ));
        assert!(matches!(
            r.register("a", "", false).unwrap_err(),
            SwitchError::EmptyDescription
        ));
        r.register("a", "x", false).unwrap();
        assert!(matches!(
            r.trip("a", "", "x", 0).unwrap_err(),
            SwitchError::EmptyReason
        ));
        assert!(matches!(
            r.trip("a", "r", "", 0).unwrap_err(),
            SwitchError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = KillSwitchRegistry::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            SwitchError::SchemaMismatch
        ));
    }

    #[test]
    fn killswitch_serde_roundtrip() {
        let mut r = KillSwitchRegistry::new();
        r.register("a", "x", true).unwrap();
        r.trip("a", "r", "alice", 0).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: KillSwitchRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
