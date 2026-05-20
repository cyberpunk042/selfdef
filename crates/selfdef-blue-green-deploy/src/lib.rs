//! `selfdef-blue-green-deploy` — active/standby slots.
//!
//! Per service id, two slots: `Slot::Blue` and `Slot::Green`. Each
//! holds an optional version. `active(svc)` returns the current
//! active slot's version. `stage(svc, slot, version)` writes to
//! the inactive slot. `swap(svc)` flips active iff the staged slot
//! has been `warmed` (caller-set via `mark_warm`). Rollback is just
//! another swap.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Slot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Slot {
    /// Blue.
    Blue,
    /// Green.
    Green,
}

impl Slot {
    /// The other slot.
    pub fn other(self) -> Slot {
        match self { Slot::Blue => Slot::Green, Slot::Green => Slot::Blue }
    }
}

/// Per-slot record.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlotState {
    /// Deployed version.
    pub version: Option<String>,
    /// Warmed (ready to take traffic).
    pub warmed: bool,
}

/// Per-service state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceState {
    /// Active slot.
    pub active: Slot,
    /// Blue slot.
    pub blue: SlotState,
    /// Green slot.
    pub green: SlotState,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlueGreenDeploy {
    /// Schema version.
    pub schema_version: String,
    /// service → state.
    pub services: BTreeMap<String, ServiceState>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DeployError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("version empty")]
    EmptyVersion,
    /// Unknown.
    #[error("unknown service: {0}")]
    UnknownService(String),
    /// Stage to active.
    #[error("cannot stage to active slot for {svc}: stage to inactive ({inactive:?})")]
    StageToActive {
        /// svc.
        svc: String,
        /// inactive.
        inactive: Slot,
    },
    /// Not warm.
    #[error("inactive slot for {0} not warmed yet")]
    NotWarm(String),
    /// No version in inactive.
    #[error("inactive slot for {0} has no version")]
    NoVersionInInactive(String),
}

impl BlueGreenDeploy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            services: BTreeMap::new(),
        }
    }

    /// Register service (defaults to Blue active, both slots empty).
    pub fn register(&mut self, svc: &str) -> Result<(), DeployError> {
        if svc.is_empty() { return Err(DeployError::EmptyId); }
        self.services.entry(svc.into()).or_insert(ServiceState {
            active: Slot::Blue,
            blue: SlotState::default(),
            green: SlotState::default(),
        });
        Ok(())
    }

    fn slot_mut<'a>(state: &'a mut ServiceState, slot: Slot) -> &'a mut SlotState {
        match slot { Slot::Blue => &mut state.blue, Slot::Green => &mut state.green }
    }

    fn slot<'a>(state: &'a ServiceState, slot: Slot) -> &'a SlotState {
        match slot { Slot::Blue => &state.blue, Slot::Green => &state.green }
    }

    /// Stage a version to a (must-be-inactive) slot.
    pub fn stage(&mut self, svc: &str, slot: Slot, version: &str) -> Result<(), DeployError> {
        if version.is_empty() { return Err(DeployError::EmptyVersion); }
        let s = self.services.get_mut(svc).ok_or_else(|| DeployError::UnknownService(svc.into()))?;
        if s.active == slot {
            return Err(DeployError::StageToActive { svc: svc.into(), inactive: s.active.other() });
        }
        let slot_state = Self::slot_mut(s, slot);
        slot_state.version = Some(version.into());
        slot_state.warmed = false; // new staging resets warm flag.
        Ok(())
    }

    /// Mark a staged slot warm.
    pub fn mark_warm(&mut self, svc: &str, slot: Slot) -> Result<(), DeployError> {
        let s = self.services.get_mut(svc).ok_or_else(|| DeployError::UnknownService(svc.into()))?;
        Self::slot_mut(s, slot).warmed = true;
        Ok(())
    }

    /// Swap active ↔ inactive (requires inactive to be warmed + have a version).
    pub fn swap(&mut self, svc: &str) -> Result<(), DeployError> {
        let s = self.services.get_mut(svc).ok_or_else(|| DeployError::UnknownService(svc.into()))?;
        let inactive = s.active.other();
        let inactive_state = Self::slot(s, inactive);
        if inactive_state.version.is_none() {
            return Err(DeployError::NoVersionInInactive(svc.into()));
        }
        if !inactive_state.warmed {
            return Err(DeployError::NotWarm(svc.into()));
        }
        s.active = inactive;
        Ok(())
    }

    /// Active version of a service.
    pub fn active_version(&self, svc: &str) -> Option<String> {
        let s = self.services.get(svc)?;
        Self::slot(s, s.active).version.clone()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DeployError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DeployError::SchemaMismatch); }
        for (id, _) in &self.services {
            if id.is_empty() { return Err(DeployError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for BlueGreenDeploy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_defaults_to_blue() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        assert_eq!(d.services["api"].active, Slot::Blue);
        assert!(d.active_version("api").is_none());
    }

    #[test]
    fn happy_swap_path() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        d.stage("api", Slot::Green, "v2").unwrap();
        d.mark_warm("api", Slot::Green).unwrap();
        d.swap("api").unwrap();
        assert_eq!(d.active_version("api"), Some("v2".into()));
        assert_eq!(d.services["api"].active, Slot::Green);
    }

    #[test]
    fn cannot_stage_to_active() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        assert!(matches!(d.stage("api", Slot::Blue, "v1").unwrap_err(), DeployError::StageToActive { .. }));
    }

    #[test]
    fn cannot_swap_unwarmed() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        d.stage("api", Slot::Green, "v2").unwrap();
        assert!(matches!(d.swap("api").unwrap_err(), DeployError::NotWarm(_)));
    }

    #[test]
    fn cannot_swap_to_empty_slot() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        assert!(matches!(d.swap("api").unwrap_err(), DeployError::NoVersionInInactive(_)));
    }

    #[test]
    fn rollback_is_another_swap() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        // Forward.
        d.stage("api", Slot::Green, "v2").unwrap();
        d.mark_warm("api", Slot::Green).unwrap();
        d.swap("api").unwrap();
        // Roll back to blue (still has version=None — so first stage v1 there).
        d.stage("api", Slot::Blue, "v1").unwrap();
        d.mark_warm("api", Slot::Blue).unwrap();
        d.swap("api").unwrap();
        assert_eq!(d.active_version("api"), Some("v1".into()));
        assert_eq!(d.services["api"].active, Slot::Blue);
    }

    #[test]
    fn new_stage_resets_warm() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        d.stage("api", Slot::Green, "v2").unwrap();
        d.mark_warm("api", Slot::Green).unwrap();
        d.stage("api", Slot::Green, "v3").unwrap();
        // Warm reset.
        assert!(!d.services["api"].green.warmed);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut d = BlueGreenDeploy::new();
        assert!(matches!(d.register("").unwrap_err(), DeployError::EmptyId));
        d.register("a").unwrap();
        assert!(matches!(d.stage("a", Slot::Green, "").unwrap_err(), DeployError::EmptyVersion));
    }

    #[test]
    fn unknown_service_rejected() {
        let mut d = BlueGreenDeploy::new();
        assert!(matches!(d.stage("nope", Slot::Green, "v").unwrap_err(), DeployError::UnknownService(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = BlueGreenDeploy::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DeployError::SchemaMismatch));
    }

    #[test]
    fn deploy_serde_roundtrip() {
        let mut d = BlueGreenDeploy::new();
        d.register("api").unwrap();
        d.stage("api", Slot::Green, "v2").unwrap();
        d.mark_warm("api", Slot::Green).unwrap();
        d.swap("api").unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: BlueGreenDeploy = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
