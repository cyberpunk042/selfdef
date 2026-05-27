//! `selfdef-readiness-gate` — component-aggregated readiness.
//!
//! Components register with required=true/false. update(id,
//! ready) records state. aggregate() returns:
//! - Healthy: all required components ready.
//! - Degraded: all required ready, some optional unready.
//! - Unready: at least one required unready (or no required
//!   components registered → counts as Unready).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Component.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    /// Required (false = optional).
    pub required: bool,
    /// Last reported ready.
    pub ready: bool,
}

/// Aggregate state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Aggregate {
    /// All required ready; all optional ready too.
    Healthy,
    /// All required ready; some optional unready.
    Degraded,
    /// At least one required unready (or no required).
    Unready,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessGate {
    /// Schema version.
    pub schema_version: String,
    /// id → component.
    pub components: BTreeMap<String, Component>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("component id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate component: {0}")]
    DuplicateComponent(String),
    /// Unknown.
    #[error("unknown component: {0}")]
    UnknownComponent(String),
}

impl ReadinessGate {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            components: BTreeMap::new(),
        }
    }

    /// Register a component (initial ready=false).
    pub fn register(&mut self, id: &str, required: bool) -> Result<(), GateError> {
        if id.is_empty() {
            return Err(GateError::EmptyId);
        }
        if self.components.contains_key(id) {
            return Err(GateError::DuplicateComponent(id.into()));
        }
        self.components.insert(
            id.into(),
            Component {
                required,
                ready: false,
            },
        );
        Ok(())
    }

    /// Update ready state.
    pub fn update(&mut self, id: &str, ready: bool) -> Result<(), GateError> {
        let c = self
            .components
            .get_mut(id)
            .ok_or_else(|| GateError::UnknownComponent(id.into()))?;
        c.ready = ready;
        Ok(())
    }

    /// Aggregate state.
    pub fn aggregate(&self) -> Aggregate {
        let mut any_required = false;
        let mut any_required_unready = false;
        let mut any_optional_unready = false;
        for c in self.components.values() {
            if c.required {
                any_required = true;
                if !c.ready {
                    any_required_unready = true;
                }
            } else if !c.ready {
                any_optional_unready = true;
            }
        }
        if !any_required || any_required_unready {
            Aggregate::Unready
        } else if any_optional_unready {
            Aggregate::Degraded
        } else {
            Aggregate::Healthy
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GateError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GateError::SchemaMismatch);
        }
        for k in self.components.keys() {
            if k.is_empty() {
                return Err(GateError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for ReadinessGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_components_is_unready() {
        let g = ReadinessGate::new();
        assert_eq!(g.aggregate(), Aggregate::Unready);
    }

    #[test]
    fn all_required_ready_is_healthy() {
        let mut g = ReadinessGate::new();
        g.register("db", true).unwrap();
        g.register("cache", true).unwrap();
        g.update("db", true).unwrap();
        g.update("cache", true).unwrap();
        assert_eq!(g.aggregate(), Aggregate::Healthy);
    }

    #[test]
    fn missing_required_is_unready() {
        let mut g = ReadinessGate::new();
        g.register("db", true).unwrap();
        g.register("cache", true).unwrap();
        g.update("db", true).unwrap();
        assert_eq!(g.aggregate(), Aggregate::Unready);
    }

    #[test]
    fn optional_unready_is_degraded() {
        let mut g = ReadinessGate::new();
        g.register("db", true).unwrap();
        g.register("analytics", false).unwrap();
        g.update("db", true).unwrap();
        // analytics still false.
        assert_eq!(g.aggregate(), Aggregate::Degraded);
    }

    #[test]
    fn only_optionals_is_unready() {
        let mut g = ReadinessGate::new();
        g.register("analytics", false).unwrap();
        g.update("analytics", true).unwrap();
        // No required → Unready.
        assert_eq!(g.aggregate(), Aggregate::Unready);
    }

    #[test]
    fn duplicate_component_rejected() {
        let mut g = ReadinessGate::new();
        g.register("db", true).unwrap();
        assert!(matches!(
            g.register("db", true).unwrap_err(),
            GateError::DuplicateComponent(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut g = ReadinessGate::new();
        assert!(matches!(
            g.register("", true).unwrap_err(),
            GateError::EmptyId
        ));
    }

    #[test]
    fn unknown_update_rejected() {
        let mut g = ReadinessGate::new();
        assert!(matches!(
            g.update("nope", true).unwrap_err(),
            GateError::UnknownComponent(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = ReadinessGate::new();
        g.schema_version = "9.9.9".into();
        assert!(matches!(
            g.validate().unwrap_err(),
            GateError::SchemaMismatch
        ));
    }

    #[test]
    fn gate_serde_roundtrip() {
        let mut g = ReadinessGate::new();
        g.register("db", true).unwrap();
        g.update("db", true).unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: ReadinessGate = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
