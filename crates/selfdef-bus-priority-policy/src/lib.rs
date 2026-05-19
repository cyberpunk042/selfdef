//! `selfdef-bus-priority-policy` — per-event-class priority.
//!
//! 4 priority classes: Critical / High / Normal / Low. Event class
//! examples: Quarantine / SecurityIncident / PolicyDecision / TraceSpan /
//! TelemetryTick. The bus delivers higher-priority events first under
//! pressure.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 4 priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Low.
    Low,
    /// Normal.
    Normal,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// 8 canonical event classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventClass {
    /// Quarantine event.
    Quarantine,
    /// Security incident.
    SecurityIncident,
    /// Policy decision.
    PolicyDecision,
    /// Trace span.
    TraceSpan,
    /// Audit chain link.
    AuditChainLink,
    /// Telemetry tick.
    TelemetryTick,
    /// Anomaly hint.
    AnomalyHint,
    /// Cockpit toast.
    CockpitToast,
}

/// Per-class assignment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassPriority {
    /// Class.
    pub class: EventClass,
    /// Priority.
    pub priority: Priority,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusPriorityPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 8 class priorities.
    pub assignments: Vec<ClassPriority>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PriorityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("assignment count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing class: {0:?}")]
    Missing(EventClass),
}

const REQUIRED: [EventClass; 8] = [
    EventClass::Quarantine, EventClass::SecurityIncident,
    EventClass::PolicyDecision, EventClass::TraceSpan,
    EventClass::AuditChainLink, EventClass::TelemetryTick,
    EventClass::AnomalyHint, EventClass::CockpitToast,
];

impl BusPriorityPolicy {
    /// Canonical assignment.
    pub fn canonical() -> Self {
        let assignments = vec![
            ClassPriority { class: EventClass::Quarantine,       priority: Priority::Critical },
            ClassPriority { class: EventClass::SecurityIncident, priority: Priority::Critical },
            ClassPriority { class: EventClass::PolicyDecision,   priority: Priority::High },
            ClassPriority { class: EventClass::AuditChainLink,   priority: Priority::High },
            ClassPriority { class: EventClass::TraceSpan,        priority: Priority::Normal },
            ClassPriority { class: EventClass::AnomalyHint,      priority: Priority::Normal },
            ClassPriority { class: EventClass::TelemetryTick,    priority: Priority::Low },
            ClassPriority { class: EventClass::CockpitToast,     priority: Priority::Low },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            assignments,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PriorityError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PriorityError::SchemaMismatch);
        }
        if self.assignments.len() != 8 {
            return Err(PriorityError::CountInvalid(self.assignments.len()));
        }
        for c in REQUIRED {
            if !self.assignments.iter().any(|a| a.class == c) {
                return Err(PriorityError::Missing(c));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn priority_of(&self, class: EventClass) -> Priority {
        self.assignments.iter().find(|a| a.class == class).map(|a| a.priority).unwrap_or(Priority::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        BusPriorityPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn eight_classes_present() {
        let p = BusPriorityPolicy::canonical();
        for c in REQUIRED {
            assert!(p.assignments.iter().any(|a| a.class == c), "missing {c:?}");
        }
    }

    #[test]
    fn quarantine_is_critical() {
        assert_eq!(BusPriorityPolicy::canonical().priority_of(EventClass::Quarantine), Priority::Critical);
    }

    #[test]
    fn telemetry_is_low() {
        assert_eq!(BusPriorityPolicy::canonical().priority_of(EventClass::TelemetryTick), Priority::Low);
    }

    #[test]
    fn priority_ordering() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::Critical);
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = BusPriorityPolicy::canonical();
        p.assignments.pop();
        assert!(matches!(p.validate().unwrap_err(), PriorityError::CountInvalid(7)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = BusPriorityPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PriorityError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&EventClass::SecurityIncident).unwrap(), "\"security-incident\"");
        assert_eq!(serde_json::to_string(&EventClass::AuditChainLink).unwrap(), "\"audit-chain-link\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = BusPriorityPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: BusPriorityPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
