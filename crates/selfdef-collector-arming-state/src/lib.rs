//! `selfdef-collector-arming-state` — per-collector arming state machine.
//!
//! Each of the 7 IPS collectors lives in one of 6 states:
//!
//! ```text
//!   Disabled ──arm──▶ Arming ──ack──▶ Armed ──subscribe──▶ Active
//!                                                            │
//!                              ┌─────── drain ◀──────────────┘
//!                              ▼                              │
//!                          Draining ──disable──▶ Disabled    quarantine
//!                                                             │
//!                                                             ▼
//!                                                       Quarantined
//!                                                             │
//!                                                          rearm ──▶ Arming
//! ```
//!
//! Transitions outside the allowed set return `TransitionInvalid`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_collector_source_taxonomy::CollectorKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Arming state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArmingState {
    /// Collector is administratively off.
    Disabled,
    /// Collector is starting up; not yet on bus.
    Arming,
    /// Collector reported ready; not yet subscribed.
    Armed,
    /// Collector subscribed + emitting events to bus.
    Active,
    /// Collector being shut down; events still drain.
    Draining,
    /// Collector pulled off bus due to a quarantine event.
    Quarantined,
}

/// Transition event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArmingEvent {
    /// Operator armed.
    Arm,
    /// Collector reported ready.
    Ack,
    /// Daemon subscribed to bus.
    Subscribe,
    /// Operator initiated drain.
    Drain,
    /// Collector finished drain.
    Disable,
    /// Quarantine triggered (budget breach / schema invalid / …).
    Quarantine,
    /// Operator re-armed after quarantine cleared.
    Rearm,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ArmingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Invalid transition from a state on an event.
    #[error("invalid transition for {kind:?}: state={state:?} event={event:?}")]
    TransitionInvalid {
        /// Collector.
        kind: CollectorKind,
        /// Current state.
        state: ArmingState,
        /// Event applied.
        event: ArmingEvent,
    },
    /// Unknown collector in vector.
    #[error("collector vector missing: {0:?}")]
    Missing(CollectorKind),
    /// Wrong count.
    #[error("collector vector count {0} != 7")]
    CountInvalid(usize),
}

impl ArmingState {
    /// Apply an event; returns the new state if legal.
    pub fn step(self, event: ArmingEvent) -> Option<ArmingState> {
        use ArmingState::*;
        use ArmingEvent::*;
        let next = match (self, event) {
            (Disabled, Arm) => Arming,
            (Arming, Ack) => Armed,
            (Armed, Subscribe) => Active,
            (Active, Drain) => Draining,
            (Draining, Disable) => Disabled,
            (Active, Quarantine) => Quarantined,
            (Armed, Quarantine) => Quarantined,
            (Arming, Quarantine) => Quarantined,
            (Quarantined, Rearm) => Arming,
            _ => return None,
        };
        Some(next)
    }

    /// True if this state means events are currently flowing.
    pub fn is_flowing(self) -> bool {
        matches!(self, ArmingState::Active | ArmingState::Draining)
    }
}

/// Per-collector arming snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorArming {
    /// Kind.
    pub kind: CollectorKind,
    /// Current state.
    pub state: ArmingState,
    /// ISO-8601 UTC last transition.
    pub transitioned_at: String,
}

/// 7-collector arming vector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArmingVector {
    /// Schema version.
    pub schema_version: String,
    /// Exactly 7 entries.
    pub collectors: Vec<CollectorArming>,
}

impl ArmingVector {
    /// All-disabled canonical vector.
    pub fn empty_canonical(at: &str) -> Self {
        let collectors = [
            CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
            CollectorKind::EventStream, CollectorKind::Journald,
            CollectorKind::Suricata, CollectorKind::Tetragon,
        ].into_iter().map(|k| CollectorArming {
            kind: k,
            state: ArmingState::Disabled,
            transitioned_at: at.into(),
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            collectors,
        }
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<(), ArmingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ArmingError::SchemaMismatch);
        }
        if self.collectors.len() != 7 {
            return Err(ArmingError::CountInvalid(self.collectors.len()));
        }
        for k in [
            CollectorKind::Auditd, CollectorKind::Canary, CollectorKind::Ebpf,
            CollectorKind::EventStream, CollectorKind::Journald,
            CollectorKind::Suricata, CollectorKind::Tetragon,
        ] {
            if !self.collectors.iter().any(|c| c.kind == k) {
                return Err(ArmingError::Missing(k));
            }
        }
        Ok(())
    }

    /// Apply a transition for one collector. Returns the new state.
    pub fn apply(&mut self, kind: CollectorKind, event: ArmingEvent, at: &str) -> Result<ArmingState, ArmingError> {
        let entry = self.collectors.iter_mut().find(|c| c.kind == kind)
            .ok_or(ArmingError::Missing(kind))?;
        match entry.state.step(event) {
            Some(next) => {
                entry.state = next;
                entry.transitioned_at = at.into();
                Ok(next)
            }
            None => Err(ArmingError::TransitionInvalid { kind, state: entry.state, event }),
        }
    }

    /// Lookup.
    pub fn get(&self, kind: CollectorKind) -> Option<&CollectorArming> {
        self.collectors.iter().find(|c| c.kind == kind)
    }

    /// Count collectors currently in Active state.
    pub fn active_count(&self) -> usize {
        self.collectors.iter().filter(|c| c.state == ArmingState::Active).count()
    }

    /// Count quarantined collectors.
    pub fn quarantined_count(&self) -> usize {
        self.collectors.iter().filter(|c| c.state == ArmingState::Quarantined).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_canonical_validates() {
        ArmingVector::empty_canonical("t").validate().unwrap();
    }

    #[test]
    fn happy_path_disabled_to_active() {
        let mut v = ArmingVector::empty_canonical("t0");
        assert_eq!(v.apply(CollectorKind::Auditd, ArmingEvent::Arm, "t1").unwrap(), ArmingState::Arming);
        assert_eq!(v.apply(CollectorKind::Auditd, ArmingEvent::Ack, "t2").unwrap(), ArmingState::Armed);
        assert_eq!(v.apply(CollectorKind::Auditd, ArmingEvent::Subscribe, "t3").unwrap(), ArmingState::Active);
        assert_eq!(v.active_count(), 1);
    }

    #[test]
    fn drain_then_disable() {
        let mut v = ArmingVector::empty_canonical("t0");
        v.apply(CollectorKind::Ebpf, ArmingEvent::Arm, "t1").unwrap();
        v.apply(CollectorKind::Ebpf, ArmingEvent::Ack, "t2").unwrap();
        v.apply(CollectorKind::Ebpf, ArmingEvent::Subscribe, "t3").unwrap();
        v.apply(CollectorKind::Ebpf, ArmingEvent::Drain, "t4").unwrap();
        assert_eq!(v.get(CollectorKind::Ebpf).unwrap().state, ArmingState::Draining);
        v.apply(CollectorKind::Ebpf, ArmingEvent::Disable, "t5").unwrap();
        assert_eq!(v.get(CollectorKind::Ebpf).unwrap().state, ArmingState::Disabled);
    }

    #[test]
    fn quarantine_then_rearm() {
        let mut v = ArmingVector::empty_canonical("t0");
        v.apply(CollectorKind::Suricata, ArmingEvent::Arm, "t1").unwrap();
        v.apply(CollectorKind::Suricata, ArmingEvent::Ack, "t2").unwrap();
        v.apply(CollectorKind::Suricata, ArmingEvent::Subscribe, "t3").unwrap();
        v.apply(CollectorKind::Suricata, ArmingEvent::Quarantine, "t4").unwrap();
        assert_eq!(v.quarantined_count(), 1);
        v.apply(CollectorKind::Suricata, ArmingEvent::Rearm, "t5").unwrap();
        assert_eq!(v.get(CollectorKind::Suricata).unwrap().state, ArmingState::Arming);
    }

    #[test]
    fn invalid_transition_caught() {
        let mut v = ArmingVector::empty_canonical("t0");
        // Disabled + Subscribe is not allowed (must Arm first).
        let err = v.apply(CollectorKind::Auditd, ArmingEvent::Subscribe, "t1").unwrap_err();
        match err {
            ArmingError::TransitionInvalid { kind, state, event } => {
                assert_eq!(kind, CollectorKind::Auditd);
                assert_eq!(state, ArmingState::Disabled);
                assert_eq!(event, ArmingEvent::Subscribe);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn is_flowing_only_active_and_draining() {
        assert!(!ArmingState::Disabled.is_flowing());
        assert!(!ArmingState::Arming.is_flowing());
        assert!(!ArmingState::Armed.is_flowing());
        assert!(ArmingState::Active.is_flowing());
        assert!(ArmingState::Draining.is_flowing());
        assert!(!ArmingState::Quarantined.is_flowing());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = ArmingVector::empty_canonical("t");
        v.schema_version = "9.9.9".into();
        assert!(matches!(v.validate().unwrap_err(), ArmingError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut v = ArmingVector::empty_canonical("t");
        v.collectors.pop();
        assert!(matches!(v.validate().unwrap_err(), ArmingError::CountInvalid(6)));
    }

    #[test]
    fn quarantine_from_armed_legal() {
        let mut v = ArmingVector::empty_canonical("t0");
        v.apply(CollectorKind::Canary, ArmingEvent::Arm, "t1").unwrap();
        v.apply(CollectorKind::Canary, ArmingEvent::Ack, "t2").unwrap();
        // Quarantine from Armed (e.g. schema invalid on first event)
        v.apply(CollectorKind::Canary, ArmingEvent::Quarantine, "t3").unwrap();
        assert_eq!(v.get(CollectorKind::Canary).unwrap().state, ArmingState::Quarantined);
    }

    #[test]
    fn state_serde_kebab() {
        assert_eq!(serde_json::to_string(&ArmingState::Quarantined).unwrap(), "\"quarantined\"");
        assert_eq!(serde_json::to_string(&ArmingState::Draining).unwrap(), "\"draining\"");
    }

    #[test]
    fn event_serde_kebab() {
        assert_eq!(serde_json::to_string(&ArmingEvent::Subscribe).unwrap(), "\"subscribe\"");
        assert_eq!(serde_json::to_string(&ArmingEvent::Rearm).unwrap(), "\"rearm\"");
    }

    #[test]
    fn vector_serde_roundtrip() {
        let mut v = ArmingVector::empty_canonical("t0");
        v.apply(CollectorKind::Auditd, ArmingEvent::Arm, "t1").unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let back: ArmingVector = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
