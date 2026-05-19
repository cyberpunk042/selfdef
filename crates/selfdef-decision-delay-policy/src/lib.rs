//! `selfdef-decision-delay-policy` — mandatory cool-off before dispatch.
//!
//! Per BlastRadius minimum_delay_ms. dispatch_ready_at(radius,
//! confirmed_at_ms) returns the earliest wall-time the action may
//! actually run. is_ready(radius, confirmed_at_ms, now_ms) bool.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Blast radius (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlastRadius {
    /// LocalEphemeral.
    LocalEphemeral,
    /// LocalPersistent.
    LocalPersistent,
    /// CrossSession.
    CrossSession,
    /// CrossMachine.
    CrossMachine,
    /// Public.
    Public,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionDelayPolicy {
    /// Schema version.
    pub schema_version: String,
    /// local-ephemeral delay ms.
    pub local_ephemeral_ms: u32,
    /// local-persistent ms.
    pub local_persistent_ms: u32,
    /// cross-session ms.
    pub cross_session_ms: u32,
    /// cross-machine ms.
    pub cross_machine_ms: u32,
    /// public ms.
    pub public_ms: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DelayError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl DecisionDelayPolicy {
    /// Canonical:
    /// Local 0/100, CrossSession 1s, CrossMachine 3s, Public 5s.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            local_ephemeral_ms: 0,
            local_persistent_ms: 100,
            cross_session_ms: 1_000,
            cross_machine_ms: 3_000,
            public_ms: 5_000,
        }
    }

    /// Delay for radius.
    pub fn delay_ms(&self, r: BlastRadius) -> u32 {
        match r {
            BlastRadius::LocalEphemeral => self.local_ephemeral_ms,
            BlastRadius::LocalPersistent => self.local_persistent_ms,
            BlastRadius::CrossSession => self.cross_session_ms,
            BlastRadius::CrossMachine => self.cross_machine_ms,
            BlastRadius::Public => self.public_ms,
        }
    }

    /// Earliest dispatch time.
    pub fn dispatch_ready_at(&self, r: BlastRadius, confirmed_at_ms: u64) -> u64 {
        confirmed_at_ms.saturating_add(self.delay_ms(r) as u64)
    }

    /// Ready now?
    pub fn is_ready(&self, r: BlastRadius, confirmed_at_ms: u64, now_ms: u64) -> bool {
        now_ms >= self.dispatch_ready_at(r, confirmed_at_ms)
    }

    /// Remaining ms (0 if ready).
    pub fn remaining_ms(&self, r: BlastRadius, confirmed_at_ms: u64, now_ms: u64) -> u64 {
        let ready = self.dispatch_ready_at(r, confirmed_at_ms);
        ready.saturating_sub(now_ms)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DelayError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DelayError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        DecisionDelayPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn local_ephemeral_zero_delay() {
        let p = DecisionDelayPolicy::canonical();
        assert!(p.is_ready(BlastRadius::LocalEphemeral, 100, 100));
    }

    #[test]
    fn public_5s_delay() {
        let p = DecisionDelayPolicy::canonical();
        assert!(!p.is_ready(BlastRadius::Public, 100, 4_000));
        assert!(p.is_ready(BlastRadius::Public, 100, 5_100));
    }

    #[test]
    fn dispatch_ready_at_correct() {
        let p = DecisionDelayPolicy::canonical();
        assert_eq!(p.dispatch_ready_at(BlastRadius::CrossSession, 1_000), 2_000);
    }

    #[test]
    fn remaining_ms_zero_when_ready() {
        let p = DecisionDelayPolicy::canonical();
        assert_eq!(p.remaining_ms(BlastRadius::CrossMachine, 100, 100_000), 0);
    }

    #[test]
    fn remaining_ms_counts_down() {
        let p = DecisionDelayPolicy::canonical();
        // cross-machine = 3000ms. confirmed at 100, now at 1100. remaining = 2000.
        assert_eq!(p.remaining_ms(BlastRadius::CrossMachine, 100, 1100), 2000);
    }

    #[test]
    fn monotonic_delay_by_radius() {
        let p = DecisionDelayPolicy::canonical();
        assert!(p.delay_ms(BlastRadius::LocalEphemeral) <= p.delay_ms(BlastRadius::LocalPersistent));
        assert!(p.delay_ms(BlastRadius::LocalPersistent) <= p.delay_ms(BlastRadius::CrossSession));
        assert!(p.delay_ms(BlastRadius::CrossSession) <= p.delay_ms(BlastRadius::CrossMachine));
        assert!(p.delay_ms(BlastRadius::CrossMachine) <= p.delay_ms(BlastRadius::Public));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = DecisionDelayPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), DelayError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = DecisionDelayPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: DecisionDelayPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
