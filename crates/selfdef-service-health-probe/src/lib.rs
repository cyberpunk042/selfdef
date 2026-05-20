//! `selfdef-service-health-probe` — hysteresis-based health.
//!
//! Each service has thresholds: `fail_to_down` and `pass_to_healthy`.
//! State transitions:
//!   * Healthy → Degraded after first fail.
//!   * Degraded → Down after `fail_to_down` consecutive failures.
//!   * Down → Degraded after first success.
//!   * Degraded → Healthy after `pass_to_healthy` consecutive successes.
//!
//! Hysteresis prevents thrashing between Healthy and Down.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Health state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Health {
    /// Healthy.
    Healthy,
    /// Degraded.
    Degraded,
    /// Down.
    Down,
}

/// Per-service state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceProbe {
    /// State.
    pub health: Health,
    /// Consecutive failures.
    pub consec_fail: u32,
    /// Consecutive successes.
    pub consec_pass: u32,
    /// Probes total.
    pub total_probes: u64,
    /// Failure total.
    pub total_failures: u64,
    /// Last probe ts.
    pub last_probe_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceHealthProbe {
    /// Schema version.
    pub schema_version: String,
    /// Fail count to go Down from Degraded.
    pub fail_to_down: u32,
    /// Pass count to go Healthy from Degraded.
    pub pass_to_healthy: u32,
    /// service → probe.
    pub services: BTreeMap<String, ServiceProbe>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HealthError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("service id empty")]
    EmptyService,
    /// Zero threshold.
    #[error("thresholds must be >= 1")]
    ZeroThreshold,
}

impl ServiceHealthProbe {
    /// New.
    pub fn new(fail_to_down: u32, pass_to_healthy: u32) -> Result<Self, HealthError> {
        if fail_to_down == 0 || pass_to_healthy == 0 {
            return Err(HealthError::ZeroThreshold);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            fail_to_down,
            pass_to_healthy,
            services: BTreeMap::new(),
        })
    }

    /// Register (defaults to Healthy).
    pub fn register(&mut self, svc: &str) -> Result<(), HealthError> {
        if svc.is_empty() { return Err(HealthError::EmptyService); }
        self.services.entry(svc.into()).or_insert(ServiceProbe {
            health: Health::Healthy,
            consec_fail: 0,
            consec_pass: 0,
            total_probes: 0,
            total_failures: 0,
            last_probe_ms: 0,
        });
        Ok(())
    }

    /// Record a probe (success/failure). Returns the new health.
    pub fn record(&mut self, svc: &str, success: bool, ts_ms: u64) -> Result<Health, HealthError> {
        if svc.is_empty() { return Err(HealthError::EmptyService); }
        let fail_thresh = self.fail_to_down;
        let pass_thresh = self.pass_to_healthy;
        let s = self.services.entry(svc.into()).or_insert(ServiceProbe {
            health: Health::Healthy,
            consec_fail: 0,
            consec_pass: 0,
            total_probes: 0,
            total_failures: 0,
            last_probe_ms: 0,
        });
        s.total_probes = s.total_probes.saturating_add(1);
        s.last_probe_ms = ts_ms;
        if success {
            s.consec_pass = s.consec_pass.saturating_add(1);
            s.consec_fail = 0;
            // Transitions on success.
            s.health = match s.health {
                Health::Down => Health::Degraded,
                Health::Degraded => {
                    if s.consec_pass >= pass_thresh { Health::Healthy }
                    else { Health::Degraded }
                }
                Health::Healthy => Health::Healthy,
            };
        } else {
            s.consec_fail = s.consec_fail.saturating_add(1);
            s.consec_pass = 0;
            s.total_failures = s.total_failures.saturating_add(1);
            // Transitions on failure.
            s.health = match s.health {
                Health::Healthy => Health::Degraded,
                Health::Degraded => {
                    if s.consec_fail >= fail_thresh { Health::Down }
                    else { Health::Degraded }
                }
                Health::Down => Health::Down,
            };
        }
        Ok(s.health)
    }

    /// Snapshot.
    pub fn health_of(&self, svc: &str) -> Option<Health> {
        self.services.get(svc).map(|s| s.health)
    }

    /// All currently Down.
    pub fn down_services(&self) -> Vec<String> {
        self.services.iter()
            .filter(|(_, s)| s.health == Health::Down)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HealthError> {
        if self.schema_version != SCHEMA_VERSION { return Err(HealthError::SchemaMismatch); }
        if self.fail_to_down == 0 || self.pass_to_healthy == 0 {
            return Err(HealthError::ZeroThreshold);
        }
        for k in self.services.keys() {
            if k.is_empty() { return Err(HealthError::EmptyService); }
        }
        Ok(())
    }
}

impl Default for ServiceHealthProbe {
    fn default() -> Self { Self::new(3, 3).unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.register("api").unwrap();
        assert_eq!(h.health_of("api"), Some(Health::Healthy));
    }

    #[test]
    fn first_failure_degrades() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.record("api", false, 0).unwrap();
        assert_eq!(h.health_of("api"), Some(Health::Degraded));
    }

    #[test]
    fn three_failures_down() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        for _ in 0..3 { h.record("api", false, 0).unwrap(); }
        assert_eq!(h.health_of("api"), Some(Health::Down));
    }

    #[test]
    fn first_success_after_down_degrades() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        for _ in 0..3 { h.record("api", false, 0).unwrap(); }
        h.record("api", true, 0).unwrap();
        assert_eq!(h.health_of("api"), Some(Health::Degraded));
    }

    #[test]
    fn three_successes_back_to_healthy() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.record("api", false, 0).unwrap(); // Healthy → Degraded
        for _ in 0..3 { h.record("api", true, 0).unwrap(); }
        assert_eq!(h.health_of("api"), Some(Health::Healthy));
    }

    #[test]
    fn no_thrash_one_fail_one_pass() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.record("api", false, 0).unwrap();
        h.record("api", true, 1).unwrap();
        // Still Degraded — needs 3 consecutive passes to be healthy.
        assert_eq!(h.health_of("api"), Some(Health::Degraded));
    }

    #[test]
    fn consec_resets_on_opposite() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.record("api", false, 0).unwrap();
        h.record("api", false, 0).unwrap();
        h.record("api", true, 0).unwrap();
        // consec_fail should reset.
        assert_eq!(h.services["api"].consec_fail, 0);
        assert_eq!(h.services["api"].consec_pass, 1);
    }

    #[test]
    fn down_services_lists() {
        let mut h = ServiceHealthProbe::new(2, 2).unwrap();
        for _ in 0..2 { h.record("a", false, 0).unwrap(); }
        assert_eq!(h.down_services(), vec!["a".to_string()]);
    }

    #[test]
    fn zero_threshold_rejected() {
        assert!(matches!(ServiceHealthProbe::new(0, 1).unwrap_err(), HealthError::ZeroThreshold));
        assert!(matches!(ServiceHealthProbe::new(1, 0).unwrap_err(), HealthError::ZeroThreshold));
    }

    #[test]
    fn empty_service_rejected() {
        let mut h = ServiceHealthProbe::new(1, 1).unwrap();
        assert!(matches!(h.record("", true, 0).unwrap_err(), HealthError::EmptyService));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = ServiceHealthProbe::new(1, 1).unwrap();
        h.schema_version = "9.9.9".into();
        assert!(matches!(h.validate().unwrap_err(), HealthError::SchemaMismatch));
    }

    #[test]
    fn health_serde_roundtrip() {
        let mut h = ServiceHealthProbe::new(3, 3).unwrap();
        h.record("api", false, 100).unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let back: ServiceHealthProbe = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
