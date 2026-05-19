//! `selfdef-substrate-self-test-cadence` — when to run self-tests.
//!
//! Per CheckClass: interval_seconds + must_run_before_first_use.
//! due(class, now_unix, last_run_unix) returns true when the
//! interval has elapsed or the check has never run AND is required.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Check class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckClass {
    /// Fingerprint match (substrate binary).
    FingerprintMatch,
    /// Attestation chain intact.
    AttestationChain,
    /// Canary tripwire baseline OK.
    CanaryBaseline,
    /// Network egress reachable.
    NetworkEgressProbe,
    /// LocalAI / inference smoke test.
    InferenceSmoke,
}

/// One cadence entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassCadence {
    /// interval in seconds (re-run after this elapses).
    pub interval_seconds: u64,
    /// Must run before first use (boot-time mandatory)?
    pub must_run_before_first_use: bool,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateSelfTestCadence {
    /// Schema version.
    pub schema_version: String,
    /// fingerprint-match.
    pub fingerprint_match: ClassCadence,
    /// attestation-chain.
    pub attestation_chain: ClassCadence,
    /// canary-baseline.
    pub canary_baseline: ClassCadence,
    /// network-egress-probe.
    pub network_egress_probe: ClassCadence,
    /// inference-smoke.
    pub inference_smoke: ClassCadence,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CadenceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Interval zero (with non-mandatory class).
    #[error("class {0:?} interval_seconds is zero")]
    IntervalZero(CheckClass),
}

impl SubstrateSelfTestCadence {
    /// Canonical:
    /// * FingerprintMatch: 1h, mandatory.
    /// * AttestationChain: 5m, mandatory.
    /// * CanaryBaseline: 1m, mandatory.
    /// * NetworkEgressProbe: 5m, optional.
    /// * InferenceSmoke: 15m, optional.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            fingerprint_match: ClassCadence { interval_seconds: 3600, must_run_before_first_use: true },
            attestation_chain: ClassCadence { interval_seconds: 300, must_run_before_first_use: true },
            canary_baseline: ClassCadence { interval_seconds: 60, must_run_before_first_use: true },
            network_egress_probe: ClassCadence { interval_seconds: 300, must_run_before_first_use: false },
            inference_smoke: ClassCadence { interval_seconds: 900, must_run_before_first_use: false },
        }
    }

    /// Get cadence for a class.
    pub fn cadence(&self, class: CheckClass) -> ClassCadence {
        match class {
            CheckClass::FingerprintMatch => self.fingerprint_match,
            CheckClass::AttestationChain => self.attestation_chain,
            CheckClass::CanaryBaseline => self.canary_baseline,
            CheckClass::NetworkEgressProbe => self.network_egress_probe,
            CheckClass::InferenceSmoke => self.inference_smoke,
        }
    }

    /// Due to run?
    /// * `last_run_unix == 0` means never run.
    pub fn due(&self, class: CheckClass, now_unix: u64, last_run_unix: u64) -> bool {
        let cadence = self.cadence(class);
        if last_run_unix == 0 {
            return cadence.must_run_before_first_use;
        }
        now_unix.saturating_sub(last_run_unix) >= cadence.interval_seconds
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CadenceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CadenceError::SchemaMismatch);
        }
        for (c, cad) in [
            (CheckClass::FingerprintMatch, self.fingerprint_match),
            (CheckClass::AttestationChain, self.attestation_chain),
            (CheckClass::CanaryBaseline, self.canary_baseline),
            (CheckClass::NetworkEgressProbe, self.network_egress_probe),
            (CheckClass::InferenceSmoke, self.inference_smoke),
        ] {
            if cad.interval_seconds == 0 {
                return Err(CadenceError::IntervalZero(c));
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
        SubstrateSelfTestCadence::canonical().validate().unwrap();
    }

    #[test]
    fn mandatory_class_due_when_never_run() {
        let p = SubstrateSelfTestCadence::canonical();
        assert!(p.due(CheckClass::FingerprintMatch, 100, 0));
    }

    #[test]
    fn optional_class_not_due_when_never_run() {
        let p = SubstrateSelfTestCadence::canonical();
        assert!(!p.due(CheckClass::NetworkEgressProbe, 100, 0));
    }

    #[test]
    fn interval_elapsed_due() {
        let p = SubstrateSelfTestCadence::canonical();
        // canary baseline interval = 60s
        assert!(p.due(CheckClass::CanaryBaseline, 200, 100));
    }

    #[test]
    fn interval_not_elapsed_not_due() {
        let p = SubstrateSelfTestCadence::canonical();
        // attestation chain 300s
        assert!(!p.due(CheckClass::AttestationChain, 200, 100));
    }

    #[test]
    fn interval_zero_rejected() {
        let mut p = SubstrateSelfTestCadence::canonical();
        p.canary_baseline.interval_seconds = 0;
        assert!(matches!(p.validate().unwrap_err(), CadenceError::IntervalZero(CheckClass::CanaryBaseline)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateSelfTestCadence::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), CadenceError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&CheckClass::FingerprintMatch).unwrap(), "\"fingerprint-match\"");
        assert_eq!(serde_json::to_string(&CheckClass::InferenceSmoke).unwrap(), "\"inference-smoke\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SubstrateSelfTestCadence::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateSelfTestCadence = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
