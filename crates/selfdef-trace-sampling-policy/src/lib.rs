//! `selfdef-trace-sampling-policy` — per-class sampling authority.
//!
//! sample(trace_id, class) is deterministic: FNV-1a hash of
//! trace_id mod 1_000_000 < sample_rate_ppm for the class. Some
//! classes are in `force_keep` and are never dropped.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Span class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpanClass {
    /// LLM call.
    Llm,
    /// Tool exec.
    Tool,
    /// Policy decision.
    Decision,
    /// Policy decision = Deny (always kept).
    DecisionDenial,
    /// Canary tripwire firing (always kept).
    CanaryTrip,
    /// HTTP request.
    Http,
    /// Internal compute.
    Compute,
}

/// Sample decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SampleDecision {
    /// Keep.
    Keep,
    /// Drop.
    Drop,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceSamplingPolicy {
    /// Schema version.
    pub schema_version: String,
    /// llm sample rate (ppm).
    pub llm_ppm: u32,
    /// tool sample rate (ppm).
    pub tool_ppm: u32,
    /// decision sample rate (ppm).
    pub decision_ppm: u32,
    /// http sample rate (ppm).
    pub http_ppm: u32,
    /// compute sample rate (ppm).
    pub compute_ppm: u32,
    /// Force-keep classes (always sampled).
    pub force_keep: Vec<SpanClass>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SamplingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// ppm > 1_000_000.
    #[error("class {0:?} ppm {1} > 1_000_000")]
    PpmOutOfRange(SpanClass, u32),
}

impl TraceSamplingPolicy {
    /// Canonical: 100% decisions, 10% llm, 1% tool/http, 0.1% compute;
    /// DecisionDenial + CanaryTrip force-kept.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            llm_ppm: 100_000,
            tool_ppm: 10_000,
            decision_ppm: 1_000_000,
            http_ppm: 10_000,
            compute_ppm: 1_000,
            force_keep: vec![SpanClass::DecisionDenial, SpanClass::CanaryTrip],
        }
    }

    /// Get ppm for class.
    pub fn ppm_for(&self, c: SpanClass) -> u32 {
        match c {
            SpanClass::Llm => self.llm_ppm,
            SpanClass::Tool => self.tool_ppm,
            SpanClass::Decision => self.decision_ppm,
            SpanClass::DecisionDenial => 1_000_000,
            SpanClass::CanaryTrip => 1_000_000,
            SpanClass::Http => self.http_ppm,
            SpanClass::Compute => self.compute_ppm,
        }
    }

    /// Sample.
    pub fn sample(&self, trace_id: &str, class: SpanClass) -> SampleDecision {
        if self.force_keep.contains(&class) {
            return SampleDecision::Keep;
        }
        let h = fnv1a_64(trace_id.as_bytes());
        let mod_ppm = (h % 1_000_000) as u32;
        if mod_ppm < self.ppm_for(class) {
            SampleDecision::Keep
        } else {
            SampleDecision::Drop
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SamplingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SamplingError::SchemaMismatch);
        }
        for (c, p) in [
            (SpanClass::Llm, self.llm_ppm),
            (SpanClass::Tool, self.tool_ppm),
            (SpanClass::Decision, self.decision_ppm),
            (SpanClass::Http, self.http_ppm),
            (SpanClass::Compute, self.compute_ppm),
        ] {
            if p > 1_000_000 {
                return Err(SamplingError::PpmOutOfRange(c, p));
            }
        }
        Ok(())
    }
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        TraceSamplingPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn decision_denial_always_kept() {
        let p = TraceSamplingPolicy::canonical();
        for i in 0..100 {
            assert_eq!(
                p.sample(&format!("t{i}"), SpanClass::DecisionDenial),
                SampleDecision::Keep
            );
        }
    }

    #[test]
    fn canary_trip_always_kept() {
        let p = TraceSamplingPolicy::canonical();
        for i in 0..100 {
            assert_eq!(
                p.sample(&format!("t{i}"), SpanClass::CanaryTrip),
                SampleDecision::Keep
            );
        }
    }

    #[test]
    fn decision_100pct_always_kept() {
        let p = TraceSamplingPolicy::canonical();
        for i in 0..100 {
            assert_eq!(
                p.sample(&format!("t{i}"), SpanClass::Decision),
                SampleDecision::Keep
            );
        }
    }

    #[test]
    fn compute_low_rate_drops_most() {
        let p = TraceSamplingPolicy::canonical();
        let mut kept = 0;
        for i in 0..10_000 {
            if p.sample(&format!("compute-{i}"), SpanClass::Compute) == SampleDecision::Keep {
                kept += 1;
            }
        }
        // 0.1% of 10k = 10; allow generous tolerance.
        assert!(kept < 50);
    }

    #[test]
    fn determinism_same_trace_same_decision() {
        let p = TraceSamplingPolicy::canonical();
        let a = p.sample("abc", SpanClass::Tool);
        let b = p.sample("abc", SpanClass::Tool);
        assert_eq!(a, b);
    }

    #[test]
    fn ppm_out_of_range_rejected() {
        let mut p = TraceSamplingPolicy::canonical();
        p.llm_ppm = 2_000_000;
        assert!(matches!(
            p.validate().unwrap_err(),
            SamplingError::PpmOutOfRange(SpanClass::Llm, 2_000_000)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TraceSamplingPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            SamplingError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&SpanClass::DecisionDenial).unwrap(),
            "\"decision-denial\""
        );
        assert_eq!(
            serde_json::to_string(&SpanClass::CanaryTrip).unwrap(),
            "\"canary-trip\""
        );
    }

    #[test]
    fn zero_ppm_drops_unless_force_kept() {
        let mut p = TraceSamplingPolicy::canonical();
        p.tool_ppm = 0;
        for i in 0..50 {
            assert_eq!(
                p.sample(&format!("t{i}"), SpanClass::Tool),
                SampleDecision::Drop
            );
        }
    }

    #[test]
    fn full_ppm_always_keeps() {
        let mut p = TraceSamplingPolicy::canonical();
        p.tool_ppm = 1_000_000;
        for i in 0..50 {
            assert_eq!(
                p.sample(&format!("t{i}"), SpanClass::Tool),
                SampleDecision::Keep
            );
        }
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = TraceSamplingPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: TraceSamplingPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
