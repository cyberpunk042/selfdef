//! `selfdef-retry-policy` — per-class retry authority.
//!
//! Per FailureClass, declares max_attempts + base_delay_ms +
//! multiplier + max_delay_ms + jitter_pct. should_retry(class,
//! attempt, seed) returns Some(delay_ms) when retry permitted, None
//! when exhausted or class is Permanent.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    /// Transient (network blip, 5xx).
    Transient,
    /// Throttled (429, rate limit).
    Throttled,
    /// Auth (401/403, key issue).
    Auth,
    /// Permanent (400, NotFound, programming error).
    Permanent,
}

/// Per-class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ClassRetry {
    /// Max attempts (including first try).
    pub max_attempts: u32,
    /// Base delay.
    pub base_delay_ms: u32,
    /// Multiplier (1.5x..3.0x typical).
    pub multiplier: f32,
    /// Max delay cap.
    pub max_delay_ms: u32,
    /// Jitter % [0..=100] applied to the computed delay.
    pub jitter_pct: u8,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryPolicy {
    /// Schema version.
    pub schema_version: String,
    /// transient.
    pub transient: ClassRetry,
    /// throttled.
    pub throttled: ClassRetry,
    /// auth.
    pub auth: ClassRetry,
    /// permanent.
    pub permanent: ClassRetry,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RetryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad config.
    #[error("class {0:?} multiplier {1} < 1.0 or NaN")]
    BadMultiplier(FailureClass, f32),
    /// Bad jitter.
    #[error("class {0:?} jitter_pct {1} > 100")]
    BadJitter(FailureClass, u8),
}

impl RetryPolicy {
    /// Canonical:
    /// * Transient: 5 attempts, 200ms base, 2.0×, max 30s, 25% jitter
    /// * Throttled: 4 attempts, 1000ms base, 2.0×, max 60s, 50% jitter
    /// * Auth: 2 attempts (one retry after refresh), 500ms, 2.0×, max 5s, 10%
    /// * Permanent: 1 attempt (no retry).
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            transient: ClassRetry { max_attempts: 5, base_delay_ms: 200, multiplier: 2.0, max_delay_ms: 30_000, jitter_pct: 25 },
            throttled: ClassRetry { max_attempts: 4, base_delay_ms: 1_000, multiplier: 2.0, max_delay_ms: 60_000, jitter_pct: 50 },
            auth: ClassRetry { max_attempts: 2, base_delay_ms: 500, multiplier: 2.0, max_delay_ms: 5_000, jitter_pct: 10 },
            permanent: ClassRetry { max_attempts: 1, base_delay_ms: 0, multiplier: 1.0, max_delay_ms: 0, jitter_pct: 0 },
        }
    }

    /// Class config.
    pub fn class(&self, c: FailureClass) -> ClassRetry {
        match c {
            FailureClass::Transient => self.transient,
            FailureClass::Throttled => self.throttled,
            FailureClass::Auth => self.auth,
            FailureClass::Permanent => self.permanent,
        }
    }

    /// Decide. attempt is 1-based (1=first try, 2=first retry).
    /// `seed` provides deterministic jitter (e.g., fnv1a of trace_id).
    pub fn should_retry(&self, class: FailureClass, attempt: u32, seed: u64) -> Option<u32> {
        let cfg = self.class(class);
        if attempt >= cfg.max_attempts || cfg.max_attempts <= 1 {
            return None;
        }
        // Compute delay = base * multiplier^(attempt-1), capped, with jitter.
        let exp = (attempt - 1) as i32;
        let mult = (cfg.multiplier as f64).powi(exp);
        let base = (cfg.base_delay_ms as f64) * mult;
        let capped = base.min(cfg.max_delay_ms as f64);
        let jitter_amount = capped * (cfg.jitter_pct as f64 / 100.0);
        // Deterministic jitter in [-jitter_amount, +jitter_amount].
        let mix = ((seed.wrapping_mul(0x9E3779B97F4A7C15) >> 32) as u32 as f64) / (u32::MAX as f64);
        let signed = (mix * 2.0 - 1.0) * jitter_amount;
        let with_jitter = (capped + signed).max(0.0);
        Some(with_jitter.min(cfg.max_delay_ms as f64) as u32)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RetryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RetryError::SchemaMismatch);
        }
        for (c, cfg) in [
            (FailureClass::Transient, self.transient),
            (FailureClass::Throttled, self.throttled),
            (FailureClass::Auth, self.auth),
            (FailureClass::Permanent, self.permanent),
        ] {
            if cfg.multiplier.is_nan() || cfg.multiplier < 1.0 {
                return Err(RetryError::BadMultiplier(c, cfg.multiplier));
            }
            if cfg.jitter_pct > 100 {
                return Err(RetryError::BadJitter(c, cfg.jitter_pct));
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
        RetryPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn permanent_never_retries() {
        let p = RetryPolicy::canonical();
        for attempt in 1..10 {
            assert!(p.should_retry(FailureClass::Permanent, attempt, 42).is_none());
        }
    }

    #[test]
    fn transient_retries_within_max() {
        let p = RetryPolicy::canonical();
        // max_attempts=5, attempt 1..4 should retry, attempt 5 stops.
        assert!(p.should_retry(FailureClass::Transient, 1, 42).is_some());
        assert!(p.should_retry(FailureClass::Transient, 4, 42).is_some());
        assert!(p.should_retry(FailureClass::Transient, 5, 42).is_none());
    }

    #[test]
    fn delay_grows_with_attempt() {
        let mut p = RetryPolicy::canonical();
        p.transient.jitter_pct = 0;
        let d1 = p.should_retry(FailureClass::Transient, 1, 0).unwrap();
        let d2 = p.should_retry(FailureClass::Transient, 2, 0).unwrap();
        let d3 = p.should_retry(FailureClass::Transient, 3, 0).unwrap();
        assert!(d2 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn delay_caps_at_max() {
        let mut p = RetryPolicy::canonical();
        p.transient.jitter_pct = 0;
        // attempt 20 would explode without cap.
        let d = p.should_retry(FailureClass::Transient, 4, 0).unwrap();
        assert!(d <= p.transient.max_delay_ms);
    }

    #[test]
    fn jitter_deterministic_per_seed() {
        let p = RetryPolicy::canonical();
        let a = p.should_retry(FailureClass::Throttled, 2, 0xdeadbeef).unwrap();
        let b = p.should_retry(FailureClass::Throttled, 2, 0xdeadbeef).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn auth_retries_once() {
        let p = RetryPolicy::canonical();
        // max=2, attempt 1 retries, attempt 2 stops.
        assert!(p.should_retry(FailureClass::Auth, 1, 0).is_some());
        assert!(p.should_retry(FailureClass::Auth, 2, 0).is_none());
    }

    #[test]
    fn bad_multiplier_rejected() {
        let mut p = RetryPolicy::canonical();
        p.transient.multiplier = 0.5;
        assert!(matches!(p.validate().unwrap_err(), RetryError::BadMultiplier(_, _)));
    }

    #[test]
    fn bad_jitter_rejected() {
        let mut p = RetryPolicy::canonical();
        p.throttled.jitter_pct = 150;
        assert!(matches!(p.validate().unwrap_err(), RetryError::BadJitter(_, _)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RetryPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), RetryError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&FailureClass::Throttled).unwrap(), "\"throttled\"");
        assert_eq!(serde_json::to_string(&FailureClass::Permanent).unwrap(), "\"permanent\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = RetryPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: RetryPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
