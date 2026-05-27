//! `selfdef-exponential-backoff` — deterministic backoff.
//!
//! Policy{base_ms, multiplier_bp (10000 = 1×), max_ms,
//! jitter_pct_bp}. compute(attempt, seed) returns delay_ms:
//! min(max_ms, base_ms × multiplier_bp^attempt / 10000^attempt)
//! ± jitter where jitter is FNV-1a-64(seed, attempt) % jitter_pct.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

fn fnv1a_64_with_seed(bytes: &[u8], seed: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325 ^ seed;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExponentialBackoff {
    /// Schema version marker.
    pub schema_version_marker: u32,
    /// Base delay (ms).
    pub base_ms: u64,
    /// Multiplier in basis points (10000 = 1×).
    pub multiplier_bp: u32,
    /// Max delay (ms).
    pub max_ms: u64,
    /// Jitter as percentage in basis points (e.g. 1000 = 10% jitter).
    pub jitter_pct_bp: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BackoffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero base.
    #[error("base_ms must be > 0")]
    ZeroBase,
    /// Multiplier < 10000 (< 1×).
    #[error("multiplier_bp must be >= 10000")]
    SubLinearMultiplier,
}

impl ExponentialBackoff {
    /// New.
    pub fn new(
        base_ms: u64,
        multiplier_bp: u32,
        max_ms: u64,
        jitter_pct_bp: u32,
    ) -> Result<Self, BackoffError> {
        if base_ms == 0 {
            return Err(BackoffError::ZeroBase);
        }
        if multiplier_bp < 10000 {
            return Err(BackoffError::SubLinearMultiplier);
        }
        Ok(Self {
            schema_version_marker: 1,
            base_ms,
            multiplier_bp,
            max_ms,
            jitter_pct_bp,
        })
    }

    /// Compute delay for attempt (0-based).
    pub fn compute(&self, attempt: u32, seed: u64) -> u64 {
        // delay = base × (multiplier/10000)^attempt
        // Integer-safe: iteratively multiply by multiplier_bp and divide by 10000.
        let mut delay = self.base_ms;
        for _ in 0..attempt {
            delay = delay.saturating_mul(self.multiplier_bp as u64) / 10000;
            if delay >= self.max_ms {
                delay = self.max_ms;
                break;
            }
        }
        delay = delay.min(self.max_ms);
        if self.jitter_pct_bp > 0 {
            // Jitter ± jitter_pct_bp / 10000 of delay.
            let max_jitter = delay.saturating_mul(self.jitter_pct_bp as u64) / 10000;
            if max_jitter > 0 {
                let h = fnv1a_64_with_seed(&attempt.to_le_bytes(), seed);
                let signed_jitter = (h % (2 * max_jitter + 1)) as i64 - max_jitter as i64;
                if signed_jitter >= 0 {
                    delay = delay.saturating_add(signed_jitter as u64).min(self.max_ms);
                } else {
                    delay = delay.saturating_sub((-signed_jitter) as u64);
                }
            }
        }
        delay
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BackoffError> {
        if self.schema_version_marker != 1 {
            return Err(BackoffError::SchemaMismatch);
        }
        if self.base_ms == 0 {
            return Err(BackoffError::ZeroBase);
        }
        if self.multiplier_bp < 10000 {
            return Err(BackoffError::SubLinearMultiplier);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_is_base() {
        let b = ExponentialBackoff::new(100, 20000, 10_000, 0).unwrap();
        assert_eq!(b.compute(0, 0), 100);
    }

    #[test]
    fn doubling() {
        let b = ExponentialBackoff::new(100, 20000, 100_000, 0).unwrap();
        // 0:100, 1:200, 2:400, 3:800, 4:1600.
        assert_eq!(b.compute(1, 0), 200);
        assert_eq!(b.compute(2, 0), 400);
        assert_eq!(b.compute(3, 0), 800);
        assert_eq!(b.compute(4, 0), 1600);
    }

    #[test]
    fn capped_at_max() {
        let b = ExponentialBackoff::new(100, 20000, 1000, 0).unwrap();
        assert_eq!(b.compute(20, 0), 1000);
    }

    #[test]
    fn jitter_changes_result() {
        let b = ExponentialBackoff::new(1000, 10000, 1_000_000, 5000).unwrap();
        let a = b.compute(0, 1);
        let c = b.compute(0, 2);
        // Different seeds → different jitter.
        assert!(a != c || (a == c && a == 1000));
    }

    #[test]
    fn jitter_deterministic() {
        let b = ExponentialBackoff::new(1000, 10000, 1_000_000, 5000).unwrap();
        assert_eq!(b.compute(0, 42), b.compute(0, 42));
    }

    #[test]
    fn zero_base_rejected() {
        assert!(matches!(
            ExponentialBackoff::new(0, 20000, 100, 0).unwrap_err(),
            BackoffError::ZeroBase
        ));
    }

    #[test]
    fn sublinear_multiplier_rejected() {
        assert!(matches!(
            ExponentialBackoff::new(100, 5000, 100, 0).unwrap_err(),
            BackoffError::SubLinearMultiplier
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ExponentialBackoff::new(100, 20000, 1000, 0).unwrap();
        b.schema_version_marker = 99;
        assert!(matches!(
            b.validate().unwrap_err(),
            BackoffError::SchemaMismatch
        ));
    }

    #[test]
    fn backoff_serde_roundtrip() {
        let b = ExponentialBackoff::new(100, 20000, 10000, 1000).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: ExponentialBackoff = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
