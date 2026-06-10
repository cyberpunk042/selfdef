//! `selfdef-burn-rate-alert` — fast/slow burn-rate alerting.
//!
//! Two windows: fast (short, e.g., 5 min) and slow (long, e.g.,
//! 1 hr). Each tracks total + bad counts. evaluate() returns
//! Severity{None/Slow/Fast/Both}: Fast when fast burn ≥
//! fast_factor; Slow when slow burn ≥ slow_factor; Both when
//! both. Burn = bad_count / (total * slo_target).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Severity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// None.
    None,
    /// Slow only.
    Slow,
    /// Fast only.
    Fast,
    /// Both.
    Both,
}

/// Window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    /// Total events.
    pub total: u64,
    /// Bad events.
    pub bad: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BurnRateAlert {
    /// Schema version.
    pub schema_version: String,
    /// SLO target bad rate in basis points (e.g., 100 bp = 1% allowed bad).
    pub slo_bad_rate_bp: u32,
    /// Fast burn factor (e.g., 14.4x → 144 in tenths).
    pub fast_factor_tenths: u32,
    /// Slow burn factor.
    pub slow_factor_tenths: u32,
    /// Fast window.
    pub fast: Window,
    /// Slow window.
    pub slow: Window,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AlertError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad slo.
    #[error("slo_bad_rate_bp must be 1..=10000")]
    BadSloRate,
    /// Zero factor.
    #[error("factors must be >= 1 (in tenths)")]
    ZeroFactor,
}

impl BurnRateAlert {
    /// New.
    pub fn new(
        slo_bad_rate_bp: u32,
        fast_factor_tenths: u32,
        slow_factor_tenths: u32,
    ) -> Result<Self, AlertError> {
        if slo_bad_rate_bp == 0 || slo_bad_rate_bp > 10000 {
            return Err(AlertError::BadSloRate);
        }
        if fast_factor_tenths == 0 || slow_factor_tenths == 0 {
            return Err(AlertError::ZeroFactor);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            slo_bad_rate_bp,
            fast_factor_tenths,
            slow_factor_tenths,
            fast: Window { total: 0, bad: 0 },
            slow: Window { total: 0, bad: 0 },
        })
    }

    /// Set windows.
    pub fn set_windows(&mut self, fast: Window, slow: Window) {
        self.fast = fast;
        self.slow = slow;
    }

    /// Burn rate of a window in tenths-of-x (so burn=2.5x → 25).
    pub fn burn_tenths(&self, w: Window) -> u64 {
        if w.total == 0 {
            return 0;
        }
        // new()/validate() reject slo_bad_rate_bp==0, but serde deserialization
        // can set it directly; the `/ self.slo_bad_rate_bp` below would then
        // panic in every build (integer div-by-zero is never masked). A zero
        // SLO bad-rate tolerates no errors, so any observed bad is infinite
        // burn — report max (fail-CLOSED: trips the alert) rather than crash.
        if self.slo_bad_rate_bp == 0 {
            return u64::MAX;
        }
        // observed_bad_rate_bp = bad * 10000 / total
        let observed_bp = (w.bad as u128 * 10_000) / w.total as u128;
        // burn = observed / slo  → in tenths
        let burn_tenths = (observed_bp * 10) / self.slo_bad_rate_bp as u128;
        burn_tenths.min(u64::MAX as u128) as u64
    }

    /// Severity.
    pub fn evaluate(&self) -> Severity {
        let fast_b = self.burn_tenths(self.fast);
        let slow_b = self.burn_tenths(self.slow);
        let fast_hit = fast_b >= self.fast_factor_tenths as u64;
        let slow_hit = slow_b >= self.slow_factor_tenths as u64;
        match (fast_hit, slow_hit) {
            (true, true) => Severity::Both,
            (true, false) => Severity::Fast,
            (false, true) => Severity::Slow,
            (false, false) => Severity::None,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AlertError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AlertError::SchemaMismatch);
        }
        if self.slo_bad_rate_bp == 0 || self.slo_bad_rate_bp > 10000 {
            return Err(AlertError::BadSloRate);
        }
        if self.fast_factor_tenths == 0 || self.slow_factor_tenths == 0 {
            return Err(AlertError::ZeroFactor);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_slo_serde_bypass_does_not_panic() {
        // new()/validate() reject slo_bad_rate_bp==0, but serde can construct
        // it. `/ self.slo_bad_rate_bp` would panic in every build. Guard reports
        // max burn (fail-closed: trips the alert) instead of crashing.
        let a = BurnRateAlert {
            schema_version: SCHEMA_VERSION.into(),
            slo_bad_rate_bp: 0,
            fast_factor_tenths: 10,
            slow_factor_tenths: 10,
            fast: Window { total: 100, bad: 1 },
            slow: Window { total: 100, bad: 1 },
        };
        assert_eq!(a.burn_tenths(Window { total: 100, bad: 1 }), u64::MAX); // no panic
        // No-data window still returns 0 (no false alarm) even with zero SLO.
        assert_eq!(a.burn_tenths(Window { total: 0, bad: 0 }), 0);
    }

    #[test]
    fn no_traffic_is_none() {
        let a = BurnRateAlert::new(100, 144, 10).unwrap(); // 1% SLO, 14.4x fast, 1x slow
        assert_eq!(a.evaluate(), Severity::None);
    }

    #[test]
    fn under_slo_is_none() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.set_windows(
            Window {
                total: 1000,
                bad: 5,
            }, // 0.5% bad → 0.5x burn → 5 tenths
            Window {
                total: 10000,
                bad: 50,
            }, // 0.5% bad → 5 tenths
        );
        assert_eq!(a.evaluate(), Severity::None);
    }

    #[test]
    fn slow_only_alert() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.set_windows(
            Window {
                total: 1000,
                bad: 5,
            }, // 0.5x = 5 tenths < 14.4
            Window {
                total: 10000,
                bad: 200,
            }, // 2% bad = 2x → 20 tenths >= 10
        );
        assert_eq!(a.evaluate(), Severity::Slow);
    }

    #[test]
    fn fast_only_alert() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.set_windows(
            Window {
                total: 1000,
                bad: 200,
            }, // 20% bad = 20x → 200 tenths >= 144
            Window {
                total: 10000,
                bad: 50,
            }, // 0.5% = 5 tenths < 10
        );
        assert_eq!(a.evaluate(), Severity::Fast);
    }

    #[test]
    fn both_alert() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.set_windows(
            Window {
                total: 1000,
                bad: 200,
            }, // 200 tenths
            Window {
                total: 10000,
                bad: 500,
            }, // 5% = 5x → 50 tenths >= 10
        );
        assert_eq!(a.evaluate(), Severity::Both);
    }

    #[test]
    fn burn_zero_when_no_total() {
        let a = BurnRateAlert::new(100, 144, 10).unwrap();
        assert_eq!(a.burn_tenths(Window { total: 0, bad: 0 }), 0);
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(matches!(
            BurnRateAlert::new(0, 10, 10).unwrap_err(),
            AlertError::BadSloRate
        ));
        assert!(matches!(
            BurnRateAlert::new(10001, 10, 10).unwrap_err(),
            AlertError::BadSloRate
        ));
        assert!(matches!(
            BurnRateAlert::new(100, 0, 10).unwrap_err(),
            AlertError::ZeroFactor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.schema_version = "9.9.9".into();
        assert!(matches!(
            a.validate().unwrap_err(),
            AlertError::SchemaMismatch
        ));
    }

    #[test]
    fn alert_serde_roundtrip() {
        let mut a = BurnRateAlert::new(100, 144, 10).unwrap();
        a.set_windows(
            Window {
                total: 1000,
                bad: 10,
            },
            Window {
                total: 10000,
                bad: 100,
            },
        );
        let j = serde_json::to_string(&a).unwrap();
        let back: BurnRateAlert = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
