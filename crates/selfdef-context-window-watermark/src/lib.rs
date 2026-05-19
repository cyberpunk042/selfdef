//! `selfdef-context-window-watermark` — 4-zone context watermark.
//!
//! used/total → zone in {Cool, Warm, Hot, Critical} with per-zone
//! threshold percentages and a recommended Action {Continue,
//! SoftWarn, Compact, EmergencyCompact}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Watermark zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Zone {
    /// Plenty of headroom.
    Cool,
    /// Comfortable.
    Warm,
    /// Approaching limit.
    Hot,
    /// At/over limit.
    Critical,
}

/// Recommended action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Nothing to do.
    Continue,
    /// Show a soft warning to operator.
    SoftWarn,
    /// Compact now.
    Compact,
    /// Emergency compaction.
    EmergencyCompact,
}

/// Snapshot of context.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextSnapshot {
    /// Tokens consumed.
    pub used_tokens: u64,
    /// Total budget.
    pub total_tokens: u64,
}

/// Decision returned.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatermarkDecision {
    /// Zone.
    pub zone: Zone,
    /// Recommended action.
    pub action: Action,
    /// Percent used (0..=100, integer).
    pub used_pct: u8,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextWindowWatermark {
    /// Schema version.
    pub schema_version: String,
    /// Pct where Cool ends and Warm begins.
    pub cool_max_pct: u8,
    /// Pct where Warm ends and Hot begins.
    pub warm_max_pct: u8,
    /// Pct where Hot ends and Critical begins.
    pub hot_max_pct: u8,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WatermarkError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Out-of-order thresholds.
    #[error("thresholds out of order: cool {cool} warm {warm} hot {hot}")]
    BadOrder {
        /// cool.
        cool: u8,
        /// warm.
        warm: u8,
        /// hot.
        hot: u8,
    },
    /// total_tokens zero.
    #[error("total_tokens is zero")]
    TotalZero,
}

impl ContextWindowWatermark {
    /// Canonical: 50/75/90 → Cool/Warm/Hot/Critical.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cool_max_pct: 50,
            warm_max_pct: 75,
            hot_max_pct: 90,
        }
    }

    /// Compute decision.
    pub fn decide(&self, snap: ContextSnapshot) -> Result<WatermarkDecision, WatermarkError> {
        if snap.total_tokens == 0 {
            return Err(WatermarkError::TotalZero);
        }
        let used_pct = ((snap.used_tokens.min(snap.total_tokens) * 100) / snap.total_tokens) as u8;
        let zone = if used_pct < self.cool_max_pct {
            Zone::Cool
        } else if used_pct < self.warm_max_pct {
            Zone::Warm
        } else if used_pct < self.hot_max_pct {
            Zone::Hot
        } else {
            Zone::Critical
        };
        let action = match zone {
            Zone::Cool => Action::Continue,
            Zone::Warm => Action::SoftWarn,
            Zone::Hot => Action::Compact,
            Zone::Critical => Action::EmergencyCompact,
        };
        Ok(WatermarkDecision { zone, action, used_pct })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WatermarkError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WatermarkError::SchemaMismatch);
        }
        if !(self.cool_max_pct < self.warm_max_pct && self.warm_max_pct < self.hot_max_pct && self.hot_max_pct <= 100) {
            return Err(WatermarkError::BadOrder {
                cool: self.cool_max_pct,
                warm: self.warm_max_pct,
                hot: self.hot_max_pct,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(used: u64, total: u64) -> ContextSnapshot {
        ContextSnapshot { used_tokens: used, total_tokens: total }
    }

    #[test]
    fn cool_continue() {
        let p = ContextWindowWatermark::canonical();
        let d = p.decide(snap(20, 100)).unwrap();
        assert_eq!(d.zone, Zone::Cool);
        assert_eq!(d.action, Action::Continue);
        assert_eq!(d.used_pct, 20);
    }

    #[test]
    fn warm_soft_warn() {
        let p = ContextWindowWatermark::canonical();
        let d = p.decide(snap(60, 100)).unwrap();
        assert_eq!(d.zone, Zone::Warm);
        assert_eq!(d.action, Action::SoftWarn);
    }

    #[test]
    fn hot_compact() {
        let p = ContextWindowWatermark::canonical();
        let d = p.decide(snap(80, 100)).unwrap();
        assert_eq!(d.zone, Zone::Hot);
        assert_eq!(d.action, Action::Compact);
    }

    #[test]
    fn critical_emergency() {
        let p = ContextWindowWatermark::canonical();
        let d = p.decide(snap(95, 100)).unwrap();
        assert_eq!(d.zone, Zone::Critical);
        assert_eq!(d.action, Action::EmergencyCompact);
    }

    #[test]
    fn boundary_at_threshold_belongs_to_next_zone() {
        let p = ContextWindowWatermark::canonical();
        // At 50% → Warm (cool < 50).
        let d = p.decide(snap(50, 100)).unwrap();
        assert_eq!(d.zone, Zone::Warm);
    }

    #[test]
    fn used_caps_at_total() {
        let p = ContextWindowWatermark::canonical();
        let d = p.decide(snap(200, 100)).unwrap();
        assert_eq!(d.used_pct, 100);
        assert_eq!(d.zone, Zone::Critical);
    }

    #[test]
    fn total_zero_rejected() {
        let p = ContextWindowWatermark::canonical();
        assert!(matches!(p.decide(snap(0, 0)).unwrap_err(), WatermarkError::TotalZero));
    }

    #[test]
    fn out_of_order_thresholds_rejected() {
        let mut p = ContextWindowWatermark::canonical();
        p.warm_max_pct = 30;
        assert!(matches!(p.validate().unwrap_err(), WatermarkError::BadOrder { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ContextWindowWatermark::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), WatermarkError::SchemaMismatch));
    }

    #[test]
    fn action_serde_kebab() {
        assert_eq!(serde_json::to_string(&Action::EmergencyCompact).unwrap(), "\"emergency-compact\"");
    }

    #[test]
    fn zone_serde_kebab() {
        assert_eq!(serde_json::to_string(&Zone::Critical).unwrap(), "\"critical\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = ContextWindowWatermark::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: ContextWindowWatermark = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
