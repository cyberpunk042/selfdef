//! `selfdef-bundle-replay-window` — replay-against-version window.
//!
//! decide(recorded_version_unix, current_version_unix, allow_self)
//! returns Allow / OutOfWindow / IdentityRequiredButDiffer.
//! Exact-version match always allowed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleReplayWindow {
    /// Schema version.
    pub schema_version: String,
    /// Max age delta in seconds between recorded and current version.
    pub max_age_seconds: u64,
    /// When true, ONLY exact-version replay is allowed (no window).
    pub require_exact: bool,
}

/// Decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReplayDecision {
    /// Allowed.
    Allow,
    /// Beyond window.
    OutOfWindow {
        /// recorded.
        recorded: u64,
        /// current.
        current: u64,
        /// delta seconds.
        delta_seconds: u64,
        /// cap.
        cap_seconds: u64,
    },
    /// require_exact: but versions differ.
    IdentityRequiredButDiffer {
        /// recorded.
        recorded: u64,
        /// current.
        current: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum WindowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_age zero (only valid when require_exact).
    #[error("max_age_seconds zero requires require_exact=true")]
    MaxAgeZeroNotExact,
}

impl BundleReplayWindow {
    /// Canonical: 30-day window, identity not required.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_age_seconds: 30 * 86_400,
            require_exact: false,
        }
    }

    /// Identity-only mode.
    pub fn identity_only() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_age_seconds: 0,
            require_exact: true,
        }
    }

    /// Decide.
    pub fn decide(&self, recorded_version_unix: u64, current_version_unix: u64) -> ReplayDecision {
        if recorded_version_unix == current_version_unix {
            return ReplayDecision::Allow;
        }
        if self.require_exact {
            return ReplayDecision::IdentityRequiredButDiffer {
                recorded: recorded_version_unix,
                current: current_version_unix,
            };
        }
        let delta = recorded_version_unix.abs_diff(current_version_unix);
        if delta <= self.max_age_seconds {
            ReplayDecision::Allow
        } else {
            ReplayDecision::OutOfWindow {
                recorded: recorded_version_unix,
                current: current_version_unix,
                delta_seconds: delta,
                cap_seconds: self.max_age_seconds,
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WindowError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WindowError::SchemaMismatch);
        }
        if self.max_age_seconds == 0 && !self.require_exact {
            return Err(WindowError::MaxAgeZeroNotExact);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        BundleReplayWindow::canonical().validate().unwrap();
    }

    #[test]
    fn identity_validates() {
        BundleReplayWindow::identity_only().validate().unwrap();
    }

    #[test]
    fn same_version_allow() {
        let w = BundleReplayWindow::canonical();
        assert!(matches!(w.decide(1000, 1000), ReplayDecision::Allow));
    }

    #[test]
    fn within_window_allow() {
        let w = BundleReplayWindow::canonical();
        // 1 day within 30 day window.
        assert!(matches!(
            w.decide(1000, 1000 + 86400),
            ReplayDecision::Allow
        ));
    }

    #[test]
    fn outside_window_rejected() {
        let w = BundleReplayWindow::canonical();
        let recorded = 1_000;
        let current = recorded + 100 * 86400;
        match w.decide(recorded, current) {
            ReplayDecision::OutOfWindow { delta_seconds, .. } => {
                assert!(delta_seconds > 30 * 86400)
            }
            _ => panic!(),
        }
    }

    #[test]
    fn identity_only_rejects_drift() {
        let w = BundleReplayWindow::identity_only();
        assert!(matches!(
            w.decide(100, 101),
            ReplayDecision::IdentityRequiredButDiffer { .. }
        ));
    }

    #[test]
    fn identity_only_allows_exact() {
        let w = BundleReplayWindow::identity_only();
        assert!(matches!(w.decide(100, 100), ReplayDecision::Allow));
    }

    #[test]
    fn backward_delta_also_capped() {
        let w = BundleReplayWindow::canonical();
        // recorded > current by huge delta.
        let recorded = 100 * 86400;
        let current = 0;
        assert!(matches!(
            w.decide(recorded, current),
            ReplayDecision::OutOfWindow { .. }
        ));
    }

    #[test]
    fn max_age_zero_without_exact_rejected() {
        let mut w = BundleReplayWindow::canonical();
        w.max_age_seconds = 0;
        assert!(matches!(
            w.validate().unwrap_err(),
            WindowError::MaxAgeZeroNotExact
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = BundleReplayWindow::canonical();
        w.schema_version = "9.9.9".into();
        assert!(matches!(
            w.validate().unwrap_err(),
            WindowError::SchemaMismatch
        ));
    }

    #[test]
    fn decision_serde_kebab() {
        let d = ReplayDecision::Allow;
        assert!(
            serde_json::to_string(&d)
                .unwrap()
                .contains("\"kind\":\"allow\"")
        );
    }

    #[test]
    fn window_serde_roundtrip() {
        let w = BundleReplayWindow::canonical();
        let j = serde_json::to_string(&w).unwrap();
        let back: BundleReplayWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
