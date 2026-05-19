//! `selfdef-promotion-throttle` — per-subject sliding-window cap.
//!
//! Tracks promotion epoch-ms timestamps per subject; refuses any new
//! promotion if `count_in_window` ≥ ceiling. Demotions never use this
//! tracker (operator can demote freely).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Throttle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionThrottle {
    /// Schema version.
    pub schema_version: String,
    /// Window in milliseconds.
    pub window_ms: u64,
    /// Ceiling per window.
    pub ceiling: u32,
    /// Per-subject epoch-ms timestamps.
    pub timestamps: HashMap<String, Vec<u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ThrottleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Window 0.
    #[error("window_ms zero")]
    ZeroWindow,
    /// Ceiling 0.
    #[error("ceiling zero")]
    ZeroCeiling,
    /// Subject empty.
    #[error("subject empty")]
    EmptySubject,
    /// Throttled.
    #[error("subject {subject} throttled: {count} promotions in window {window_ms}ms >= ceiling {ceiling}")]
    Throttled {
        /// subject.
        subject: String,
        /// count.
        count: u32,
        /// window.
        window_ms: u64,
        /// ceiling.
        ceiling: u32,
    },
}

impl PromotionThrottle {
    /// New with `window_ms` + `ceiling`.
    pub fn new(window_ms: u64, ceiling: u32) -> Result<Self, ThrottleError> {
        if window_ms == 0 { return Err(ThrottleError::ZeroWindow); }
        if ceiling == 0 { return Err(ThrottleError::ZeroCeiling); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            ceiling,
            timestamps: HashMap::new(),
        })
    }

    /// Try to record a promotion.
    pub fn try_promote(&mut self, subject: &str, now_ms: u64) -> Result<(), ThrottleError> {
        if subject.is_empty() { return Err(ThrottleError::EmptySubject); }
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let entry = self.timestamps.entry(subject.into()).or_default();
        entry.retain(|t| *t >= cutoff);
        if entry.len() as u32 >= self.ceiling {
            let count = entry.len() as u32;
            return Err(ThrottleError::Throttled {
                subject: subject.into(),
                count,
                window_ms: self.window_ms,
                ceiling: self.ceiling,
            });
        }
        entry.push(now_ms);
        Ok(())
    }

    /// Count promotions in window for subject (also prunes).
    pub fn count(&mut self, subject: &str, now_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let entry = match self.timestamps.get_mut(subject) {
            Some(e) => e,
            None => return 0,
        };
        entry.retain(|t| *t >= cutoff);
        let n = entry.len() as u32;
        if n == 0 {
            self.timestamps.remove(subject);
        }
        n
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ThrottleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ThrottleError::SchemaMismatch);
        }
        if self.window_ms == 0 { return Err(ThrottleError::ZeroWindow); }
        if self.ceiling == 0 { return Err(ThrottleError::ZeroCeiling); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_zero_window_rejected() {
        assert!(matches!(PromotionThrottle::new(0, 1).unwrap_err(), ThrottleError::ZeroWindow));
    }

    #[test]
    fn new_with_zero_ceiling_rejected() {
        assert!(matches!(PromotionThrottle::new(1000, 0).unwrap_err(), ThrottleError::ZeroCeiling));
    }

    #[test]
    fn first_promotion_ok() {
        let mut t = PromotionThrottle::new(3_600_000, 1).unwrap();
        t.try_promote("alice", 1_000).unwrap();
    }

    #[test]
    fn second_within_window_blocked() {
        let mut t = PromotionThrottle::new(3_600_000, 1).unwrap();
        t.try_promote("alice", 1_000).unwrap();
        assert!(matches!(t.try_promote("alice", 100_000).unwrap_err(), ThrottleError::Throttled { .. }));
    }

    #[test]
    fn second_after_window_ok() {
        let mut t = PromotionThrottle::new(1000, 1).unwrap();
        t.try_promote("alice", 1_000).unwrap();
        t.try_promote("alice", 5_000).unwrap();
    }

    #[test]
    fn ceiling_higher_allows_n() {
        let mut t = PromotionThrottle::new(1_000_000, 3).unwrap();
        t.try_promote("alice", 1).unwrap();
        t.try_promote("alice", 2).unwrap();
        t.try_promote("alice", 3).unwrap();
        assert!(matches!(t.try_promote("alice", 4).unwrap_err(), ThrottleError::Throttled { .. }));
    }

    #[test]
    fn distinct_subjects_independent() {
        let mut t = PromotionThrottle::new(1_000_000, 1).unwrap();
        t.try_promote("alice", 1).unwrap();
        t.try_promote("bob", 1).unwrap();
    }

    #[test]
    fn count_prunes_old() {
        let mut t = PromotionThrottle::new(1000, 5).unwrap();
        t.try_promote("alice", 1_000).unwrap();
        // 5_000 ms later — past window.
        assert_eq!(t.count("alice", 5_000), 0);
    }

    #[test]
    fn empty_subject_rejected() {
        let mut t = PromotionThrottle::new(1000, 1).unwrap();
        assert!(matches!(t.try_promote("", 0).unwrap_err(), ThrottleError::EmptySubject));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = PromotionThrottle::new(1000, 1).unwrap();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), ThrottleError::SchemaMismatch));
    }

    #[test]
    fn throttle_serde_roundtrip() {
        let mut t = PromotionThrottle::new(1000, 1).unwrap();
        t.try_promote("alice", 1).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: PromotionThrottle = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
