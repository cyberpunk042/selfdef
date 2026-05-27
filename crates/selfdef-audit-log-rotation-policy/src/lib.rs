//! `selfdef-audit-log-rotation-policy` — rotate-decision authority.
//!
//! decide(stats) returns RotateReason iff any of size/age/lines
//! threshold exceeded; first-cause wins for the reason field. Pure
//! decision — file ops live in the worker.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Observed log stats.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogStats {
    /// Current size in bytes.
    pub size_bytes: u64,
    /// Age in seconds.
    pub age_seconds: u64,
    /// Line count.
    pub line_count: u64,
}

/// Rotate decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RotateReason {
    /// Size exceeded.
    Size {
        /// observed.
        observed: u64,
        /// max.
        max: u64,
    },
    /// Age exceeded.
    Age {
        /// observed.
        observed: u64,
        /// max.
        max: u64,
    },
    /// Lines exceeded.
    Lines {
        /// observed.
        observed: u64,
        /// max.
        max: u64,
    },
}

/// Policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogRotationPolicy {
    /// Max size bytes.
    pub max_size_bytes: u64,
    /// Max age seconds.
    pub max_age_seconds: u64,
    /// Max lines.
    pub max_lines: u64,
}

/// Envelope (for schema versioning).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogRotation {
    /// Schema version.
    pub schema_version: String,
    /// Thresholds.
    pub policy: AuditLogRotationPolicy,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Threshold zero.
    #[error("threshold {0} is zero")]
    ThresholdZero(&'static str),
}

impl AuditLogRotation {
    /// Canonical: 64 MiB / 24 h / 1M lines.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            policy: AuditLogRotationPolicy {
                max_size_bytes: 64 * 1024 * 1024,
                max_age_seconds: 24 * 3600,
                max_lines: 1_000_000,
            },
        }
    }

    /// Decide. Order: Size > Age > Lines for the reason reported.
    pub fn decide(&self, s: LogStats) -> Option<RotateReason> {
        if s.size_bytes > self.policy.max_size_bytes {
            return Some(RotateReason::Size {
                observed: s.size_bytes,
                max: self.policy.max_size_bytes,
            });
        }
        if s.age_seconds > self.policy.max_age_seconds {
            return Some(RotateReason::Age {
                observed: s.age_seconds,
                max: self.policy.max_age_seconds,
            });
        }
        if s.line_count > self.policy.max_lines {
            return Some(RotateReason::Lines {
                observed: s.line_count,
                max: self.policy.max_lines,
            });
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RotationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RotationError::SchemaMismatch);
        }
        if self.policy.max_size_bytes == 0 {
            return Err(RotationError::ThresholdZero("max_size_bytes"));
        }
        if self.policy.max_age_seconds == 0 {
            return Err(RotationError::ThresholdZero("max_age_seconds"));
        }
        if self.policy.max_lines == 0 {
            return Err(RotationError::ThresholdZero("max_lines"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(s: u64, a: u64, l: u64) -> LogStats {
        LogStats {
            size_bytes: s,
            age_seconds: a,
            line_count: l,
        }
    }

    #[test]
    fn under_thresholds_no_rotate() {
        let p = AuditLogRotation::canonical();
        assert!(p.decide(stats(1024, 60, 100)).is_none());
    }

    #[test]
    fn size_triggers_first() {
        let p = AuditLogRotation::canonical();
        let s = stats(
            p.policy.max_size_bytes + 1,
            p.policy.max_age_seconds + 1,
            p.policy.max_lines + 1,
        );
        match p.decide(s).unwrap() {
            RotateReason::Size { .. } => {}
            _ => panic!("Size should win"),
        }
    }

    #[test]
    fn age_triggers_when_only_age() {
        let p = AuditLogRotation::canonical();
        let s = stats(100, p.policy.max_age_seconds + 10, 100);
        match p.decide(s).unwrap() {
            RotateReason::Age { observed, .. } => assert!(observed > p.policy.max_age_seconds),
            _ => panic!(),
        }
    }

    #[test]
    fn lines_triggers_when_only_lines() {
        let p = AuditLogRotation::canonical();
        let s = stats(100, 60, p.policy.max_lines + 1);
        match p.decide(s).unwrap() {
            RotateReason::Lines { .. } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn equal_to_threshold_no_rotate() {
        let p = AuditLogRotation::canonical();
        let s = stats(
            p.policy.max_size_bytes,
            p.policy.max_age_seconds,
            p.policy.max_lines,
        );
        assert!(p.decide(s).is_none());
    }

    #[test]
    fn threshold_zero_rejected() {
        let mut p = AuditLogRotation::canonical();
        p.policy.max_size_bytes = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            RotationError::ThresholdZero("max_size_bytes")
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = AuditLogRotation::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RotationError::SchemaMismatch
        ));
    }

    #[test]
    fn reason_serde_kebab() {
        let r = RotateReason::Size {
            observed: 1,
            max: 0,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"kind\":\"size\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = AuditLogRotation::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: AuditLogRotation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
