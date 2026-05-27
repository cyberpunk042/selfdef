//! `selfdef-time-window-policy` — wall-clock IPS gating.
//!
//! Restricts when high-risk operation classes are allowed by weekday
//! and hour-of-day. Designed so the operator can say "no autonomous
//! changes between 22:00 and 07:00, and never on Sunday." Per-class
//! windows; outside the window the gate denies regardless of profile.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Weekday (ISO: Mon=1..Sun=7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Weekday {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

/// Operation class subject to time-window gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationClass {
    /// Autonomous changes (no human in the loop).
    AutonomousChange,
    /// Bulk operations (mass updates).
    BulkOp,
    /// Production deployment.
    ProductionDeploy,
    /// Long-running task launch.
    LongTaskLaunch,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimeWindowDecision {
    /// Within the window.
    Allow,
    /// Outside the window.
    Deny,
}

/// One window: weekdays + start hour (inclusive) + end hour (exclusive).
/// Windows wrapping past midnight (start_hour > end_hour) are supported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    /// Operation this window applies to.
    pub op: OperationClass,
    /// Allowed weekdays.
    pub days: Vec<Weekday>,
    /// Start hour [0..24).
    pub start_hour: u8,
    /// End hour [0..=24] (24 means end-of-day).
    pub end_hour: u8,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeWindowPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Configured windows.
    pub windows: Vec<Window>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TimeWindowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty days.
    #[error("window for {0:?} has no days")]
    EmptyDays(OperationClass),
    /// Bad hours.
    #[error("window for {op:?} hours invalid: start {start} end {end}")]
    BadHours {
        /// op.
        op: OperationClass,
        /// start.
        start: u8,
        /// end.
        end: u8,
    },
    /// Duplicate window for same op.
    #[error("duplicate window for {0:?}")]
    DuplicateOp(OperationClass),
}

impl TimeWindowPolicy {
    /// New empty policy.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            windows: Vec::new(),
        }
    }

    /// Add a window.
    pub fn add(&mut self, w: Window) -> Result<(), TimeWindowError> {
        check_window(&w)?;
        if self.windows.iter().any(|x| x.op == w.op) {
            return Err(TimeWindowError::DuplicateOp(w.op));
        }
        self.windows.push(w);
        Ok(())
    }

    /// Decide for (op, weekday, hour). If no window matches the op,
    /// the policy defaults to Allow (operator hasn't opted into
    /// gating that class).
    pub fn decide(&self, op: OperationClass, day: Weekday, hour: u8) -> TimeWindowDecision {
        let w = match self.windows.iter().find(|w| w.op == op) {
            Some(w) => w,
            None => return TimeWindowDecision::Allow,
        };
        if !w.days.contains(&day) {
            return TimeWindowDecision::Deny;
        }
        if in_hour_range(w.start_hour, w.end_hour, hour) {
            TimeWindowDecision::Allow
        } else {
            TimeWindowDecision::Deny
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TimeWindowError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TimeWindowError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<OperationClass> = HashSet::new();
        for w in &self.windows {
            check_window(w)?;
            if !seen.insert(w.op) {
                return Err(TimeWindowError::DuplicateOp(w.op));
            }
        }
        Ok(())
    }
}

fn check_window(w: &Window) -> Result<(), TimeWindowError> {
    if w.days.is_empty() {
        return Err(TimeWindowError::EmptyDays(w.op));
    }
    if w.start_hour >= 24 || w.end_hour > 24 || w.start_hour == w.end_hour {
        return Err(TimeWindowError::BadHours {
            op: w.op,
            start: w.start_hour,
            end: w.end_hour,
        });
    }
    Ok(())
}

fn in_hour_range(start: u8, end: u8, h: u8) -> bool {
    if h >= 24 {
        return false;
    }
    if start < end {
        h >= start && h < end
    } else {
        // Wrap past midnight: e.g., 22..7 means 22, 23, 0..7.
        h >= start || h < end
    }
}

impl Default for TimeWindowPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OperationClass::*;
    use TimeWindowDecision::*;
    use Weekday::*;

    fn weekdays() -> Vec<Weekday> {
        vec![Mon, Tue, Wed, Thu, Fri]
    }

    #[test]
    fn empty_policy_allows_all() {
        let p = TimeWindowPolicy::new();
        assert_eq!(p.decide(AutonomousChange, Sun, 3), Allow);
    }

    #[test]
    fn within_window_allows() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 9,
            end_hour: 18,
        })
        .unwrap();
        assert_eq!(p.decide(AutonomousChange, Tue, 10), Allow);
    }

    #[test]
    fn outside_hours_denies() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 9,
            end_hour: 18,
        })
        .unwrap();
        assert_eq!(p.decide(AutonomousChange, Tue, 22), Deny);
        assert_eq!(p.decide(AutonomousChange, Tue, 5), Deny);
    }

    #[test]
    fn wrong_day_denies() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 0,
            end_hour: 24,
        })
        .unwrap();
        assert_eq!(p.decide(AutonomousChange, Sat, 10), Deny);
        assert_eq!(p.decide(AutonomousChange, Sun, 10), Deny);
    }

    #[test]
    fn wrap_past_midnight_window() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: ProductionDeploy,
            days: vec![Sat],
            start_hour: 22,
            end_hour: 5,
        })
        .unwrap();
        assert_eq!(p.decide(ProductionDeploy, Sat, 23), Allow);
        assert_eq!(p.decide(ProductionDeploy, Sat, 3), Allow);
        assert_eq!(p.decide(ProductionDeploy, Sat, 10), Deny);
    }

    #[test]
    fn bad_hours_rejected() {
        let mut p = TimeWindowPolicy::new();
        assert!(matches!(
            p.add(Window {
                op: AutonomousChange,
                days: weekdays(),
                start_hour: 30,
                end_hour: 5
            })
            .unwrap_err(),
            TimeWindowError::BadHours { .. }
        ));
        assert!(matches!(
            p.add(Window {
                op: BulkOp,
                days: weekdays(),
                start_hour: 9,
                end_hour: 9
            })
            .unwrap_err(),
            TimeWindowError::BadHours { .. }
        ));
    }

    #[test]
    fn empty_days_rejected() {
        let mut p = TimeWindowPolicy::new();
        assert!(matches!(
            p.add(Window {
                op: AutonomousChange,
                days: vec![],
                start_hour: 9,
                end_hour: 18
            })
            .unwrap_err(),
            TimeWindowError::EmptyDays(_)
        ));
    }

    #[test]
    fn duplicate_op_rejected() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 9,
            end_hour: 18,
        })
        .unwrap();
        assert!(matches!(
            p.add(Window {
                op: AutonomousChange,
                days: weekdays(),
                start_hour: 0,
                end_hour: 24
            })
            .unwrap_err(),
            TimeWindowError::DuplicateOp(_)
        ));
    }

    #[test]
    fn unconfigured_op_allows() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 9,
            end_hour: 18,
        })
        .unwrap();
        // BulkOp not configured → Allow.
        assert_eq!(p.decide(BulkOp, Sun, 3), Allow);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TimeWindowPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            TimeWindowError::SchemaMismatch
        ));
    }

    #[test]
    fn weekday_serde_kebab() {
        assert_eq!(serde_json::to_string(&Mon).unwrap(), "\"mon\"");
        assert_eq!(serde_json::to_string(&Sun).unwrap(), "\"sun\"");
    }

    #[test]
    fn op_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&AutonomousChange).unwrap(),
            "\"autonomous-change\""
        );
        assert_eq!(
            serde_json::to_string(&LongTaskLaunch).unwrap(),
            "\"long-task-launch\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = TimeWindowPolicy::new();
        p.add(Window {
            op: AutonomousChange,
            days: weekdays(),
            start_hour: 9,
            end_hour: 18,
        })
        .unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: TimeWindowPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
