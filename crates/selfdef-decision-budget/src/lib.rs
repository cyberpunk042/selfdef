//! `selfdef-decision-budget` — per-(profile, action) budget.
//!
//! Operator defines `(daily, weekly, monthly)` caps for each
//! `(Profile, ActionClass)` tuple. Caller passes the observed counts;
//! the gate refuses if any cap is exhausted.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_action_class_taxonomy::ActionClass;
use selfdef_profile_authority_gate::Profile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Budget caps tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    /// Daily cap.
    pub daily: u32,
    /// Weekly cap.
    pub weekly: u32,
    /// Monthly cap.
    pub monthly: u32,
}

/// Budget envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionBudget {
    /// Schema version.
    pub schema_version: String,
    /// Caps keyed by "Profile|ActionClass" string.
    pub caps: HashMap<String, Caps>,
}

/// Observed counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCounts {
    /// In last 24h.
    pub daily: u32,
    /// In last 7 days.
    pub weekly: u32,
    /// In last 30 days.
    pub monthly: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Cap exceeded.
    #[error("({profile:?}, {action:?}) {window} budget exceeded: observed {observed} >= cap {cap}")]
    Exceeded {
        /// profile.
        profile: Profile,
        /// action.
        action: ActionClass,
        /// window.
        window: &'static str,
        /// observed.
        observed: u32,
        /// cap.
        cap: u32,
    },
}

fn key(p: Profile, a: ActionClass) -> String {
    format!("{p:?}|{a:?}")
}

impl DecisionBudget {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            caps: HashMap::new(),
        }
    }

    /// Set caps for a (profile, action) pair.
    pub fn set_caps(&mut self, profile: Profile, action: ActionClass, caps: Caps) {
        self.caps.insert(key(profile, action), caps);
    }

    /// Lookup caps.
    pub fn get_caps(&self, profile: Profile, action: ActionClass) -> Option<&Caps> {
        self.caps.get(&key(profile, action))
    }

    /// Admit a decision against the budget.
    /// If no caps are set for the (profile, action), the decision is admitted.
    pub fn admit(
        &self,
        profile: Profile,
        action: ActionClass,
        observed: ObservedCounts,
    ) -> Result<(), BudgetError> {
        let Some(c) = self.get_caps(profile, action) else {
            return Ok(());
        };
        if c.daily > 0 && observed.daily >= c.daily {
            return Err(BudgetError::Exceeded {
                profile,
                action,
                window: "daily",
                observed: observed.daily,
                cap: c.daily,
            });
        }
        if c.weekly > 0 && observed.weekly >= c.weekly {
            return Err(BudgetError::Exceeded {
                profile,
                action,
                window: "weekly",
                observed: observed.weekly,
                cap: c.weekly,
            });
        }
        if c.monthly > 0 && observed.monthly >= c.monthly {
            return Err(BudgetError::Exceeded {
                profile,
                action,
                window: "monthly",
                observed: observed.monthly,
                cap: c.monthly,
            });
        }
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for DecisionBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ob(d: u32, w: u32, m: u32) -> ObservedCounts {
        ObservedCounts {
            daily: d,
            weekly: w,
            monthly: m,
        }
    }

    #[test]
    fn no_caps_admits() {
        let b = DecisionBudget::new();
        b.admit(
            Profile::Careful,
            ActionClass::FsWrite,
            ob(1000, 5000, 20000),
        )
        .unwrap();
    }

    #[test]
    fn within_caps_ok() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 100,
                weekly: 500,
                monthly: 2000,
            },
        );
        b.admit(Profile::Careful, ActionClass::FsWrite, ob(50, 200, 1000))
            .unwrap();
    }

    #[test]
    fn daily_exceeded_rejected() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 100,
                weekly: 500,
                monthly: 2000,
            },
        );
        let err = b
            .admit(Profile::Careful, ActionClass::FsWrite, ob(100, 200, 1000))
            .unwrap_err();
        match err {
            BudgetError::Exceeded {
                window,
                observed,
                cap,
                ..
            } => {
                assert_eq!(window, "daily");
                assert_eq!(observed, 100);
                assert_eq!(cap, 100);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn weekly_exceeded_rejected() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 100,
                weekly: 500,
                monthly: 2000,
            },
        );
        let err = b
            .admit(Profile::Careful, ActionClass::FsWrite, ob(50, 600, 1000))
            .unwrap_err();
        match err {
            BudgetError::Exceeded { window, .. } => assert_eq!(window, "weekly"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn monthly_exceeded_rejected() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 100,
                weekly: 500,
                monthly: 2000,
            },
        );
        let err = b
            .admit(Profile::Careful, ActionClass::FsWrite, ob(50, 200, 3000))
            .unwrap_err();
        match err {
            BudgetError::Exceeded { window, .. } => assert_eq!(window, "monthly"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn zero_cap_disables_that_window() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 0,
                weekly: 500,
                monthly: 2000,
            },
        );
        // Daily 0 → disabled, so 10_000 daily is fine.
        b.admit(
            Profile::Careful,
            ActionClass::FsWrite,
            ob(10_000, 200, 1000),
        )
        .unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = DecisionBudget::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BudgetError::SchemaMismatch
        ));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let mut b = DecisionBudget::new();
        b.set_caps(
            Profile::Careful,
            ActionClass::FsWrite,
            Caps {
                daily: 100,
                weekly: 500,
                monthly: 2000,
            },
        );
        let j = serde_json::to_string(&b).unwrap();
        let back: DecisionBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
