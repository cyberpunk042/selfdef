//! `selfdef-llm-thinking-budget` — per-Profile cap on reasoning tokens.
//!
//! Each Profile carries `max_thinking_tokens`. `plan(profile, n)`
//! returns:
//!   * `Granted` — under cap.
//!   * `Capped { adjusted }` — clamped to cap.
//!   * `Unconfigured` — no entry.
//!
//! Distinct from the per-response output-size cap (user-visible
//! completion) and from the cumulative-token throttle (window across
//! many requests).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmThinkingBudget {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile cap.
    pub max_thinking_tokens: BTreeMap<Profile, u32>,
}

/// Plan verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PlanVerdict {
    /// Within cap.
    Granted,
    /// Capped to per-Profile maximum.
    Capped {
        /// adjusted token count.
        adjusted: u32,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl LlmThinkingBudget {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut t = BTreeMap::new();
        t.insert(Profile::Private, 1024);
        t.insert(Profile::Fast, 2048);
        t.insert(Profile::Careful, 4096);
        t.insert(Profile::Autonomous, 8192);
        t.insert(Profile::Experimental, 32_768);
        t.insert(Profile::Production, 4096);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_thinking_tokens: t,
        }
    }

    /// Plan.
    pub fn plan(&self, profile: Profile, requested: u32) -> PlanVerdict {
        let cap = match self.max_thinking_tokens.get(&profile) {
            Some(&c) => c,
            None => return PlanVerdict::Unconfigured,
        };
        if requested <= cap {
            PlanVerdict::Granted
        } else {
            PlanVerdict::Capped { adjusted: cap }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BudgetError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        LlmThinkingBudget::canonical().validate().unwrap();
    }

    #[test]
    fn grant_under_cap() {
        let b = LlmThinkingBudget::canonical();
        assert_eq!(b.plan(Profile::Fast, 1000), PlanVerdict::Granted);
    }

    #[test]
    fn cap_at_max() {
        let b = LlmThinkingBudget::canonical();
        let v = b.plan(Profile::Production, 99_999);
        assert_eq!(v, PlanVerdict::Capped { adjusted: 4096 });
    }

    #[test]
    fn experimental_admits_large() {
        let b = LlmThinkingBudget::canonical();
        assert_eq!(b.plan(Profile::Experimental, 16_000), PlanVerdict::Granted);
    }

    #[test]
    fn unconfigured_profile() {
        let mut b = LlmThinkingBudget::canonical();
        b.max_thinking_tokens.clear();
        assert_eq!(b.plan(Profile::Fast, 100), PlanVerdict::Unconfigured);
    }

    #[test]
    fn private_lowest() {
        let b = LlmThinkingBudget::canonical();
        let v = b.plan(Profile::Private, 2000);
        assert_eq!(v, PlanVerdict::Capped { adjusted: 1024 });
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = LlmThinkingBudget::canonical();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BudgetError::SchemaMismatch
        ));
    }

    #[test]
    fn budget_serde_roundtrip() {
        let b = LlmThinkingBudget::canonical();
        let j = serde_json::to_string(&b).unwrap();
        let back: LlmThinkingBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
