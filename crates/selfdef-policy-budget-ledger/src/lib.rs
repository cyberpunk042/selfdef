//! `selfdef-policy-budget-ledger` — per-subject token + cost accounting.
//!
//! Maintains a per-(subject, provider) bucket of:
//! - `tokens_in`
//! - `tokens_out`
//! - `millicents` (1 millicent = 0.001 cent)
//!
//! Each subject has a per-window budget (daily / weekly / monthly). When
//! cost breaches the cap, the ledger returns a `BudgetVerdict::Breach`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Budget window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Window {
    /// Per day.
    Daily,
    /// Per week.
    Weekly,
    /// Per month.
    Monthly,
}

/// Per-(subject, provider) accumulator.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bucket {
    /// Tokens in.
    pub tokens_in: u64,
    /// Tokens out.
    pub tokens_out: u64,
    /// Millicents spent.
    pub millicents: u64,
}

/// Per-subject budget cap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cap {
    /// Subject id.
    pub subject: String,
    /// Window.
    pub window: Window,
    /// Cap in millicents.
    pub millicents_cap: u64,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetVerdict {
    /// Within budget.
    Within,
    /// Approaching (90%+).
    Near,
    /// Breached.
    Breach,
}

/// Ledger envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetLedger {
    /// Schema version.
    pub schema_version: String,
    /// Buckets keyed by "subject|provider".
    pub buckets: HashMap<String, Bucket>,
    /// Operator-set caps.
    pub caps: Vec<Cap>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Empty provider.
    #[error("provider empty")]
    EmptyProvider,
    /// Cap empty subject.
    #[error("cap has empty subject")]
    CapEmptySubject,
    /// Cap millicents 0 (would always breach).
    #[error("cap for {subject} window {window:?} has 0 millicents")]
    CapZero {
        /// subject.
        subject: String,
        /// window.
        window: Window,
    },
}

fn key(subject: &str, provider: &str) -> String {
    format!("{subject}|{provider}")
}

impl BudgetLedger {
    /// New empty ledger.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: HashMap::new(),
            caps: Vec::new(),
        }
    }

    /// Add a cap.
    pub fn set_cap(&mut self, cap: Cap) -> Result<(), LedgerError> {
        if cap.subject.is_empty() {
            return Err(LedgerError::CapEmptySubject);
        }
        if cap.millicents_cap == 0 {
            return Err(LedgerError::CapZero {
                subject: cap.subject,
                window: cap.window,
            });
        }
        // Replace existing cap for same (subject, window).
        self.caps
            .retain(|c| !(c.subject == cap.subject && c.window == cap.window));
        self.caps.push(cap);
        Ok(())
    }

    /// Charge a usage event.
    pub fn charge(
        &mut self,
        subject: &str,
        provider: &str,
        tokens_in: u64,
        tokens_out: u64,
        millicents: u64,
    ) -> Result<(), LedgerError> {
        if subject.is_empty() {
            return Err(LedgerError::EmptySubject);
        }
        if provider.is_empty() {
            return Err(LedgerError::EmptyProvider);
        }
        let b = self.buckets.entry(key(subject, provider)).or_default();
        b.tokens_in += tokens_in;
        b.tokens_out += tokens_out;
        b.millicents += millicents;
        Ok(())
    }

    /// Total millicents spent by subject (sum across all providers).
    pub fn subject_total_millicents(&self, subject: &str) -> u64 {
        self.buckets
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{subject}|")))
            .map(|(_, b)| b.millicents)
            .sum()
    }

    /// Evaluate verdict against a specific cap (subject, window).
    pub fn evaluate(&self, subject: &str, window: Window) -> BudgetVerdict {
        let cap_mc = self
            .caps
            .iter()
            .find(|c| c.subject == subject && c.window == window)
            .map(|c| c.millicents_cap);
        let Some(cap) = cap_mc else {
            return BudgetVerdict::Within;
        };
        let spent = self.subject_total_millicents(subject);
        if spent >= cap {
            return BudgetVerdict::Breach;
        }
        if spent * 10 >= cap * 9 {
            return BudgetVerdict::Near;
        }
        BudgetVerdict::Within
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::SchemaMismatch);
        }
        for c in &self.caps {
            if c.subject.is_empty() {
                return Err(LedgerError::CapEmptySubject);
            }
            if c.millicents_cap == 0 {
                return Err(LedgerError::CapZero {
                    subject: c.subject.clone(),
                    window: c.window,
                });
            }
        }
        Ok(())
    }
}

impl Default for BudgetLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ledger_validates() {
        BudgetLedger::new().validate().unwrap();
    }

    #[test]
    fn charge_accumulates() {
        let mut l = BudgetLedger::new();
        l.charge("alice", "cloud-anthropic", 100, 50, 200).unwrap();
        l.charge("alice", "cloud-anthropic", 50, 30, 80).unwrap();
        let b = l.buckets.get("alice|cloud-anthropic").unwrap();
        assert_eq!(b.tokens_in, 150);
        assert_eq!(b.tokens_out, 80);
        assert_eq!(b.millicents, 280);
    }

    #[test]
    fn subject_total_sums_across_providers() {
        let mut l = BudgetLedger::new();
        l.charge("alice", "cloud-anthropic", 0, 0, 200).unwrap();
        l.charge("alice", "cloud-openai", 0, 0, 300).unwrap();
        l.charge("bob", "cloud-anthropic", 0, 0, 100).unwrap();
        assert_eq!(l.subject_total_millicents("alice"), 500);
        assert_eq!(l.subject_total_millicents("bob"), 100);
        assert_eq!(l.subject_total_millicents("carol"), 0);
    }

    #[test]
    fn verdict_within_below_threshold() {
        let mut l = BudgetLedger::new();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Daily,
            millicents_cap: 1000,
        })
        .unwrap();
        l.charge("alice", "p", 0, 0, 300).unwrap();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Within);
    }

    #[test]
    fn verdict_near_at_90_percent() {
        let mut l = BudgetLedger::new();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Daily,
            millicents_cap: 1000,
        })
        .unwrap();
        l.charge("alice", "p", 0, 0, 900).unwrap();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Near);
    }

    #[test]
    fn verdict_breach_at_cap() {
        let mut l = BudgetLedger::new();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Daily,
            millicents_cap: 1000,
        })
        .unwrap();
        l.charge("alice", "p", 0, 0, 1000).unwrap();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Breach);
        l.charge("alice", "p", 0, 0, 5000).unwrap();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Breach);
    }

    #[test]
    fn no_cap_returns_within() {
        let l = BudgetLedger::new();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Within);
    }

    #[test]
    fn set_cap_replaces_existing() {
        let mut l = BudgetLedger::new();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Daily,
            millicents_cap: 1000,
        })
        .unwrap();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Daily,
            millicents_cap: 5000,
        })
        .unwrap();
        // Now 4000 spent should be Within (not breach).
        l.charge("alice", "p", 0, 0, 4000).unwrap();
        assert_eq!(l.evaluate("alice", Window::Daily), BudgetVerdict::Within);
    }

    #[test]
    fn cap_zero_rejected() {
        let mut l = BudgetLedger::new();
        let err = l
            .set_cap(Cap {
                subject: "alice".into(),
                window: Window::Daily,
                millicents_cap: 0,
            })
            .unwrap_err();
        assert!(matches!(err, LedgerError::CapZero { .. }));
    }

    #[test]
    fn empty_subject_caught() {
        let mut l = BudgetLedger::new();
        let err = l.charge("", "p", 0, 0, 0).unwrap_err();
        assert!(matches!(err, LedgerError::EmptySubject));
    }

    #[test]
    fn empty_provider_caught() {
        let mut l = BudgetLedger::new();
        let err = l.charge("alice", "", 0, 0, 0).unwrap_err();
        assert!(matches!(err, LedgerError::EmptyProvider));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = BudgetLedger::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LedgerError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&BudgetVerdict::Within).unwrap(),
            "\"within\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetVerdict::Near).unwrap(),
            "\"near\""
        );
        assert_eq!(
            serde_json::to_string(&BudgetVerdict::Breach).unwrap(),
            "\"breach\""
        );
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut l = BudgetLedger::new();
        l.set_cap(Cap {
            subject: "alice".into(),
            window: Window::Monthly,
            millicents_cap: 50_000,
        })
        .unwrap();
        l.charge("alice", "cloud-anthropic", 100, 50, 200).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: BudgetLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
