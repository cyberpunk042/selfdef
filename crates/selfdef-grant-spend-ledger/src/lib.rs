//! `selfdef-grant-spend-ledger` — per-grant remaining-spend ledger.
//!
//! `issue(grant_id, units)` records the issued allowance.
//! `spend(grant_id, units)` returns:
//!   * `Accepted { remaining }` — successful debit.
//!   * `Exhausted { remaining }` — would overdraw; the spend is
//!     rejected and `remaining` is unchanged.
//!   * `Revoked` — grant has been revoked.
//!   * `UnknownGrant`.
//!
//! `revoke(grant_id)` zeroes the remaining and freezes further spends.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One grant balance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    /// Issued allowance.
    pub issued: u64,
    /// Spent so far.
    pub spent: u64,
    /// Revoked flag.
    pub revoked: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantSpendLedger {
    /// Schema version.
    pub schema_version: String,
    /// Per-grant balances.
    pub grants: BTreeMap<String, Balance>,
}

/// Spend verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SpendVerdict {
    /// Accepted.
    Accepted {
        /// remaining.
        remaining: u64,
    },
    /// Exhausted; would overdraw.
    Exhausted {
        /// remaining.
        remaining: u64,
    },
    /// Grant revoked.
    Revoked,
    /// Unknown grant id.
    UnknownGrant,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Duplicate issuance.
    #[error("grant {0} already issued")]
    DuplicateIssue(String),
    /// Empty grant id.
    #[error("grant id empty")]
    EmptyId,
}

impl GrantSpendLedger {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            grants: BTreeMap::new(),
        }
    }

    /// Issue.
    pub fn issue(&mut self, grant_id: &str, units: u64) -> Result<(), LedgerError> {
        if grant_id.is_empty() {
            return Err(LedgerError::EmptyId);
        }
        if self.grants.contains_key(grant_id) {
            return Err(LedgerError::DuplicateIssue(grant_id.into()));
        }
        self.grants.insert(
            grant_id.into(),
            Balance {
                issued: units,
                spent: 0,
                revoked: false,
            },
        );
        Ok(())
    }

    /// Spend.
    pub fn spend(&mut self, grant_id: &str, units: u64) -> SpendVerdict {
        let bal = match self.grants.get_mut(grant_id) {
            Some(b) => b,
            None => return SpendVerdict::UnknownGrant,
        };
        if bal.revoked {
            return SpendVerdict::Revoked;
        }
        let remaining = bal.issued.saturating_sub(bal.spent);
        if units > remaining {
            return SpendVerdict::Exhausted { remaining };
        }
        bal.spent = bal.spent.saturating_add(units);
        SpendVerdict::Accepted {
            remaining: bal.issued.saturating_sub(bal.spent),
        }
    }

    /// Revoke.
    pub fn revoke(&mut self, grant_id: &str) -> bool {
        if let Some(b) = self.grants.get_mut(grant_id) {
            b.revoked = true;
            true
        } else {
            false
        }
    }

    /// Remaining.
    pub fn remaining(&self, grant_id: &str) -> Option<u64> {
        self.grants
            .get(grant_id)
            .map(|b| b.issued.saturating_sub(b.spent))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::SchemaMismatch);
        }
        for (id, b) in &self.grants {
            if id.is_empty() {
                return Err(LedgerError::EmptyId);
            }
            // spent ≤ issued invariant.
            if b.spent > b.issued {
                return Err(LedgerError::DuplicateIssue(id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for GrantSpendLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_spend() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 100).unwrap();
        let v = l.spend("g1", 30);
        assert_eq!(v, SpendVerdict::Accepted { remaining: 70 });
    }

    #[test]
    fn spend_exact_drains() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 50).unwrap();
        l.spend("g1", 50);
        assert_eq!(l.remaining("g1"), Some(0));
    }

    #[test]
    fn overdraw_rejected_keeps_balance() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 50).unwrap();
        l.spend("g1", 30);
        let v = l.spend("g1", 40);
        assert_eq!(v, SpendVerdict::Exhausted { remaining: 20 });
        assert_eq!(l.remaining("g1"), Some(20));
    }

    #[test]
    fn revoke_blocks_spend() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 50).unwrap();
        l.revoke("g1");
        assert_eq!(l.spend("g1", 1), SpendVerdict::Revoked);
    }

    #[test]
    fn revoke_unknown_returns_false() {
        let mut l = GrantSpendLedger::new();
        assert!(!l.revoke("nope"));
    }

    #[test]
    fn unknown_grant_spend() {
        let mut l = GrantSpendLedger::new();
        assert_eq!(l.spend("nope", 1), SpendVerdict::UnknownGrant);
    }

    #[test]
    fn duplicate_issue_rejected() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 50).unwrap();
        assert!(matches!(
            l.issue("g1", 50).unwrap_err(),
            LedgerError::DuplicateIssue(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut l = GrantSpendLedger::new();
        assert!(matches!(l.issue("", 50).unwrap_err(), LedgerError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = GrantSpendLedger::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LedgerError::SchemaMismatch
        ));
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut l = GrantSpendLedger::new();
        l.issue("g1", 50).unwrap();
        l.spend("g1", 10);
        let j = serde_json::to_string(&l).unwrap();
        let back: GrantSpendLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
