//! `selfdef-usage-receipt` — per-operation usage records.
//!
//! Each receipt is `Receipt { id, actor, resource, ts_ms,
//! input_bytes, output_bytes, tokens, duration_ms }`. record() appends
//! and bumps per-(actor,resource) aggregates. `totals_by_actor(actor)`
//! and `totals_by_resource(resource)` return aggregated tallies.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    /// Id.
    pub id: String,
    /// Actor.
    pub actor: String,
    /// Resource.
    pub resource: String,
    /// Ts.
    pub ts_ms: u64,
    /// Input bytes.
    pub input_bytes: u64,
    /// Output bytes.
    pub output_bytes: u64,
    /// Tokens.
    pub tokens: u64,
    /// Duration ms.
    pub duration_ms: u64,
}

/// Aggregated totals.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Totals {
    /// Receipts counted.
    pub receipts: u64,
    /// Input bytes.
    pub input_bytes: u64,
    /// Output bytes.
    pub output_bytes: u64,
    /// Tokens.
    pub tokens: u64,
    /// Duration ms.
    pub duration_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageReceipt {
    /// Schema version.
    pub schema_version: String,
    /// receipt id → receipt.
    pub receipts: BTreeMap<String, Receipt>,
    /// actor → totals.
    pub by_actor: BTreeMap<String, Totals>,
    /// resource → totals.
    pub by_resource: BTreeMap<String, Totals>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum UsageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Empty.
    #[error("resource empty")]
    EmptyResource,
    /// Duplicate.
    #[error("duplicate receipt id: {0}")]
    DuplicateId(String),
}

fn accumulate(t: &mut Totals, r: &Receipt) {
    t.receipts = t.receipts.saturating_add(1);
    t.input_bytes = t.input_bytes.saturating_add(r.input_bytes);
    t.output_bytes = t.output_bytes.saturating_add(r.output_bytes);
    t.tokens = t.tokens.saturating_add(r.tokens);
    t.duration_ms = t.duration_ms.saturating_add(r.duration_ms);
}

impl UsageReceipt {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            receipts: BTreeMap::new(),
            by_actor: BTreeMap::new(),
            by_resource: BTreeMap::new(),
        }
    }

    /// Record.
    pub fn record(&mut self, receipt: Receipt) -> Result<(), UsageError> {
        if receipt.id.is_empty() {
            return Err(UsageError::EmptyId);
        }
        if receipt.actor.is_empty() {
            return Err(UsageError::EmptyActor);
        }
        if receipt.resource.is_empty() {
            return Err(UsageError::EmptyResource);
        }
        if self.receipts.contains_key(&receipt.id) {
            return Err(UsageError::DuplicateId(receipt.id));
        }
        let a_total = self.by_actor.entry(receipt.actor.clone()).or_default();
        accumulate(a_total, &receipt);
        let r_total = self
            .by_resource
            .entry(receipt.resource.clone())
            .or_default();
        accumulate(r_total, &receipt);
        self.receipts.insert(receipt.id.clone(), receipt);
        Ok(())
    }

    /// Totals for actor.
    pub fn totals_by_actor(&self, actor: &str) -> Totals {
        self.by_actor.get(actor).copied().unwrap_or_default()
    }

    /// Totals for resource.
    pub fn totals_by_resource(&self, resource: &str) -> Totals {
        self.by_resource.get(resource).copied().unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), UsageError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(UsageError::SchemaMismatch);
        }
        for (id, r) in &self.receipts {
            if id.is_empty() {
                return Err(UsageError::EmptyId);
            }
            if r.actor.is_empty() {
                return Err(UsageError::EmptyActor);
            }
            if r.resource.is_empty() {
                return Err(UsageError::EmptyResource);
            }
        }
        Ok(())
    }
}

impl Default for UsageReceipt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &str, actor: &str, res: &str, tokens: u64) -> Receipt {
        Receipt {
            id: id.into(),
            actor: actor.into(),
            resource: res.into(),
            ts_ms: 0,
            input_bytes: 100,
            output_bytes: 200,
            tokens,
            duration_ms: 500,
        }
    }

    #[test]
    fn record_aggregates_actor_and_resource() {
        let mut u = UsageReceipt::new();
        u.record(r("r1", "alice", "llm-opus", 1000)).unwrap();
        u.record(r("r2", "alice", "llm-haiku", 500)).unwrap();
        u.record(r("r3", "bob", "llm-opus", 2000)).unwrap();

        let a = u.totals_by_actor("alice");
        assert_eq!(a.receipts, 2);
        assert_eq!(a.tokens, 1500);

        let res = u.totals_by_resource("llm-opus");
        assert_eq!(res.receipts, 2);
        assert_eq!(res.tokens, 3000);
    }

    #[test]
    fn duplicate_rejected() {
        let mut u = UsageReceipt::new();
        u.record(r("r1", "a", "x", 1)).unwrap();
        assert!(matches!(
            u.record(r("r1", "a", "x", 1)).unwrap_err(),
            UsageError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut u = UsageReceipt::new();
        assert!(matches!(
            u.record(r("", "a", "x", 1)).unwrap_err(),
            UsageError::EmptyId
        ));
        assert!(matches!(
            u.record(r("r", "", "x", 1)).unwrap_err(),
            UsageError::EmptyActor
        ));
        assert!(matches!(
            u.record(r("r", "a", "", 1)).unwrap_err(),
            UsageError::EmptyResource
        ));
    }

    #[test]
    fn unknown_actor_totals_zero() {
        let u = UsageReceipt::new();
        assert_eq!(u.totals_by_actor("nope").receipts, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut u = UsageReceipt::new();
        u.schema_version = "9.9.9".into();
        assert!(matches!(
            u.validate().unwrap_err(),
            UsageError::SchemaMismatch
        ));
    }

    #[test]
    fn usage_serde_roundtrip() {
        let mut u = UsageReceipt::new();
        u.record(r("r1", "a", "x", 100)).unwrap();
        let j = serde_json::to_string(&u).unwrap();
        let back: UsageReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(u, back);
    }
}
