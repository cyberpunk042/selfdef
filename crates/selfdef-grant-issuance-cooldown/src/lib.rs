//! `selfdef-grant-issuance-cooldown` — per-template issuance cooldown.
//!
//! `record_issued(template_id, ts)` records a fresh issuance.
//! `classify(template_id, now)` returns:
//!   * `Ready` — no prior, or cooldown elapsed.
//!   * `Cooldown { ready_at }` — must wait until `ready_at`.
//!
//! `cooldown_ms` is a global constant per ledger.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantIssuanceCooldown {
    /// Schema version.
    pub schema_version: String,
    /// Cooldown window (ms).
    pub cooldown_ms: u64,
    /// Per-template last-issued ts.
    pub last: BTreeMap<String, u64>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CooldownVerdict {
    /// Ready to issue.
    Ready,
    /// In cooldown.
    Cooldown {
        /// epoch-ms at which the cooldown ends.
        ready_at_ms: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CooldownError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty template id.
    #[error("template id empty")]
    EmptyId,
}

impl GrantIssuanceCooldown {
    /// New.
    pub fn new(cooldown_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            cooldown_ms,
            last: BTreeMap::new(),
        }
    }

    /// Record an issuance.
    pub fn record_issued(&mut self, template_id: &str, ts_ms: u64) -> Result<(), CooldownError> {
        if template_id.is_empty() { return Err(CooldownError::EmptyId); }
        self.last.insert(template_id.into(), ts_ms);
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, template_id: &str, now_ms: u64) -> CooldownVerdict {
        match self.last.get(template_id).copied() {
            None => CooldownVerdict::Ready,
            Some(prev) => {
                let ready_at_ms = prev.saturating_add(self.cooldown_ms);
                if now_ms >= ready_at_ms {
                    CooldownVerdict::Ready
                } else {
                    CooldownVerdict::Cooldown { ready_at_ms }
                }
            }
        }
    }

    /// Drop expired records.
    pub fn rotate(&mut self, now_ms: u64) {
        let w = self.cooldown_ms;
        self.last.retain(|_, t| now_ms.saturating_sub(*t) < w);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CooldownError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CooldownError::SchemaMismatch); }
        for k in self.last.keys() {
            if k.is_empty() { return Err(CooldownError::EmptyId); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_is_ready() {
        let c = GrantIssuanceCooldown::new(60_000);
        assert_eq!(c.classify("t1", 0), CooldownVerdict::Ready);
    }

    #[test]
    fn record_then_in_cooldown() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        c.record_issued("t1", 1_000).unwrap();
        assert_eq!(c.classify("t1", 30_000), CooldownVerdict::Cooldown { ready_at_ms: 61_000 });
    }

    #[test]
    fn ready_after_window() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        c.record_issued("t1", 1_000).unwrap();
        assert_eq!(c.classify("t1", 61_000), CooldownVerdict::Ready);
    }

    #[test]
    fn per_template_independent() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        c.record_issued("t1", 1_000).unwrap();
        assert_eq!(c.classify("t2", 1_000), CooldownVerdict::Ready);
    }

    #[test]
    fn empty_id_rejected() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        assert!(matches!(c.record_issued("", 0).unwrap_err(), CooldownError::EmptyId));
    }

    #[test]
    fn rotate_drops_expired() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        c.record_issued("t1", 0).unwrap();
        c.rotate(120_000);
        assert!(c.last.is_empty());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = GrantIssuanceCooldown::new(1);
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CooldownError::SchemaMismatch));
    }

    #[test]
    fn cooldown_serde_roundtrip() {
        let mut c = GrantIssuanceCooldown::new(60_000);
        c.record_issued("t1", 1_000).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: GrantIssuanceCooldown = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
