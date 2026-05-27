//! `selfdef-policy-revert-window` — bounded operator-revert window.
//!
//! `record_change(policy_id, ts, prior_blob)` opens a revert window
//! of `revert_ms`. `revert(policy_id, now)` returns:
//!   * `Accepted { prior_blob }` — restores the prior blob and
//!     consumes the window entry.
//!   * `Stale` — past the window; the change is sealed.
//!   * `Unknown` — no recorded change for this policy_id.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One outstanding revertable change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    /// timestamp ms.
    pub ts_ms: u64,
    /// Prior policy blob.
    pub prior_blob: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRevertWindow {
    /// Schema version.
    pub schema_version: String,
    /// Window width (ms).
    pub revert_ms: u64,
    /// Per-policy outstanding changes.
    pub changes: BTreeMap<String, Change>,
}

/// Revert verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RevertVerdict {
    /// Accepted; prior blob returned.
    Accepted {
        /// blob.
        prior_blob: String,
    },
    /// Past window.
    Stale,
    /// No record.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RevertError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyId,
}

impl PolicyRevertWindow {
    /// New.
    pub fn new(revert_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            revert_ms,
            changes: BTreeMap::new(),
        }
    }

    /// Record a change.
    pub fn record_change(
        &mut self,
        policy_id: &str,
        ts_ms: u64,
        prior_blob: &str,
    ) -> Result<(), RevertError> {
        if policy_id.is_empty() {
            return Err(RevertError::EmptyId);
        }
        self.changes.insert(
            policy_id.into(),
            Change {
                ts_ms,
                prior_blob: prior_blob.into(),
            },
        );
        Ok(())
    }

    /// Revert.
    pub fn revert(&mut self, policy_id: &str, now_ms: u64) -> RevertVerdict {
        let entry = match self.changes.get(policy_id).cloned() {
            Some(e) => e,
            None => return RevertVerdict::Unknown,
        };
        if now_ms.saturating_sub(entry.ts_ms) > self.revert_ms {
            return RevertVerdict::Stale;
        }
        self.changes.remove(policy_id);
        RevertVerdict::Accepted {
            prior_blob: entry.prior_blob,
        }
    }

    /// Drop expired entries.
    pub fn rotate(&mut self, now_ms: u64) {
        let w = self.revert_ms;
        self.changes
            .retain(|_, c| now_ms.saturating_sub(c.ts_ms) <= w);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RevertError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RevertError::SchemaMismatch);
        }
        for id in self.changes.keys() {
            if id.is_empty() {
                return Err(RevertError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_then_revert_accepts() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD").unwrap();
        let v = w.revert("p1", 1000);
        match v {
            RevertVerdict::Accepted { prior_blob } => assert_eq!(prior_blob, "OLD"),
            _ => panic!("expected accepted"),
        }
    }

    #[test]
    fn revert_consumes_entry() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD").unwrap();
        w.revert("p1", 1000);
        assert_eq!(w.revert("p1", 2000), RevertVerdict::Unknown);
    }

    #[test]
    fn stale_past_window() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD").unwrap();
        assert_eq!(w.revert("p1", 120_000), RevertVerdict::Stale);
    }

    #[test]
    fn unknown_no_record() {
        let mut w = PolicyRevertWindow::new(60_000);
        assert_eq!(w.revert("missing", 0), RevertVerdict::Unknown);
    }

    #[test]
    fn empty_id_rejected() {
        let mut w = PolicyRevertWindow::new(60_000);
        assert!(matches!(
            w.record_change("", 0, "x").unwrap_err(),
            RevertError::EmptyId
        ));
    }

    #[test]
    fn record_overwrites_previous() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD1").unwrap();
        w.record_change("p1", 1000, "OLD2").unwrap();
        let v = w.revert("p1", 2000);
        match v {
            RevertVerdict::Accepted { prior_blob } => assert_eq!(prior_blob, "OLD2"),
            _ => panic!(),
        }
    }

    #[test]
    fn rotate_drops_expired() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD").unwrap();
        w.rotate(120_000);
        assert_eq!(w.revert("p1", 120_000), RevertVerdict::Unknown);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = PolicyRevertWindow::new(1);
        w.schema_version = "9.9.9".into();
        assert!(matches!(
            w.validate().unwrap_err(),
            RevertError::SchemaMismatch
        ));
    }

    #[test]
    fn window_serde_roundtrip() {
        let mut w = PolicyRevertWindow::new(60_000);
        w.record_change("p1", 0, "OLD").unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let back: PolicyRevertWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
