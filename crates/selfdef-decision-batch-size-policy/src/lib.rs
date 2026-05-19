//! `selfdef-decision-batch-size-policy` — per-class batch flush gate.
//!
//! Per DecisionClass: batch_size cap + max_wait_ms. should_flush(
//! class, pending_count, oldest_age_ms) returns true when pending
//! ≥ batch_size OR oldest_age_ms ≥ max_wait_ms OR pending > 0 and
//! force flag set externally (not modeled here).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    /// Interactive (operator waiting; small batches, short wait).
    Interactive,
    /// Background (no operator wait; larger batches OK).
    Background,
    /// Bulk (huge batches, long wait OK).
    Bulk,
}

/// Per-class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassBatch {
    /// Max items per batch.
    pub batch_size: u32,
    /// Max wait ms before flushing.
    pub max_wait_ms: u32,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionBatchSizePolicy {
    /// Schema version.
    pub schema_version: String,
    /// interactive.
    pub interactive: ClassBatch,
    /// background.
    pub background: ClassBatch,
    /// bulk.
    pub bulk: ClassBatch,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BatchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// batch_size zero.
    #[error("class {0:?} batch_size zero")]
    BatchZero(DecisionClass),
    /// max_wait zero.
    #[error("class {0:?} max_wait_ms zero")]
    WaitZero(DecisionClass),
}

impl DecisionBatchSizePolicy {
    /// Canonical: Interactive 4/50ms, Background 16/1000ms, Bulk 128/5000ms.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            interactive: ClassBatch { batch_size: 4, max_wait_ms: 50 },
            background: ClassBatch { batch_size: 16, max_wait_ms: 1_000 },
            bulk: ClassBatch { batch_size: 128, max_wait_ms: 5_000 },
        }
    }

    /// Get class config.
    pub fn class(&self, c: DecisionClass) -> ClassBatch {
        match c {
            DecisionClass::Interactive => self.interactive,
            DecisionClass::Background => self.background,
            DecisionClass::Bulk => self.bulk,
        }
    }

    /// Should flush?
    pub fn should_flush(&self, class: DecisionClass, pending: u32, oldest_age_ms: u32) -> bool {
        if pending == 0 { return false; }
        let cfg = self.class(class);
        pending >= cfg.batch_size || oldest_age_ms >= cfg.max_wait_ms
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BatchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BatchError::SchemaMismatch);
        }
        for (c, cfg) in [
            (DecisionClass::Interactive, self.interactive),
            (DecisionClass::Background, self.background),
            (DecisionClass::Bulk, self.bulk),
        ] {
            if cfg.batch_size == 0 { return Err(BatchError::BatchZero(c)); }
            if cfg.max_wait_ms == 0 { return Err(BatchError::WaitZero(c)); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        DecisionBatchSizePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn empty_pending_does_not_flush() {
        let p = DecisionBatchSizePolicy::canonical();
        assert!(!p.should_flush(DecisionClass::Interactive, 0, 999_999));
    }

    #[test]
    fn full_batch_flushes() {
        let p = DecisionBatchSizePolicy::canonical();
        assert!(p.should_flush(DecisionClass::Interactive, 4, 0));
    }

    #[test]
    fn old_oldest_flushes() {
        let p = DecisionBatchSizePolicy::canonical();
        // Interactive max_wait=50ms.
        assert!(p.should_flush(DecisionClass::Interactive, 1, 100));
    }

    #[test]
    fn within_window_doesnt_flush() {
        let p = DecisionBatchSizePolicy::canonical();
        assert!(!p.should_flush(DecisionClass::Interactive, 1, 10));
    }

    #[test]
    fn bulk_larger_batches() {
        let p = DecisionBatchSizePolicy::canonical();
        assert!(!p.should_flush(DecisionClass::Bulk, 64, 100));
        assert!(p.should_flush(DecisionClass::Bulk, 128, 0));
    }

    #[test]
    fn zero_batch_rejected() {
        let mut p = DecisionBatchSizePolicy::canonical();
        p.interactive.batch_size = 0;
        assert!(matches!(p.validate().unwrap_err(), BatchError::BatchZero(_)));
    }

    #[test]
    fn zero_wait_rejected() {
        let mut p = DecisionBatchSizePolicy::canonical();
        p.background.max_wait_ms = 0;
        assert!(matches!(p.validate().unwrap_err(), BatchError::WaitZero(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = DecisionBatchSizePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), BatchError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&DecisionClass::Bulk).unwrap(), "\"bulk\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = DecisionBatchSizePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: DecisionBatchSizePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
