//! `selfdef-event-bus-backpressure` — per-event-kind pending-count cap.
//!
//! `register(kind, high_water, cap)` configures thresholds; `enqueue
//! (kind)` returns:
//!
//!   * `Accepted{pending}` — pending < high_water.
//!   * `HighWater{pending, high_water}` — high_water ≤ pending ≤ cap.
//!     The event is still accepted; back-pressure signaling. This band runs up
//!     to and INCLUDING the enqueue that fills the queue to `cap` (that accept
//!     returns `HighWater{pending == cap}`, not `Saturated`).
//!   * `Saturated{pending, cap}` — pending was already `cap`, so the new event
//!     is rejected (pending unchanged). This is the enqueue *after* the queue
//!     filled, distinguished from `HighWater{pending == cap}` by accept-vs-reject.
//!   * `UnknownKind`.
//!
//! `dequeue(kind)` decrements; saturates at 0.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-kind config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KindConfig {
    /// High-water mark.
    pub high_water: u32,
    /// Hard cap.
    pub cap: u32,
    /// Current pending count.
    pub pending: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBusBackpressure {
    /// Schema version.
    pub schema_version: String,
    /// Per-kind configs.
    pub kinds: BTreeMap<String, KindConfig>,
}

/// Enqueue verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnqueueVerdict {
    /// Accepted.
    Accepted {
        /// pending after.
        pending: u32,
    },
    /// Accepted but over high-water (back-pressure signal).
    HighWater {
        /// pending after.
        pending: u32,
        /// high-water.
        high_water: u32,
    },
    /// Rejected; saturated.
    Saturated {
        /// pending.
        pending: u32,
        /// cap.
        cap: u32,
    },
    /// Unknown event kind.
    UnknownKind,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty kind.
    #[error("event kind empty")]
    EmptyKind,
    /// Bad config.
    #[error("high_water {0} > cap {1}")]
    BadConfig(u32, u32),
}

impl EventBusBackpressure {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            kinds: BTreeMap::new(),
        }
    }

    /// Register or replace a kind config.
    pub fn register(&mut self, kind: &str, high_water: u32, cap: u32) -> Result<(), BpError> {
        if kind.is_empty() {
            return Err(BpError::EmptyKind);
        }
        if high_water > cap {
            return Err(BpError::BadConfig(high_water, cap));
        }
        self.kinds.insert(
            kind.into(),
            KindConfig {
                high_water,
                cap,
                pending: 0,
            },
        );
        Ok(())
    }

    /// Enqueue.
    pub fn enqueue(&mut self, kind: &str) -> EnqueueVerdict {
        let cfg = match self.kinds.get_mut(kind) {
            Some(c) => c,
            None => return EnqueueVerdict::UnknownKind,
        };
        if cfg.pending >= cfg.cap {
            return EnqueueVerdict::Saturated {
                pending: cfg.pending,
                cap: cfg.cap,
            };
        }
        cfg.pending += 1;
        if cfg.pending >= cfg.high_water {
            EnqueueVerdict::HighWater {
                pending: cfg.pending,
                high_water: cfg.high_water,
            }
        } else {
            EnqueueVerdict::Accepted {
                pending: cfg.pending,
            }
        }
    }

    /// Dequeue; saturating-sub at 0.
    pub fn dequeue(&mut self, kind: &str) -> bool {
        if let Some(c) = self.kinds.get_mut(kind) {
            c.pending = c.pending.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BpError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BpError::SchemaMismatch);
        }
        for (k, c) in &self.kinds {
            if k.is_empty() {
                return Err(BpError::EmptyKind);
            }
            if c.high_water > c.cap {
                return Err(BpError::BadConfig(c.high_water, c.cap));
            }
        }
        Ok(())
    }
}

impl Default for EventBusBackpressure {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_under_high_water() {
        let mut b = EventBusBackpressure::new();
        b.register("policy.update", 5, 10).unwrap();
        assert_eq!(
            b.enqueue("policy.update"),
            EnqueueVerdict::Accepted { pending: 1 }
        );
    }

    #[test]
    fn high_water_signal() {
        let mut b = EventBusBackpressure::new();
        b.register("policy.update", 2, 10).unwrap();
        b.enqueue("policy.update");
        let v = b.enqueue("policy.update");
        assert_eq!(
            v,
            EnqueueVerdict::HighWater {
                pending: 2,
                high_water: 2
            }
        );
    }

    #[test]
    fn saturated_rejects() {
        let mut b = EventBusBackpressure::new();
        b.register("policy.update", 1, 2).unwrap();
        b.enqueue("policy.update");
        b.enqueue("policy.update");
        let v = b.enqueue("policy.update");
        assert_eq!(v, EnqueueVerdict::Saturated { pending: 2, cap: 2 });
    }

    #[test]
    fn high_water_band_includes_the_cap_filling_accept() {
        // Contract: HighWater runs high_water ≤ pending ≤ cap. The accept that
        // fills the queue to `cap` returns HighWater{pending == cap} (still
        // accepted) — NOT Saturated. Saturated is the *next* enqueue, which is
        // rejected because pending is already == cap.
        let mut b = EventBusBackpressure::new();
        b.register("policy.update", 1, 2).unwrap();
        assert_eq!(
            b.enqueue("policy.update"),
            EnqueueVerdict::HighWater { pending: 1, high_water: 1 }
        );
        // Fills to cap=2 → HighWater{pending == cap}, accepted.
        assert_eq!(
            b.enqueue("policy.update"),
            EnqueueVerdict::HighWater { pending: 2, high_water: 1 }
        );
        // Only now, with pending already == cap, is the enqueue rejected.
        assert_eq!(
            b.enqueue("policy.update"),
            EnqueueVerdict::Saturated { pending: 2, cap: 2 }
        );
    }

    #[test]
    fn dequeue_frees_slot() {
        let mut b = EventBusBackpressure::new();
        b.register("policy.update", 1, 2).unwrap();
        b.enqueue("policy.update");
        b.enqueue("policy.update");
        b.dequeue("policy.update");
        assert!(matches!(
            b.enqueue("policy.update"),
            EnqueueVerdict::HighWater { .. } | EnqueueVerdict::Accepted { .. }
        ));
    }

    #[test]
    fn unknown_kind() {
        let mut b = EventBusBackpressure::new();
        assert_eq!(b.enqueue("missing"), EnqueueVerdict::UnknownKind);
        assert!(!b.dequeue("missing"));
    }

    #[test]
    fn bad_config_rejected() {
        let mut b = EventBusBackpressure::new();
        assert!(matches!(
            b.register("x", 10, 5).unwrap_err(),
            BpError::BadConfig(_, _)
        ));
    }

    #[test]
    fn empty_kind_rejected() {
        let mut b = EventBusBackpressure::new();
        assert!(matches!(
            b.register("", 1, 2).unwrap_err(),
            BpError::EmptyKind
        ));
    }

    #[test]
    fn dequeue_saturates_at_zero() {
        let mut b = EventBusBackpressure::new();
        b.register("x", 1, 2).unwrap();
        assert!(b.dequeue("x"));
        assert_eq!(b.kinds["x"].pending, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = EventBusBackpressure::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), BpError::SchemaMismatch));
    }

    #[test]
    fn bp_serde_roundtrip() {
        let mut b = EventBusBackpressure::new();
        b.register("x", 1, 2).unwrap();
        b.enqueue("x");
        let j = serde_json::to_string(&b).unwrap();
        let back: EventBusBackpressure = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
