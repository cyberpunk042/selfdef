//! `selfdef-event-emitter-rate-cap` — per-emitter sliding rate cap.
//!
//! `set_cap(emitter_id, events_per_min)` registers; `record(emitter_id,
//! ts)` either Accepts the event (and records its ts) or Throttles
//! with the `retry_after_ms` needed before the oldest in-window
//! record falls out.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-emitter entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmitterEntry {
    /// Events allowed per minute.
    pub events_per_min: u32,
    /// Sorted ts ledger (last_minute).
    pub recent: Vec<u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEmitterRateCap {
    /// Schema version.
    pub schema_version: String,
    /// emitter_id → entry.
    pub emitters: BTreeMap<String, EmitterEntry>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RateVerdict {
    /// Accepted.
    Accepted {
        /// remaining slots in current window.
        remaining: u32,
    },
    /// Throttled.
    Throttled {
        /// cap (events/min).
        cap: u32,
        /// ms until oldest in-window slides out.
        retry_after_ms: u64,
    },
    /// Unknown emitter.
    UnknownEmitter,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CapError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("emitter id empty")]
    EmptyId,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl EventEmitterRateCap {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            emitters: BTreeMap::new(),
        }
    }

    /// Set cap.
    pub fn set_cap(&mut self, emitter_id: &str, events_per_min: u32) -> Result<(), CapError> {
        if emitter_id.is_empty() {
            return Err(CapError::EmptyId);
        }
        let e = self
            .emitters
            .entry(emitter_id.into())
            .or_insert(EmitterEntry {
                events_per_min,
                recent: Vec::new(),
            });
        e.events_per_min = events_per_min;
        Ok(())
    }

    /// Record an event.
    pub fn record(&mut self, emitter_id: &str, ts_ms: u64) -> Result<RateVerdict, CapError> {
        let e = match self.emitters.get_mut(emitter_id) {
            Some(e) => e,
            None => return Ok(RateVerdict::UnknownEmitter),
        };
        // Drop out-of-window samples (1-minute = 60_000 ms).
        let cutoff = ts_ms.saturating_sub(60_000);
        e.recent.retain(|t| *t >= cutoff);

        if let Some(&last) = e.recent.last() {
            if ts_ms < last {
                return Err(CapError::NonMonotonic {
                    prev: last,
                    new: ts_ms,
                });
            }
        }
        if (e.recent.len() as u32) >= e.events_per_min {
            // retry_after_ms = (60_000 - (ts - oldest)) + 1
            let oldest = *e.recent.first().expect("len ≥ 1");
            let retry = 60_000u64
                .saturating_sub(ts_ms.saturating_sub(oldest))
                .saturating_add(1);
            return Ok(RateVerdict::Throttled {
                cap: e.events_per_min,
                retry_after_ms: retry,
            });
        }
        e.recent.push(ts_ms);
        Ok(RateVerdict::Accepted {
            remaining: e.events_per_min - e.recent.len() as u32,
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CapError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CapError::SchemaMismatch);
        }
        for k in self.emitters.keys() {
            if k.is_empty() {
                return Err(CapError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for EventEmitterRateCap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_emitter() {
        let mut c = EventEmitterRateCap::new();
        assert_eq!(c.record("x", 0).unwrap(), RateVerdict::UnknownEmitter);
    }

    #[test]
    fn accepts_under_cap() {
        let mut c = EventEmitterRateCap::new();
        c.set_cap("x", 2).unwrap();
        assert_eq!(
            c.record("x", 0).unwrap(),
            RateVerdict::Accepted { remaining: 1 }
        );
        assert_eq!(
            c.record("x", 1).unwrap(),
            RateVerdict::Accepted { remaining: 0 }
        );
    }

    #[test]
    fn throttles_at_cap() {
        let mut c = EventEmitterRateCap::new();
        c.set_cap("x", 2).unwrap();
        c.record("x", 0).unwrap();
        c.record("x", 1).unwrap();
        let v = c.record("x", 2).unwrap();
        match v {
            RateVerdict::Throttled {
                cap,
                retry_after_ms,
            } => {
                assert_eq!(cap, 2);
                assert!(retry_after_ms > 59_000);
            }
            _ => panic!("expected throttled"),
        }
    }

    #[test]
    fn window_slides() {
        let mut c = EventEmitterRateCap::new();
        c.set_cap("x", 1).unwrap();
        c.record("x", 0).unwrap();
        // Past 60s — old record falls out.
        assert_eq!(
            c.record("x", 61_000).unwrap(),
            RateVerdict::Accepted { remaining: 0 }
        );
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut c = EventEmitterRateCap::new();
        c.set_cap("x", 5).unwrap();
        c.record("x", 200).unwrap();
        assert!(matches!(
            c.record("x", 100).unwrap_err(),
            CapError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut c = EventEmitterRateCap::new();
        assert!(matches!(c.set_cap("", 1).unwrap_err(), CapError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = EventEmitterRateCap::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CapError::SchemaMismatch
        ));
    }

    #[test]
    fn cap_serde_roundtrip() {
        let mut c = EventEmitterRateCap::new();
        c.set_cap("x", 5).unwrap();
        c.record("x", 0).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: EventEmitterRateCap = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
