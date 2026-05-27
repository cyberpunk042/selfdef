//! `selfdef-tool-stream-watchdog` — silence + total timeout.
//!
//! Two timeouts: silence_timeout_ms (no bytes since last) and
//! total_timeout_ms (overall). observe(now, bytes_so_far) updates;
//! verdict(now) returns Ok / Silence / TotalElapsed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolStreamWatchdog {
    /// Schema version.
    pub schema_version: String,
    /// Max silence between byte observations (ms).
    pub silence_timeout_ms: u32,
    /// Total wall ms.
    pub total_timeout_ms: u32,
    /// Start time.
    pub started_at_ms: u64,
    /// Last observation time.
    pub last_byte_ms: u64,
    /// Bytes observed.
    pub bytes_so_far: u64,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StreamVerdict {
    /// Ok.
    Ok,
    /// Silence timeout exceeded.
    Silence {
        /// elapsed since last byte.
        silence_ms: u64,
        /// cap.
        cap_ms: u32,
    },
    /// Total timeout exceeded.
    TotalElapsed {
        /// elapsed.
        elapsed_ms: u64,
        /// cap.
        cap_ms: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum WatchdogError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// silence zero.
    #[error("silence_timeout_ms zero")]
    SilenceZero,
    /// total zero.
    #[error("total_timeout_ms zero")]
    TotalZero,
}

impl ToolStreamWatchdog {
    /// Start a new watchdog at given time.
    pub fn start(
        silence_timeout_ms: u32,
        total_timeout_ms: u32,
        started_at_ms: u64,
    ) -> Result<Self, WatchdogError> {
        if silence_timeout_ms == 0 {
            return Err(WatchdogError::SilenceZero);
        }
        if total_timeout_ms == 0 {
            return Err(WatchdogError::TotalZero);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            silence_timeout_ms,
            total_timeout_ms,
            started_at_ms,
            last_byte_ms: started_at_ms,
            bytes_so_far: 0,
        })
    }

    /// Observe bytes arrived.
    pub fn observe(&mut self, now_ms: u64, bytes_delta: u64) {
        self.bytes_so_far = self.bytes_so_far.saturating_add(bytes_delta);
        self.last_byte_ms = now_ms;
    }

    /// Verdict now.
    pub fn verdict(&self, now_ms: u64) -> StreamVerdict {
        let total = now_ms.saturating_sub(self.started_at_ms);
        if total > self.total_timeout_ms as u64 {
            return StreamVerdict::TotalElapsed {
                elapsed_ms: total,
                cap_ms: self.total_timeout_ms,
            };
        }
        let silence = now_ms.saturating_sub(self.last_byte_ms);
        if silence > self.silence_timeout_ms as u64 {
            return StreamVerdict::Silence {
                silence_ms: silence,
                cap_ms: self.silence_timeout_ms,
            };
        }
        StreamVerdict::Ok
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WatchdogError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WatchdogError::SchemaMismatch);
        }
        if self.silence_timeout_ms == 0 {
            return Err(WatchdogError::SilenceZero);
        }
        if self.total_timeout_ms == 0 {
            return Err(WatchdogError::TotalZero);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w() -> ToolStreamWatchdog {
        ToolStreamWatchdog::start(500, 5_000, 100).unwrap()
    }

    #[test]
    fn zero_silence_rejected() {
        assert!(matches!(
            ToolStreamWatchdog::start(0, 1000, 0).unwrap_err(),
            WatchdogError::SilenceZero
        ));
    }

    #[test]
    fn zero_total_rejected() {
        assert!(matches!(
            ToolStreamWatchdog::start(100, 0, 0).unwrap_err(),
            WatchdogError::TotalZero
        ));
    }

    #[test]
    fn ok_when_fresh() {
        let w = w();
        assert!(matches!(w.verdict(200), StreamVerdict::Ok));
    }

    #[test]
    fn silence_detected() {
        let w = w();
        // started 100, silence cap 500, total cap 5000. At 700 -> silence 600ms.
        assert!(matches!(w.verdict(700), StreamVerdict::Silence { .. }));
    }

    #[test]
    fn total_dominates_when_both_exceeded() {
        let w = w();
        // At 6000: total exceeded (5900>5000) and silence too. Total wins by order.
        assert!(matches!(
            w.verdict(6000),
            StreamVerdict::TotalElapsed { .. }
        ));
    }

    #[test]
    fn observe_resets_silence() {
        let mut w = w();
        w.observe(500, 1000);
        // silence cap 500; at 800 since-last is 300 -> Ok.
        assert!(matches!(w.verdict(800), StreamVerdict::Ok));
        assert_eq!(w.bytes_so_far, 1000);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = w();
        w.schema_version = "9.9.9".into();
        assert!(matches!(
            w.validate().unwrap_err(),
            WatchdogError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        let v = StreamVerdict::Ok;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"ok\"")
        );
        let v = StreamVerdict::TotalElapsed {
            elapsed_ms: 1,
            cap_ms: 2,
        };
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"total-elapsed\"")
        );
    }

    #[test]
    fn watchdog_serde_roundtrip() {
        let mut w = w();
        w.observe(200, 50);
        let j = serde_json::to_string(&w).unwrap();
        let back: ToolStreamWatchdog = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
