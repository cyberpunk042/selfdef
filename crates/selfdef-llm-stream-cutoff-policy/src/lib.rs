//! `selfdef-llm-stream-cutoff-policy` — early-stop authority.
//!
//! Watches a streaming generation for 4 cutoff conditions:
//! * MaxTokens exceeded
//! * StopSequence emitted in tail buffer
//! * RepetitionTrip (last `repeat_window_tokens` identical)
//! * WallTimeExceeded
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cutoff reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CutoffReason {
    /// max_tokens reached.
    MaxTokens {
        /// observed.
        observed: u32,
        /// max.
        max: u32,
    },
    /// stop sequence emitted.
    StopSequence {
        /// matched.
        matched: String,
    },
    /// repetition trip.
    RepetitionTrip {
        /// window size.
        window: u32,
    },
    /// wall time exceeded.
    WallTimeExceeded {
        /// observed seconds.
        observed_secs: u64,
        /// max seconds.
        max_secs: u64,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmStreamCutoffPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Max tokens.
    pub max_tokens: u32,
    /// Stop sequences (matched against tail-buffer).
    pub stop_sequences: Vec<String>,
    /// Trip when last N tokens identical (0 disables).
    pub repeat_window_tokens: u32,
    /// Wall-second budget.
    pub max_wall_seconds: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CutoffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_tokens zero.
    #[error("max_tokens is zero")]
    MaxTokensZero,
    /// max_wall_seconds zero.
    #[error("max_wall_seconds is zero")]
    WallZero,
}

impl LlmStreamCutoffPolicy {
    /// Canonical: 4096 tokens, ["</s>", "<|im_end|>"] stop, repeat 16, 120 s.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_tokens: 4096,
            stop_sequences: vec!["</s>".into(), "<|im_end|>".into()],
            repeat_window_tokens: 16,
            max_wall_seconds: 120,
        }
    }

    /// Decide given (tokens_emitted, recent_tokens, wall_seconds, tail_buf).
    /// Returns Some(reason) if any cutoff condition tripped.
    pub fn decide(
        &self,
        tokens_emitted: u32,
        recent_tokens: &[u32],
        wall_seconds: u64,
        tail_buf: &str,
    ) -> Option<CutoffReason> {
        if tokens_emitted > self.max_tokens {
            return Some(CutoffReason::MaxTokens {
                observed: tokens_emitted,
                max: self.max_tokens,
            });
        }
        if wall_seconds > self.max_wall_seconds {
            return Some(CutoffReason::WallTimeExceeded {
                observed_secs: wall_seconds,
                max_secs: self.max_wall_seconds,
            });
        }
        for s in &self.stop_sequences {
            if !s.is_empty() && tail_buf.contains(s.as_str()) {
                return Some(CutoffReason::StopSequence { matched: s.clone() });
            }
        }
        if self.repeat_window_tokens > 0 && recent_tokens.len() as u32 >= self.repeat_window_tokens
        {
            let window = self.repeat_window_tokens as usize;
            let tail = &recent_tokens[recent_tokens.len() - window..];
            if let Some(first) = tail.first() {
                if tail.iter().all(|t| t == first) {
                    return Some(CutoffReason::RepetitionTrip {
                        window: self.repeat_window_tokens,
                    });
                }
            }
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CutoffError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CutoffError::SchemaMismatch);
        }
        if self.max_tokens == 0 {
            return Err(CutoffError::MaxTokensZero);
        }
        if self.max_wall_seconds == 0 {
            return Err(CutoffError::WallZero);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        LlmStreamCutoffPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn under_limits_none() {
        let p = LlmStreamCutoffPolicy::canonical();
        assert!(p.decide(100, &[1, 2, 3], 10, "ok").is_none());
    }

    #[test]
    fn max_tokens_trips() {
        let p = LlmStreamCutoffPolicy::canonical();
        let r = p.decide(5000, &[], 10, "").unwrap();
        assert!(matches!(r, CutoffReason::MaxTokens { .. }));
    }

    #[test]
    fn wall_time_trips() {
        let p = LlmStreamCutoffPolicy::canonical();
        let r = p.decide(100, &[], 200, "").unwrap();
        assert!(matches!(r, CutoffReason::WallTimeExceeded { .. }));
    }

    #[test]
    fn stop_sequence_trips() {
        let p = LlmStreamCutoffPolicy::canonical();
        let r = p.decide(100, &[], 10, "tail ends </s> here").unwrap();
        assert!(matches!(r, CutoffReason::StopSequence { .. }));
    }

    #[test]
    fn repetition_trips_when_all_same() {
        let p = LlmStreamCutoffPolicy::canonical();
        let tokens = vec![42u32; 16];
        let r = p.decide(100, &tokens, 10, "").unwrap();
        assert!(matches!(r, CutoffReason::RepetitionTrip { window: 16 }));
    }

    #[test]
    fn repetition_does_not_trip_when_mixed() {
        let p = LlmStreamCutoffPolicy::canonical();
        let mut tokens = vec![42u32; 15];
        tokens.push(43);
        assert!(p.decide(100, &tokens, 10, "").is_none());
    }

    #[test]
    fn repetition_disabled_when_window_zero() {
        let mut p = LlmStreamCutoffPolicy::canonical();
        p.repeat_window_tokens = 0;
        let tokens = vec![42u32; 100];
        assert!(p.decide(100, &tokens, 10, "").is_none());
    }

    #[test]
    fn max_tokens_zero_rejected() {
        let mut p = LlmStreamCutoffPolicy::canonical();
        p.max_tokens = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            CutoffError::MaxTokensZero
        ));
    }

    #[test]
    fn wall_zero_rejected() {
        let mut p = LlmStreamCutoffPolicy::canonical();
        p.max_wall_seconds = 0;
        assert!(matches!(p.validate().unwrap_err(), CutoffError::WallZero));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = LlmStreamCutoffPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            CutoffError::SchemaMismatch
        ));
    }

    #[test]
    fn reason_serde_kebab() {
        let r = CutoffReason::MaxTokens {
            observed: 1,
            max: 0,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"kind\":\"max-tokens\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = LlmStreamCutoffPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: LlmStreamCutoffPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
