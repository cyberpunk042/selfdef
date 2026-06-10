//! `selfdef-llm-token-throttle` — per-Profile LLM token-per-minute throttle.
//!
//! Each Profile carries a rolling window width (default 60 000 ms) and a
//! `window_token_budget`. `consume()` accounts a prompt+completion token
//! cost and returns `Granted` or `Throttled { retry_after_ms }`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Per-Profile token throttle config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileTokens {
    /// Window width (ms).
    pub window_ms: u64,
    /// Total prompt+completion tokens allowed within the window.
    pub window_token_budget: u64,
}

/// One token consumption record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRecord {
    /// monotonic ts ms.
    pub ts_ms: u64,
    /// total tokens (prompt + completion).
    pub tokens: u64,
    /// profile.
    pub profile: Profile,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmTokenThrottle {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileTokens>,
    /// Outstanding records.
    pub records: Vec<TokenRecord>,
}

/// Consumption verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConsumeVerdict {
    /// Recorded.
    Granted,
    /// Window budget exhausted; oldest record falls out in retry_after_ms.
    Throttled {
        /// ms until oldest in-window record expires.
        retry_after_ms: u64,
        /// observed in-window + requested.
        would_total: u64,
        /// budget.
        budget: u64,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ThrottleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl LlmTokenThrottle {
    /// Canonical defaults (1-minute windows).
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        let m: u64 = 60_000;
        profiles.insert(
            Profile::Private,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 20_000,
            },
        );
        profiles.insert(
            Profile::Fast,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 80_000,
            },
        );
        profiles.insert(
            Profile::Careful,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 40_000,
            },
        );
        profiles.insert(
            Profile::Autonomous,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 120_000,
            },
        );
        profiles.insert(
            Profile::Experimental,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 240_000,
            },
        );
        profiles.insert(
            Profile::Production,
            ProfileTokens {
                window_ms: m,
                window_token_budget: 60_000,
            },
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            records: Vec::new(),
        }
    }

    /// Trim records older than the largest configured window prior to `now_ms`.
    pub fn rotate(&mut self, now_ms: u64) {
        let max_window = self
            .profiles
            .values()
            .map(|p| p.window_ms)
            .max()
            .unwrap_or(0);
        let cutoff = now_ms.saturating_sub(max_window);
        self.records.retain(|r| r.ts_ms >= cutoff);
    }

    fn in_window(&self, profile: Profile, cfg: &ProfileTokens, now_ms: u64) -> (u64, Option<u64>) {
        let cutoff = now_ms.saturating_sub(cfg.window_ms);
        let mut sum = 0u64;
        let mut oldest_in: Option<u64> = None;
        for r in &self.records {
            if r.profile == profile && r.ts_ms >= cutoff && r.ts_ms <= now_ms {
                sum = sum.saturating_add(r.tokens);
                if oldest_in.is_none_or(|x| r.ts_ms < x) {
                    oldest_in = Some(r.ts_ms);
                }
            }
        }
        (sum, oldest_in)
    }

    /// Account for `tokens` at `now_ms`.
    pub fn consume(
        &mut self,
        profile: Profile,
        tokens: u64,
        now_ms: u64,
    ) -> Result<ConsumeVerdict, ThrottleError> {
        if let Some(last) = self.records.last() {
            if now_ms < last.ts_ms {
                return Err(ThrottleError::NonMonotonic {
                    prev: last.ts_ms,
                    new: now_ms,
                });
            }
        }
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return Ok(ConsumeVerdict::Unconfigured),
        };
        // Self-bound the record set. `consume` is the per-LLM-call hot path;
        // without this it appends a record on every grant and never trims, so a
        // long-running daemon that calls `consume` but forgets the separate
        // public `rotate` would grow `records` without bound AND make
        // `in_window` (a full scan) O(n) per call — O(n²) overall. Rotating
        // here drops only records older than the largest configured window,
        // which are outside every profile's window and so never contribute to
        // any `in_window` sum: verdicts are unchanged, memory and scan cost are
        // bounded to the in-window working set. `rotate` stays public for
        // explicit callers.
        self.rotate(now_ms);
        let (used, oldest_in) = self.in_window(profile, &cfg, now_ms);
        let would = used.saturating_add(tokens);
        if would > cfg.window_token_budget {
            let retry_after_ms = match oldest_in {
                Some(t) => cfg
                    .window_ms
                    .saturating_sub(now_ms.saturating_sub(t))
                    .saturating_add(1),
                None => 0,
            };
            return Ok(ConsumeVerdict::Throttled {
                retry_after_ms,
                would_total: would,
                budget: cfg.window_token_budget,
            });
        }
        self.records.push(TokenRecord {
            ts_ms: now_ms,
            tokens,
            profile,
        });
        Ok(ConsumeVerdict::Granted)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ThrottleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ThrottleError::SchemaMismatch);
        }
        let mut last = 0u64;
        for r in &self.records {
            if r.ts_ms < last {
                return Err(ThrottleError::NonMonotonic {
                    prev: last,
                    new: r.ts_ms,
                });
            }
            last = r.ts_ms;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        LlmTokenThrottle::canonical().validate().unwrap();
    }

    #[test]
    fn grant_under_budget() {
        let mut t = LlmTokenThrottle::canonical();
        assert!(matches!(
            t.consume(Profile::Fast, 1000, 0).unwrap(),
            ConsumeVerdict::Granted
        ));
    }

    #[test]
    fn throttle_when_over() {
        let mut t = LlmTokenThrottle::canonical();
        // Production budget 60k.
        assert!(matches!(
            t.consume(Profile::Production, 60_000, 0).unwrap(),
            ConsumeVerdict::Granted
        ));
        let v = t.consume(Profile::Production, 1, 1).unwrap();
        match v {
            ConsumeVerdict::Throttled {
                retry_after_ms,
                would_total,
                budget,
            } => {
                assert_eq!(would_total, 60_001);
                assert_eq!(budget, 60_000);
                // Oldest record at 0, now at 1, window 60_000 → retry in ~60_000.
                assert!(retry_after_ms > 59_000 && retry_after_ms <= 60_001);
            }
            _ => panic!("expected throttled"),
        }
    }

    #[test]
    fn unconfigured_profile() {
        let mut t = LlmTokenThrottle::canonical();
        t.profiles.clear();
        assert!(matches!(
            t.consume(Profile::Fast, 10, 0).unwrap(),
            ConsumeVerdict::Unconfigured
        ));
    }

    #[test]
    fn window_slides_free_budget() {
        let mut t = LlmTokenThrottle::canonical();
        t.consume(Profile::Production, 60_000, 0).unwrap();
        // 61 seconds later, the record is out of window.
        assert!(matches!(
            t.consume(Profile::Production, 1, 61_000).unwrap(),
            ConsumeVerdict::Granted
        ));
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut t = LlmTokenThrottle::canonical();
        t.consume(Profile::Fast, 10, 100).unwrap();
        assert!(matches!(
            t.consume(Profile::Fast, 10, 50).unwrap_err(),
            ThrottleError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn consume_self_bounds_records_without_explicit_rotate() {
        // The per-call hot path must not leak: consuming repeatedly, each call
        // more than the max window after the last, must keep `records` bounded
        // even though the caller never invokes `rotate` itself.
        let mut t = LlmTokenThrottle::canonical();
        for i in 0..1000u64 {
            let now = i * 120_000; // 2 minutes apart > 60s max window
            assert!(matches!(
                t.consume(Profile::Fast, 100, now).unwrap(),
                ConsumeVerdict::Granted
            ));
        }
        assert!(
            t.records.len() < 5,
            "records self-bounded by consume (was {})",
            t.records.len()
        );
    }

    #[test]
    fn rotate_drops_old() {
        let mut t = LlmTokenThrottle::canonical();
        t.consume(Profile::Fast, 100, 0).unwrap();
        t.rotate(120_000);
        assert!(t.records.is_empty());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = LlmTokenThrottle::canonical();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            ThrottleError::SchemaMismatch
        ));
    }

    #[test]
    fn throttle_serde_roundtrip() {
        let mut t = LlmTokenThrottle::canonical();
        t.consume(Profile::Fast, 500, 0).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: LlmTokenThrottle = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
