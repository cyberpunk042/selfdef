//! `selfdef-tool-invocation-rate-limit` — per-tool token bucket.
//!
//! Each tool has (max_calls_per_minute, burst_size, last_refill_unix,
//! tokens_available). admit(tool_id, now) refills lazily before
//! consuming a token; returns Allow / Denied.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One tool's bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolBucket {
    /// Stable tool id.
    pub tool_id: String,
    /// Max calls per minute.
    pub max_per_minute: u32,
    /// Burst size (>=1).
    pub burst_size: u32,
    /// Current tokens (floating).
    pub tokens: f64,
    /// Unix second of last refill.
    pub last_refill_unix: u64,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Allowed.
    Allow,
    /// Denied — bucket empty.
    Denied,
    /// Tool not registered.
    UnknownTool,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolInvocationRateLimit {
    /// Schema version.
    pub schema_version: String,
    /// Per-tool buckets.
    pub buckets: Vec<ToolBucket>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("tool_id empty")]
    EmptyToolId,
    /// Duplicate.
    #[error("duplicate tool_id: {0}")]
    DuplicateToolId(String),
    /// max_per_minute zero.
    #[error("tool {0} max_per_minute zero")]
    MaxZero(String),
    /// burst_size zero.
    #[error("tool {0} burst_size zero")]
    BurstZero(String),
}

impl ToolInvocationRateLimit {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: Vec::new(),
        }
    }

    /// Register a tool. Initial tokens = burst_size.
    pub fn register(
        &mut self,
        tool_id: &str,
        max_per_minute: u32,
        burst_size: u32,
        now: u64,
    ) -> Result<(), RateLimitError> {
        if tool_id.is_empty() {
            return Err(RateLimitError::EmptyToolId);
        }
        if max_per_minute == 0 {
            return Err(RateLimitError::MaxZero(tool_id.into()));
        }
        if burst_size == 0 {
            return Err(RateLimitError::BurstZero(tool_id.into()));
        }
        if self.buckets.iter().any(|b| b.tool_id == tool_id) {
            return Err(RateLimitError::DuplicateToolId(tool_id.into()));
        }
        self.buckets.push(ToolBucket {
            tool_id: tool_id.into(),
            max_per_minute,
            burst_size,
            tokens: burst_size as f64,
            last_refill_unix: now,
        });
        Ok(())
    }

    /// Refill bucket lazily based on elapsed seconds since last_refill.
    fn refill(b: &mut ToolBucket, now: u64) {
        let dt = now.saturating_sub(b.last_refill_unix);
        if dt == 0 {
            return;
        }
        let rate_per_sec = b.max_per_minute as f64 / 60.0;
        let add = rate_per_sec * dt as f64;
        b.tokens = (b.tokens + add).min(b.burst_size as f64);
        b.last_refill_unix = now;
    }

    /// Try to admit a call.
    pub fn admit(&mut self, tool_id: &str, now: u64) -> AdmitDecision {
        let b = match self.buckets.iter_mut().find(|b| b.tool_id == tool_id) {
            Some(b) => b,
            None => return AdmitDecision::UnknownTool,
        };
        Self::refill(b, now);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            AdmitDecision::Allow
        } else {
            AdmitDecision::Denied
        }
    }

    /// Current available tokens for a tool (refilled to `now`).
    pub fn tokens(&mut self, tool_id: &str, now: u64) -> Option<f64> {
        let b = self.buckets.iter_mut().find(|b| b.tool_id == tool_id)?;
        Self::refill(b, now);
        Some(b.tokens)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RateLimitError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RateLimitError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for b in &self.buckets {
            if b.tool_id.is_empty() {
                return Err(RateLimitError::EmptyToolId);
            }
            if b.max_per_minute == 0 {
                return Err(RateLimitError::MaxZero(b.tool_id.clone()));
            }
            if b.burst_size == 0 {
                return Err(RateLimitError::BurstZero(b.tool_id.clone()));
            }
            if !seen.insert(b.tool_id.as_str()) {
                return Err(RateLimitError::DuplicateToolId(b.tool_id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for ToolInvocationRateLimit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tool_returns_unknown() {
        let mut p = ToolInvocationRateLimit::new();
        assert_eq!(p.admit("none", 0), AdmitDecision::UnknownTool);
    }

    #[test]
    fn burst_consumed_then_denied() {
        let mut p = ToolInvocationRateLimit::new();
        p.register("git", 60, 3, 0).unwrap();
        assert_eq!(p.admit("git", 0), AdmitDecision::Allow);
        assert_eq!(p.admit("git", 0), AdmitDecision::Allow);
        assert_eq!(p.admit("git", 0), AdmitDecision::Allow);
        assert_eq!(p.admit("git", 0), AdmitDecision::Denied);
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        let mut p = ToolInvocationRateLimit::new();
        // 60/min = 1/sec.
        p.register("git", 60, 2, 0).unwrap();
        p.admit("git", 0);
        p.admit("git", 0);
        assert_eq!(p.admit("git", 0), AdmitDecision::Denied);
        // 1 second later -> 1 token.
        assert_eq!(p.admit("git", 1), AdmitDecision::Allow);
        // 2 seconds total -> back at full.
    }

    #[test]
    fn refill_caps_at_burst() {
        let mut p = ToolInvocationRateLimit::new();
        p.register("git", 60, 2, 0).unwrap();
        // 1 hour idle -> burst would refill to absurd; cap at 2.
        let t = p.tokens("git", 3600).unwrap();
        assert!(t <= 2.0);
    }

    #[test]
    fn duplicate_tool_id_rejected() {
        let mut p = ToolInvocationRateLimit::new();
        p.register("git", 60, 1, 0).unwrap();
        assert!(matches!(
            p.register("git", 30, 1, 0).unwrap_err(),
            RateLimitError::DuplicateToolId(_)
        ));
    }

    #[test]
    fn empty_tool_id_rejected() {
        let mut p = ToolInvocationRateLimit::new();
        assert!(matches!(
            p.register("", 1, 1, 0).unwrap_err(),
            RateLimitError::EmptyToolId
        ));
    }

    #[test]
    fn zero_max_rejected() {
        let mut p = ToolInvocationRateLimit::new();
        assert!(matches!(
            p.register("a", 0, 1, 0).unwrap_err(),
            RateLimitError::MaxZero(_)
        ));
    }

    #[test]
    fn zero_burst_rejected() {
        let mut p = ToolInvocationRateLimit::new();
        assert!(matches!(
            p.register("a", 1, 0, 0).unwrap_err(),
            RateLimitError::BurstZero(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ToolInvocationRateLimit::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RateLimitError::SchemaMismatch
        ));
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&AdmitDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&AdmitDecision::UnknownTool).unwrap(),
            "\"unknown-tool\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ToolInvocationRateLimit::new();
        p.register("git", 60, 3, 0).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ToolInvocationRateLimit = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
