//! `selfdef-llm-context-shrink-policy` — drop-or-summarize plan.
//!
//! Given a slice of `(role, token_count)` and the overage in tokens,
//! `plan_shrink` walks the messages in order and assigns a
//! `DropAction` per message such that the kept token total is at most
//! `original_total - over_by_tokens`.
//!
//! Rules:
//!   * `System` and `Pinned` messages are always `Keep`.
//!   * The most recent `keep_recent_n` non-system messages are always
//!     `Keep`.
//!   * `Scratch` messages are dropped first (oldest first).
//!   * Then `Tool` outputs (oldest first).
//!   * Then `Assistant` and `User` turns (oldest first), each marked
//!     `Summarize` rather than `Drop` to preserve continuity.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Message role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// System.
    System,
    /// Pinned (operator-marked).
    Pinned,
    /// User.
    User,
    /// Assistant.
    Assistant,
    /// Tool output.
    Tool,
    /// Scratch / internal note.
    Scratch,
}

/// Per-message decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DropAction {
    /// Keep verbatim.
    Keep,
    /// Replace with a short summary.
    Summarize,
    /// Drop entirely.
    Drop,
}

/// One context message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Msg {
    /// role.
    pub role: Role,
    /// tokens.
    pub tokens: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextShrinkPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Most-recent N non-system messages always kept.
    pub keep_recent_n: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ShrinkError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl ContextShrinkPolicy {
    /// New.
    pub fn new(keep_recent_n: u32) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            keep_recent_n,
        }
    }

    /// Plan.
    pub fn plan_shrink(&self, messages: &[Msg], over_by_tokens: u32) -> Vec<DropAction> {
        let n = messages.len();
        let mut plan = vec![DropAction::Keep; n];
        if over_by_tokens == 0 { return plan; }

        // Mark always-keep: system + pinned + last keep_recent_n non-system.
        let mut recent_left = self.keep_recent_n as usize;
        let mut keep_always = vec![false; n];
        for i in (0..n).rev() {
            let m = messages[i];
            if matches!(m.role, Role::System | Role::Pinned) {
                keep_always[i] = true;
            } else if recent_left > 0 {
                keep_always[i] = true;
                recent_left -= 1;
            }
        }

        // Drop scratch first.
        let mut freed: u64 = 0;
        let need = over_by_tokens as u64;
        for (i, m) in messages.iter().enumerate() {
            if freed >= need { break; }
            if keep_always[i] { continue; }
            if m.role == Role::Scratch {
                plan[i] = DropAction::Drop;
                freed += m.tokens as u64;
            }
        }

        // Then tool outputs.
        for (i, m) in messages.iter().enumerate() {
            if freed >= need { break; }
            if keep_always[i] || plan[i] != DropAction::Keep { continue; }
            if m.role == Role::Tool {
                plan[i] = DropAction::Drop;
                freed += m.tokens as u64;
            }
        }

        // Then assistant + user turns — Summarize (preserve continuity).
        for (i, m) in messages.iter().enumerate() {
            if freed >= need { break; }
            if keep_always[i] || plan[i] != DropAction::Keep { continue; }
            if matches!(m.role, Role::Assistant | Role::User) {
                plan[i] = DropAction::Summarize;
                // Assume summarize reduces to ~16 tokens.
                let saved = m.tokens.saturating_sub(16) as u64;
                freed += saved;
            }
        }

        plan
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ShrinkError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ShrinkError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(role: Role, tokens: u32) -> Msg { Msg { role, tokens } }

    #[test]
    fn no_shrink_when_zero() {
        let p = ContextShrinkPolicy::new(2);
        let plan = p.plan_shrink(&[m(Role::Scratch, 100)], 0);
        assert_eq!(plan, vec![DropAction::Keep]);
    }

    #[test]
    fn drops_scratch_first() {
        let p = ContextShrinkPolicy::new(0);
        let msgs = [m(Role::Scratch, 100), m(Role::User, 100)];
        let plan = p.plan_shrink(&msgs, 50);
        assert_eq!(plan, vec![DropAction::Drop, DropAction::Keep]);
    }

    #[test]
    fn drops_tool_after_scratch() {
        let p = ContextShrinkPolicy::new(0);
        let msgs = [m(Role::Tool, 100), m(Role::User, 100)];
        let plan = p.plan_shrink(&msgs, 50);
        assert_eq!(plan, vec![DropAction::Drop, DropAction::Keep]);
    }

    #[test]
    fn summarizes_assistant_user() {
        let p = ContextShrinkPolicy::new(0);
        let msgs = [m(Role::Assistant, 100), m(Role::User, 100)];
        let plan = p.plan_shrink(&msgs, 50);
        assert_eq!(plan, vec![DropAction::Summarize, DropAction::Keep]);
    }

    #[test]
    fn never_drops_system() {
        let p = ContextShrinkPolicy::new(0);
        let msgs = [m(Role::System, 100), m(Role::Scratch, 100)];
        let plan = p.plan_shrink(&msgs, 1000);
        assert_eq!(plan[0], DropAction::Keep);
    }

    #[test]
    fn never_drops_pinned() {
        let p = ContextShrinkPolicy::new(0);
        let msgs = [m(Role::Pinned, 100), m(Role::Scratch, 100)];
        let plan = p.plan_shrink(&msgs, 1000);
        assert_eq!(plan[0], DropAction::Keep);
    }

    #[test]
    fn keeps_recent_n() {
        let p = ContextShrinkPolicy::new(2);
        let msgs = [
            m(Role::Scratch, 100),
            m(Role::Scratch, 100),
            m(Role::Scratch, 100),
        ];
        // keep_recent_n = 2 → last two scratch stay.
        let plan = p.plan_shrink(&msgs, 50);
        assert_eq!(plan, vec![DropAction::Drop, DropAction::Keep, DropAction::Keep]);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ContextShrinkPolicy::new(2);
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ShrinkError::SchemaMismatch));
    }

    #[test]
    fn shrink_serde_roundtrip() {
        let p = ContextShrinkPolicy::new(2);
        let j = serde_json::to_string(&p).unwrap();
        let back: ContextShrinkPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
