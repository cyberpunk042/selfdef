//! `selfdef-prompt-size-cap` — per-actor prompt-size limits.
//!
//! Each actor has `warn_bytes` and `hard_bytes`. `evaluate(actor,
//! bytes)` returns:
//!   * `Allow` — under warn.
//!   * `Warn { headroom_bytes }` — at/over warn but under hard.
//!   * `Reject { over_bytes }` — at/over hard.
//!   * `Unknown` — no cap configured.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-actor caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorCaps {
    /// Warn at.
    pub warn_bytes: u64,
    /// Hard at.
    pub hard_bytes: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptSizeCap {
    /// Schema version.
    pub schema_version: String,
    /// actor → caps.
    pub actors: BTreeMap<String, ActorCaps>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SizeVerdict {
    /// Allow.
    Allow,
    /// Warn.
    Warn {
        /// bytes until hard.
        headroom_bytes: u64,
    },
    /// Reject.
    Reject {
        /// bytes over hard.
        over_bytes: u64,
    },
    /// Unknown.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SizeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Bad caps.
    #[error("warn ({warn}) must be < hard ({hard})")]
    BadCaps {
        /// warn.
        warn: u64,
        /// hard.
        hard: u64,
    },
}

impl PromptSizeCap {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            actors: BTreeMap::new(),
        }
    }

    /// Set caps.
    pub fn set_caps(
        &mut self,
        actor: &str,
        warn_bytes: u64,
        hard_bytes: u64,
    ) -> Result<(), SizeError> {
        if actor.is_empty() {
            return Err(SizeError::EmptyActor);
        }
        if warn_bytes >= hard_bytes {
            return Err(SizeError::BadCaps {
                warn: warn_bytes,
                hard: hard_bytes,
            });
        }
        self.actors.insert(
            actor.into(),
            ActorCaps {
                warn_bytes,
                hard_bytes,
            },
        );
        Ok(())
    }

    /// Evaluate.
    pub fn evaluate(&self, actor: &str, bytes: u64) -> SizeVerdict {
        let Some(c) = self.actors.get(actor) else {
            return SizeVerdict::Unknown;
        };
        if bytes >= c.hard_bytes {
            SizeVerdict::Reject {
                over_bytes: bytes - c.hard_bytes,
            }
        } else if bytes >= c.warn_bytes {
            SizeVerdict::Warn {
                headroom_bytes: c.hard_bytes - bytes,
            }
        } else {
            SizeVerdict::Allow
        }
    }

    /// Remove.
    pub fn remove(&mut self, actor: &str) -> bool {
        self.actors.remove(actor).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SizeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SizeError::SchemaMismatch);
        }
        for (a, c) in &self.actors {
            if a.is_empty() {
                return Err(SizeError::EmptyActor);
            }
            if c.warn_bytes >= c.hard_bytes {
                return Err(SizeError::BadCaps {
                    warn: c.warn_bytes,
                    hard: c.hard_bytes,
                });
            }
        }
        Ok(())
    }
}

impl Default for PromptSizeCap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_under_warn() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        assert_eq!(p.evaluate("a", 500), SizeVerdict::Allow);
    }

    #[test]
    fn warn_between() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        match p.evaluate("a", 1500) {
            SizeVerdict::Warn { headroom_bytes } => assert_eq!(headroom_bytes, 500),
            _ => panic!(),
        }
    }

    #[test]
    fn reject_at_or_over_hard() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        match p.evaluate("a", 2500) {
            SizeVerdict::Reject { over_bytes } => assert_eq!(over_bytes, 500),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_actor() {
        let p = PromptSizeCap::new();
        assert_eq!(p.evaluate("nope", 100), SizeVerdict::Unknown);
    }

    #[test]
    fn warn_at_boundary() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        assert!(matches!(p.evaluate("a", 1000), SizeVerdict::Warn { .. }));
    }

    #[test]
    fn hard_at_boundary() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        assert!(matches!(
            p.evaluate("a", 2000),
            SizeVerdict::Reject { over_bytes: 0 }
        ));
    }

    #[test]
    fn bad_caps_rejected() {
        let mut p = PromptSizeCap::new();
        assert!(matches!(
            p.set_caps("a", 1000, 1000).unwrap_err(),
            SizeError::BadCaps { .. }
        ));
        assert!(matches!(
            p.set_caps("a", 2000, 1000).unwrap_err(),
            SizeError::BadCaps { .. }
        ));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut p = PromptSizeCap::new();
        assert!(matches!(
            p.set_caps("", 1, 2).unwrap_err(),
            SizeError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PromptSizeCap::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            SizeError::SchemaMismatch
        ));
    }

    #[test]
    fn cap_serde_roundtrip() {
        let mut p = PromptSizeCap::new();
        p.set_caps("a", 1000, 2000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PromptSizeCap = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
