//! `selfdef-llm-prompt-cache-policy` — cache vs no-cache per kind.
//!
//! Each (Profile, PromptKind) carries a `Decision`. `classify(profile,
//! kind, contains_secret)` returns the configured Decision unless
//! `contains_secret=true`, in which case the result is forced to
//! `NoCache { reason: SecretLeakRisk }`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
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

/// Prompt kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromptKind {
    /// System prompt.
    System,
    /// Tool-call output stitched into context.
    ToolOutput,
    /// Operator turn.
    UserTurn,
    /// Pinned reference doc.
    Pinned,
    /// Scratch / chain-of-thought.
    Scratch,
}

/// Configured decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Decision {
    /// Cache.
    Cache {
        /// ttl ms.
        ttl_ms: u64,
    },
    /// Don't cache.
    NoCache {
        /// reason label.
        reason: NoCacheReason,
    },
}

/// No-cache reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoCacheReason {
    /// Policy says don't cache for this profile/kind.
    PolicyDeny,
    /// Secret detected upstream → never cache.
    SecretLeakRisk,
    /// Caching hasn't been configured.
    Unconfigured,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmPromptCachePolicy {
    /// Schema version.
    pub schema_version: String,
    /// (profile → kind → decision).
    pub decisions: BTreeMap<Profile, BTreeMap<PromptKind, Decision>>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Verdict {
    /// Cache for ttl_ms.
    Cache {
        /// ttl ms.
        ttl_ms: u64,
    },
    /// Don't cache.
    NoCache {
        /// reason.
        reason: NoCacheReason,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl LlmPromptCachePolicy {
    /// Canonical.
    pub fn canonical() -> Self {
        use Decision::*;
        use NoCacheReason::*;
        use PromptKind::*;
        let m = |pairs: &[(PromptKind, Decision)]| -> BTreeMap<PromptKind, Decision> {
            pairs.iter().copied().collect()
        };
        let mut p = BTreeMap::new();
        p.insert(Profile::Private, m(&[
            (System, NoCache { reason: PolicyDeny }),
            (ToolOutput, NoCache { reason: PolicyDeny }),
            (UserTurn, NoCache { reason: PolicyDeny }),
            (Pinned, Cache { ttl_ms: 60 * 60 * 1000 }),
            (Scratch, NoCache { reason: PolicyDeny }),
        ]));
        p.insert(Profile::Fast, m(&[
            (System, Cache { ttl_ms: 30 * 60 * 1000 }),
            (ToolOutput, Cache { ttl_ms: 5 * 60 * 1000 }),
            (UserTurn, NoCache { reason: PolicyDeny }),
            (Pinned, Cache { ttl_ms: 60 * 60 * 1000 }),
            (Scratch, NoCache { reason: PolicyDeny }),
        ]));
        p.insert(Profile::Careful, m(&[
            (System, Cache { ttl_ms: 10 * 60 * 1000 }),
            (ToolOutput, NoCache { reason: PolicyDeny }),
            (UserTurn, NoCache { reason: PolicyDeny }),
            (Pinned, Cache { ttl_ms: 60 * 60 * 1000 }),
            (Scratch, NoCache { reason: PolicyDeny }),
        ]));
        p.insert(Profile::Autonomous, m(&[
            (System, Cache { ttl_ms: 60 * 60 * 1000 }),
            (ToolOutput, Cache { ttl_ms: 10 * 60 * 1000 }),
            (UserTurn, Cache { ttl_ms: 2 * 60 * 1000 }),
            (Pinned, Cache { ttl_ms: 60 * 60 * 1000 }),
            (Scratch, NoCache { reason: PolicyDeny }),
        ]));
        p.insert(Profile::Experimental, m(&[
            (System, Cache { ttl_ms: 6 * 60 * 60 * 1000 }),
            (ToolOutput, Cache { ttl_ms: 60 * 60 * 1000 }),
            (UserTurn, Cache { ttl_ms: 30 * 60 * 1000 }),
            (Pinned, Cache { ttl_ms: 6 * 60 * 60 * 1000 }),
            (Scratch, Cache { ttl_ms: 5 * 60 * 1000 }),
        ]));
        p.insert(Profile::Production, m(&[
            (System, Cache { ttl_ms: 30 * 60 * 1000 }),
            (ToolOutput, Cache { ttl_ms: 5 * 60 * 1000 }),
            (UserTurn, NoCache { reason: PolicyDeny }),
            (Pinned, Cache { ttl_ms: 60 * 60 * 1000 }),
            (Scratch, NoCache { reason: PolicyDeny }),
        ]));
        Self {
            schema_version: SCHEMA_VERSION.into(),
            decisions: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, kind: PromptKind, contains_secret: bool) -> Verdict {
        if contains_secret {
            return Verdict::NoCache { reason: NoCacheReason::SecretLeakRisk };
        }
        let by_kind = match self.decisions.get(&profile) {
            Some(m) => m,
            None => return Verdict::NoCache { reason: NoCacheReason::Unconfigured },
        };
        match by_kind.get(&kind).copied() {
            Some(Decision::Cache { ttl_ms }) => Verdict::Cache { ttl_ms },
            Some(Decision::NoCache { reason }) => Verdict::NoCache { reason },
            None => Verdict::NoCache { reason: NoCacheReason::Unconfigured },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CacheError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        LlmPromptCachePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn secret_always_blocks() {
        let p = LlmPromptCachePolicy::canonical();
        let v = p.classify(Profile::Autonomous, PromptKind::System, true);
        assert_eq!(v, Verdict::NoCache { reason: NoCacheReason::SecretLeakRisk });
    }

    #[test]
    fn system_caches_in_fast() {
        let p = LlmPromptCachePolicy::canonical();
        match p.classify(Profile::Fast, PromptKind::System, false) {
            Verdict::Cache { ttl_ms } => assert!(ttl_ms > 0),
            _ => panic!(),
        }
    }

    #[test]
    fn user_turn_no_cache_in_production() {
        let p = LlmPromptCachePolicy::canonical();
        assert_eq!(
            p.classify(Profile::Production, PromptKind::UserTurn, false),
            Verdict::NoCache { reason: NoCacheReason::PolicyDeny }
        );
    }

    #[test]
    fn private_only_pinned_caches() {
        let p = LlmPromptCachePolicy::canonical();
        assert!(matches!(p.classify(Profile::Private, PromptKind::Pinned, false), Verdict::Cache { .. }));
        for k in [PromptKind::System, PromptKind::UserTurn, PromptKind::ToolOutput, PromptKind::Scratch] {
            assert!(matches!(p.classify(Profile::Private, k, false), Verdict::NoCache { .. }));
        }
    }

    #[test]
    fn experimental_caches_scratch() {
        let p = LlmPromptCachePolicy::canonical();
        assert!(matches!(p.classify(Profile::Experimental, PromptKind::Scratch, false), Verdict::Cache { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut p = LlmPromptCachePolicy::canonical();
        p.decisions.clear();
        assert_eq!(p.classify(Profile::Fast, PromptKind::System, false),
            Verdict::NoCache { reason: NoCacheReason::Unconfigured });
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = LlmPromptCachePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), CacheError::SchemaMismatch));
    }

    #[test]
    fn cache_serde_roundtrip() {
        let p = LlmPromptCachePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: LlmPromptCachePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
