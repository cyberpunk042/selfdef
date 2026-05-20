//! `selfdef-tool-output-byte-quota` — single-invocation output byte budget.
//!
//! Each Profile carries `warn_bytes` and `hard_bytes`. The caller
//! `start_invocation()` to get an `InvocationId`, then `admit_chunk(id,
//! bytes)` per chunk. Verdict:
//!
//!   * `Accept` — under warn.
//!   * `Truncate { kept }` — at-or-above warn, below hard; the caller
//!     is told how many bytes of this chunk to keep so the running
//!     total stays at warn_bytes.
//!   * `Reject` — would exceed hard; chunk is dropped.
//!
//! `finish(id)` discards the per-id ledger entry.
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

/// Per-Profile config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileBytes {
    /// Soft threshold; truncate above this.
    pub warn_bytes: u64,
    /// Hard threshold; reject any chunk that would cross this.
    pub hard_bytes: u64,
}

/// One in-flight invocation's ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationLedger {
    /// id.
    pub id: u64,
    /// profile.
    pub profile: Profile,
    /// running total bytes admitted (including truncated keeps).
    pub admitted: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolOutputByteQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileBytes>,
    /// In-flight ledgers.
    pub ledgers: Vec<InvocationLedger>,
    /// Next id.
    pub next_id: u64,
}

/// Chunk verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ChunkVerdict {
    /// Full chunk accepted.
    Accept,
    /// Partial; keep `kept` bytes.
    Truncate {
        /// bytes to retain.
        kept: u64,
    },
    /// Drop entirely.
    Reject,
    /// Profile unconfigured.
    Unconfigured,
    /// Unknown invocation id.
    UnknownInvocation,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown invocation id.
    #[error("unknown invocation id: {0}")]
    UnknownInvocation(u64),
    /// Bad thresholds.
    #[error("warn {0} > hard {1}")]
    BadThresholds(u64, u64),
}

impl ToolOutputByteQuota {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(Profile::Private, ProfileBytes { warn_bytes: 64 << 10, hard_bytes: 256 << 10 });
        profiles.insert(Profile::Fast, ProfileBytes { warn_bytes: 512 << 10, hard_bytes: 4 << 20 });
        profiles.insert(Profile::Careful, ProfileBytes { warn_bytes: 128 << 10, hard_bytes: 1 << 20 });
        profiles.insert(Profile::Autonomous, ProfileBytes { warn_bytes: 1 << 20, hard_bytes: 8 << 20 });
        profiles.insert(Profile::Experimental, ProfileBytes { warn_bytes: 4 << 20, hard_bytes: 32 << 20 });
        profiles.insert(Profile::Production, ProfileBytes { warn_bytes: 128 << 10, hard_bytes: 1 << 20 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            ledgers: Vec::new(),
            next_id: 1,
        }
    }

    /// Start an invocation.
    pub fn start_invocation(&mut self, profile: Profile) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.ledgers.push(InvocationLedger { id, profile, admitted: 0 });
        id
    }

    /// Admit a chunk.
    pub fn admit_chunk(&mut self, id: u64, bytes: u64) -> ChunkVerdict {
        let pos = match self.ledgers.iter().position(|l| l.id == id) {
            Some(p) => p,
            None => return ChunkVerdict::UnknownInvocation,
        };
        let prof = self.ledgers[pos].profile;
        let cfg = match self.profiles.get(&prof) {
            Some(c) => *c,
            None => return ChunkVerdict::Unconfigured,
        };
        let admitted = self.ledgers[pos].admitted;
        if admitted >= cfg.hard_bytes {
            return ChunkVerdict::Reject;
        }
        let would = admitted.saturating_add(bytes);
        if would <= cfg.warn_bytes {
            self.ledgers[pos].admitted = would;
            ChunkVerdict::Accept
        } else if admitted < cfg.warn_bytes {
            // Crossing warn — keep up to warn, drop the rest of this chunk.
            let kept = cfg.warn_bytes - admitted;
            self.ledgers[pos].admitted = cfg.warn_bytes;
            ChunkVerdict::Truncate { kept }
        } else if would <= cfg.hard_bytes {
            // Already past warn but under hard — treat as reject so caller
            // knows it should stop emitting; truncation already happened.
            ChunkVerdict::Reject
        } else {
            ChunkVerdict::Reject
        }
    }

    /// Finish.
    pub fn finish(&mut self, id: u64) -> Result<(), QuotaError> {
        let pos = self.ledgers.iter().position(|l| l.id == id)
            .ok_or(QuotaError::UnknownInvocation(id))?;
        self.ledgers.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuotaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QuotaError::SchemaMismatch);
        }
        for (_, p) in &self.profiles {
            if p.warn_bytes > p.hard_bytes {
                return Err(QuotaError::BadThresholds(p.warn_bytes, p.hard_bytes));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ToolOutputByteQuota::canonical().validate().unwrap();
    }

    #[test]
    fn accept_under_warn() {
        let mut q = ToolOutputByteQuota::canonical();
        let id = q.start_invocation(Profile::Fast);
        assert_eq!(q.admit_chunk(id, 1024), ChunkVerdict::Accept);
    }

    #[test]
    fn truncate_at_warn() {
        let mut q = ToolOutputByteQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileBytes { warn_bytes: 100, hard_bytes: 500 });
        let id = q.start_invocation(Profile::Fast);
        q.admit_chunk(id, 80);
        let v = q.admit_chunk(id, 50);
        assert_eq!(v, ChunkVerdict::Truncate { kept: 20 });
    }

    #[test]
    fn reject_past_warn() {
        let mut q = ToolOutputByteQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileBytes { warn_bytes: 100, hard_bytes: 500 });
        let id = q.start_invocation(Profile::Fast);
        q.admit_chunk(id, 80);
        q.admit_chunk(id, 50); // truncate to warn
        let v = q.admit_chunk(id, 10);
        assert_eq!(v, ChunkVerdict::Reject);
    }

    #[test]
    fn unknown_invocation() {
        let mut q = ToolOutputByteQuota::canonical();
        assert_eq!(q.admit_chunk(999, 1), ChunkVerdict::UnknownInvocation);
    }

    #[test]
    fn unconfigured_profile() {
        let mut q = ToolOutputByteQuota::canonical();
        let id = q.start_invocation(Profile::Fast);
        q.profiles.clear();
        assert_eq!(q.admit_chunk(id, 1), ChunkVerdict::Unconfigured);
    }

    #[test]
    fn finish_removes() {
        let mut q = ToolOutputByteQuota::canonical();
        let id = q.start_invocation(Profile::Fast);
        q.finish(id).unwrap();
        assert!(matches!(q.finish(id).unwrap_err(), QuotaError::UnknownInvocation(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = ToolOutputByteQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), QuotaError::SchemaMismatch));
    }

    #[test]
    fn bad_thresholds_rejected_on_validate() {
        let mut q = ToolOutputByteQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileBytes { warn_bytes: 1000, hard_bytes: 100 });
        assert!(matches!(q.validate().unwrap_err(), QuotaError::BadThresholds(_, _)));
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut q = ToolOutputByteQuota::canonical();
        let id = q.start_invocation(Profile::Fast);
        q.admit_chunk(id, 1024);
        let j = serde_json::to_string(&q).unwrap();
        let back: ToolOutputByteQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
