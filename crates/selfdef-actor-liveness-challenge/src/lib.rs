//! `selfdef-actor-liveness-challenge` — single-use nonce challenges.
//!
//! `issue(actor, ts_ms, ttl_ms)` returns a new `Challenge { nonce,
//! issued_at_ms, expires_at_ms, actor }`. The nonce is a monotonic
//! u64; we don't pretend to provide cryptographic randomness here —
//! that's the caller's job to wrap. `verify(actor, nonce, ts_ms)`
//! returns:
//!   * `Verified` — nonce matched, not expired, consumed.
//!   * `Expired` — issued but past expiry.
//!   * `AlreadyUsed` — nonce consumed previously.
//!   * `Unknown` — no such challenge for this actor.
//!   * `WrongActor` — challenge exists but for a different actor.
//!
//! Consumed nonces are retained in the history map (so replay is
//! detectable) until `prune(now)` drops entries older than the
//! configured `history_retention_ms`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One issued challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    /// Nonce.
    pub nonce: u64,
    /// Actor id.
    pub actor: String,
    /// Issued ts.
    pub issued_at_ms: u64,
    /// Expires ts.
    pub expires_at_ms: u64,
    /// Consumed?
    pub consumed: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorLivenessChallenge {
    /// Schema version.
    pub schema_version: String,
    /// Retention for consumed entries.
    pub history_retention_ms: u64,
    /// nonce → challenge.
    pub challenges: BTreeMap<u64, Challenge>,
    /// Next nonce.
    pub next_nonce: u64,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VerifyVerdict {
    /// Verified.
    Verified,
    /// Expired.
    Expired,
    /// Already used.
    AlreadyUsed,
    /// Unknown nonce.
    Unknown,
    /// Wrong actor.
    WrongActor {
        /// expected.
        expected_actor: String,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Zero ttl.
    #[error("ttl must be > 0")]
    ZeroTtl,
}

impl ActorLivenessChallenge {
    /// New.
    pub fn new(history_retention_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            history_retention_ms,
            challenges: BTreeMap::new(),
            next_nonce: 1,
        }
    }

    /// Issue.
    pub fn issue(
        &mut self,
        actor: &str,
        ts_ms: u64,
        ttl_ms: u64,
    ) -> Result<Challenge, ChallengeError> {
        if actor.is_empty() {
            return Err(ChallengeError::EmptyActor);
        }
        if ttl_ms == 0 {
            return Err(ChallengeError::ZeroTtl);
        }
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        let c = Challenge {
            nonce,
            actor: actor.into(),
            issued_at_ms: ts_ms,
            expires_at_ms: ts_ms.saturating_add(ttl_ms),
            consumed: false,
        };
        self.challenges.insert(nonce, c.clone());
        Ok(c)
    }

    /// Verify.
    pub fn verify(&mut self, actor: &str, nonce: u64, ts_ms: u64) -> VerifyVerdict {
        let Some(c) = self.challenges.get_mut(&nonce) else {
            return VerifyVerdict::Unknown;
        };
        if c.actor != actor {
            return VerifyVerdict::WrongActor {
                expected_actor: c.actor.clone(),
            };
        }
        if c.consumed {
            return VerifyVerdict::AlreadyUsed;
        }
        if ts_ms > c.expires_at_ms {
            return VerifyVerdict::Expired;
        }
        c.consumed = true;
        VerifyVerdict::Verified
    }

    /// Prune consumed entries older than retention.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(self.history_retention_ms);
        let to_drop: Vec<u64> = self
            .challenges
            .iter()
            .filter(|(_, c)| c.consumed && c.issued_at_ms < cutoff)
            .map(|(k, _)| *k)
            .collect();
        let n = to_drop.len();
        for k in to_drop {
            self.challenges.remove(&k);
        }
        n
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ChallengeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ChallengeError::SchemaMismatch);
        }
        for c in self.challenges.values() {
            if c.actor.is_empty() {
                return Err(ChallengeError::EmptyActor);
            }
        }
        Ok(())
    }
}

impl Default for ActorLivenessChallenge {
    fn default() -> Self {
        Self::new(3_600_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_verify() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        let ch = c.issue("alice", 0, 1000).unwrap();
        assert_eq!(c.verify("alice", ch.nonce, 500), VerifyVerdict::Verified);
    }

    #[test]
    fn replay_detected() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        let ch = c.issue("alice", 0, 1000).unwrap();
        c.verify("alice", ch.nonce, 100);
        assert_eq!(c.verify("alice", ch.nonce, 200), VerifyVerdict::AlreadyUsed);
    }

    #[test]
    fn expired_after_ttl() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        let ch = c.issue("alice", 0, 1000).unwrap();
        assert_eq!(c.verify("alice", ch.nonce, 2000), VerifyVerdict::Expired);
    }

    #[test]
    fn wrong_actor() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        let ch = c.issue("alice", 0, 1000).unwrap();
        match c.verify("bob", ch.nonce, 100) {
            VerifyVerdict::WrongActor { expected_actor } => assert_eq!(expected_actor, "alice"),
            _ => panic!(),
        }
        // The challenge should remain unconsumed for the legit actor.
        assert_eq!(c.verify("alice", ch.nonce, 200), VerifyVerdict::Verified);
    }

    #[test]
    fn unknown_nonce() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        assert_eq!(c.verify("alice", 999, 0), VerifyVerdict::Unknown);
    }

    #[test]
    fn nonces_monotonic() {
        let mut c = ActorLivenessChallenge::new(1_000_000);
        let a = c.issue("alice", 0, 1000).unwrap();
        let b = c.issue("alice", 0, 1000).unwrap();
        assert_eq!(b.nonce, a.nonce + 1);
    }

    #[test]
    fn prune_drops_old_consumed() {
        let mut c = ActorLivenessChallenge::new(1000);
        let ch1 = c.issue("alice", 0, 100).unwrap();
        c.verify("alice", ch1.nonce, 50);
        // ch2 issued recently (within retention).
        let ch2 = c.issue("alice", 9500, 100).unwrap();
        c.verify("alice", ch2.nonce, 9550);
        // now = 10_000, cutoff = 9000. ch1 (0) < 9000 → prune; ch2 (9500) >= 9000 → keep.
        let n = c.prune(10_000);
        assert_eq!(n, 1);
        assert!(c.challenges.contains_key(&ch2.nonce));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut c = ActorLivenessChallenge::new(1000);
        assert!(matches!(
            c.issue("", 0, 1).unwrap_err(),
            ChallengeError::EmptyActor
        ));
    }

    #[test]
    fn zero_ttl_rejected() {
        let mut c = ActorLivenessChallenge::new(1000);
        assert!(matches!(
            c.issue("a", 0, 0).unwrap_err(),
            ChallengeError::ZeroTtl
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ActorLivenessChallenge::new(1000);
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            ChallengeError::SchemaMismatch
        ));
    }

    #[test]
    fn challenge_serde_roundtrip() {
        let mut c = ActorLivenessChallenge::new(1000);
        let ch = c.issue("alice", 0, 1000).unwrap();
        c.verify("alice", ch.nonce, 100);
        let j = serde_json::to_string(&c).unwrap();
        let back: ActorLivenessChallenge = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
