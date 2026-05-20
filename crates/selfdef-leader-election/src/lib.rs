//! `selfdef-leader-election` — lease-based leader election.
//!
//! Per `group_id`, a single leader holds a lease for `lease_ms`
//! after which it must heartbeat to renew. State:
//!   * `try_acquire(group, candidate, now, lease_ms)` — succeeds
//!     if no leader OR the previous lease expired (Acquired{epoch}
//!     vs HeldByOther{leader, until_ms}).
//!   * `heartbeat(group, leader, now, lease_ms)` — succeeds only
//!     for the current leader; returns Renewed / NotLeader.
//!   * `step_down(group, leader)` — voluntary release.
//!   * `current(group, now)` — Some((leader, expires)) iff held + not
//!     expired.
//!
//! Epoch increments each time a new leader takes over.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One group's election state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Current leader.
    pub leader: String,
    /// Epoch (increments on each new acquisition).
    pub epoch: u64,
    /// Lease expires.
    pub lease_expires_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaderElection {
    /// Schema version.
    pub schema_version: String,
    /// group → group state.
    pub groups: BTreeMap<String, Group>,
}

/// Acquire verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AcquireVerdict {
    /// Acquired.
    Acquired {
        /// epoch.
        epoch: u64,
    },
    /// Self-renew (caller was already leader).
    SelfRenew {
        /// epoch.
        epoch: u64,
    },
    /// Held by another.
    HeldByOther {
        /// leader.
        leader: String,
        /// until.
        until_ms: u64,
    },
}

/// Heartbeat verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HeartbeatVerdict {
    /// Renewed.
    Renewed {
        /// new expiry.
        lease_expires_ms: u64,
    },
    /// Caller is not the current leader.
    NotLeader {
        /// current leader.
        current_leader: Option<String>,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum ElectionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty group.
    #[error("group empty")]
    EmptyGroup,
    /// Empty candidate.
    #[error("candidate empty")]
    EmptyCandidate,
    /// Zero lease.
    #[error("lease_ms must be > 0")]
    ZeroLease,
}

impl LeaderElection {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            groups: BTreeMap::new(),
        }
    }

    /// Try to acquire.
    pub fn try_acquire(&mut self, group: &str, candidate: &str, now_ms: u64, lease_ms: u64) -> Result<AcquireVerdict, ElectionError> {
        if group.is_empty() { return Err(ElectionError::EmptyGroup); }
        if candidate.is_empty() { return Err(ElectionError::EmptyCandidate); }
        if lease_ms == 0 { return Err(ElectionError::ZeroLease); }
        let entry = self.groups.get(group).cloned();
        match entry {
            None => {
                let g = Group { leader: candidate.into(), epoch: 1, lease_expires_ms: now_ms.saturating_add(lease_ms) };
                let epoch = g.epoch;
                self.groups.insert(group.into(), g);
                Ok(AcquireVerdict::Acquired { epoch })
            }
            Some(g) => {
                if g.leader == candidate {
                    let new_g = Group { leader: g.leader, epoch: g.epoch, lease_expires_ms: now_ms.saturating_add(lease_ms) };
                    let epoch = new_g.epoch;
                    self.groups.insert(group.into(), new_g);
                    Ok(AcquireVerdict::SelfRenew { epoch })
                } else if now_ms >= g.lease_expires_ms {
                    // Other leader's lease expired — take over.
                    let new_g = Group { leader: candidate.into(), epoch: g.epoch.saturating_add(1), lease_expires_ms: now_ms.saturating_add(lease_ms) };
                    let epoch = new_g.epoch;
                    self.groups.insert(group.into(), new_g);
                    Ok(AcquireVerdict::Acquired { epoch })
                } else {
                    Ok(AcquireVerdict::HeldByOther { leader: g.leader, until_ms: g.lease_expires_ms })
                }
            }
        }
    }

    /// Heartbeat.
    pub fn heartbeat(&mut self, group: &str, leader: &str, now_ms: u64, lease_ms: u64) -> Result<HeartbeatVerdict, ElectionError> {
        if group.is_empty() { return Err(ElectionError::EmptyGroup); }
        if leader.is_empty() { return Err(ElectionError::EmptyCandidate); }
        if lease_ms == 0 { return Err(ElectionError::ZeroLease); }
        let Some(g) = self.groups.get_mut(group) else {
            return Ok(HeartbeatVerdict::NotLeader { current_leader: None });
        };
        if g.leader != leader || now_ms >= g.lease_expires_ms {
            return Ok(HeartbeatVerdict::NotLeader {
                current_leader: if now_ms >= g.lease_expires_ms { None } else { Some(g.leader.clone()) },
            });
        }
        g.lease_expires_ms = now_ms.saturating_add(lease_ms);
        Ok(HeartbeatVerdict::Renewed { lease_expires_ms: g.lease_expires_ms })
    }

    /// Voluntary step down.
    pub fn step_down(&mut self, group: &str, leader: &str) -> bool {
        let Some(g) = self.groups.get(group) else { return false; };
        if g.leader != leader { return false; }
        self.groups.remove(group);
        true
    }

    /// Current leader if any (None if expired).
    pub fn current(&self, group: &str, now_ms: u64) -> Option<(String, u64)> {
        let g = self.groups.get(group)?;
        if now_ms >= g.lease_expires_ms { return None; }
        Some((g.leader.clone(), g.lease_expires_ms))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ElectionError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ElectionError::SchemaMismatch); }
        for (id, g) in &self.groups {
            if id.is_empty() { return Err(ElectionError::EmptyGroup); }
            if g.leader.is_empty() { return Err(ElectionError::EmptyCandidate); }
        }
        Ok(())
    }
}

impl Default for LeaderElection {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_acquire() {
        let mut e = LeaderElection::new();
        match e.try_acquire("g", "alice", 0, 1000).unwrap() {
            AcquireVerdict::Acquired { epoch } => assert_eq!(epoch, 1),
            _ => panic!(),
        }
    }

    #[test]
    fn self_renew_same_epoch() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        match e.try_acquire("g", "alice", 500, 1000).unwrap() {
            AcquireVerdict::SelfRenew { epoch } => assert_eq!(epoch, 1),
            _ => panic!(),
        }
    }

    #[test]
    fn held_by_other_during_lease() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        match e.try_acquire("g", "bob", 500, 1000).unwrap() {
            AcquireVerdict::HeldByOther { leader, until_ms } => {
                assert_eq!(leader, "alice");
                assert_eq!(until_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn takeover_after_lease_expires() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        match e.try_acquire("g", "bob", 5000, 1000).unwrap() {
            AcquireVerdict::Acquired { epoch } => assert_eq!(epoch, 2),
            _ => panic!(),
        }
    }

    #[test]
    fn heartbeat_renews() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        match e.heartbeat("g", "alice", 500, 1000).unwrap() {
            HeartbeatVerdict::Renewed { lease_expires_ms } => assert_eq!(lease_expires_ms, 1500),
            _ => panic!(),
        }
    }

    #[test]
    fn heartbeat_from_non_leader_rejected() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        match e.heartbeat("g", "bob", 500, 1000).unwrap() {
            HeartbeatVerdict::NotLeader { current_leader } => assert_eq!(current_leader.as_deref(), Some("alice")),
            _ => panic!(),
        }
    }

    #[test]
    fn step_down() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        assert!(e.step_down("g", "alice"));
        assert!(e.current("g", 100).is_none());
        // Now bob can acquire fresh.
        match e.try_acquire("g", "bob", 100, 1000).unwrap() {
            AcquireVerdict::Acquired { epoch } => assert_eq!(epoch, 1),
            _ => panic!(),
        }
    }

    #[test]
    fn step_down_wrong_caller_noop() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        assert!(!e.step_down("g", "bob"));
        assert!(e.current("g", 100).is_some());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut e = LeaderElection::new();
        assert!(matches!(e.try_acquire("", "a", 0, 1).unwrap_err(), ElectionError::EmptyGroup));
        assert!(matches!(e.try_acquire("g", "", 0, 1).unwrap_err(), ElectionError::EmptyCandidate));
        assert!(matches!(e.try_acquire("g", "a", 0, 0).unwrap_err(), ElectionError::ZeroLease));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = LeaderElection::new();
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), ElectionError::SchemaMismatch));
    }

    #[test]
    fn election_serde_roundtrip() {
        let mut e = LeaderElection::new();
        e.try_acquire("g", "alice", 0, 1000).unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: LeaderElection = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
