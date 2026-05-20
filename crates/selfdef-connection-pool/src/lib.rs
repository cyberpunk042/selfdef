//! `selfdef-connection-pool` — bounded id pool with health cooldown.
//!
//! Pool tracks {ids, in_use, idle, unhealthy_until_ms}. acquire(now)
//! returns the first idle id that is past its health cooldown (or
//! None when capacity exhausted). release(id) marks idle. mark_bad(
//! id, now, cooldown_ms) puts id in cooldown — acquire will skip it
//! until now >= unhealthy_until_ms. reap_idle(now, idle_max_ms)
//! removes ids that have been idle past idle_max_ms.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Conn state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Idle.
    Idle,
    /// In use.
    InUse,
}

/// Per-id record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conn {
    /// Phase.
    pub phase: Phase,
    /// Idle-since ts ms (or 0).
    pub idle_since_ms: u64,
    /// Earliest ok-to-use ts ms (0 = healthy).
    pub unhealthy_until_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionPool {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// id → conn.
    pub conns: BTreeMap<String, Conn>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PoolError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero cap.
    #[error("capacity must be >= 1")]
    ZeroCap,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Unknown.
    #[error("unknown id: {0}")]
    Unknown(String),
    /// Duplicate.
    #[error("duplicate id: {0}")]
    Duplicate(String),
    /// Full.
    #[error("pool full")]
    Full,
}

impl ConnectionPool {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, PoolError> {
        if capacity == 0 { return Err(PoolError::ZeroCap); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            conns: BTreeMap::new(),
        })
    }

    /// Register an id.
    pub fn add(&mut self, id: &str, now_ms: u64) -> Result<(), PoolError> {
        if id.is_empty() { return Err(PoolError::EmptyId); }
        if self.conns.contains_key(id) { return Err(PoolError::Duplicate(id.into())); }
        if self.conns.len() >= self.capacity as usize { return Err(PoolError::Full); }
        self.conns.insert(id.into(), Conn {
            phase: Phase::Idle,
            idle_since_ms: now_ms,
            unhealthy_until_ms: 0,
        });
        Ok(())
    }

    /// Acquire an idle, healthy id.
    pub fn acquire(&mut self, now_ms: u64) -> Option<String> {
        let pick = self.conns.iter()
            .find(|(_, c)| c.phase == Phase::Idle && c.unhealthy_until_ms <= now_ms)
            .map(|(id, _)| id.clone());
        if let Some(id) = pick {
            let c = self.conns.get_mut(&id).unwrap();
            c.phase = Phase::InUse;
            c.idle_since_ms = 0;
            return Some(id);
        }
        None
    }

    /// Release.
    pub fn release(&mut self, id: &str, now_ms: u64) -> Result<(), PoolError> {
        let c = self.conns.get_mut(id).ok_or_else(|| PoolError::Unknown(id.into()))?;
        c.phase = Phase::Idle;
        c.idle_since_ms = now_ms;
        Ok(())
    }

    /// Mark id unhealthy.
    pub fn mark_bad(&mut self, id: &str, now_ms: u64, cooldown_ms: u64) -> Result<(), PoolError> {
        let c = self.conns.get_mut(id).ok_or_else(|| PoolError::Unknown(id.into()))?;
        c.unhealthy_until_ms = now_ms.saturating_add(cooldown_ms);
        c.phase = Phase::Idle;
        c.idle_since_ms = now_ms;
        Ok(())
    }

    /// Reap idle ids that have been idle past idle_max_ms.
    pub fn reap_idle(&mut self, now_ms: u64, idle_max_ms: u64) -> u32 {
        let to_remove: Vec<String> = self.conns.iter()
            .filter(|(_, c)| c.phase == Phase::Idle
                && now_ms.saturating_sub(c.idle_since_ms) > idle_max_ms)
            .map(|(id, _)| id.clone())
            .collect();
        let n = to_remove.len() as u32;
        for id in to_remove { self.conns.remove(&id); }
        n
    }

    /// Counts (idle, in_use, unhealthy_now).
    pub fn counts(&self, now_ms: u64) -> (u32, u32, u32) {
        let mut idle = 0;
        let mut in_use = 0;
        let mut unhealthy = 0;
        for c in self.conns.values() {
            match c.phase {
                Phase::Idle => idle += 1,
                Phase::InUse => in_use += 1,
            }
            if c.unhealthy_until_ms > now_ms { unhealthy += 1; }
        }
        (idle, in_use, unhealthy)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PoolError::SchemaMismatch); }
        if self.capacity == 0 { return Err(PoolError::ZeroCap); }
        for k in self.conns.keys() {
            if k.is_empty() { return Err(PoolError::EmptyId); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_idle() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        let id = p.acquire(100).unwrap();
        assert_eq!(id, "c1");
        assert!(p.acquire(100).is_none());
    }

    #[test]
    fn release_makes_idle_again() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        p.acquire(100).unwrap();
        p.release("c1", 200).unwrap();
        assert_eq!(p.acquire(300).unwrap(), "c1");
    }

    #[test]
    fn mark_bad_skips_during_cooldown() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        p.add("c2", 0).unwrap();
        p.mark_bad("c1", 100, 5000).unwrap();
        // c1 unhealthy until 5100; acquire returns c2.
        assert_eq!(p.acquire(500).unwrap(), "c2");
    }

    #[test]
    fn mark_bad_recovers_after_cooldown() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        p.mark_bad("c1", 100, 1000).unwrap();
        assert!(p.acquire(500).is_none());
        assert_eq!(p.acquire(2000).unwrap(), "c1");
    }

    #[test]
    fn reap_idle_drops_old() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        let n = p.reap_idle(10_000, 5000);
        assert_eq!(n, 1);
        assert!(p.conns.is_empty());
    }

    #[test]
    fn full_pool_rejected() {
        let mut p = ConnectionPool::new(1).unwrap();
        p.add("c1", 0).unwrap();
        assert!(matches!(p.add("c2", 0).unwrap_err(), PoolError::Full));
    }

    #[test]
    fn unknown_release_rejected() {
        let mut p = ConnectionPool::new(5).unwrap();
        assert!(matches!(p.release("nope", 0).unwrap_err(), PoolError::Unknown(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PoolError::SchemaMismatch));
    }

    #[test]
    fn pool_serde_roundtrip() {
        let mut p = ConnectionPool::new(5).unwrap();
        p.add("c1", 0).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ConnectionPool = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
