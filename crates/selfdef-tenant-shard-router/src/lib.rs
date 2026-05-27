//! `selfdef-tenant-shard-router` — tenant→shard placement.
//!
//! `route(tenant)` returns the shard id by `FNV-1a-64(tenant) % N`
//! where N = number of shards. Sticky overrides via `pin(tenant,
//! shard)` force a specific shard. `set_shards(&[ids])` updates the
//! shard list — pinned tenants survive; un-pinned tenants are
//! re-hashed against the new list.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantShardRouter {
    /// Schema version.
    pub schema_version: String,
    /// Ordered shard ids.
    pub shards: Vec<String>,
    /// tenant → pinned shard id (overrides hash).
    pub pinned: BTreeMap<String, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RouterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty shards.
    #[error("must have ≥1 shard")]
    NoShards,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Unknown shard.
    #[error("unknown shard: {0}")]
    UnknownShard(String),
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl TenantShardRouter {
    /// New.
    pub fn new(shards: &[&str]) -> Result<Self, RouterError> {
        if shards.is_empty() {
            return Err(RouterError::NoShards);
        }
        for s in shards {
            if s.is_empty() {
                return Err(RouterError::EmptyId);
            }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            shards: shards.iter().map(|s| (*s).into()).collect(),
            pinned: BTreeMap::new(),
        })
    }

    /// Set shard list (preserves valid pins, drops invalid ones).
    pub fn set_shards(&mut self, shards: &[&str]) -> Result<usize, RouterError> {
        if shards.is_empty() {
            return Err(RouterError::NoShards);
        }
        for s in shards {
            if s.is_empty() {
                return Err(RouterError::EmptyId);
            }
        }
        let new_set: std::collections::BTreeSet<String> =
            shards.iter().map(|s| (*s).into()).collect();
        let to_unpin: Vec<String> = self
            .pinned
            .iter()
            .filter(|(_, v)| !new_set.contains(v.as_str()))
            .map(|(k, _)| k.clone())
            .collect();
        let n = to_unpin.len();
        for k in to_unpin {
            self.pinned.remove(&k);
        }
        self.shards = shards.iter().map(|s| (*s).into()).collect();
        Ok(n)
    }

    /// Pin tenant to a shard.
    pub fn pin(&mut self, tenant: &str, shard: &str) -> Result<(), RouterError> {
        if tenant.is_empty() {
            return Err(RouterError::EmptyId);
        }
        if shard.is_empty() {
            return Err(RouterError::EmptyId);
        }
        if !self.shards.iter().any(|s| s == shard) {
            return Err(RouterError::UnknownShard(shard.into()));
        }
        self.pinned.insert(tenant.into(), shard.into());
        Ok(())
    }

    /// Unpin.
    pub fn unpin(&mut self, tenant: &str) -> bool {
        self.pinned.remove(tenant).is_some()
    }

    /// Route.
    pub fn route(&self, tenant: &str) -> Result<String, RouterError> {
        if tenant.is_empty() {
            return Err(RouterError::EmptyId);
        }
        if self.shards.is_empty() {
            return Err(RouterError::NoShards);
        }
        if let Some(s) = self.pinned.get(tenant) {
            return Ok(s.clone());
        }
        let h = fnv1a_64(tenant.as_bytes());
        let idx = (h % self.shards.len() as u64) as usize;
        Ok(self.shards[idx].clone())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RouterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RouterError::SchemaMismatch);
        }
        if self.shards.is_empty() {
            return Err(RouterError::NoShards);
        }
        for s in &self.shards {
            if s.is_empty() {
                return Err(RouterError::EmptyId);
            }
        }
        let set: std::collections::BTreeSet<&String> = self.shards.iter().collect();
        for (t, s) in &self.pinned {
            if t.is_empty() {
                return Err(RouterError::EmptyId);
            }
            if !set.contains(s) {
                return Err(RouterError::UnknownShard(s.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_is_deterministic() {
        let r = TenantShardRouter::new(&["s1", "s2", "s3"]).unwrap();
        let a = r.route("alice").unwrap();
        let b = r.route("alice").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn pin_overrides_hash() {
        let mut r = TenantShardRouter::new(&["s1", "s2", "s3"]).unwrap();
        r.pin("alice", "s3").unwrap();
        assert_eq!(r.route("alice").unwrap(), "s3");
    }

    #[test]
    fn unpin_returns_to_hash() {
        let mut r = TenantShardRouter::new(&["s1", "s2", "s3"]).unwrap();
        let original = r.route("alice").unwrap();
        r.pin("alice", "s3").unwrap();
        r.unpin("alice");
        assert_eq!(r.route("alice").unwrap(), original);
    }

    #[test]
    fn set_shards_drops_invalid_pins() {
        let mut r = TenantShardRouter::new(&["s1", "s2", "s3"]).unwrap();
        r.pin("alice", "s3").unwrap();
        r.pin("bob", "s2").unwrap();
        // Drop s3.
        let n = r.set_shards(&["s1", "s2", "s4"]).unwrap();
        assert_eq!(n, 1);
        assert!(!r.pinned.contains_key("alice"));
        assert!(r.pinned.contains_key("bob"));
    }

    #[test]
    fn distribution_uses_all_shards() {
        let r = TenantShardRouter::new(&["a", "b", "c"]).unwrap();
        let mut counts = std::collections::BTreeMap::<String, u32>::new();
        for i in 0..1000 {
            let s = r.route(&format!("tenant-{i}")).unwrap();
            *counts.entry(s).or_default() += 1;
        }
        assert_eq!(counts.len(), 3);
        // No shard wildly skewed (within ~30%).
        for &c in counts.values() {
            assert!(c > 200 && c < 500);
        }
    }

    #[test]
    fn unknown_shard_pin_rejected() {
        let mut r = TenantShardRouter::new(&["s1"]).unwrap();
        assert!(matches!(
            r.pin("alice", "s2").unwrap_err(),
            RouterError::UnknownShard(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(matches!(
            TenantShardRouter::new(&[]).unwrap_err(),
            RouterError::NoShards
        ));
        assert!(matches!(
            TenantShardRouter::new(&[""]).unwrap_err(),
            RouterError::EmptyId
        ));
        let r = TenantShardRouter::new(&["s1"]).unwrap();
        assert!(matches!(r.route("").unwrap_err(), RouterError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = TenantShardRouter::new(&["s1"]).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RouterError::SchemaMismatch
        ));
    }

    #[test]
    fn router_serde_roundtrip() {
        let mut r = TenantShardRouter::new(&["s1", "s2"]).unwrap();
        r.pin("alice", "s2").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: TenantShardRouter = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
