//! `selfdef-tenant-quota-pool` — multi-tenant capacity pool.
//!
//! Each tenant has a `(capacity, in_use)` pair. `request(units)` is
//! granted when `in_use + units ≤ capacity`. `release(units)` frees
//! capacity (saturating at 0).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pool slot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pool {
    /// Capacity.
    pub capacity: u64,
    /// In-use.
    pub in_use: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantQuotaPool {
    /// Schema version.
    pub schema_version: String,
    /// tenant → pool.
    pub pools: BTreeMap<String, Pool>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RequestVerdict {
    /// Granted.
    Granted {
        /// remaining after grant.
        remaining: u64,
    },
    /// Capacity exhausted.
    Exhausted {
        /// total capacity.
        capacity: u64,
    },
    /// Unknown tenant.
    UnknownTenant,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PoolError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tenant.
    #[error("tenant empty")]
    EmptyTenant,
}

impl TenantQuotaPool {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pools: BTreeMap::new(),
        }
    }

    /// Set pool (replaces existing; in-use preserved).
    pub fn set_pool(&mut self, tenant: &str, capacity: u64) -> Result<(), PoolError> {
        if tenant.is_empty() {
            return Err(PoolError::EmptyTenant);
        }
        let in_use = self.pools.get(tenant).map(|p| p.in_use).unwrap_or(0);
        self.pools.insert(tenant.into(), Pool { capacity, in_use });
        Ok(())
    }

    /// Request units.
    pub fn request(&mut self, tenant: &str, units: u64) -> RequestVerdict {
        let p = match self.pools.get_mut(tenant) {
            Some(p) => p,
            None => return RequestVerdict::UnknownTenant,
        };
        let would = p.in_use.saturating_add(units);
        if would > p.capacity {
            return RequestVerdict::Exhausted {
                capacity: p.capacity,
            };
        }
        p.in_use = would;
        RequestVerdict::Granted {
            remaining: p.capacity - p.in_use,
        }
    }

    /// Release units (saturating at 0).
    pub fn release(&mut self, tenant: &str, units: u64) -> bool {
        if let Some(p) = self.pools.get_mut(tenant) {
            p.in_use = p.in_use.saturating_sub(units);
            return true;
        }
        false
    }

    /// In-use for a tenant.
    pub fn in_use(&self, tenant: &str) -> Option<u64> {
        self.pools.get(tenant).map(|p| p.in_use)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PoolError::SchemaMismatch);
        }
        for t in self.pools.keys() {
            if t.is_empty() {
                return Err(PoolError::EmptyTenant);
            }
        }
        Ok(())
    }
}

impl Default for TenantQuotaPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tenant_returns_unknown() {
        let mut p = TenantQuotaPool::new();
        assert_eq!(p.request("t", 1), RequestVerdict::UnknownTenant);
    }

    #[test]
    fn grant_under_capacity() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        assert_eq!(
            p.request("t", 30),
            RequestVerdict::Granted { remaining: 70 }
        );
    }

    #[test]
    fn exhausted_when_over() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        p.request("t", 80);
        assert_eq!(
            p.request("t", 50),
            RequestVerdict::Exhausted { capacity: 100 }
        );
        assert_eq!(p.in_use("t"), Some(80));
    }

    #[test]
    fn release_frees_units() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        p.request("t", 80);
        p.release("t", 30);
        assert_eq!(p.in_use("t"), Some(50));
    }

    #[test]
    fn release_saturates_at_zero() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        p.request("t", 10);
        p.release("t", 999);
        assert_eq!(p.in_use("t"), Some(0));
    }

    #[test]
    fn set_pool_preserves_in_use() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        p.request("t", 30);
        p.set_pool("t", 200).unwrap();
        assert_eq!(p.in_use("t"), Some(30));
    }

    #[test]
    fn empty_tenant_rejected() {
        let mut p = TenantQuotaPool::new();
        assert!(matches!(
            p.set_pool("", 1).unwrap_err(),
            PoolError::EmptyTenant
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TenantQuotaPool::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PoolError::SchemaMismatch
        ));
    }

    #[test]
    fn pool_serde_roundtrip() {
        let mut p = TenantQuotaPool::new();
        p.set_pool("t", 100).unwrap();
        p.request("t", 30);
        let j = serde_json::to_string(&p).unwrap();
        let back: TenantQuotaPool = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
