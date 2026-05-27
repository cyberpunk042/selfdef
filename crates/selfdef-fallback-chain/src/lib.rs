//! `selfdef-fallback-chain` — generic provider fallback.
//!
//! Each chain has an ordered list of provider ids. Each provider
//! has a `healthy` flag; `pick(now)` returns the first healthy
//! provider. `mark_unhealthy(id)` / `mark_healthy(id)` flip state.
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Provider entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provider {
    /// Id.
    pub id: String,
    /// Healthy.
    pub healthy: bool,
    /// Failure count.
    pub failures: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackChain {
    /// Schema version.
    pub schema_version: String,
    /// Ordered providers.
    pub providers: Vec<Provider>,
    /// Lookup index.
    pub index: BTreeMap<String, usize>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FallbackError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate provider: {0}")]
    Duplicate(String),
    /// Unknown.
    #[error("unknown provider: {0}")]
    Unknown(String),
}

impl FallbackChain {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            providers: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Append provider.
    pub fn append(&mut self, id: &str) -> Result<(), FallbackError> {
        if id.is_empty() {
            return Err(FallbackError::EmptyId);
        }
        if self.index.contains_key(id) {
            return Err(FallbackError::Duplicate(id.into()));
        }
        let idx = self.providers.len();
        self.providers.push(Provider {
            id: id.into(),
            healthy: true,
            failures: 0,
        });
        self.index.insert(id.into(), idx);
        Ok(())
    }

    /// Mark unhealthy.
    pub fn mark_unhealthy(&mut self, id: &str) -> Result<(), FallbackError> {
        let idx = self
            .index
            .get(id)
            .copied()
            .ok_or_else(|| FallbackError::Unknown(id.into()))?;
        let p = &mut self.providers[idx];
        p.healthy = false;
        p.failures = p.failures.saturating_add(1);
        Ok(())
    }

    /// Mark healthy.
    pub fn mark_healthy(&mut self, id: &str) -> Result<(), FallbackError> {
        let idx = self
            .index
            .get(id)
            .copied()
            .ok_or_else(|| FallbackError::Unknown(id.into()))?;
        self.providers[idx].healthy = true;
        Ok(())
    }

    /// Pick first healthy.
    pub fn pick(&self) -> Option<String> {
        self.providers
            .iter()
            .find(|p| p.healthy)
            .map(|p| p.id.clone())
    }

    /// All healthy.
    pub fn all_healthy(&self) -> Vec<String> {
        self.providers
            .iter()
            .filter(|p| p.healthy)
            .map(|p| p.id.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FallbackError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FallbackError::SchemaMismatch);
        }
        for p in &self.providers {
            if p.id.is_empty() {
                return Err(FallbackError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_first_healthy() {
        let mut c = FallbackChain::new();
        c.append("primary").unwrap();
        c.append("secondary").unwrap();
        assert_eq!(c.pick().as_deref(), Some("primary"));
    }

    #[test]
    fn skip_unhealthy() {
        let mut c = FallbackChain::new();
        c.append("primary").unwrap();
        c.append("secondary").unwrap();
        c.mark_unhealthy("primary").unwrap();
        assert_eq!(c.pick().as_deref(), Some("secondary"));
    }

    #[test]
    fn all_unhealthy_returns_none() {
        let mut c = FallbackChain::new();
        c.append("a").unwrap();
        c.append("b").unwrap();
        c.mark_unhealthy("a").unwrap();
        c.mark_unhealthy("b").unwrap();
        assert!(c.pick().is_none());
    }

    #[test]
    fn recovery() {
        let mut c = FallbackChain::new();
        c.append("a").unwrap();
        c.mark_unhealthy("a").unwrap();
        c.mark_healthy("a").unwrap();
        assert_eq!(c.pick().as_deref(), Some("a"));
    }

    #[test]
    fn failures_count() {
        let mut c = FallbackChain::new();
        c.append("a").unwrap();
        c.mark_unhealthy("a").unwrap();
        c.mark_unhealthy("a").unwrap();
        assert_eq!(c.providers[0].failures, 2);
    }

    #[test]
    fn duplicate_rejected() {
        let mut c = FallbackChain::new();
        c.append("a").unwrap();
        assert!(matches!(
            c.append("a").unwrap_err(),
            FallbackError::Duplicate(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut c = FallbackChain::new();
        assert!(matches!(c.append("").unwrap_err(), FallbackError::EmptyId));
    }

    #[test]
    fn unknown_mark_rejected() {
        let mut c = FallbackChain::new();
        assert!(matches!(
            c.mark_unhealthy("nope").unwrap_err(),
            FallbackError::Unknown(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = FallbackChain::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            FallbackError::SchemaMismatch
        ));
    }

    #[test]
    fn chain_serde_roundtrip() {
        let mut c = FallbackChain::new();
        c.append("a").unwrap();
        c.append("b").unwrap();
        c.mark_unhealthy("a").unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: FallbackChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
