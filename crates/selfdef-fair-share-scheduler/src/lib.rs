//! `selfdef-fair-share-scheduler` — weighted fair share.
//!
//! Each tenant has a `weight` (≥1) and a `cumulative_service` count.
//! `pick_next(eligible)` returns the eligible tenant minimizing
//! `cumulative_service / weight` — ties broken alphabetically. After
//! the caller does the work, `charge(tenant, units)` adds units
//! divided by weight (so high-weight tenants are charged less per
//! unit).
//!
//! `reset_service()` zeros all cumulative counters (e.g. end of an
//! epoch).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-tenant state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantState {
    /// Weight (≥1).
    pub weight: u32,
    /// Cumulative service charged (already weight-adjusted).
    pub cumulative_service: u64,
    /// Times picked.
    pub picks: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FairShareScheduler {
    /// Schema version.
    pub schema_version: String,
    /// tenant → state.
    pub tenants: BTreeMap<String, TenantState>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FairShareError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("tenant id empty")]
    EmptyTenant,
    /// Zero weight.
    #[error("weight must be >= 1")]
    ZeroWeight,
    /// Unknown.
    #[error("unknown tenant: {0}")]
    UnknownTenant(String),
}

impl FairShareScheduler {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tenants: BTreeMap::new(),
        }
    }

    /// Register or update tenant.
    pub fn set_weight(&mut self, tenant: &str, weight: u32) -> Result<(), FairShareError> {
        if tenant.is_empty() { return Err(FairShareError::EmptyTenant); }
        if weight == 0 { return Err(FairShareError::ZeroWeight); }
        let entry = self.tenants.entry(tenant.into()).or_insert(TenantState {
            weight,
            cumulative_service: 0,
            picks: 0,
        });
        entry.weight = weight;
        Ok(())
    }

    /// Pick next among eligible.
    pub fn pick_next(&mut self, eligible: &[&str]) -> Option<String> {
        let mut best: Option<(u64, String)> = None;
        for &id in eligible {
            let Some(s) = self.tenants.get(id) else { continue; };
            // Score: cumulative * 1000 / weight (higher weight = lower score).
            let score = s.cumulative_service.saturating_mul(1000) / (s.weight as u64);
            let is_better = match &best {
                None => true,
                Some((bs, bid)) => score < *bs || (score == *bs && id < bid.as_str()),
            };
            if is_better {
                best = Some((score, id.into()));
            }
        }
        if let Some((_, ref id)) = best {
            if let Some(s) = self.tenants.get_mut(id) {
                s.picks = s.picks.saturating_add(1);
            }
        }
        best.map(|(_, id)| id)
    }

    /// Charge service (divided by weight).
    pub fn charge(&mut self, tenant: &str, units: u64) -> Result<(), FairShareError> {
        let s = self.tenants.get_mut(tenant).ok_or_else(|| FairShareError::UnknownTenant(tenant.into()))?;
        let adjusted = units.saturating_mul(1000) / (s.weight as u64);
        s.cumulative_service = s.cumulative_service.saturating_add(adjusted);
        Ok(())
    }

    /// Reset cumulative service.
    pub fn reset_service(&mut self) {
        for s in self.tenants.values_mut() {
            s.cumulative_service = 0;
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FairShareError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FairShareError::SchemaMismatch); }
        for (t, s) in &self.tenants {
            if t.is_empty() { return Err(FairShareError::EmptyTenant); }
            if s.weight == 0 { return Err(FairShareError::ZeroWeight); }
        }
        Ok(())
    }
}

impl Default for FairShareScheduler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_weights_round_robin_like() {
        let mut s = FairShareScheduler::new();
        s.set_weight("a", 1).unwrap();
        s.set_weight("b", 1).unwrap();
        // First pick: tie → alphabetical = "a".
        assert_eq!(s.pick_next(&["a", "b"]).as_deref(), Some("a"));
        s.charge("a", 1).unwrap();
        // Now b has lower cumulative; b picked.
        assert_eq!(s.pick_next(&["a", "b"]).as_deref(), Some("b"));
    }

    #[test]
    fn higher_weight_gets_more_picks() {
        let mut s = FairShareScheduler::new();
        s.set_weight("light", 1).unwrap();
        s.set_weight("heavy", 4).unwrap();
        let mut picks: BTreeMap<String, u32> = BTreeMap::new();
        for _ in 0..50 {
            let p = s.pick_next(&["light", "heavy"]).unwrap();
            s.charge(&p, 1).unwrap();
            *picks.entry(p).or_default() += 1;
        }
        // heavy should win roughly 4x more often.
        assert!(picks["heavy"] > picks["light"] * 2);
    }

    #[test]
    fn unregistered_tenants_skipped() {
        let mut s = FairShareScheduler::new();
        s.set_weight("a", 1).unwrap();
        let pick = s.pick_next(&["a", "ghost"]);
        assert_eq!(pick.as_deref(), Some("a"));
    }

    #[test]
    fn empty_eligible_returns_none() {
        let mut s = FairShareScheduler::new();
        assert!(s.pick_next(&[]).is_none());
    }

    #[test]
    fn reset_service_zeros_cumulative() {
        let mut s = FairShareScheduler::new();
        s.set_weight("a", 1).unwrap();
        s.charge("a", 100).unwrap();
        s.reset_service();
        assert_eq!(s.tenants["a"].cumulative_service, 0);
    }

    #[test]
    fn picks_counter_increments() {
        let mut s = FairShareScheduler::new();
        s.set_weight("a", 1).unwrap();
        s.pick_next(&["a"]);
        s.pick_next(&["a"]);
        assert_eq!(s.tenants["a"].picks, 2);
    }

    #[test]
    fn charge_unknown_rejected() {
        let mut s = FairShareScheduler::new();
        assert!(matches!(s.charge("nope", 1).unwrap_err(), FairShareError::UnknownTenant(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = FairShareScheduler::new();
        assert!(matches!(s.set_weight("", 1).unwrap_err(), FairShareError::EmptyTenant));
        assert!(matches!(s.set_weight("a", 0).unwrap_err(), FairShareError::ZeroWeight));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = FairShareScheduler::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), FairShareError::SchemaMismatch));
    }

    #[test]
    fn share_serde_roundtrip() {
        let mut s = FairShareScheduler::new();
        s.set_weight("a", 2).unwrap();
        s.charge("a", 10).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: FairShareScheduler = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
