//! `selfdef-weighted-round-robin` — fair lane scheduler.
//!
//! Smooth WRR (Nginx-style): each pick selects the lane with the
//! highest current_weight; that lane is decremented by total_weight;
//! before each round, every lane's current_weight is incremented by
//! its configured weight.
//!
//! Lanes register with weight >= 1. pick() returns the next lane id
//! deterministically (ties: by lane registration order).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lane {
    /// Id.
    pub id: String,
    /// Configured weight.
    pub weight: i64,
    /// Current weight (running counter).
    pub current_weight: i64,
    /// Times picked.
    pub picks: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeightedRoundRobin {
    /// Schema version.
    pub schema_version: String,
    /// Lanes in registration order.
    pub lanes: Vec<Lane>,
    /// Total weight (sum).
    pub total_weight: i64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WrrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("lane id empty")]
    EmptyId,
    /// Zero weight.
    #[error("weight must be >= 1")]
    ZeroWeight,
    /// Duplicate.
    #[error("duplicate lane: {0}")]
    DuplicateLane(String),
    /// Empty pool.
    #[error("no lanes registered")]
    NoLanes,
}

impl WeightedRoundRobin {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            lanes: Vec::new(),
            total_weight: 0,
        }
    }

    /// Register lane.
    pub fn register(&mut self, id: &str, weight: u32) -> Result<(), WrrError> {
        if id.is_empty() { return Err(WrrError::EmptyId); }
        if weight == 0 { return Err(WrrError::ZeroWeight); }
        if self.lanes.iter().any(|l| l.id == id) {
            return Err(WrrError::DuplicateLane(id.into()));
        }
        let w = weight as i64;
        self.lanes.push(Lane {
            id: id.into(),
            weight: w,
            current_weight: 0,
            picks: 0,
        });
        self.total_weight = self.total_weight.saturating_add(w);
        Ok(())
    }

    /// Pick next lane id.
    pub fn pick(&mut self) -> Result<String, WrrError> {
        if self.lanes.is_empty() { return Err(WrrError::NoLanes); }
        // Increment every lane's current_weight by its configured weight.
        for l in self.lanes.iter_mut() {
            l.current_weight = l.current_weight.saturating_add(l.weight);
        }
        // Find lane with max current_weight (ties: first by registration order).
        let (idx, _) = self.lanes
            .iter()
            .enumerate()
            .max_by_key(|(i, l)| (l.current_weight, std::cmp::Reverse(*i)))
            .unwrap();
        self.lanes[idx].current_weight = self.lanes[idx].current_weight.saturating_sub(self.total_weight);
        self.lanes[idx].picks = self.lanes[idx].picks.saturating_add(1);
        Ok(self.lanes[idx].id.clone())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WrrError> {
        if self.schema_version != SCHEMA_VERSION { return Err(WrrError::SchemaMismatch); }
        let mut sum: i64 = 0;
        for l in &self.lanes {
            if l.id.is_empty() { return Err(WrrError::EmptyId); }
            if l.weight < 1 { return Err(WrrError::ZeroWeight); }
            sum = sum.saturating_add(l.weight);
        }
        if sum != self.total_weight { return Err(WrrError::ZeroWeight); }
        Ok(())
    }
}

impl Default for WeightedRoundRobin {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn empty_pool_errors() {
        let mut w = WeightedRoundRobin::new();
        assert!(matches!(w.pick().unwrap_err(), WrrError::NoLanes));
    }

    #[test]
    fn single_lane_always_picked() {
        let mut w = WeightedRoundRobin::new();
        w.register("only", 3).unwrap();
        for _ in 0..5 {
            assert_eq!(w.pick().unwrap(), "only");
        }
    }

    #[test]
    fn equal_weights_round_robin() {
        let mut w = WeightedRoundRobin::new();
        w.register("a", 1).unwrap();
        w.register("b", 1).unwrap();
        w.register("c", 1).unwrap();
        let picks: Vec<String> = (0..9).map(|_| w.pick().unwrap()).collect();
        let mut counts = BTreeMap::new();
        for p in &picks { *counts.entry(p.clone()).or_insert(0) += 1; }
        assert_eq!(counts["a"], 3);
        assert_eq!(counts["b"], 3);
        assert_eq!(counts["c"], 3);
    }

    #[test]
    fn weighted_picks_match_weights() {
        let mut w = WeightedRoundRobin::new();
        w.register("a", 5).unwrap();
        w.register("b", 1).unwrap();
        let mut counts = BTreeMap::new();
        for _ in 0..600 {
            *counts.entry(w.pick().unwrap()).or_insert(0) += 1;
        }
        // 5:1 ratio → a ≈ 500, b ≈ 100
        assert_eq!(counts["a"], 500);
        assert_eq!(counts["b"], 100);
    }

    #[test]
    fn smoothness_interleaves() {
        let mut w = WeightedRoundRobin::new();
        w.register("a", 5).unwrap();
        w.register("b", 1).unwrap();
        // 6 picks: with smoothing, 'b' shouldn't be at the very end.
        let picks: Vec<String> = (0..6).map(|_| w.pick().unwrap()).collect();
        let last_b = picks.iter().rposition(|p| p == "b").unwrap();
        assert!(last_b < 5, "b should be interleaved, got: {:?}", picks);
    }

    #[test]
    fn duplicate_lane_rejected() {
        let mut w = WeightedRoundRobin::new();
        w.register("a", 1).unwrap();
        assert!(matches!(w.register("a", 1).unwrap_err(), WrrError::DuplicateLane(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut w = WeightedRoundRobin::new();
        assert!(matches!(w.register("", 1).unwrap_err(), WrrError::EmptyId));
        assert!(matches!(w.register("a", 0).unwrap_err(), WrrError::ZeroWeight));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = WeightedRoundRobin::new();
        w.schema_version = "9.9.9".into();
        assert!(matches!(w.validate().unwrap_err(), WrrError::SchemaMismatch));
    }

    #[test]
    fn wrr_serde_roundtrip() {
        let mut w = WeightedRoundRobin::new();
        w.register("a", 1).unwrap();
        w.pick().unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let back: WeightedRoundRobin = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
