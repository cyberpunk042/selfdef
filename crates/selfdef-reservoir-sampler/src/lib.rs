//! `selfdef-reservoir-sampler` — Algorithm R sample of K from N.
//!
//! First k items fill the reservoir. For each subsequent item at
//! 1-based index i, replace a random reservoir slot with the new
//! item with probability k/i. PRNG is deterministic xorshift64*
//! seeded at construction.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservoirSampler {
    /// Schema version.
    pub schema_version: String,
    /// Capacity k.
    pub k: u32,
    /// Items seen so far (1-based index of next item: seen+1).
    pub seen: u64,
    /// Reservoir items (id strings).
    pub reservoir: Vec<String>,
    /// PRNG state (xorshift64*; non-zero).
    pub prng_state: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SamplerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("k must be >= 1")]
    ZeroCapacity,
    /// Zero seed.
    #[error("seed must be != 0")]
    ZeroSeed,
}

fn xorshift64s(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

impl ReservoirSampler {
    /// New (capacity k, PRNG seed != 0).
    pub fn new(k: u32, seed: u64) -> Result<Self, SamplerError> {
        if k == 0 { return Err(SamplerError::ZeroCapacity); }
        if seed == 0 { return Err(SamplerError::ZeroSeed); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            k,
            seen: 0,
            reservoir: Vec::with_capacity(k as usize),
            prng_state: seed,
        })
    }

    /// Observe an item; record its position in the reservoir if selected.
    pub fn observe(&mut self, item: &str) {
        self.seen = self.seen.saturating_add(1);
        if (self.reservoir.len() as u32) < self.k {
            self.reservoir.push(item.into());
            return;
        }
        // Replace slot j (0..seen) with probability k/seen.
        let r = xorshift64s(&mut self.prng_state);
        let j = (r % self.seen) as usize;
        if j < self.k as usize {
            self.reservoir[j] = item.into();
        }
    }

    /// Current sample.
    pub fn sample(&self) -> &[String] { &self.reservoir }

    /// Reset (preserve seed).
    pub fn reset(&mut self) {
        self.seen = 0;
        self.reservoir.clear();
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SamplerError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SamplerError::SchemaMismatch); }
        if self.k == 0 { return Err(SamplerError::ZeroCapacity); }
        if self.prng_state == 0 { return Err(SamplerError::ZeroSeed); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_k_fill_reservoir() {
        let mut s = ReservoirSampler::new(3, 42).unwrap();
        s.observe("a");
        s.observe("b");
        s.observe("c");
        assert_eq!(s.sample(), &["a".to_string(), "b".into(), "c".into()]);
        assert_eq!(s.seen, 3);
    }

    #[test]
    fn fewer_than_k_items_keeps_all() {
        let mut s = ReservoirSampler::new(5, 42).unwrap();
        s.observe("a");
        s.observe("b");
        assert_eq!(s.sample().len(), 2);
    }

    #[test]
    fn deterministic_with_seed() {
        let mut s1 = ReservoirSampler::new(3, 7).unwrap();
        let mut s2 = ReservoirSampler::new(3, 7).unwrap();
        for i in 0..100 { s1.observe(&i.to_string()); s2.observe(&i.to_string()); }
        assert_eq!(s1.sample(), s2.sample());
    }

    #[test]
    fn different_seeds_diverge() {
        let mut s1 = ReservoirSampler::new(3, 7).unwrap();
        let mut s2 = ReservoirSampler::new(3, 1234567).unwrap();
        for i in 0..100 { s1.observe(&i.to_string()); s2.observe(&i.to_string()); }
        assert_ne!(s1.sample(), s2.sample());
    }

    #[test]
    fn reservoir_size_caps_at_k() {
        let mut s = ReservoirSampler::new(3, 42).unwrap();
        for i in 0..1000 { s.observe(&i.to_string()); }
        assert_eq!(s.sample().len(), 3);
        assert_eq!(s.seen, 1000);
    }

    #[test]
    fn uniformity_within_tolerance() {
        // Sample 10 from 100000 with 100 different seeds — count how often each item appears.
        // Each item should appear roughly 10*100/100000 = 0.01 → not great signal.
        // Cheaper: with k=1 and N=1000, item index should average around 500.
        let mut total = 0u64;
        let trials = 200;
        for seed in 1..=trials {
            let mut s = ReservoirSampler::new(1, seed).unwrap();
            for i in 0..1000u32 { s.observe(&i.to_string()); }
            total += s.sample()[0].parse::<u64>().unwrap();
        }
        let mean = total / trials;
        // Mean across 200 seeds should land near 500 (50% slack).
        assert!((250..=750).contains(&mean), "mean was {}", mean);
    }

    #[test]
    fn reset_clears() {
        let mut s = ReservoirSampler::new(3, 42).unwrap();
        s.observe("a");
        s.reset();
        assert_eq!(s.sample().len(), 0);
        assert_eq!(s.seen, 0);
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(matches!(ReservoirSampler::new(0, 1).unwrap_err(), SamplerError::ZeroCapacity));
        assert!(matches!(ReservoirSampler::new(3, 0).unwrap_err(), SamplerError::ZeroSeed));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ReservoirSampler::new(3, 42).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SamplerError::SchemaMismatch));
    }

    #[test]
    fn sampler_serde_roundtrip() {
        let mut s = ReservoirSampler::new(3, 42).unwrap();
        s.observe("a"); s.observe("b");
        let j = serde_json::to_string(&s).unwrap();
        let back: ReservoirSampler = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
