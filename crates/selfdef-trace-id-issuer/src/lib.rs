//! `selfdef-trace-id-issuer` — IPS-side deterministic trace_id minter.
//!
//! Format: `tr-{nano-epoch}-{sequence}-{actor-hash16}` where:
//! - `nano-epoch`   — nanoseconds since Unix epoch (caller-provided)
//! - `sequence`     — per-issuer monotonic counter
//! - `actor-hash16` — first 16 hex chars of FNV-1a64 of the actor MS003 id
//!
//! The issuer maintains a sliding-window seen-set to detect collisions
//! immediately. The daemon mints every trace_id through this issuer.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sliding window depth for collision detection.
pub const WINDOW_DEPTH: usize = 10_000;

/// FNV-1a 64-bit.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Issuer state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceIdIssuer {
    /// Schema version.
    pub schema_version: String,
    /// Monotonic counter incremented on every mint.
    pub sequence: u64,
    /// Recently-minted ids (sliding window).
    pub seen: VecDeque<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TraceIdError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Collision detected.
    #[error("trace_id collision: {0}")]
    Collision(String),
    /// nano_epoch 0.
    #[error("nano_epoch zero rejected")]
    ZeroEpoch,
}

impl TraceIdIssuer {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            sequence: 0,
            seen: VecDeque::with_capacity(WINDOW_DEPTH),
        }
    }

    /// Mint a fresh trace_id.
    pub fn mint(&mut self, nano_epoch: u64, actor: &str) -> Result<String, TraceIdError> {
        if actor.is_empty() { return Err(TraceIdError::EmptyActor); }
        if nano_epoch == 0 { return Err(TraceIdError::ZeroEpoch); }
        let actor_hash = fnv1a_64(actor.as_bytes());
        let actor_hash16 = format!("{actor_hash:016x}");
        let id = format!("tr-{nano_epoch}-{}-{actor_hash16}", self.sequence);
        if self.seen.iter().any(|s| s == &id) {
            return Err(TraceIdError::Collision(id));
        }
        self.sequence += 1;
        self.seen.push_back(id.clone());
        while self.seen.len() > WINDOW_DEPTH {
            self.seen.pop_front();
        }
        Ok(id)
    }

    /// Number of ids retained in window.
    pub fn window_len(&self) -> usize { self.seen.len() }

    /// Validate.
    pub fn validate(&self) -> Result<(), TraceIdError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TraceIdError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for TraceIdIssuer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a_64(b"abc"), fnv1a_64(b"abc"));
    }

    #[test]
    fn mint_produces_format() {
        let mut i = TraceIdIssuer::new();
        let id = i.mint(1_700_000_000_000_000_000, "operator-fp").unwrap();
        assert!(id.starts_with("tr-"));
        let parts: Vec<&str> = id.split('-').collect();
        // tr - nano_epoch - seq - actor_hash16 → 4 parts
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "tr");
        assert_eq!(parts[2], "0");
        assert_eq!(parts[3].len(), 16);
    }

    #[test]
    fn mint_increments_sequence() {
        let mut i = TraceIdIssuer::new();
        i.mint(1, "a").unwrap();
        i.mint(2, "a").unwrap();
        assert_eq!(i.sequence, 2);
    }

    #[test]
    fn empty_actor_rejected() {
        let mut i = TraceIdIssuer::new();
        assert!(matches!(i.mint(1, "").unwrap_err(), TraceIdError::EmptyActor));
    }

    #[test]
    fn zero_epoch_rejected() {
        let mut i = TraceIdIssuer::new();
        assert!(matches!(i.mint(0, "a").unwrap_err(), TraceIdError::ZeroEpoch));
    }

    #[test]
    fn distinct_actors_distinct_hashes() {
        let mut i = TraceIdIssuer::new();
        let id_a = i.mint(1, "alice").unwrap();
        let id_b = i.mint(2, "bob").unwrap();
        let parts_a: Vec<&str> = id_a.split('-').collect();
        let parts_b: Vec<&str> = id_b.split('-').collect();
        assert_ne!(parts_a[3], parts_b[3]);
    }

    #[test]
    fn window_caps_growth() {
        let mut i = TraceIdIssuer::new();
        // Mint slightly above window depth.
        for k in 1..=10_005 {
            i.mint(k as u64, "a").unwrap();
        }
        assert_eq!(i.window_len(), WINDOW_DEPTH);
    }

    #[test]
    fn collision_detected() {
        let mut i = TraceIdIssuer::new();
        let _id = i.mint(100, "a").unwrap();
        // Force-replay the same id by inserting a duplicate before mint.
        // The natural mint path increments sequence each call so true
        // collisions require manual injection.
        // Simulate by injecting an entry with the next expected id.
        let next_id = format!("tr-{}-{}-{:016x}", 100, i.sequence, fnv1a_64(b"a"));
        i.seen.push_back(next_id.clone());
        let err = i.mint(100, "a").unwrap_err();
        assert!(matches!(err, TraceIdError::Collision(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut i = TraceIdIssuer::new();
        i.schema_version = "9.9.9".into();
        assert!(matches!(i.validate().unwrap_err(), TraceIdError::SchemaMismatch));
    }

    #[test]
    fn issuer_serde_roundtrip() {
        let mut i = TraceIdIssuer::new();
        i.mint(1, "a").unwrap();
        let j = serde_json::to_string(&i).unwrap();
        let back: TraceIdIssuer = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }
}
