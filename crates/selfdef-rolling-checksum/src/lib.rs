//! `selfdef-rolling-checksum` — Adler-32 rolling checksum.
//!
//! Starts a = 1, b = 0; for each byte: a = (a + byte) mod MOD,
//! b = (b + a) mod MOD; result = (b << 16) | a. roll(out, in,
//! window_len) updates in O(1) when removing `out` from the head
//! and adding `in` to the tail. Useful for content-defined
//! chunking, dedup, and rsync-style sync.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Adler-32 modulus (largest prime < 2^16).
pub const MOD_ADLER: u32 = 65_521;

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollingChecksum {
    /// Schema version stub.
    pub a: u32,
    /// b.
    pub b: u32,
    /// Length absorbed.
    pub len: u64,
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollingChecksumState {
    /// Schema version.
    pub schema_version: String,
    /// Inner state.
    pub state: RollingChecksum,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ChecksumError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad window.
    #[error("window length must be >= 1")]
    BadWindow,
}

impl RollingChecksum {
    /// New (empty: a=1, b=0).
    pub fn new() -> Self {
        Self { a: 1, b: 0, len: 0 }
    }

    /// Absorb one byte.
    pub fn push(&mut self, byte: u8) {
        self.a = (self.a + byte as u32) % MOD_ADLER;
        self.b = (self.b + self.a) % MOD_ADLER;
        self.len = self.len.saturating_add(1);
    }

    /// Absorb a slice.
    pub fn extend(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.push(b);
        }
    }

    /// 32-bit digest.
    pub fn digest(&self) -> u32 {
        (self.b << 16) | self.a
    }

    /// Rolling update: remove `out` from head, add `in_byte` at tail.
    /// `window_len` must equal the current window length (>= 1).
    pub fn roll(&mut self, out: u8, in_byte: u8, window_len: u32) -> Result<(), ChecksumError> {
        if window_len == 0 { return Err(ChecksumError::BadWindow); }
        let modu = MOD_ADLER as u64;
        let a64 = self.a as u64;
        let b64 = self.b as u64;
        // a_new = (a - out + in) mod MOD.
        let mut a = (a64 + modu - out as u64) % modu;
        a = (a + in_byte as u64) % modu;
        // b_new = (b - window_len*out + a_new - 1) mod MOD.
        let l_out = (window_len as u64 % modu) * (out as u64 % modu) % modu;
        let mut b = (b64 + modu - l_out) % modu;
        b = (b + a) % modu;
        b = (b + modu - 1) % modu;
        self.a = a as u32;
        self.b = b as u32;
        Ok(())
    }
}

impl Default for RollingChecksum {
    fn default() -> Self { Self::new() }
}

impl RollingChecksumState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            state: RollingChecksum::new(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ChecksumError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ChecksumError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for RollingChecksumState {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest_is_one() {
        let c = RollingChecksum::new();
        assert_eq!(c.digest(), 1);
    }

    #[test]
    fn known_value() {
        // Adler-32("Wikipedia") = 0x11E60398
        let mut c = RollingChecksum::new();
        c.extend(b"Wikipedia");
        assert_eq!(c.digest(), 0x11E60398);
    }

    #[test]
    fn extend_equivalent_to_push_loop() {
        let mut a = RollingChecksum::new();
        a.extend(b"abc");
        let mut b = RollingChecksum::new();
        b.push(b'a'); b.push(b'b'); b.push(b'c');
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn roll_matches_fresh_window() {
        // Window of 4 bytes. Absorb "ABCD", then roll to "BCDE", compare to fresh "BCDE".
        let mut w = RollingChecksum::new();
        w.extend(b"ABCD");
        w.roll(b'A', b'E', 4).unwrap();
        let mut fresh = RollingChecksum::new();
        fresh.extend(b"BCDE");
        assert_eq!(w.digest(), fresh.digest());
    }

    #[test]
    fn multi_roll_matches_fresh() {
        let mut w = RollingChecksum::new();
        let initial = b"abcdef";
        w.extend(initial);
        // Slide window to "defghi".
        let stream = b"abcdefghi";
        for i in 0..3 {
            w.roll(stream[i], stream[6 + i], 6).unwrap();
        }
        let mut fresh = RollingChecksum::new();
        fresh.extend(&stream[3..9]);
        assert_eq!(w.digest(), fresh.digest());
    }

    #[test]
    fn zero_window_rejected() {
        let mut c = RollingChecksum::new();
        c.push(b'a');
        assert!(matches!(c.roll(b'a', b'b', 0).unwrap_err(), ChecksumError::BadWindow));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = RollingChecksumState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), ChecksumError::SchemaMismatch));
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut s = RollingChecksumState::new();
        s.state.extend(b"hello");
        let j = serde_json::to_string(&s).unwrap();
        let back: RollingChecksumState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
