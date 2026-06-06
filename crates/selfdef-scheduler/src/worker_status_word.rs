//! `worker_status_word` — 64-bit per-worker telemetry word (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Bit-Level Control With Telemetry"**
//! status word verbatim (dump lines 3187-3200): *"Telemetry should become bits
//! too. Each worker gets a status word:"*
//!
//! ```text
//! bits  0..7   load bucket
//! bits  8..15  memory pressure
//! bits 16..23  thermal pressure
//! bits 24..31  queue depth
//! bits 32..39  error state
//! bits 40..47  health
//! bits 48..55  policy mode
//! bits 56..63  flags
//! ```
//!
//! Packing telemetry into a `u64` lets the AVX-512 scheduler *"evaluate
//! multiple workers/queues/branches with the same mask logic"* (dump 3200) —
//! the same structure-of-arrays + mask approach as [`crate::branch_masks`].
//! The eight byte-fields are verbatim from the dump; the layout is the dump's
//! own bit assignment — none invented (operator rule: "you cannot invent
//! crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// A packed 64-bit worker telemetry word (eight 8-bit fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerStatusWord(pub u64);

/// The eight byte-fields, in bit order (each occupies one byte).
const LOAD_BUCKET: u32 = 0;
const MEMORY_PRESSURE: u32 = 1;
const THERMAL_PRESSURE: u32 = 2;
const QUEUE_DEPTH: u32 = 3;
const ERROR_STATE: u32 = 4;
const HEALTH: u32 = 5;
const POLICY_MODE: u32 = 6;
const FLAGS: u32 = 7;

#[inline]
const fn get_byte(word: u64, idx: u32) -> u8 {
    ((word >> (idx * 8)) & 0xFF) as u8
}

#[inline]
const fn set_byte(word: u64, idx: u32, val: u8) -> u64 {
    let cleared = word & !(0xFFu64 << (idx * 8));
    cleared | ((val as u64) << (idx * 8))
}

impl WorkerStatusWord {
    /// Construct from the eight verbatim fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        load_bucket: u8,
        memory_pressure: u8,
        thermal_pressure: u8,
        queue_depth: u8,
        error_state: u8,
        health: u8,
        policy_mode: u8,
        flags: u8,
    ) -> Self {
        let mut w = 0u64;
        w = set_byte(w, LOAD_BUCKET, load_bucket);
        w = set_byte(w, MEMORY_PRESSURE, memory_pressure);
        w = set_byte(w, THERMAL_PRESSURE, thermal_pressure);
        w = set_byte(w, QUEUE_DEPTH, queue_depth);
        w = set_byte(w, ERROR_STATE, error_state);
        w = set_byte(w, HEALTH, health);
        w = set_byte(w, POLICY_MODE, policy_mode);
        w = set_byte(w, FLAGS, flags);
        Self(w)
    }

    /// The raw packed `u64`.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// bits 0..7 — load bucket.
    #[must_use]
    pub const fn load_bucket(self) -> u8 {
        get_byte(self.0, LOAD_BUCKET)
    }
    /// bits 8..15 — memory pressure.
    #[must_use]
    pub const fn memory_pressure(self) -> u8 {
        get_byte(self.0, MEMORY_PRESSURE)
    }
    /// bits 16..23 — thermal pressure.
    #[must_use]
    pub const fn thermal_pressure(self) -> u8 {
        get_byte(self.0, THERMAL_PRESSURE)
    }
    /// bits 24..31 — queue depth.
    #[must_use]
    pub const fn queue_depth(self) -> u8 {
        get_byte(self.0, QUEUE_DEPTH)
    }
    /// bits 32..39 — error state.
    #[must_use]
    pub const fn error_state(self) -> u8 {
        get_byte(self.0, ERROR_STATE)
    }
    /// bits 40..47 — health.
    #[must_use]
    pub const fn health(self) -> u8 {
        get_byte(self.0, HEALTH)
    }
    /// bits 48..55 — policy mode.
    #[must_use]
    pub const fn policy_mode(self) -> u8 {
        get_byte(self.0, POLICY_MODE)
    }
    /// bits 56..63 — flags.
    #[must_use]
    pub const fn flags(self) -> u8 {
        get_byte(self.0, FLAGS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_roundtrip_through_the_packed_word() {
        let w = WorkerStatusWord::new(1, 2, 3, 4, 5, 6, 7, 8);
        assert_eq!(w.load_bucket(), 1);
        assert_eq!(w.memory_pressure(), 2);
        assert_eq!(w.thermal_pressure(), 3);
        assert_eq!(w.queue_depth(), 4);
        assert_eq!(w.error_state(), 5);
        assert_eq!(w.health(), 6);
        assert_eq!(w.policy_mode(), 7);
        assert_eq!(w.flags(), 8);
    }

    #[test]
    fn fields_occupy_their_dump_specified_bytes() {
        // load bucket in the lowest byte
        assert_eq!(
            WorkerStatusWord::new(0xAB, 0, 0, 0, 0, 0, 0, 0).bits(),
            0xAB
        );
        // flags in the highest byte
        assert_eq!(
            WorkerStatusWord::new(0, 0, 0, 0, 0, 0, 0, 0xCD).bits(),
            0xCDu64 << 56
        );
        // queue depth in byte 3
        assert_eq!(
            WorkerStatusWord::new(0, 0, 0, 0xEF, 0, 0, 0, 0).bits(),
            0xEFu64 << 24
        );
    }

    #[test]
    fn max_values_do_not_bleed_across_fields() {
        let w = WorkerStatusWord::new(255, 255, 255, 255, 255, 255, 255, 255);
        assert_eq!(w.bits(), u64::MAX);
        assert_eq!(w.load_bucket(), 255);
        assert_eq!(w.flags(), 255);
    }

    #[test]
    fn one_field_set_leaves_others_zero() {
        let w = WorkerStatusWord::new(0, 0, 0, 0, 99, 0, 0, 0);
        assert_eq!(w.error_state(), 99);
        assert_eq!(w.load_bucket(), 0);
        assert_eq!(w.health(), 0);
        assert_eq!(w.flags(), 0);
    }

    #[test]
    fn serde_roundtrip() {
        let w = WorkerStatusWord::new(10, 20, 30, 40, 50, 60, 70, 80);
        let j = serde_json::to_string(&w).unwrap();
        let back: WorkerStatusWord = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
