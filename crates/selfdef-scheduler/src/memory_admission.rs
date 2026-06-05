//! `memory_admission` — KV-cache admission policy (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Memory Admission Policy"** section
//! verbatim (dump lines 2648-2683): *"Not everything deserves KV."* Where
//! [`crate::memory_scheduling`] is the retrieval pipeline and
//! [`crate::kv_context_scheduling`] is the per-request routing preference, this
//! is the *what-to-cache* decision — the dump's cache-if / do-not-cache rules,
//! plus *"That policy is a bitfield, not a prompt."*
//!
//! Cache if (dump 2654-2661):
//!
//! ```text
//! reused often / expensive to prefill / stable content / high trust /
//! common across branches / part of tool/system/project base
//! ```
//!
//! Do not cache if (dump 2663-2669):
//!
//! ```text
//! one-off / low trust / user-private but cross-session forbidden /
//! likely to mutate / branch-specific noise
//! ```
//!
//! The admission bitfield (dump 2673-2680):
//!
//! ```text
//! bits  0..3   cache tier
//! bits  4..7   trust
//! bits  8..15  reuse count
//! bits 16..31  token cost
//! bits 32..47  owner/session
//! bits 48..63  flags
//! ```
//!
//! Every rule + field is verbatim — none invented (operator rule: "you cannot
//! invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The six "cache if" rules (dump 2654-2661, verbatim).
pub const CACHE_IF: [&str; 6] = [
    "reused often",
    "expensive to prefill",
    "stable content",
    "high trust",
    "common across branches",
    "part of tool/system/project base",
];

/// The five "do not cache if" rules (dump 2663-2669, verbatim).
pub const DO_NOT_CACHE_IF: [&str; 5] = [
    "one-off",
    "low trust",
    "user-private but cross-session forbidden",
    "likely to mutate",
    "branch-specific noise",
];

/// Doctrine (dump 2671, verbatim).
pub const DOCTRINE: &str = "That policy is a bitfield, not a prompt.";

// Bit layout (offset, width) per the dump's bitfield (2673-2680).
const CACHE_TIER: (u32, u32) = (0, 4);
const TRUST: (u32, u32) = (4, 4);
const REUSE_COUNT: (u32, u32) = (8, 8);
const TOKEN_COST: (u32, u32) = (16, 16);
const OWNER_SESSION: (u32, u32) = (32, 16);
const FLAGS: (u32, u32) = (48, 16);

#[inline]
const fn mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

#[inline]
const fn get_field(word: u64, (offset, width): (u32, u32)) -> u64 {
    (word >> offset) & mask(width)
}

#[inline]
const fn set_field(word: u64, (offset, width): (u32, u32), val: u64) -> u64 {
    let m = mask(width) << offset;
    (word & !m) | ((val & mask(width)) << offset)
}

/// The 64-bit memory-admission word (mixed-width fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryAdmissionWord(pub u64);

impl MemoryAdmissionWord {
    /// Construct from the six fields (each truncated to its width).
    #[must_use]
    pub const fn new(
        cache_tier: u8,
        trust: u8,
        reuse_count: u8,
        token_cost: u16,
        owner_session: u16,
        flags: u16,
    ) -> Self {
        let mut w = 0u64;
        w = set_field(w, CACHE_TIER, cache_tier as u64);
        w = set_field(w, TRUST, trust as u64);
        w = set_field(w, REUSE_COUNT, reuse_count as u64);
        w = set_field(w, TOKEN_COST, token_cost as u64);
        w = set_field(w, OWNER_SESSION, owner_session as u64);
        w = set_field(w, FLAGS, flags as u64);
        Self(w)
    }

    /// Raw packed word.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// bits 0..3 — cache tier (0..=15).
    #[must_use]
    pub const fn cache_tier(self) -> u8 {
        get_field(self.0, CACHE_TIER) as u8
    }
    /// bits 4..7 — trust (0..=15).
    #[must_use]
    pub const fn trust(self) -> u8 {
        get_field(self.0, TRUST) as u8
    }
    /// bits 8..15 — reuse count (0..=255).
    #[must_use]
    pub const fn reuse_count(self) -> u8 {
        get_field(self.0, REUSE_COUNT) as u8
    }
    /// bits 16..31 — token cost (0..=65535).
    #[must_use]
    pub const fn token_cost(self) -> u16 {
        get_field(self.0, TOKEN_COST) as u16
    }
    /// bits 32..47 — owner/session (0..=65535).
    #[must_use]
    pub const fn owner_session(self) -> u16 {
        get_field(self.0, OWNER_SESSION) as u16
    }
    /// bits 48..63 — flags (0..=65535).
    #[must_use]
    pub const fn flags(self) -> u16 {
        get_field(self.0, FLAGS) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_sets_are_verbatim() {
        assert_eq!(CACHE_IF.len(), 6);
        assert_eq!(DO_NOT_CACHE_IF.len(), 5);
        assert_eq!(CACHE_IF[0], "reused often");
        assert_eq!(CACHE_IF[5], "part of tool/system/project base");
        assert_eq!(DO_NOT_CACHE_IF[2], "user-private but cross-session forbidden");
        assert_eq!(DOCTRINE, "That policy is a bitfield, not a prompt.");
    }

    #[test]
    fn cache_if_and_do_not_cache_are_disjoint() {
        for c in CACHE_IF {
            assert!(!DO_NOT_CACHE_IF.contains(&c), "{c} on both lists");
        }
    }

    #[test]
    fn all_fields_roundtrip() {
        let w = MemoryAdmissionWord::new(3, 2, 100, 40000, 12345, 0xBEEF);
        assert_eq!(w.cache_tier(), 3);
        assert_eq!(w.trust(), 2);
        assert_eq!(w.reuse_count(), 100);
        assert_eq!(w.token_cost(), 40000);
        assert_eq!(w.owner_session(), 12345);
        assert_eq!(w.flags(), 0xBEEF);
    }

    #[test]
    fn fields_occupy_their_dump_specified_bits() {
        // cache tier lowest nibble
        assert_eq!(MemoryAdmissionWord::new(0xF, 0, 0, 0, 0, 0).bits(), 0xF);
        // trust next nibble
        assert_eq!(MemoryAdmissionWord::new(0, 0xF, 0, 0, 0, 0).bits(), 0xF0);
        // flags top 16 bits
        assert_eq!(
            MemoryAdmissionWord::new(0, 0, 0, 0, 0, 0xFFFF).bits(),
            0xFFFFu64 << 48
        );
        // token cost bits 16..31
        assert_eq!(
            MemoryAdmissionWord::new(0, 0, 0, 0xFFFF, 0, 0).bits(),
            0xFFFFu64 << 16
        );
    }

    #[test]
    fn max_values_pack_to_all_ones() {
        let w = MemoryAdmissionWord::new(15, 15, 255, 65535, 65535, 65535);
        assert_eq!(w.bits(), u64::MAX);
    }

    #[test]
    fn cache_tier_truncates_to_four_bits() {
        // values above 15 truncate (4-bit field)
        let w = MemoryAdmissionWord::new(0xFF, 0, 0, 0, 0, 0);
        assert_eq!(w.cache_tier(), 0xF);
        // and do not bleed into trust
        assert_eq!(w.trust(), 0);
    }

    #[test]
    fn serde_roundtrip() {
        let w = MemoryAdmissionWord::new(1, 2, 3, 4, 5, 6);
        let j = serde_json::to_string(&w).unwrap();
        let back: MemoryAdmissionWord = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
