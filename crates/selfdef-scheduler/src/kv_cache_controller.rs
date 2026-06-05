//! `kv_cache_controller` — CPU-governed KV cache hierarchy (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Treat KV Cache As Memory Hierarchy"** +
//! **"The CPU As KV Cache Controller"** sections verbatim (dump lines
//! 2477-2540). This is the detail of the [`crate::runtime_shape`] *KV Cache
//! Controller* engine (#8): in long-context local AI the KV cache is the real
//! working memory, and the CPU — not the model — governs it. Doctrine (2540,
//! verbatim): *"do not ask the model. Let the CPU govern memory."*
//!
//! The four-tier hierarchy (dump 2491-2495):
//!
//! ```text
//! VRAM KV cache = L1/L2 cache
//! System RAM    = L3 / page cache
//! NVMe ZFS      = cold cache / replay / persisted context
//! CPU AVX-512   = cache controller
//! ```
//!
//! Per reusable context, the controller keeps a `KvBlockMeta` (dump 2516-2526
//! verbatim C struct), over which SIMD scans answer the six membership
//! questions (dump 2530-2537). Every tier, decision, field, and question is
//! verbatim — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump line 2540, verbatim).
pub const DOCTRINE: &str = "do not ask the model. Let the CPU govern memory.";

/// The seven KV-cache decisions the CPU makes (dump 2506-2512, verbatim).
pub const CPU_KV_DECISIONS: [&str; 7] = [
    "which prefixes deserve hot KV",
    "which branches share prefixes",
    "which contexts should be prefetched",
    "which KV blocks should be offloaded",
    "which blocks should be evicted",
    "which repeated tool schemas get permanent cache",
    "which project docs are worth prefill-once reuse",
];

/// The six SIMD-scan membership questions (dump 2530-2537, verbatim).
pub const SCAN_QUESTIONS: [&str; 6] = [
    "same model?",
    "same tokenizer?",
    "same block hash?",
    "allowed for this session?",
    "hot enough to keep?",
    "stale enough to evict?",
];

/// The four KV memory-hierarchy tiers (dump 2491-2495).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KvTier {
    /// VRAM KV cache.
    Vram,
    /// System RAM.
    SystemRam,
    /// NVMe ZFS.
    NvmeZfs,
    /// CPU AVX-512 (the controller, not a storage tier).
    CpuAvx512,
}

impl KvTier {
    /// The verbatim cache-hierarchy role.
    #[must_use]
    pub const fn role(self) -> &'static str {
        match self {
            Self::Vram => "L1/L2 cache",
            Self::SystemRam => "L3 / page cache",
            Self::NvmeZfs => "cold cache / replay / persisted context",
            Self::CpuAvx512 => "cache controller",
        }
    }

    /// Whether this tier stores KV blocks (the CPU is the controller, not
    /// storage).
    #[must_use]
    pub const fn is_storage(self) -> bool {
        !matches!(self, Self::CpuAvx512)
    }
}

/// The per-KV-block metadata the controller scans (dump 2516-2526, verbatim
/// `KvBlockMeta` C struct — eight `uint64_t` fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvBlockMeta {
    /// `uint64_t hash_hi`.
    pub hash_hi: u64,
    /// `uint64_t hash_lo`.
    pub hash_lo: u64,
    /// `uint64_t model_id`.
    pub model_id: u64,
    /// `uint64_t token_range`.
    pub token_range: u64,
    /// `uint64_t trust_flags`.
    pub trust_flags: u64,
    /// `uint64_t heat`.
    pub heat: u64,
    /// `uint64_t last_used`.
    pub last_used: u64,
    /// `uint64_t owner_policy`.
    pub owner_policy: u64,
}

/// The four tiers in dump order.
#[must_use]
pub fn hierarchy() -> [KvTier; 4] {
    [KvTier::Vram, KvTier::SystemRam, KvTier::NvmeZfs, KvTier::CpuAvx512]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_tiers_with_verbatim_roles() {
        assert_eq!(KvTier::Vram.role(), "L1/L2 cache");
        assert_eq!(KvTier::SystemRam.role(), "L3 / page cache");
        assert_eq!(KvTier::NvmeZfs.role(), "cold cache / replay / persisted context");
        assert_eq!(KvTier::CpuAvx512.role(), "cache controller");
    }

    #[test]
    fn cpu_is_controller_not_storage() {
        assert!(!KvTier::CpuAvx512.is_storage());
        for t in [KvTier::Vram, KvTier::SystemRam, KvTier::NvmeZfs] {
            assert!(t.is_storage(), "{t:?} should be storage");
        }
    }

    #[test]
    fn seven_kv_decisions_verbatim() {
        assert_eq!(CPU_KV_DECISIONS.len(), 7);
        assert_eq!(CPU_KV_DECISIONS[0], "which prefixes deserve hot KV");
        assert_eq!(CPU_KV_DECISIONS[6], "which project docs are worth prefill-once reuse");
    }

    #[test]
    fn six_scan_questions_verbatim() {
        assert_eq!(SCAN_QUESTIONS.len(), 6);
        assert_eq!(SCAN_QUESTIONS[0], "same model?");
        assert_eq!(SCAN_QUESTIONS[5], "stale enough to evict?");
    }

    #[test]
    fn kv_block_meta_has_eight_u64_fields_and_roundtrips() {
        let m = KvBlockMeta {
            hash_hi: 1,
            hash_lo: 2,
            model_id: 3,
            token_range: 4,
            trust_flags: 5,
            heat: 6,
            last_used: 7,
            owner_policy: 8,
        };
        let j = serde_json::to_string(&m).unwrap();
        let back: KvBlockMeta = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
        assert_eq!(m.owner_policy, 8);
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "do not ask the model. Let the CPU govern memory.");
    }

    #[test]
    fn tier_serde_roundtrip() {
        for t in hierarchy() {
            let j = serde_json::to_string(&t).unwrap();
            let back: KvTier = serde_json::from_str(&j).unwrap();
            assert_eq!(t, back);
        }
    }
}
