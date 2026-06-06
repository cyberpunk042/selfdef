//! `avx512_features` — AVX-512 instructions as AI infrastructure (MS048).
//!
//! Encodes the avx-plus-plus dump's **"AVX-512 Features As AI Infrastructure"**
//! catalog verbatim (dump lines 2312-2340) — the heart of the operator's
//! "avx-plus-plus" mandate ("exploit the stack and techno to the max,
//! avx-plus-plus base reason being"). Each AVX-512 instruction maps to the
//! deterministic-data-plane job it accelerates:
//!
//! ```text
//! VPTERNLOG          fuse policy logic: commit = verified & valid | trusted_fast_path
//! VPCOMPRESS/VPEXPAND pack active branches into dense GPU batches
//! VPOPCNTDQ          count overlap in memory sketches / permission masks
//! VP2INTERSECT       fast candidate-id intersections on Zen 5, useful for memory/query sets
//! VPCONFLICT         detect duplicates/collisions inside vectorized hash/table updates
//! VBMI/VBMI2         byte shuffles, token-class LUTs, compact parser tricks
//! k-mask registers   tiny hardware routing planes for branch validity
//! ```
//!
//! The dump's engineering caution (line 2336, verbatim): *"we are engineers,
//! not priests of instruction mnemonics"* — VP2INTERSECT in particular is
//! benchmark-not-worship (emulation can beat native when you only need one
//! mask). Every instruction + use is verbatim — none invented (operator rule:
//! "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Engineering caution (dump line 2336, verbatim).
pub const CAUTION: &str = "we are engineers, not priests of instruction mnemonics";

/// The seven AVX-512 instruction families the dump catalogs as AI
/// infrastructure (dump 2316-2334).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Avx512Feature {
    /// VPTERNLOG.
    Vpternlog,
    /// VPCOMPRESS / VPEXPAND.
    VpcompressVpexpand,
    /// VPOPCNTDQ.
    Vpopcntdq,
    /// VP2INTERSECT.
    Vp2intersect,
    /// VPCONFLICT.
    Vpconflict,
    /// VBMI / VBMI2.
    VbmiVbmi2,
    /// k-mask registers.
    KMaskRegisters,
}

impl Avx512Feature {
    /// The verbatim instruction mnemonic.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Vpternlog => "VPTERNLOG",
            Self::VpcompressVpexpand => "VPCOMPRESS/VPEXPAND",
            Self::Vpopcntdq => "VPOPCNTDQ",
            Self::Vp2intersect => "VP2INTERSECT",
            Self::Vpconflict => "VPCONFLICT",
            Self::VbmiVbmi2 => "VBMI/VBMI2",
            Self::KMaskRegisters => "k-mask registers",
        }
    }

    /// The verbatim AI-infrastructure use.
    #[must_use]
    pub const fn ai_use(self) -> &'static str {
        match self {
            Self::Vpternlog => "fuse policy logic: commit = verified & valid | trusted_fast_path",
            Self::VpcompressVpexpand => "pack active branches into dense GPU batches",
            Self::Vpopcntdq => "count overlap in memory sketches / permission masks",
            Self::Vp2intersect => {
                "fast candidate-id intersections on Zen 5, useful for memory/query sets"
            }
            Self::Vpconflict => "detect duplicates/collisions inside vectorized hash/table updates",
            Self::VbmiVbmi2 => "byte shuffles, token-class LUTs, compact parser tricks",
            Self::KMaskRegisters => "tiny hardware routing planes for branch validity",
        }
    }

    /// Whether the dump flags this feature as "benchmark, not worship" (only
    /// VP2INTERSECT — emulation can beat native when you need one mask).
    #[must_use]
    pub const fn benchmark_not_worship(self) -> bool {
        matches!(self, Self::Vp2intersect)
    }
}

/// All seven features in dump order.
#[must_use]
pub fn all_features() -> [Avx512Feature; 7] {
    [
        Avx512Feature::Vpternlog,
        Avx512Feature::VpcompressVpexpand,
        Avx512Feature::Vpopcntdq,
        Avx512Feature::Vp2intersect,
        Avx512Feature::Vpconflict,
        Avx512Feature::VbmiVbmi2,
        Avx512Feature::KMaskRegisters,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_features_with_verbatim_mnemonics() {
        let f = all_features();
        assert_eq!(f.len(), 7);
        assert_eq!(f[0].mnemonic(), "VPTERNLOG");
        assert_eq!(Avx512Feature::Vp2intersect.mnemonic(), "VP2INTERSECT");
        assert_eq!(Avx512Feature::KMaskRegisters.mnemonic(), "k-mask registers");
    }

    #[test]
    fn vpternlog_fuses_policy_logic_verbatim() {
        assert_eq!(
            Avx512Feature::Vpternlog.ai_use(),
            "fuse policy logic: commit = verified & valid | trusted_fast_path"
        );
    }

    #[test]
    fn every_feature_has_a_nonempty_use() {
        for f in all_features() {
            assert!(!f.ai_use().is_empty(), "{f:?} has no use");
        }
    }

    #[test]
    fn only_vp2intersect_is_benchmark_not_worship() {
        for f in all_features() {
            assert_eq!(
                f.benchmark_not_worship(),
                f == Avx512Feature::Vp2intersect,
                "{f:?} benchmark flag wrong"
            );
        }
    }

    #[test]
    fn features_and_uses_are_distinct() {
        let f = all_features();
        for i in 0..7 {
            for j in (i + 1)..7 {
                assert_ne!(f[i], f[j]);
                assert_ne!(f[i].mnemonic(), f[j].mnemonic());
                assert_ne!(f[i].ai_use(), f[j].ai_use());
            }
        }
    }

    #[test]
    fn caution_is_verbatim() {
        assert_eq!(
            CAUTION,
            "we are engineers, not priests of instruction mnemonics"
        );
    }

    #[test]
    fn serde_roundtrip() {
        for f in all_features() {
            let j = serde_json::to_string(&f).unwrap();
            let back: Avx512Feature = serde_json::from_str(&j).unwrap();
            assert_eq!(f, back);
        }
    }
}
