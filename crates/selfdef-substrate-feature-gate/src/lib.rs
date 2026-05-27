//! `selfdef-substrate-feature-gate` — hardware-aware feature gate.
//!
//! Each feature carries a `Vec<Requirement>` listing what the host
//! must offer. `classify(feature_id, snapshot)` returns
//! `Enabled` / `Disabled { missing: Vec<...> }` / `UnknownFeature`.
//!
//! `Snapshot` is a small mirror of the relevant subset of
//! `selfdef-hardware::HardwareSnapshot` — pass that crate's value
//! through `Snapshot::from(...)`-style builder at the call site to
//! avoid the heavy dep here.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Requirement {
    /// AVX2.
    Avx2,
    /// AVX-512 family present.
    Avx512,
    /// ARM NEON.
    Neon,
    /// At least one NVIDIA GPU device node.
    NvidiaGpu,
    /// RAM ≥ N gigabytes.
    RamAtLeastGB {
        /// gigabytes.
        gb: u32,
    },
    /// Logical CPU cores ≥ N.
    CoresAtLeast {
        /// cores.
        cores: u32,
    },
}

/// Snapshot of host features, mirrored from selfdef-hardware.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// AVX2 present?
    pub avx2: bool,
    /// AVX-512 present (any variant)?
    pub avx512: bool,
    /// ARM NEON present?
    pub neon: bool,
    /// At least one NVIDIA GPU present?
    pub nvidia_gpu: bool,
    /// RAM in MiB (None if undetected).
    pub ram_mib: Option<u64>,
    /// Logical core count (None if undetected).
    pub cores: Option<u32>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateFeatureGate {
    /// Schema version.
    pub schema_version: String,
    /// feature_id → requirements.
    pub features: BTreeMap<String, Vec<Requirement>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FeatureVerdict {
    /// All requirements met.
    Enabled,
    /// One or more unmet.
    Disabled {
        /// missing requirements.
        missing: Vec<Requirement>,
    },
    /// Feature not declared.
    UnknownFeature,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GateError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty feature id.
    #[error("feature id empty")]
    EmptyId,
}

impl SubstrateFeatureGate {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            features: BTreeMap::new(),
        }
    }

    /// Set requirements for a feature.
    pub fn set(&mut self, feature_id: &str, reqs: Vec<Requirement>) -> Result<(), GateError> {
        if feature_id.is_empty() {
            return Err(GateError::EmptyId);
        }
        self.features.insert(feature_id.into(), reqs);
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, feature_id: &str, snap: &Snapshot) -> FeatureVerdict {
        let reqs = match self.features.get(feature_id) {
            Some(r) => r,
            None => return FeatureVerdict::UnknownFeature,
        };
        let mut missing = Vec::new();
        for r in reqs {
            if !Self::passes(r, snap) {
                missing.push(r.clone());
            }
        }
        if missing.is_empty() {
            FeatureVerdict::Enabled
        } else {
            FeatureVerdict::Disabled { missing }
        }
    }

    fn passes(r: &Requirement, s: &Snapshot) -> bool {
        match r {
            Requirement::Avx2 => s.avx2,
            Requirement::Avx512 => s.avx512,
            Requirement::Neon => s.neon,
            Requirement::NvidiaGpu => s.nvidia_gpu,
            Requirement::RamAtLeastGB { gb } => s.ram_mib.is_some_and(|m| m >= (*gb as u64) * 1024),
            Requirement::CoresAtLeast { cores } => s.cores.is_some_and(|c| c >= *cores),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GateError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GateError::SchemaMismatch);
        }
        for k in self.features.keys() {
            if k.is_empty() {
                return Err(GateError::EmptyId);
            }
        }
        Ok(())
    }
}

impl Default for SubstrateFeatureGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_snapshot() -> Snapshot {
        Snapshot {
            avx2: true,
            avx512: true,
            neon: false,
            nvidia_gpu: true,
            ram_mib: Some(256 * 1024),
            cores: Some(32),
        }
    }

    #[test]
    fn unknown_feature() {
        let g = SubstrateFeatureGate::new();
        assert_eq!(
            g.classify("f", &full_snapshot()),
            FeatureVerdict::UnknownFeature
        );
    }

    #[test]
    fn all_passing() {
        let mut g = SubstrateFeatureGate::new();
        g.set("simd-path", vec![Requirement::Avx2, Requirement::Avx512])
            .unwrap();
        assert_eq!(
            g.classify("simd-path", &full_snapshot()),
            FeatureVerdict::Enabled
        );
    }

    #[test]
    fn missing_avx512() {
        let mut g = SubstrateFeatureGate::new();
        g.set("simd-path", vec![Requirement::Avx512]).unwrap();
        let mut s = full_snapshot();
        s.avx512 = false;
        match g.classify("simd-path", &s) {
            FeatureVerdict::Disabled { missing } => {
                assert_eq!(missing, vec![Requirement::Avx512]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ram_at_least() {
        let mut g = SubstrateFeatureGate::new();
        g.set("big-model", vec![Requirement::RamAtLeastGB { gb: 128 }])
            .unwrap();
        assert_eq!(
            g.classify("big-model", &full_snapshot()),
            FeatureVerdict::Enabled
        );
        let mut s = full_snapshot();
        s.ram_mib = Some(64 * 1024);
        assert!(matches!(
            g.classify("big-model", &s),
            FeatureVerdict::Disabled { .. }
        ));
    }

    #[test]
    fn cores_at_least() {
        let mut g = SubstrateFeatureGate::new();
        g.set("parallel", vec![Requirement::CoresAtLeast { cores: 16 }])
            .unwrap();
        assert_eq!(
            g.classify("parallel", &full_snapshot()),
            FeatureVerdict::Enabled
        );
    }

    #[test]
    fn nvidia_gpu_required() {
        let mut g = SubstrateFeatureGate::new();
        g.set("gpu-path", vec![Requirement::NvidiaGpu]).unwrap();
        let mut s = full_snapshot();
        s.nvidia_gpu = false;
        assert!(matches!(
            g.classify("gpu-path", &s),
            FeatureVerdict::Disabled { .. }
        ));
    }

    #[test]
    fn unknown_metric_treated_as_missing() {
        let mut g = SubstrateFeatureGate::new();
        g.set("big-model", vec![Requirement::RamAtLeastGB { gb: 128 }])
            .unwrap();
        let mut s = full_snapshot();
        s.ram_mib = None;
        assert!(matches!(
            g.classify("big-model", &s),
            FeatureVerdict::Disabled { .. }
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut g = SubstrateFeatureGate::new();
        assert!(matches!(g.set("", vec![]).unwrap_err(), GateError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = SubstrateFeatureGate::new();
        g.schema_version = "9.9.9".into();
        assert!(matches!(
            g.validate().unwrap_err(),
            GateError::SchemaMismatch
        ));
    }

    #[test]
    fn gate_serde_roundtrip() {
        let mut g = SubstrateFeatureGate::new();
        g.set("simd-path", vec![Requirement::Avx2, Requirement::Avx512])
            .unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: SubstrateFeatureGate = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
