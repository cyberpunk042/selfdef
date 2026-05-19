//! `selfdef-functional-modules` — MS006 14-functional-module IPS catalog.
//!
//! Per MS006 + E0056-E0070 — the 14 operator-selectable IPS modules
//! that compose into the selfdef stack. detect-host (E0060) is the
//! substrate every other module feeds into.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 14 canonical IPS functional modules per MS006 E0057-E0070.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpsModule {
    /// 1. Tetragon TracingPolicies for AI agents.
    AgentGuard,
    /// 2. GPU-side BitNet ternary inference provisioning.
    BitnetGpuInference,
    /// 3. Transparent Layer-2 bridge (foundation).
    BridgeL2,
    /// 4. selfdef daemon packaged module (substrate).
    DetectHost,
    /// 5. Hardware-tune cache for selfdefctl hardware tune.
    HardwareTuneCache,
    /// 6. SHA256 baseline + fail-closed drift detection.
    IntegritySentinel,
    /// 7. Prometheus + Grafana stack for selfdef.
    Observability,
    /// 8. Transparent PolarProxy TLS termination + PCAP-over-IP.
    Polarproxy,
    /// 9. SLM-on-CPU agent loop pinned to CCD-0.
    SlmCpuLoop,
    /// 10. Inline Suricata IDS + bridge-l2 hook + eve.json.
    Suricata,
    /// 11. Tensor-parallel inference splits across GPUs.
    TensorParallelInference,
    /// 12. Tetragon substrate (config + policy drop + metrics).
    Tetragon,
    /// 13. VPN remote-network connectivity.
    VpnBridge,
    /// 14. AOT-compiled WASM cache for WASM-plugin tier.
    WasmAotCache,
}

impl IpsModule {
    /// Canonical 1..14 position per E0057-E0070.
    pub fn position(self) -> u8 {
        match self {
            IpsModule::AgentGuard => 1,
            IpsModule::BitnetGpuInference => 2,
            IpsModule::BridgeL2 => 3,
            IpsModule::DetectHost => 4,
            IpsModule::HardwareTuneCache => 5,
            IpsModule::IntegritySentinel => 6,
            IpsModule::Observability => 7,
            IpsModule::Polarproxy => 8,
            IpsModule::SlmCpuLoop => 9,
            IpsModule::Suricata => 10,
            IpsModule::TensorParallelInference => 11,
            IpsModule::Tetragon => 12,
            IpsModule::VpnBridge => 13,
            IpsModule::WasmAotCache => 14,
        }
    }
    /// On-disk module directory under `modules/`.
    pub fn module_dir(self) -> &'static str {
        match self {
            IpsModule::AgentGuard => "agent-guard",
            IpsModule::BitnetGpuInference => "bitnet-gpu-inference",
            IpsModule::BridgeL2 => "bridge-l2",
            IpsModule::DetectHost => "detect-host",
            IpsModule::HardwareTuneCache => "hardware-tune-cache",
            IpsModule::IntegritySentinel => "integrity-sentinel",
            IpsModule::Observability => "observability",
            IpsModule::Polarproxy => "polarproxy",
            IpsModule::SlmCpuLoop => "slm-cpu-loop",
            IpsModule::Suricata => "suricata",
            IpsModule::TensorParallelInference => "tensor-parallel-inference",
            IpsModule::Tetragon => "tetragon",
            IpsModule::VpnBridge => "vpn-bridge",
            IpsModule::WasmAotCache => "wasm-aot-cache",
        }
    }
    /// Whether this module is the substrate (detect-host only).
    pub fn is_substrate(self) -> bool {
        self == IpsModule::DetectHost
    }
}

/// Per-module install state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleState {
    /// Module not installed.
    Absent,
    /// Module installed + active.
    Active,
    /// Module installed but disabled by operator.
    Disabled,
    /// Module installed but failed health check.
    Failed,
}

/// One module entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleEntry {
    /// Module discriminator.
    pub module: IpsModule,
    /// Module dir (must match IpsModule::module_dir()).
    pub module_dir: String,
    /// Current state.
    pub state: ModuleState,
    /// Operator notes.
    pub notes: String,
}

/// Catalog envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpsModuleCatalog {
    /// Schema version.
    pub schema_version: String,
    /// 14 entries (MUST be exactly 14).
    pub entries: Vec<ModuleEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ModuleError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Entry count != 14.
    #[error("entry count {0} != 14 canonical IPS modules")]
    EntryCountInvalid(usize),
    /// Required module missing.
    #[error("required module missing: {0:?}")]
    ModuleMissing(IpsModule),
    /// Duplicate module.
    #[error("duplicate module: {0:?}")]
    DuplicateModule(IpsModule),
    /// module_dir does not match canonical.
    #[error("module_dir mismatch for {module:?}: expected {expected}, got {actual}")]
    DirMismatch {
        /// Module.
        module: IpsModule,
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Substrate module (detect-host) is not Active — selfdef cannot function.
    #[error("substrate detect-host not Active (substrate doctrine violated)")]
    SubstrateNotActive,
}

impl IpsModuleCatalog {
    /// Construct empty canonical catalog (all 14 modules Absent + detect-host Active prerequisite).
    pub fn empty_canonical() -> Self {
        let modules = [
            IpsModule::AgentGuard, IpsModule::BitnetGpuInference, IpsModule::BridgeL2,
            IpsModule::DetectHost, IpsModule::HardwareTuneCache, IpsModule::IntegritySentinel,
            IpsModule::Observability, IpsModule::Polarproxy, IpsModule::SlmCpuLoop,
            IpsModule::Suricata, IpsModule::TensorParallelInference, IpsModule::Tetragon,
            IpsModule::VpnBridge, IpsModule::WasmAotCache,
        ];
        let entries = modules.into_iter().map(|m| ModuleEntry {
            module: m,
            module_dir: m.module_dir().into(),
            state: if m == IpsModule::DetectHost { ModuleState::Active } else { ModuleState::Absent },
            notes: String::new(),
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries,
        }
    }

    /// Validate canonical invariants.
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ModuleError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.entries.len() != 14 {
            return Err(ModuleError::EntryCountInvalid(self.entries.len()));
        }
        let required = [
            IpsModule::AgentGuard, IpsModule::BitnetGpuInference, IpsModule::BridgeL2,
            IpsModule::DetectHost, IpsModule::HardwareTuneCache, IpsModule::IntegritySentinel,
            IpsModule::Observability, IpsModule::Polarproxy, IpsModule::SlmCpuLoop,
            IpsModule::Suricata, IpsModule::TensorParallelInference, IpsModule::Tetragon,
            IpsModule::VpnBridge, IpsModule::WasmAotCache,
        ];
        for m in required {
            if !self.entries.iter().any(|e| e.module == m) {
                return Err(ModuleError::ModuleMissing(m));
            }
        }
        use std::collections::HashSet;
        let mut seen: HashSet<IpsModule> = HashSet::new();
        for e in &self.entries {
            if !seen.insert(e.module) {
                return Err(ModuleError::DuplicateModule(e.module));
            }
            let canonical = e.module.module_dir();
            if e.module_dir != canonical {
                return Err(ModuleError::DirMismatch {
                    module: e.module,
                    expected: canonical.into(),
                    actual: e.module_dir.clone(),
                });
            }
        }
        // Substrate must be Active.
        let substrate = self.entries.iter().find(|e| e.module == IpsModule::DetectHost).unwrap();
        if substrate.state != ModuleState::Active {
            return Err(ModuleError::SubstrateNotActive);
        }
        Ok(())
    }

    /// Lookup entry by module.
    pub fn entry(&self, module: IpsModule) -> Option<&ModuleEntry> {
        self.entries.iter().find(|e| e.module == module)
    }

    /// State counts (absent, active, disabled, failed).
    pub fn state_counts(&self) -> (u32, u32, u32, u32) {
        let mut a = 0; let mut ac = 0; let mut d = 0; let mut f = 0;
        for e in &self.entries {
            match e.state {
                ModuleState::Absent => a += 1,
                ModuleState::Active => ac += 1,
                ModuleState::Disabled => d += 1,
                ModuleState::Failed => f += 1,
            }
        }
        (a, ac, d, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_canonical_validates() {
        IpsModuleCatalog::empty_canonical().validate().unwrap();
    }

    #[test]
    fn fourteen_modules_positioned_1_to_14() {
        let order = [
            (IpsModule::AgentGuard, 1), (IpsModule::BitnetGpuInference, 2),
            (IpsModule::BridgeL2, 3), (IpsModule::DetectHost, 4),
            (IpsModule::HardwareTuneCache, 5), (IpsModule::IntegritySentinel, 6),
            (IpsModule::Observability, 7), (IpsModule::Polarproxy, 8),
            (IpsModule::SlmCpuLoop, 9), (IpsModule::Suricata, 10),
            (IpsModule::TensorParallelInference, 11), (IpsModule::Tetragon, 12),
            (IpsModule::VpnBridge, 13), (IpsModule::WasmAotCache, 14),
        ];
        for (m, p) in order {
            assert_eq!(m.position(), p);
        }
    }

    #[test]
    fn detect_host_is_substrate() {
        assert!(IpsModule::DetectHost.is_substrate());
        for m in [
            IpsModule::AgentGuard, IpsModule::BridgeL2, IpsModule::Suricata,
            IpsModule::Tetragon, IpsModule::WasmAotCache,
        ] {
            assert!(!m.is_substrate());
        }
    }

    #[test]
    fn module_dirs_match_canonical_names() {
        assert_eq!(IpsModule::AgentGuard.module_dir(), "agent-guard");
        assert_eq!(IpsModule::TensorParallelInference.module_dir(), "tensor-parallel-inference");
        assert_eq!(IpsModule::WasmAotCache.module_dir(), "wasm-aot-cache");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = IpsModuleCatalog::empty_canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ModuleError::SchemaMismatch { .. }));
    }

    #[test]
    fn substrate_not_active_caught() {
        let mut c = IpsModuleCatalog::empty_canonical();
        // Find detect-host entry and set to Absent
        for e in c.entries.iter_mut() {
            if e.module == IpsModule::DetectHost {
                e.state = ModuleState::Absent;
            }
        }
        assert!(matches!(c.validate().unwrap_err(), ModuleError::SubstrateNotActive));
    }

    #[test]
    fn entry_count_invalid_caught() {
        let mut c = IpsModuleCatalog::empty_canonical();
        c.entries.pop();
        assert!(matches!(c.validate().unwrap_err(), ModuleError::EntryCountInvalid(13)));
    }

    #[test]
    fn dir_mismatch_caught() {
        let mut c = IpsModuleCatalog::empty_canonical();
        c.entries[0].module_dir = "wrong-name".into();
        match c.validate().unwrap_err() {
            ModuleError::DirMismatch { module, expected, actual } => {
                assert_eq!(module, IpsModule::AgentGuard);
                assert_eq!(expected, "agent-guard");
                assert_eq!(actual, "wrong-name");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn state_counts_initial() {
        let c = IpsModuleCatalog::empty_canonical();
        let (absent, active, disabled, failed) = c.state_counts();
        assert_eq!(absent, 13);
        assert_eq!(active, 1);  // only DetectHost
        assert_eq!(disabled, 0);
        assert_eq!(failed, 0);
    }

    #[test]
    fn ips_module_serde_kebab() {
        assert_eq!(serde_json::to_string(&IpsModule::TensorParallelInference).unwrap(), "\"tensor-parallel-inference\"");
        assert_eq!(serde_json::to_string(&IpsModule::WasmAotCache).unwrap(), "\"wasm-aot-cache\"");
        assert_eq!(serde_json::to_string(&IpsModule::SlmCpuLoop).unwrap(), "\"slm-cpu-loop\"");
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let c = IpsModuleCatalog::empty_canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: IpsModuleCatalog = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
