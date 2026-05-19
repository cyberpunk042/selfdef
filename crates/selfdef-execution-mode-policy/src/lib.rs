//! `selfdef-execution-mode-policy` — IPS authority over execution modes.
//!
//! Selfdef owns the SEMANTICS of every mode: what side-effects are
//! permitted, whether a snapshot is required before entry, whether a
//! replay source is mandatory. The runtime (sovereign-os) mirrors this
//! catalog and never invents new mode rules. Any deviation between the
//! runtime's declared mode capability tuple and this authority's tuple
//! is a `PolicyDrift` error.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 7 canonical execution modes (IPS-authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    /// Plan-only: no host writes, no network, no snapshot.
    Plan,
    /// Dry-run: network allowed, no writes.
    DryRun,
    /// Shadow: network mirror, no writes.
    Shadow,
    /// Sandbox: writes restricted to sandbox FS, no network.
    Sandbox,
    /// Execute: full live execution; snapshot required first.
    Execute,
    /// Replay: replay-source required; no writes, no network.
    Replay,
    /// Debug: full execute + verbose telemetry; no snapshot.
    Debug,
}

/// Capability tuple — IPS-authoritative semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeCapabilities {
    /// Host writes allowed.
    pub writes_allowed: bool,
    /// Network egress allowed.
    pub network_allowed: bool,
    /// ZFS snapshot required before entering this mode.
    pub snapshot_required: bool,
    /// Replay source JSONL required.
    pub replay_source_required: bool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Runtime's declared tuple deviated from the IPS authoritative tuple.
    #[error("policy drift for {mode:?}: runtime={runtime:?}, ips={ips:?}")]
    PolicyDrift {
        /// Mode in question.
        mode: ExecutionMode,
        /// Tuple the runtime claimed.
        runtime: ModeCapabilities,
        /// IPS-authoritative tuple.
        ips: ModeCapabilities,
    },
}

impl ExecutionMode {
    /// All 7 canonical modes in canonical order.
    pub const ALL: [ExecutionMode; 7] = [
        ExecutionMode::Plan,
        ExecutionMode::DryRun,
        ExecutionMode::Shadow,
        ExecutionMode::Sandbox,
        ExecutionMode::Execute,
        ExecutionMode::Replay,
        ExecutionMode::Debug,
    ];

    /// IPS-authoritative capability tuple for this mode.
    /// This function is the SINGLE SOURCE OF TRUTH for mode semantics.
    pub fn capabilities(self) -> ModeCapabilities {
        match self {
            ExecutionMode::Plan => ModeCapabilities {
                writes_allowed: false, network_allowed: false,
                snapshot_required: false, replay_source_required: false,
            },
            ExecutionMode::DryRun => ModeCapabilities {
                writes_allowed: false, network_allowed: true,
                snapshot_required: false, replay_source_required: false,
            },
            ExecutionMode::Shadow => ModeCapabilities {
                writes_allowed: false, network_allowed: true,
                snapshot_required: false, replay_source_required: false,
            },
            ExecutionMode::Sandbox => ModeCapabilities {
                writes_allowed: true, network_allowed: false,
                snapshot_required: false, replay_source_required: false,
            },
            ExecutionMode::Execute => ModeCapabilities {
                writes_allowed: true, network_allowed: true,
                snapshot_required: true, replay_source_required: false,
            },
            ExecutionMode::Replay => ModeCapabilities {
                writes_allowed: false, network_allowed: false,
                snapshot_required: false, replay_source_required: true,
            },
            ExecutionMode::Debug => ModeCapabilities {
                writes_allowed: true, network_allowed: true,
                snapshot_required: false, replay_source_required: false,
            },
        }
    }

    /// Does the IPS authority permit a write under this mode?
    pub fn permits_write(self) -> bool {
        self.capabilities().writes_allowed
    }

    /// Does the IPS authority permit a network call under this mode?
    pub fn permits_network(self) -> bool {
        self.capabilities().network_allowed
    }

    /// Must the daemon take a ZFS snapshot before entering this mode?
    pub fn requires_snapshot(self) -> bool {
        self.capabilities().snapshot_required
    }

    /// Must a replay source be supplied at mode entry?
    pub fn requires_replay_source(self) -> bool {
        self.capabilities().replay_source_required
    }
}

/// IPS authority assertion: runtime's declared tuple must equal IPS's.
/// The selfdef daemon calls this when validating a sovereign-os mirror.
pub fn assert_runtime_matches(mode: ExecutionMode, runtime: ModeCapabilities) -> Result<(), PolicyError> {
    let ips = mode.capabilities();
    if runtime != ips {
        return Err(PolicyError::PolicyDrift { mode, runtime, ips });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_modes_in_all() {
        assert_eq!(ExecutionMode::ALL.len(), 7);
    }

    #[test]
    fn plan_forbids_writes_and_network() {
        assert!(!ExecutionMode::Plan.permits_write());
        assert!(!ExecutionMode::Plan.permits_network());
        assert!(!ExecutionMode::Plan.requires_snapshot());
        assert!(!ExecutionMode::Plan.requires_replay_source());
    }

    #[test]
    fn execute_requires_snapshot() {
        assert!(ExecutionMode::Execute.permits_write());
        assert!(ExecutionMode::Execute.permits_network());
        assert!(ExecutionMode::Execute.requires_snapshot());
        assert!(!ExecutionMode::Execute.requires_replay_source());
    }

    #[test]
    fn sandbox_writes_no_network() {
        assert!(ExecutionMode::Sandbox.permits_write());
        assert!(!ExecutionMode::Sandbox.permits_network());
    }

    #[test]
    fn replay_only_mode_requiring_source() {
        for m in ExecutionMode::ALL {
            assert_eq!(m.requires_replay_source(), m == ExecutionMode::Replay,
                "{m:?} replay-source mismatch");
        }
    }

    #[test]
    fn execute_only_mode_requiring_snapshot() {
        for m in ExecutionMode::ALL {
            assert_eq!(m.requires_snapshot(), m == ExecutionMode::Execute,
                "{m:?} snapshot mismatch");
        }
    }

    #[test]
    fn debug_writes_and_network_no_snapshot() {
        assert!(ExecutionMode::Debug.permits_write());
        assert!(ExecutionMode::Debug.permits_network());
        assert!(!ExecutionMode::Debug.requires_snapshot());
    }

    #[test]
    fn dry_run_and_shadow_same_tuple() {
        assert_eq!(ExecutionMode::DryRun.capabilities(), ExecutionMode::Shadow.capabilities());
    }

    #[test]
    fn assert_runtime_matches_succeeds_on_canonical() {
        for m in ExecutionMode::ALL {
            assert_runtime_matches(m, m.capabilities()).unwrap();
        }
    }

    #[test]
    fn assert_runtime_matches_catches_drift() {
        let bad = ModeCapabilities {
            writes_allowed: true, network_allowed: true,
            snapshot_required: false, replay_source_required: false,
        };
        match assert_runtime_matches(ExecutionMode::Plan, bad).unwrap_err() {
            PolicyError::PolicyDrift { mode, .. } => assert_eq!(mode, ExecutionMode::Plan),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn mode_serde_kebab() {
        assert_eq!(serde_json::to_string(&ExecutionMode::Plan).unwrap(), "\"plan\"");
        assert_eq!(serde_json::to_string(&ExecutionMode::DryRun).unwrap(), "\"dry-run\"");
        assert_eq!(serde_json::to_string(&ExecutionMode::Sandbox).unwrap(), "\"sandbox\"");
    }

    #[test]
    fn capabilities_serde_roundtrip() {
        let c = ExecutionMode::Execute.capabilities();
        let j = serde_json::to_string(&c).unwrap();
        let back: ModeCapabilities = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
