//! `selfdef-sandbox-mirror` — MS007 typed-mirror crate exposing
//! selfdef MS036 sandbox tier A/B/C/D allocations READ-ONLY for
//! sovereign-os D-15 sandboxes dashboard consumption.
//!
//! Per MS043 R10185 + R10193, mirrors expose state read-only; mutations
//! proxy via MS003-signed operator request only.
//!
//! Sandbox tiers per MS036 E0362-E0365 (dump 3528-3549):
//! - **Tier A** — deterministic host tools (rg, parsers, formatters,
//!   read-only queries). Maps to MS032 sandbox tier 1.
//! - **Tier B** — controlled host tools (tests, builds, package
//!   managers, file edits). Maps to MS032 sandbox tiers 2-3.
//! - **Tier C** — VM tools (risky deps, unknown scripts, browser
//!   actions). Maps to MS032 sandbox tier 6a/6b.
//! - **Tier D** — disposable microVM (untrusted binaries, unknown
//!   archives, hostile inputs). Maps to MS032 sandbox tier 7+.
//!
//! Composes with:
//! - MS032 sandbox tier 1-9 catalog (graduated isolation per F04201)
//! - MS035 capability tokens (tier-aware enforcement per M00940)
//! - MS037 filesystem boundary (per-tier path reach)
//! - MS038 network boundary (Tier A/B network-denied default)
//! - MS042 declaration-vs-observed (tier escalation detection)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// MS036 sandbox tier discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxTier {
    /// Tier A — deterministic host tools (MS036 E0362, MS032 tier 1).
    TierA,
    /// Tier B — controlled host tools (MS036 E0363, MS032 tiers 2-3).
    TierB,
    /// Tier C — VM tools (MS036 E0364, MS032 tier 6).
    TierC,
    /// Tier D — disposable microVM (MS036 E0365, MS032 tier 7+).
    TierD,
}

/// Sandbox allocation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationState {
    /// Reservation requested, not yet bound to underlying isolation.
    Pending,
    /// Active allocation; resources committed; tool can run.
    Running,
    /// Allocation paused (CRIU checkpoint per MS032 tier 7a).
    Checkpointed,
    /// Idle / draining; awaiting reuse or reap.
    Idle,
    /// Released; resources freed; receipt retained per MS042.
    Released,
    /// Quarantined per MS042 declaration-vs-observed mismatch.
    Quarantined,
}

/// Underlying isolation primitive per MS032 tier mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationPrimitive {
    /// MS032 tier 1 — host process with seccomp + landlock.
    HostSeccomp,
    /// MS032 tier 2-3 — bubblewrap / firejail user-namespace.
    UserNamespace,
    /// MS032 tier 4-5 — network-denied / network-allowed bwrap.
    NetworkedNamespace,
    /// MS032 tier 6a — VFIO-passthrough KVM guest (RTX 3090).
    KvmVfio,
    /// MS032 tier 6b — KVM guest without GPU passthrough.
    KvmHeadless,
    /// MS032 tier 7a — CRIU checkpoint container.
    CriuCheckpoint,
    /// MS032 tier 7b — ZFS-clone disposable workspace.
    ZfsClone,
    /// MS032 tier 8+ — Firecracker microVM.
    FirecrackerMicrovm,
}

/// Single sandbox allocation entry. Wire-stable for D-15 rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocationEntry {
    /// Selfdef-internal allocation id (ULID).
    pub allocation_id: String,
    /// MS036 sandbox tier.
    pub tier: SandboxTier,
    /// MS032 sandbox tier index (1..9).
    pub ms032_tier: u8,
    /// Underlying isolation primitive.
    pub isolation: IsolationPrimitive,
    /// Tool name occupying this allocation (e.g. "rg", "cargo", "browser").
    pub tool: String,
    /// Capability token id bound to this allocation (MS035).
    pub capability_token_id: String,
    /// Active profile at allocation time (MS040).
    pub profile: String,
    /// Operator MS003 fingerprint who authorized.
    pub actor: String,
    /// ISO-8601 UTC allocation timestamp.
    pub allocated_at: String,
    /// ISO-8601 UTC scheduled release timestamp (TTL).
    pub release_at: String,
    /// TTL in seconds at allocation time.
    pub ttl_seconds: u32,
    /// Resident memory in MiB at last sample (MS042 observed metric).
    pub resident_mb: u32,
    /// CPU usage percent (0..400 for 4-core sandbox) at last sample.
    pub cpu_percent: u32,
    /// Current state.
    pub state: AllocationState,
    /// M049 trace_id reference.
    pub trace_id: String,
    /// MS003 signature over the allocation envelope (hex).
    pub signature: String,
}

/// Aggregate counts per sandbox tier, suitable for D-15 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierSummary {
    /// Sandbox tier.
    pub tier: SandboxTier,
    /// Count of allocations currently Running in this tier.
    pub running: u32,
    /// Count of allocations Pending in this tier.
    pub pending: u32,
    /// Count of allocations Checkpointed in this tier.
    pub checkpointed: u32,
    /// Count of allocations Idle in this tier.
    pub idle: u32,
    /// Count of allocations Released in this tier in the last 24h.
    pub released_24h: u32,
    /// Count of allocations Quarantined in this tier.
    pub quarantined: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os D-15 dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-tier tiles.
    pub summaries: Vec<TierSummary>,
    /// Full allocation list (may be empty if consumer requested summary).
    pub allocations: Vec<AllocationEntry>,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
    /// MS032 tier index out of expected 1..9 range.
    #[error("MS032 tier index {0} outside valid range 1..9")]
    InvalidMs032Tier(u8),
}

impl SandboxMirrorSnapshot {
    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }

    /// Validate that every allocation has a valid MS032 tier index.
    pub fn validate_ms032_indices(&self) -> Result<(), MirrorError> {
        for a in &self.allocations {
            if a.ms032_tier == 0 || a.ms032_tier > 9 {
                return Err(MirrorError::InvalidMs032Tier(a.ms032_tier));
            }
        }
        Ok(())
    }

    /// Aggregate allocations by tier. Read-only cross-check helper.
    pub fn recompute_summaries(&self) -> Vec<TierSummary> {
        use std::collections::HashMap;
        let mut by_tier: HashMap<SandboxTier, TierSummary> = HashMap::new();
        for a in &self.allocations {
            let entry = by_tier.entry(a.tier).or_insert(TierSummary {
                tier: a.tier,
                running: 0,
                pending: 0,
                checkpointed: 0,
                idle: 0,
                released_24h: 0,
                quarantined: 0,
            });
            match a.state {
                AllocationState::Running => entry.running += 1,
                AllocationState::Pending => entry.pending += 1,
                AllocationState::Checkpointed => entry.checkpointed += 1,
                AllocationState::Idle => entry.idle += 1,
                AllocationState::Released => entry.released_24h += 1,
                AllocationState::Quarantined => entry.quarantined += 1,
            }
        }
        let mut out: Vec<TierSummary> = by_tier.into_values().collect();
        out.sort_by_key(|s| match s.tier {
            SandboxTier::TierA => 0,
            SandboxTier::TierB => 1,
            SandboxTier::TierC => 2,
            SandboxTier::TierD => 3,
        });
        out
    }

    /// Count of allocations currently Running across all tiers.
    pub fn running_count(&self) -> usize {
        self.allocations.iter().filter(|a| a.state == AllocationState::Running).count()
    }

    /// Total resident memory across active (Running + Checkpointed) allocations, in MiB.
    pub fn total_resident_mb(&self) -> u64 {
        self.allocations.iter()
            .filter(|a| matches!(a.state, AllocationState::Running | AllocationState::Checkpointed))
            .map(|a| a.resident_mb as u64)
            .sum()
    }

    /// Map MS036 tier → expected MS032 tier index range. Static per E0368.
    pub fn ms032_range_for(tier: SandboxTier) -> (u8, u8) {
        match tier {
            SandboxTier::TierA => (1, 1),
            SandboxTier::TierB => (2, 5),
            SandboxTier::TierC => (6, 6),
            SandboxTier::TierD => (7, 9),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_alloc(id: &str, tier: SandboxTier, ms032: u8, state: AllocationState) -> AllocationEntry {
        AllocationEntry {
            allocation_id: id.into(),
            tier,
            ms032_tier: ms032,
            isolation: IsolationPrimitive::HostSeccomp,
            tool: "rg".into(),
            capability_token_id: format!("cap-{id}"),
            profile: "private".into(),
            actor: "operator-fp".into(),
            allocated_at: "2026-05-19T00:00:00Z".into(),
            release_at: "2026-05-19T00:30:00Z".into(),
            ttl_seconds: 1800,
            resident_mb: 256,
            cpu_percent: 12,
            state,
            trace_id: format!("trace-{id}"),
            signature: format!("sig-{id}"),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let snap = SandboxMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![],
            signature: String::new(),
        };
        assert!(matches!(snap.validate_schema().unwrap_err(), MirrorError::SchemaMismatch { .. }));
    }

    #[test]
    fn recompute_summaries_groups_by_tier() {
        let snap = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![
                mk_alloc("a", SandboxTier::TierA, 1, AllocationState::Running),
                mk_alloc("b", SandboxTier::TierA, 1, AllocationState::Running),
                mk_alloc("c", SandboxTier::TierB, 3, AllocationState::Pending),
                mk_alloc("d", SandboxTier::TierC, 6, AllocationState::Checkpointed),
                mk_alloc("e", SandboxTier::TierD, 8, AllocationState::Quarantined),
            ],
            signature: String::new(),
        };
        let summaries = snap.recompute_summaries();
        assert_eq!(summaries.len(), 4);
        let a = summaries.iter().find(|s| s.tier == SandboxTier::TierA).unwrap();
        assert_eq!(a.running, 2);
        let d = summaries.iter().find(|s| s.tier == SandboxTier::TierD).unwrap();
        assert_eq!(d.quarantined, 1);
    }

    #[test]
    fn ms032_range_for_each_tier() {
        assert_eq!(SandboxMirrorSnapshot::ms032_range_for(SandboxTier::TierA), (1, 1));
        assert_eq!(SandboxMirrorSnapshot::ms032_range_for(SandboxTier::TierB), (2, 5));
        assert_eq!(SandboxMirrorSnapshot::ms032_range_for(SandboxTier::TierC), (6, 6));
        assert_eq!(SandboxMirrorSnapshot::ms032_range_for(SandboxTier::TierD), (7, 9));
    }

    #[test]
    fn validate_ms032_indices_rejects_zero_and_oversize() {
        let bad_zero = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![mk_alloc("z", SandboxTier::TierA, 0, AllocationState::Running)],
            signature: String::new(),
        };
        assert!(matches!(bad_zero.validate_ms032_indices().unwrap_err(), MirrorError::InvalidMs032Tier(0)));

        let bad_high = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![mk_alloc("h", SandboxTier::TierD, 10, AllocationState::Running)],
            signature: String::new(),
        };
        assert!(matches!(bad_high.validate_ms032_indices().unwrap_err(), MirrorError::InvalidMs032Tier(10)));
    }

    #[test]
    fn total_resident_mb_sums_active_only() {
        let snap = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![
                {
                    let mut a = mk_alloc("a", SandboxTier::TierA, 1, AllocationState::Running);
                    a.resident_mb = 100;
                    a
                },
                {
                    let mut a = mk_alloc("b", SandboxTier::TierB, 3, AllocationState::Checkpointed);
                    a.resident_mb = 250;
                    a
                },
                {
                    let mut a = mk_alloc("c", SandboxTier::TierA, 1, AllocationState::Released);
                    a.resident_mb = 99999;
                    a
                },
            ],
            signature: String::new(),
        };
        assert_eq!(snap.total_resident_mb(), 350);
    }

    #[test]
    fn running_count_filters_state() {
        let snap = SandboxMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            allocations: vec![
                mk_alloc("a", SandboxTier::TierA, 1, AllocationState::Running),
                mk_alloc("b", SandboxTier::TierA, 1, AllocationState::Idle),
                mk_alloc("c", SandboxTier::TierA, 1, AllocationState::Running),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.running_count(), 2);
    }

    #[test]
    fn roundtrip_serde_preserves_fields() {
        let original = mk_alloc("alpha", SandboxTier::TierC, 6, AllocationState::Running);
        let j = serde_json::to_string(&original).unwrap();
        let back: AllocationEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn sandbox_tier_serde_uses_kebab_case() {
        let j = serde_json::to_string(&SandboxTier::TierA).unwrap();
        assert_eq!(j, "\"tier-a\"");
    }

    #[test]
    fn allocation_state_serde_uses_snake_case() {
        let j = serde_json::to_string(&AllocationState::Checkpointed).unwrap();
        assert_eq!(j, "\"checkpointed\"");
    }

    #[test]
    fn isolation_primitive_serde_uses_snake_case() {
        let j = serde_json::to_string(&IsolationPrimitive::FirecrackerMicrovm).unwrap();
        assert_eq!(j, "\"firecracker_microvm\"");
    }
}
