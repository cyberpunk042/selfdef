//! `selfdef-substrate-gpu-quota` — per-profile GPU slot + VRAM gate.
//!
//! Concurrent slot count (max parallel inference jobs) and per-job
//! vram_mb cap per Profile. acquire returns a slot id; release frees.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Per-profile config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileGpu {
    /// Max concurrent slots.
    pub max_slots: u32,
    /// Per-job vram cap (MB).
    pub max_vram_mb_per_job: u32,
}

/// One active job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuJob {
    /// Slot id.
    pub slot_id: u64,
    /// Profile.
    pub profile: Profile,
    /// vram_mb.
    pub vram_mb: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateGpuQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileGpu>,
    /// Active jobs.
    pub active: Vec<GpuJob>,
    /// Next slot id.
    pub next_slot_id: u64,
}

/// Acquire decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AcquireDecision {
    /// Granted; carries slot_id.
    Granted {
        /// slot id.
        slot_id: u64,
    },
    /// All slots in use.
    NoSlots {
        /// active count.
        active: u32,
        /// cap.
        cap: u32,
    },
    /// Per-job VRAM exceeded.
    VramExceeded {
        /// observed.
        observed: u32,
        /// cap.
        cap: u32,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GpuError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown slot.
    #[error("unknown slot: {0}")]
    UnknownSlot(u64),
}

impl SubstrateGpuQuota {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            Profile::Private,
            ProfileGpu {
                max_slots: 2,
                max_vram_mb_per_job: 4096,
            },
        );
        profiles.insert(
            Profile::Fast,
            ProfileGpu {
                max_slots: 4,
                max_vram_mb_per_job: 4096,
            },
        );
        profiles.insert(
            Profile::Careful,
            ProfileGpu {
                max_slots: 1,
                max_vram_mb_per_job: 8192,
            },
        );
        profiles.insert(
            Profile::Autonomous,
            ProfileGpu {
                max_slots: 2,
                max_vram_mb_per_job: 6144,
            },
        );
        profiles.insert(
            Profile::Experimental,
            ProfileGpu {
                max_slots: 4,
                max_vram_mb_per_job: 8192,
            },
        );
        profiles.insert(
            Profile::Production,
            ProfileGpu {
                max_slots: 1,
                max_vram_mb_per_job: 4096,
            },
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            active: Vec::new(),
            next_slot_id: 1,
        }
    }

    /// Acquire.
    pub fn acquire(&mut self, profile: Profile, vram_mb: u32) -> AcquireDecision {
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return AcquireDecision::Unconfigured,
        };
        if vram_mb > cfg.max_vram_mb_per_job {
            return AcquireDecision::VramExceeded {
                observed: vram_mb,
                cap: cfg.max_vram_mb_per_job,
            };
        }
        let in_use = self.active.iter().filter(|j| j.profile == profile).count() as u32;
        if in_use >= cfg.max_slots {
            return AcquireDecision::NoSlots {
                active: in_use,
                cap: cfg.max_slots,
            };
        }
        let slot_id = self.next_slot_id;
        self.next_slot_id = self.next_slot_id.wrapping_add(1);
        self.active.push(GpuJob {
            slot_id,
            profile,
            vram_mb,
        });
        AcquireDecision::Granted { slot_id }
    }

    /// Release.
    pub fn release(&mut self, slot_id: u64) -> Result<(), GpuError> {
        let pos = self
            .active
            .iter()
            .position(|j| j.slot_id == slot_id)
            .ok_or(GpuError::UnknownSlot(slot_id))?;
        self.active.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GpuError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GpuError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateGpuQuota::canonical().validate().unwrap();
    }

    #[test]
    fn acquire_grants() {
        let mut q = SubstrateGpuQuota::canonical();
        match q.acquire(Profile::Fast, 1024) {
            AcquireDecision::Granted { .. } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn vram_exceeded() {
        let mut q = SubstrateGpuQuota::canonical();
        // Fast cap 4096.
        assert!(matches!(
            q.acquire(Profile::Fast, 8000),
            AcquireDecision::VramExceeded { .. }
        ));
    }

    #[test]
    fn no_slots_when_full() {
        let mut q = SubstrateGpuQuota::canonical();
        // Production has 1 slot.
        let r = q.acquire(Profile::Production, 1024);
        assert!(matches!(r, AcquireDecision::Granted { .. }));
        assert!(matches!(
            q.acquire(Profile::Production, 1024),
            AcquireDecision::NoSlots { .. }
        ));
    }

    #[test]
    fn release_frees_slot() {
        let mut q = SubstrateGpuQuota::canonical();
        let id = match q.acquire(Profile::Production, 1024) {
            AcquireDecision::Granted { slot_id } => slot_id,
            _ => unreachable!(),
        };
        q.release(id).unwrap();
        assert!(matches!(
            q.acquire(Profile::Production, 1024),
            AcquireDecision::Granted { .. }
        ));
    }

    #[test]
    fn release_unknown_rejected() {
        let mut q = SubstrateGpuQuota::canonical();
        assert!(matches!(
            q.release(999).unwrap_err(),
            GpuError::UnknownSlot(_)
        ));
    }

    #[test]
    fn unconfigured_returns_unconfigured() {
        let mut q = SubstrateGpuQuota::canonical();
        q.profiles.clear();
        assert!(matches!(
            q.acquire(Profile::Fast, 100),
            AcquireDecision::Unconfigured
        ));
    }

    #[test]
    fn slot_ids_unique() {
        let mut q = SubstrateGpuQuota::canonical();
        let ids: Vec<u64> = (0..3)
            .map(|_| match q.acquire(Profile::Fast, 100) {
                AcquireDecision::Granted { slot_id } => slot_id,
                _ => 0,
            })
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateGpuQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            GpuError::SchemaMismatch
        ));
    }

    #[test]
    fn quota_serde_roundtrip() {
        let mut q = SubstrateGpuQuota::canonical();
        q.acquire(Profile::Fast, 1024);
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateGpuQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
