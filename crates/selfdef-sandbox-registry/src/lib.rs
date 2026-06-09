//! `selfdef-sandbox-registry` — daemon-resident, persistent registry of
//! MS036 sandbox allocations. The live D-15 state the selfdef daemon
//! projects into the `selfdef-sandbox-mirror` MS007 snapshot for
//! sovereign-os to render READ-ONLY.
//!
//! Same shape as `selfdef-grant-registry` + `selfdef-capability-registry`:
//! holds a [`SandboxMirrorSnapshot`], persists atomically to
//! `/var/lib/selfdef/sandboxes.json` ([`DEFAULT_STATE_PATH`]), drives the
//! allocation lifecycle (Pending → Running → Checkpointed/Idle →
//! Released/Quarantined), validates `ms032_tier` against the configured
//! [`SandboxTier`]'s range per `ms032_range_for`.
//!
//! Mutation is an IPS-side verb (selfdefctl + MS003); sovereign-os never
//! mutates this — it renders the published mirror READ-ONLY (MS043 R10212).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports.
pub use selfdef_sandbox_mirror::{
    AllocationEntry, AllocationState, IsolationPrimitive, SCHEMA_VERSION, SandboxMirrorSnapshot,
    SandboxTier, TierSummary,
};

/// MS036 tier → MS032 tier index range (E0368). Free-function facade
/// over [`SandboxMirrorSnapshot::ms032_range_for`] so consumers can
/// validate against the range without naming the snapshot type.
#[must_use]
pub fn ms032_range_for(tier: SandboxTier) -> (u8, u8) {
    SandboxMirrorSnapshot::ms032_range_for(tier)
}

/// Default on-disk path for the persisted registry (operator override
/// via `SELFDEF_SANDBOXES_PATH`).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/sandboxes.json";

/// Hard upper bound on allocation TTL — 86400 seconds (24h).
pub const MAX_TTL_SECONDS: u32 = 86_400;

/// Operator-signed sandbox-allocation request. The MS003 signature is
/// mandatory per the verify-only signing doctrine (operators sign
/// externally with the `minisign` CLI).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocationRequest {
    /// Requesting actor MS003 fingerprint.
    pub actor: String,
    /// Active profile at allocation time (MS040).
    pub profile: String,
    /// MS036 sandbox tier (A/B/C/D).
    pub tier: SandboxTier,
    /// MS032 sandbox tier index (must lie within `ms032_range_for(tier)`).
    pub ms032_tier: u8,
    /// Underlying isolation primitive.
    pub isolation: IsolationPrimitive,
    /// Tool occupying the allocation (e.g. `rg`, `cargo`, `browser`).
    pub tool: String,
    /// Capability-token id bound to this allocation (MS035 linkage).
    pub capability_token_id: String,
    /// Desired TTL in seconds (≤ [`MAX_TTL_SECONDS`]).
    pub ttl_seconds: u32,
    /// MS003 signature over the canonical-JSON request (hex).
    pub signature: String,
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Request missing the MS003 signature.
    #[error("request unsigned (MS003 signature required)")]
    Unsigned,
    /// Mandatory string field empty.
    #[error("mandatory field empty: {0}")]
    EmptyField(&'static str),
    /// `ms032_tier` outside the configured tier's range.
    #[error("ms032_tier {0} outside range {1}..{2} for tier {3:?}")]
    Ms032OutOfRange(u8, u8, u8, SandboxTier),
    /// TTL above ceiling.
    #[error("ttl {0}s above {1}s ceiling")]
    TtlAboveCeiling(u32, u32),
    /// TTL zero.
    #[error("ttl=0 not allowed (allocations must have non-zero lifetime)")]
    TtlZero,
    /// Persisted store was present but malformed.
    #[error("malformed sandboxes store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("sandboxes store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed (should not happen with Rfc3339).
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// Daemon-resident sandbox-allocation registry.
#[derive(Debug, Clone)]
pub struct SandboxRegistry {
    snapshot: SandboxMirrorSnapshot,
}

impl Default for SandboxRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxRegistry {
    /// New empty registry, schema pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: SandboxMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                allocations: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot as the registry state.
    #[must_use]
    pub fn from_snapshot(snapshot: SandboxMirrorSnapshot) -> Self {
        Self { snapshot }
    }

    /// Load the persisted registry. Absent → empty; malformed → error.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => {
                return Err(RegistryError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        let snapshot = serde_json::from_str(&text).map_err(|e| RegistryError::Malformed {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(Self { snapshot })
    }

    /// Atomically and durably persist (tempfile + fsync + rename + dir fsync).
    ///
    /// Rename gives crash *consistency* (no torn read), the fsyncs give crash
    /// *durability*: write+rename can both return Ok with the bytes still in
    /// the page cache, so a power loss right after allocating or releasing a
    /// sandbox could lose the mutation, resurrect a stale file, or leave a
    /// zero-length store the daemon reloads as an empty sandbox set. Fsync the
    /// tempfile contents before the rename, then fsync the parent directory so
    /// the rename's new directory entry is durable too. Directory fsync is
    /// best-effort. Matches the selfdef-cli init / guardian fsync convention.
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        use std::io::Write as _;

        let io_err = |e: std::io::Error| RegistryError::Io {
            path: path.display().to_string(),
            source: e,
        };
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(io_err)?;
            }
        }
        let body =
            serde_json::to_string_pretty(&self.snapshot).map_err(|e| RegistryError::Malformed {
                path: path.display().to_string(),
                source: e,
            })?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
            f.write_all(body.as_bytes()).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        std::fs::rename(&tmp, path).map_err(io_err)?;
        if let Some(dir) = path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    /// Allocate a sandbox from a signed request. Computes
    /// `allocated_at`/`release_at` (now + ttl), appends a Pending entry,
    /// recomputes per-tier summaries + capture timestamp.
    pub fn allocate(
        &mut self,
        req: &AllocationRequest,
        allocation_id: &str,
        trace_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, RegistryError> {
        if req.signature.is_empty() {
            return Err(RegistryError::Unsigned);
        }
        if req.actor.is_empty() {
            return Err(RegistryError::EmptyField("actor"));
        }
        if req.profile.is_empty() {
            return Err(RegistryError::EmptyField("profile"));
        }
        if req.tool.is_empty() {
            return Err(RegistryError::EmptyField("tool"));
        }
        if req.capability_token_id.is_empty() {
            return Err(RegistryError::EmptyField("capability_token_id"));
        }
        if req.ttl_seconds == 0 {
            return Err(RegistryError::TtlZero);
        }
        if req.ttl_seconds > MAX_TTL_SECONDS {
            return Err(RegistryError::TtlAboveCeiling(
                req.ttl_seconds,
                MAX_TTL_SECONDS,
            ));
        }
        let (lo, hi) = ms032_range_for(req.tier);
        if req.ms032_tier < lo || req.ms032_tier > hi {
            return Err(RegistryError::Ms032OutOfRange(
                req.ms032_tier,
                lo,
                hi,
                req.tier,
            ));
        }
        let allocated_at = now.format(&Rfc3339)?;
        let release = now + time::Duration::seconds(i64::from(req.ttl_seconds));
        let release_at = release.format(&Rfc3339)?;
        let entry = AllocationEntry {
            allocation_id: allocation_id.to_string(),
            tier: req.tier,
            ms032_tier: req.ms032_tier,
            isolation: req.isolation,
            tool: req.tool.clone(),
            capability_token_id: req.capability_token_id.clone(),
            profile: req.profile.clone(),
            actor: req.actor.clone(),
            allocated_at,
            release_at,
            ttl_seconds: req.ttl_seconds,
            resident_mb: 0,
            cpu_percent: 0,
            state: AllocationState::Pending,
            trace_id: trace_id.to_string(),
            signature: req.signature.clone(),
        };
        self.snapshot.allocations.push(entry);
        self.recompute(now)?;
        Ok(allocation_id.to_string())
    }

    /// Transition Pending → Running.
    pub fn start(
        &mut self,
        allocation_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        self.set_state(allocation_id, AllocationState::Running, now)
    }

    /// Transition → Released (operator release / planned drain).
    pub fn release(
        &mut self,
        allocation_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        self.set_state(allocation_id, AllocationState::Released, now)
    }

    /// Mark every Running/Pending allocation whose `release_at` is past
    /// `now` as Released. Presentation-time hygiene the daemon export
    /// runs each tick.
    pub fn expire_due(&mut self, now: OffsetDateTime) -> Result<usize, RegistryError> {
        let mut changed = 0usize;
        for a in &mut self.snapshot.allocations {
            if matches!(a.state, AllocationState::Running | AllocationState::Pending) {
                let release = match OffsetDateTime::parse(&a.release_at, &Rfc3339) {
                    Ok(rel) => rel <= now,
                    // Unparseable release time: `allocate()` always writes
                    // RFC3339, so a malformed value means the persisted store was
                    // corrupted or tampered. Fail safe — release an allocation
                    // whose lifecycle window we cannot read, rather than leaving
                    // it Running indefinitely (fail-open: a leaked sandbox slot).
                    Err(_) => true,
                };
                if release {
                    a.state = AllocationState::Released;
                    changed += 1;
                }
            }
        }
        if changed > 0 {
            self.recompute(now)?;
        }
        Ok(changed)
    }

    fn set_state(
        &mut self,
        allocation_id: &str,
        state: AllocationState,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        let found = self
            .snapshot
            .allocations
            .iter_mut()
            .find(|a| a.allocation_id == allocation_id);
        match found {
            Some(a) => {
                a.state = state;
                self.recompute(now)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        Ok(())
    }

    /// Current published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &SandboxMirrorSnapshot {
        &self.snapshot
    }

    /// Live allocations.
    #[must_use]
    pub fn allocations(&self) -> &[AllocationEntry] {
        &self.snapshot.allocations
    }

    /// Count of allocations currently Running.
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.snapshot.running_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn req(tier: SandboxTier, ms032: u8) -> AllocationRequest {
        AllocationRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            tier,
            ms032_tier: ms032,
            isolation: IsolationPrimitive::HostSeccomp,
            tool: "rg".into(),
            capability_token_id: "tok-1".into(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = SandboxRegistry::new();
        assert!(r.allocations().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn allocate_appends_pending_and_sets_release() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        r.allocate(&req(SandboxTier::TierA, lo), "alloc-1", "t1", now())
            .unwrap();
        let a = &r.allocations()[0];
        assert_eq!(a.state, AllocationState::Pending);
        assert_eq!(a.tier, SandboxTier::TierA);
        assert_eq!(a.allocated_at, "2027-01-15T08:00:00Z");
        assert_eq!(a.release_at, "2027-01-15T09:00:00Z");
        assert_eq!(a.resident_mb, 0);
        let s = r
            .snapshot()
            .summaries
            .iter()
            .find(|s| s.tier == SandboxTier::TierA)
            .unwrap();
        assert_eq!(s.pending, 1);
    }

    #[test]
    fn allocate_rejects_unsigned() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let mut bad = req(SandboxTier::TierA, lo);
        bad.signature = String::new();
        assert!(matches!(
            r.allocate(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::Unsigned
        ));
    }

    #[test]
    fn allocate_rejects_ms032_out_of_range() {
        let mut r = SandboxRegistry::new();
        let (_, hi) = ms032_range_for(SandboxTier::TierA);
        let bad = req(SandboxTier::TierA, hi + 1);
        assert!(matches!(
            r.allocate(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::Ms032OutOfRange(_, _, _, SandboxTier::TierA)
        ));
    }

    #[test]
    fn allocate_rejects_empty_required_fields() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let mut bad = req(SandboxTier::TierA, lo);
        bad.tool = String::new();
        assert!(matches!(
            r.allocate(&bad, "x", "t", now()).unwrap_err(),
            RegistryError::EmptyField("tool")
        ));
        let mut bad2 = req(SandboxTier::TierA, lo);
        bad2.capability_token_id = String::new();
        assert!(matches!(
            r.allocate(&bad2, "x", "t", now()).unwrap_err(),
            RegistryError::EmptyField("capability_token_id")
        ));
    }

    #[test]
    fn allocate_rejects_ttl_zero_and_above_ceiling() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let mut z = req(SandboxTier::TierA, lo);
        z.ttl_seconds = 0;
        assert!(matches!(
            r.allocate(&z, "x", "t", now()).unwrap_err(),
            RegistryError::TtlZero
        ));
        let mut big = req(SandboxTier::TierA, lo);
        big.ttl_seconds = MAX_TTL_SECONDS + 1;
        assert!(matches!(
            r.allocate(&big, "x", "t", now()).unwrap_err(),
            RegistryError::TtlAboveCeiling(_, MAX_TTL_SECONDS)
        ));
    }

    #[test]
    fn start_then_release_transitions_state() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        r.allocate(&req(SandboxTier::TierA, lo), "alloc-1", "t1", now())
            .unwrap();
        assert!(r.start("alloc-1", now()).unwrap());
        assert_eq!(r.allocations()[0].state, AllocationState::Running);
        assert_eq!(r.running_count(), 1);
        assert!(r.release("alloc-1", now()).unwrap());
        assert_eq!(r.allocations()[0].state, AllocationState::Released);
        assert_eq!(r.running_count(), 0);
    }

    #[test]
    fn expire_due_marks_past_release() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let mut q = req(SandboxTier::TierA, lo);
        q.ttl_seconds = 60;
        r.allocate(&q, "alloc-1", "t1", now()).unwrap();
        r.start("alloc-1", now()).unwrap();
        let later = now() + time::Duration::seconds(61);
        assert_eq!(r.expire_due(later).unwrap(), 1);
        assert_eq!(r.allocations()[0].state, AllocationState::Released);
        assert_eq!(r.expire_due(later).unwrap(), 0);
    }

    #[test]
    fn expire_due_fails_safe_on_unparseable_release_at() {
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let mut q = req(SandboxTier::TierA, lo);
        q.ttl_seconds = 3600;
        r.allocate(&q, "alloc-1", "t1", now()).unwrap();
        r.start("alloc-1", now()).unwrap();
        // Tamper/corrupt the persisted release time to a non-RFC3339 value.
        r.snapshot.allocations[0].release_at = "not-a-timestamp".into();
        // `now` is within the original 3600s TTL, yet an allocation whose
        // release time can't be parsed must be released (fail-safe), never left
        // Running indefinitely.
        assert_eq!(r.expire_due(now()).unwrap(), 1);
        assert_eq!(r.allocations()[0].state, AllocationState::Released);
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandboxes.json");
        let mut r = SandboxRegistry::new();
        let (lo, _) = ms032_range_for(SandboxTier::TierD);
        r.allocate(&req(SandboxTier::TierD, lo), "alloc-1", "t1", now())
            .unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let back = SandboxRegistry::load(&path).unwrap();
        assert_eq!(back.allocations().len(), 1);
        assert_eq!(back.allocations()[0].tier, SandboxTier::TierD);
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn save_overwrites_existing_and_creates_missing_dirs() {
        // Durable save must create absent parent dirs and truncate a longer
        // prior file (File::create) so a shorter re-save leaves no stale tail.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/sandboxes.json");
        let (lo, _) = ms032_range_for(SandboxTier::TierD);

        let mut r = SandboxRegistry::new();
        r.allocate(&req(SandboxTier::TierD, lo), "alloc-1", "t1", now())
            .unwrap();
        r.allocate(&req(SandboxTier::TierD, lo), "alloc-2", "t2", now())
            .unwrap();
        r.save(&path).unwrap();
        assert_eq!(SandboxRegistry::load(&path).unwrap().allocations().len(), 2);

        let mut r2 = SandboxRegistry::new();
        r2.allocate(&req(SandboxTier::TierD, lo), "alloc-9", "t9", now())
            .unwrap();
        r2.save(&path).unwrap();

        let back = SandboxRegistry::load(&path).unwrap();
        assert_eq!(back.allocations().len(), 1);
        assert_eq!(back.allocations()[0].allocation_id, "alloc-9");
        back.snapshot().validate_schema().unwrap();
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = SandboxRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.allocations().is_empty());
    }

    /// All 4 tiers + the ms032 lower bound round-trip cleanly.
    #[test]
    fn all_tiers_allocate_at_ms032_lower_bound() {
        for tier in [
            SandboxTier::TierA,
            SandboxTier::TierB,
            SandboxTier::TierC,
            SandboxTier::TierD,
        ] {
            let mut r = SandboxRegistry::new();
            let (lo, _) = ms032_range_for(tier);
            r.allocate(&req(tier, lo), "alloc", "t", now()).unwrap();
            assert_eq!(r.allocations()[0].tier, tier);
            assert_eq!(r.allocations()[0].ms032_tier, lo);
        }
    }
}
