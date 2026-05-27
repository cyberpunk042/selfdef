//! `selfdef-substrate-allocator-policy` — per-class allocation gate.
//!
//! 4 ResourceClass (Heap/Stack/Mmap/Tmpfile) each with per-alloc cap
//! and total cap (lifetime). admit() updates cumulative counter on
//! success.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Resource class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceClass {
    /// Heap allocation.
    Heap,
    /// Stack allocation (large frame).
    Stack,
    /// Mmap region.
    Mmap,
    /// Tmp file write.
    Tmpfile,
}

/// Per-class config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassQuota {
    /// Per-allocation cap (bytes).
    pub per_alloc_max: u64,
    /// Total lifetime cap (bytes).
    pub total_max: u64,
    /// Cumulative bytes allocated.
    pub total_used: u64,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateAllocatorPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Heap.
    pub heap: ClassQuota,
    /// Stack.
    pub stack: ClassQuota,
    /// Mmap.
    pub mmap: ClassQuota,
    /// Tmpfile.
    pub tmpfile: ClassQuota,
}

/// Decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AllocVerdict {
    /// Allow.
    Allow,
    /// Per-alloc cap exceeded.
    DeniedPerAlloc {
        /// observed.
        observed: u64,
        /// cap.
        cap: u64,
    },
    /// Total cap exceeded.
    DeniedTotal {
        /// would_total.
        would_total: u64,
        /// cap.
        cap: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum AllocError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// per_alloc_max zero.
    #[error("class {0:?} per_alloc_max zero")]
    PerAllocZero(ResourceClass),
    /// total_max zero.
    #[error("class {0:?} total_max zero")]
    TotalZero(ResourceClass),
    /// total_used > total_max.
    #[error("class {0:?} total_used exceeds total_max")]
    UsedExceedsTotal(ResourceClass),
}

impl SubstrateAllocatorPolicy {
    /// Canonical:
    /// * Heap: 64 MiB per-alloc, 4 GiB total.
    /// * Stack: 8 MiB per-alloc, 64 MiB total.
    /// * Mmap: 1 GiB per-alloc, 8 GiB total.
    /// * Tmpfile: 4 GiB per-alloc, 32 GiB total.
    pub fn canonical() -> Self {
        let mb = 1024 * 1024u64;
        let gb = 1024 * mb;
        Self {
            schema_version: SCHEMA_VERSION.into(),
            heap: ClassQuota {
                per_alloc_max: 64 * mb,
                total_max: 4 * gb,
                total_used: 0,
            },
            stack: ClassQuota {
                per_alloc_max: 8 * mb,
                total_max: 64 * mb,
                total_used: 0,
            },
            mmap: ClassQuota {
                per_alloc_max: gb,
                total_max: 8 * gb,
                total_used: 0,
            },
            tmpfile: ClassQuota {
                per_alloc_max: 4 * gb,
                total_max: 32 * gb,
                total_used: 0,
            },
        }
    }

    /// Mut quota for class.
    fn quota_mut(&mut self, c: ResourceClass) -> &mut ClassQuota {
        match c {
            ResourceClass::Heap => &mut self.heap,
            ResourceClass::Stack => &mut self.stack,
            ResourceClass::Mmap => &mut self.mmap,
            ResourceClass::Tmpfile => &mut self.tmpfile,
        }
    }

    /// Read quota for class.
    pub fn quota(&self, c: ResourceClass) -> ClassQuota {
        match c {
            ResourceClass::Heap => self.heap,
            ResourceClass::Stack => self.stack,
            ResourceClass::Mmap => self.mmap,
            ResourceClass::Tmpfile => self.tmpfile,
        }
    }

    /// Admit.
    pub fn admit(&mut self, c: ResourceClass, bytes: u64) -> AllocVerdict {
        let q = self.quota(c);
        if bytes > q.per_alloc_max {
            return AllocVerdict::DeniedPerAlloc {
                observed: bytes,
                cap: q.per_alloc_max,
            };
        }
        let would_total = q.total_used.saturating_add(bytes);
        if would_total > q.total_max {
            return AllocVerdict::DeniedTotal {
                would_total,
                cap: q.total_max,
            };
        }
        self.quota_mut(c).total_used = would_total;
        AllocVerdict::Allow
    }

    /// Release bytes (called when memory freed).
    pub fn release(&mut self, c: ResourceClass, bytes: u64) {
        let q = self.quota_mut(c);
        q.total_used = q.total_used.saturating_sub(bytes);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AllocError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AllocError::SchemaMismatch);
        }
        for (c, q) in [
            (ResourceClass::Heap, self.heap),
            (ResourceClass::Stack, self.stack),
            (ResourceClass::Mmap, self.mmap),
            (ResourceClass::Tmpfile, self.tmpfile),
        ] {
            if q.per_alloc_max == 0 {
                return Err(AllocError::PerAllocZero(c));
            }
            if q.total_max == 0 {
                return Err(AllocError::TotalZero(c));
            }
            if q.total_used > q.total_max {
                return Err(AllocError::UsedExceedsTotal(c));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateAllocatorPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn small_alloc_allows() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        assert!(matches!(
            p.admit(ResourceClass::Heap, 1024),
            AllocVerdict::Allow
        ));
    }

    #[test]
    fn per_alloc_cap_hit() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        // Stack per_alloc_max = 8 MiB.
        assert!(matches!(
            p.admit(ResourceClass::Stack, 1024 * 1024 * 100),
            AllocVerdict::DeniedPerAlloc { .. }
        ));
    }

    #[test]
    fn total_cap_hit() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        // Stack total = 64MiB. Allocate 7MiB 10 times: first 9 admit, 10th denied.
        for _ in 0..9 {
            assert!(matches!(
                p.admit(ResourceClass::Stack, 7 * 1024 * 1024),
                AllocVerdict::Allow
            ));
        }
        assert!(matches!(
            p.admit(ResourceClass::Stack, 7 * 1024 * 1024),
            AllocVerdict::DeniedTotal { .. }
        ));
    }

    #[test]
    fn release_frees_budget() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        let _ = p.admit(ResourceClass::Heap, 1024);
        let used_before = p.quota(ResourceClass::Heap).total_used;
        assert_eq!(used_before, 1024);
        p.release(ResourceClass::Heap, 1024);
        assert_eq!(p.quota(ResourceClass::Heap).total_used, 0);
    }

    #[test]
    fn per_alloc_zero_rejected() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        p.heap.per_alloc_max = 0;
        assert!(matches!(
            p.validate().unwrap_err(),
            AllocError::PerAllocZero(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateAllocatorPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            AllocError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ResourceClass::Tmpfile).unwrap(),
            "\"tmpfile\""
        );
    }

    #[test]
    fn verdict_serde_kebab() {
        let v = AllocVerdict::Allow;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"allow\"")
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = SubstrateAllocatorPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateAllocatorPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
