//! `selfdef-substrate-storage-quota` — per-Profile storage footprint cap.
//!
//! Each Profile has (soft_bytes, hard_bytes). `classify(profile,
//! used_bytes)` returns:
//!   * `Healthy` — used < soft.
//!   * `OverSoft { soft_bytes, used_bytes }` — soft ≤ used < hard.
//!   * `OverHard { hard_bytes, used_bytes }` — used ≥ hard.
//!   * `Unconfigured`.
//!
//! Pairs with `selfdef-substrate-disk-quota` (write budget over
//! window). This is the persistent-footprint lane.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
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

/// Caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileCaps {
    /// Soft threshold.
    pub soft_bytes: u64,
    /// Hard threshold.
    pub hard_bytes: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateStorageQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile caps.
    pub profiles: BTreeMap<Profile, ProfileCaps>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StorageVerdict {
    /// Healthy.
    Healthy,
    /// Soft cap exceeded.
    OverSoft {
        /// soft.
        soft_bytes: u64,
        /// used.
        used_bytes: u64,
    },
    /// Hard cap exceeded.
    OverHard {
        /// hard.
        hard_bytes: u64,
        /// used.
        used_bytes: u64,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Soft > hard.
    #[error("soft_bytes {0} > hard_bytes {1}")]
    BadThresholds(u64, u64),
}

impl SubstrateStorageQuota {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        let gb: u64 = 1 << 30;
        p.insert(
            Profile::Private,
            ProfileCaps {
                soft_bytes: 1 * gb,
                hard_bytes: 2 * gb,
            },
        );
        p.insert(
            Profile::Fast,
            ProfileCaps {
                soft_bytes: 4 * gb,
                hard_bytes: 8 * gb,
            },
        );
        p.insert(
            Profile::Careful,
            ProfileCaps {
                soft_bytes: 2 * gb,
                hard_bytes: 4 * gb,
            },
        );
        p.insert(
            Profile::Autonomous,
            ProfileCaps {
                soft_bytes: 16 * gb,
                hard_bytes: 32 * gb,
            },
        );
        p.insert(
            Profile::Experimental,
            ProfileCaps {
                soft_bytes: 64 * gb,
                hard_bytes: 128 * gb,
            },
        );
        p.insert(
            Profile::Production,
            ProfileCaps {
                soft_bytes: 8 * gb,
                hard_bytes: 16 * gb,
            },
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, used_bytes: u64) -> StorageVerdict {
        let caps = match self.profiles.get(&profile).copied() {
            Some(c) => c,
            None => return StorageVerdict::Unconfigured,
        };
        if used_bytes >= caps.hard_bytes {
            StorageVerdict::OverHard {
                hard_bytes: caps.hard_bytes,
                used_bytes,
            }
        } else if used_bytes >= caps.soft_bytes {
            StorageVerdict::OverSoft {
                soft_bytes: caps.soft_bytes,
                used_bytes,
            }
        } else {
            StorageVerdict::Healthy
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StorageError::SchemaMismatch);
        }
        for c in self.profiles.values() {
            if c.soft_bytes > c.hard_bytes {
                return Err(StorageError::BadThresholds(c.soft_bytes, c.hard_bytes));
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
        SubstrateStorageQuota::canonical().validate().unwrap();
    }

    #[test]
    fn healthy() {
        let q = SubstrateStorageQuota::canonical();
        assert_eq!(q.classify(Profile::Private, 100), StorageVerdict::Healthy);
    }

    #[test]
    fn over_soft() {
        let q = SubstrateStorageQuota::canonical();
        // Private soft 1 GiB.
        let gb = 1u64 << 30;
        let v = q.classify(Profile::Private, gb + 1);
        assert!(matches!(v, StorageVerdict::OverSoft { .. }));
    }

    #[test]
    fn over_hard() {
        let q = SubstrateStorageQuota::canonical();
        // Private hard 2 GiB.
        let gb = 1u64 << 30;
        let v = q.classify(Profile::Private, 3 * gb);
        assert!(matches!(v, StorageVerdict::OverHard { .. }));
    }

    #[test]
    fn experimental_admits_more() {
        let q = SubstrateStorageQuota::canonical();
        let gb = 1u64 << 30;
        assert_eq!(
            q.classify(Profile::Experimental, 30 * gb),
            StorageVerdict::Healthy
        );
    }

    #[test]
    fn unconfigured_profile() {
        let mut q = SubstrateStorageQuota::canonical();
        q.profiles.clear();
        assert_eq!(
            q.classify(Profile::Production, 0),
            StorageVerdict::Unconfigured
        );
    }

    #[test]
    fn bad_thresholds_rejected() {
        let mut q = SubstrateStorageQuota::canonical();
        q.profiles.insert(
            Profile::Production,
            ProfileCaps {
                soft_bytes: 1000,
                hard_bytes: 500,
            },
        );
        assert!(matches!(
            q.validate().unwrap_err(),
            StorageError::BadThresholds(_, _)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateStorageQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            StorageError::SchemaMismatch
        ));
    }

    #[test]
    fn storage_serde_roundtrip() {
        let q = SubstrateStorageQuota::canonical();
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateStorageQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
