//! `selfdef-substrate-tmpdir-policy` — per-Profile tmpdir caps.
//!
//! Per Profile, two independent caps: `max_bytes` (total tmpdir size)
//! and `max_age_ms` (oldest file age). `classify(profile, used_bytes,
//! oldest_age_ms)` returns:
//!   * `Healthy` — under both caps.
//!   * `OverSize { cap_bytes, used_bytes }` — size cap exceeded.
//!   * `OverAge { cap_ms, oldest_age_ms }` — age cap exceeded.
//!   * `OverBoth { ... }` — both caps exceeded.
//!   * `Unconfigured`.
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

/// Per-profile caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileCaps {
    /// Max tmpdir bytes.
    pub max_bytes: u64,
    /// Max age (ms).
    pub max_age_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateTmpdirPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile caps.
    pub profiles: BTreeMap<Profile, ProfileCaps>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TmpdirVerdict {
    /// Healthy.
    Healthy,
    /// Over size cap.
    OverSize {
        /// cap.
        cap_bytes: u64,
        /// used.
        used_bytes: u64,
    },
    /// Over age cap.
    OverAge {
        /// cap.
        cap_ms: u64,
        /// oldest.
        oldest_age_ms: u64,
    },
    /// Over both caps.
    OverBoth {
        /// cap bytes.
        cap_bytes: u64,
        /// used bytes.
        used_bytes: u64,
        /// cap age.
        cap_ms: u64,
        /// oldest age.
        oldest_age_ms: u64,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TmpdirError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SubstrateTmpdirPolicy {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        let mib = 1u64 << 20;
        let day = 24 * 60 * 60 * 1000;
        p.insert(Profile::Private,      ProfileCaps { max_bytes: 16 * mib, max_age_ms: 1 * day });
        p.insert(Profile::Fast,         ProfileCaps { max_bytes: 256 * mib, max_age_ms: 1 * day });
        p.insert(Profile::Careful,      ProfileCaps { max_bytes: 64 * mib, max_age_ms: 1 * day });
        p.insert(Profile::Autonomous,   ProfileCaps { max_bytes: 1024 * mib, max_age_ms: 7 * day });
        p.insert(Profile::Experimental, ProfileCaps { max_bytes: 4096 * mib, max_age_ms: 7 * day });
        p.insert(Profile::Production,   ProfileCaps { max_bytes: 512 * mib, max_age_ms: 1 * day });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, used_bytes: u64, oldest_age_ms: u64) -> TmpdirVerdict {
        let caps = match self.profiles.get(&profile).copied() {
            Some(c) => c,
            None => return TmpdirVerdict::Unconfigured,
        };
        let over_size = used_bytes >= caps.max_bytes;
        let over_age = oldest_age_ms >= caps.max_age_ms;
        match (over_size, over_age) {
            (false, false) => TmpdirVerdict::Healthy,
            (true, false) => TmpdirVerdict::OverSize { cap_bytes: caps.max_bytes, used_bytes },
            (false, true) => TmpdirVerdict::OverAge { cap_ms: caps.max_age_ms, oldest_age_ms },
            (true, true) => TmpdirVerdict::OverBoth {
                cap_bytes: caps.max_bytes, used_bytes,
                cap_ms: caps.max_age_ms, oldest_age_ms,
            },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TmpdirError> {
        if self.schema_version != SCHEMA_VERSION { return Err(TmpdirError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateTmpdirPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn healthy() {
        let p = SubstrateTmpdirPolicy::canonical();
        assert_eq!(p.classify(Profile::Production, 100, 100), TmpdirVerdict::Healthy);
    }

    #[test]
    fn over_size_only() {
        let p = SubstrateTmpdirPolicy::canonical();
        let mib = 1u64 << 20;
        // Production max 512 MiB.
        let v = p.classify(Profile::Production, 600 * mib, 100);
        assert!(matches!(v, TmpdirVerdict::OverSize { .. }));
    }

    #[test]
    fn over_age_only() {
        let p = SubstrateTmpdirPolicy::canonical();
        let day = 24 * 60 * 60 * 1000;
        let v = p.classify(Profile::Production, 100, 2 * day);
        assert!(matches!(v, TmpdirVerdict::OverAge { .. }));
    }

    #[test]
    fn over_both() {
        let p = SubstrateTmpdirPolicy::canonical();
        let mib = 1u64 << 20;
        let day = 24 * 60 * 60 * 1000;
        let v = p.classify(Profile::Production, 1000 * mib, 2 * day);
        assert!(matches!(v, TmpdirVerdict::OverBoth { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut p = SubstrateTmpdirPolicy::canonical();
        p.profiles.clear();
        assert_eq!(p.classify(Profile::Production, 0, 0), TmpdirVerdict::Unconfigured);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SubstrateTmpdirPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), TmpdirError::SchemaMismatch));
    }

    #[test]
    fn tmpdir_serde_roundtrip() {
        let p = SubstrateTmpdirPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: SubstrateTmpdirPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
