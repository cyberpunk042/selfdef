//! `selfdef-substrate-disk-quota` — per-profile disk-write budget + max-file gate.
//!
//! Each Profile has a rolling-window byte budget (window_ms wide) and a
//! per-write max-file-bytes cap. `account` records a write attempt and
//! returns a verdict; `rotate` trims expired records from the window.
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
pub struct ProfileDisk {
    /// Rolling window width (ms).
    pub window_ms: u64,
    /// Bytes allowed within window.
    pub window_budget_bytes: u64,
    /// Per-write max bytes.
    pub max_file_bytes: u64,
}

/// One recorded write.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteRecord {
    /// monotonic ts ms.
    pub ts_ms: u64,
    /// bytes written.
    pub bytes: u64,
    /// profile.
    pub profile: Profile,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateDiskQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileDisk>,
    /// Outstanding records.
    pub records: Vec<WriteRecord>,
}

/// Account verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AccountVerdict {
    /// Accepted; recorded.
    Accepted,
    /// Per-write cap exceeded.
    FileTooLarge {
        /// requested.
        requested: u64,
        /// cap.
        cap: u64,
    },
    /// Window budget exceeded.
    BudgetExhausted {
        /// in-window total + requested.
        would_total: u64,
        /// budget.
        budget: u64,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DiskQuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Non-monotonic timestamp.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl SubstrateDiskQuota {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        let day_ms: u64 = 24 * 60 * 60 * 1000;
        profiles.insert(Profile::Private, ProfileDisk { window_ms: day_ms, window_budget_bytes: 256 << 20, max_file_bytes: 32 << 20 });
        profiles.insert(Profile::Fast, ProfileDisk { window_ms: day_ms, window_budget_bytes: 1 << 30, max_file_bytes: 128 << 20 });
        profiles.insert(Profile::Careful, ProfileDisk { window_ms: day_ms, window_budget_bytes: 512 << 20, max_file_bytes: 64 << 20 });
        profiles.insert(Profile::Autonomous, ProfileDisk { window_ms: day_ms, window_budget_bytes: 2 << 30, max_file_bytes: 256 << 20 });
        profiles.insert(Profile::Experimental, ProfileDisk { window_ms: day_ms, window_budget_bytes: 4u64 << 30, max_file_bytes: 512 << 20 });
        profiles.insert(Profile::Production, ProfileDisk { window_ms: day_ms, window_budget_bytes: 512 << 20, max_file_bytes: 64 << 20 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            records: Vec::new(),
        }
    }

    /// Trim records older than the largest configured window prior to `now_ms`.
    pub fn rotate(&mut self, now_ms: u64) {
        let max_window = self.profiles.values().map(|p| p.window_ms).max().unwrap_or(0);
        let cutoff = now_ms.saturating_sub(max_window);
        self.records.retain(|r| r.ts_ms >= cutoff);
    }

    /// Sum bytes for a profile within its window ending at now_ms.
    fn in_window_bytes(&self, profile: Profile, cfg: &ProfileDisk, now_ms: u64) -> u64 {
        let cutoff = now_ms.saturating_sub(cfg.window_ms);
        self.records.iter()
            .filter(|r| r.profile == profile && r.ts_ms >= cutoff && r.ts_ms <= now_ms)
            .map(|r| r.bytes)
            .sum()
    }

    /// Account for a candidate write of `bytes` at `now_ms`.
    pub fn account(&mut self, profile: Profile, bytes: u64, now_ms: u64) -> Result<AccountVerdict, DiskQuotaError> {
        if let Some(last) = self.records.last() {
            if now_ms < last.ts_ms {
                return Err(DiskQuotaError::NonMonotonic { prev: last.ts_ms, new: now_ms });
            }
        }
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return Ok(AccountVerdict::Unconfigured),
        };
        if bytes > cfg.max_file_bytes {
            return Ok(AccountVerdict::FileTooLarge { requested: bytes, cap: cfg.max_file_bytes });
        }
        let used = self.in_window_bytes(profile, &cfg, now_ms);
        let would = used.saturating_add(bytes);
        if would > cfg.window_budget_bytes {
            return Ok(AccountVerdict::BudgetExhausted { would_total: would, budget: cfg.window_budget_bytes });
        }
        self.records.push(WriteRecord { ts_ms: now_ms, bytes, profile });
        Ok(AccountVerdict::Accepted)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DiskQuotaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DiskQuotaError::SchemaMismatch);
        }
        let mut last = 0u64;
        for r in &self.records {
            if r.ts_ms < last {
                return Err(DiskQuotaError::NonMonotonic { prev: last, new: r.ts_ms });
            }
            last = r.ts_ms;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateDiskQuota::canonical().validate().unwrap();
    }

    #[test]
    fn accept_under_caps() {
        let mut q = SubstrateDiskQuota::canonical();
        assert!(matches!(q.account(Profile::Fast, 1 << 20, 100).unwrap(), AccountVerdict::Accepted));
    }

    #[test]
    fn file_too_large() {
        let mut q = SubstrateDiskQuota::canonical();
        // Private max_file 32MB.
        assert!(matches!(
            q.account(Profile::Private, 64 << 20, 100).unwrap(),
            AccountVerdict::FileTooLarge { .. }
        ));
    }

    #[test]
    fn budget_exhausted() {
        let mut q = SubstrateDiskQuota::canonical();
        // Production budget 512 MB. Write 64 MB nine times: ninth exceeds.
        for _ in 0..8 {
            assert!(matches!(q.account(Profile::Production, 64 << 20, 100).unwrap(), AccountVerdict::Accepted));
        }
        let v = q.account(Profile::Production, 64 << 20, 100).unwrap();
        assert!(matches!(v, AccountVerdict::BudgetExhausted { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut q = SubstrateDiskQuota::canonical();
        q.profiles.clear();
        assert!(matches!(q.account(Profile::Fast, 100, 100).unwrap(), AccountVerdict::Unconfigured));
    }

    #[test]
    fn rotate_drops_old() {
        let mut q = SubstrateDiskQuota::canonical();
        q.account(Profile::Fast, 1024, 100).unwrap();
        // Day window + 1ms later, rotate.
        let day_ms: u64 = 24 * 60 * 60 * 1000;
        q.rotate(day_ms + 1000);
        assert!(q.records.is_empty());
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut q = SubstrateDiskQuota::canonical();
        q.account(Profile::Fast, 100, 200).unwrap();
        let err = q.account(Profile::Fast, 100, 100).unwrap_err();
        assert!(matches!(err, DiskQuotaError::NonMonotonic { .. }));
    }

    #[test]
    fn window_slides() {
        let mut q = SubstrateDiskQuota::canonical();
        // Production 512MB budget, 64MB writes.
        for i in 0..8 {
            q.account(Profile::Production, 64 << 20, i * 1000).unwrap();
        }
        // Without rotate, ninth at same instant fails.
        assert!(matches!(q.account(Profile::Production, 64 << 20, 8000).unwrap(), AccountVerdict::BudgetExhausted { .. }));
        // After a day, oldest records are out of window. account() respects window directly.
        let day_ms: u64 = 24 * 60 * 60 * 1000;
        let v = q.account(Profile::Production, 64 << 20, day_ms + 10_000).unwrap();
        assert!(matches!(v, AccountVerdict::Accepted));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateDiskQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), DiskQuotaError::SchemaMismatch));
    }

    #[test]
    fn quota_serde_roundtrip() {
        let mut q = SubstrateDiskQuota::canonical();
        q.account(Profile::Fast, 1024, 100).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateDiskQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
