//! `selfdef-substrate-network-egress-quota` — per-Profile network-egress byte budget.
//!
//! Each Profile carries a rolling window (window_ms) with a byte budget
//! (window_budget_bytes) and a per-request max-bytes cap. `account()`
//! returns Accepted / RequestTooLarge / BudgetExhausted / Unconfigured.
//! `rotate()` trims records older than the widest configured window.
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
pub struct ProfileEgress {
    /// Rolling window (ms).
    pub window_ms: u64,
    /// Bytes allowed within window.
    pub window_budget_bytes: u64,
    /// Per-request max bytes.
    pub max_request_bytes: u64,
}

/// One recorded send.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRecord {
    /// monotonic ts ms.
    pub ts_ms: u64,
    /// bytes sent.
    pub bytes: u64,
    /// profile.
    pub profile: Profile,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateEgressQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileEgress>,
    /// Outstanding records.
    pub records: Vec<EgressRecord>,
}

/// Account verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EgressVerdict {
    /// Accepted; recorded.
    Accepted,
    /// Per-request cap exceeded.
    RequestTooLarge {
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
pub enum EgressError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl SubstrateEgressQuota {
    /// Canonical defaults (5-minute windows).
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        let m: u64 = 5 * 60 * 1000;
        profiles.insert(
            Profile::Private,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 8 << 20,
                max_request_bytes: 1 << 20,
            },
        );
        profiles.insert(
            Profile::Fast,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 64 << 20,
                max_request_bytes: 8 << 20,
            },
        );
        profiles.insert(
            Profile::Careful,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 32 << 20,
                max_request_bytes: 4 << 20,
            },
        );
        profiles.insert(
            Profile::Autonomous,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 128 << 20,
                max_request_bytes: 16 << 20,
            },
        );
        profiles.insert(
            Profile::Experimental,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 256 << 20,
                max_request_bytes: 32 << 20,
            },
        );
        profiles.insert(
            Profile::Production,
            ProfileEgress {
                window_ms: m,
                window_budget_bytes: 32 << 20,
                max_request_bytes: 4 << 20,
            },
        );
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            records: Vec::new(),
        }
    }

    /// Trim records older than widest window prior to now_ms.
    pub fn rotate(&mut self, now_ms: u64) {
        let max_window = self
            .profiles
            .values()
            .map(|p| p.window_ms)
            .max()
            .unwrap_or(0);
        let cutoff = now_ms.saturating_sub(max_window);
        self.records.retain(|r| r.ts_ms >= cutoff);
    }

    fn in_window_bytes(&self, profile: Profile, cfg: &ProfileEgress, now_ms: u64) -> u64 {
        let cutoff = now_ms.saturating_sub(cfg.window_ms);
        self.records
            .iter()
            .filter(|r| r.profile == profile && r.ts_ms >= cutoff && r.ts_ms <= now_ms)
            .map(|r| r.bytes)
            .sum()
    }

    /// Account for a candidate send of `bytes` at `now_ms`.
    pub fn account(
        &mut self,
        profile: Profile,
        bytes: u64,
        now_ms: u64,
    ) -> Result<EgressVerdict, EgressError> {
        if let Some(last) = self.records.last() {
            if now_ms < last.ts_ms {
                return Err(EgressError::NonMonotonic {
                    prev: last.ts_ms,
                    new: now_ms,
                });
            }
        }
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return Ok(EgressVerdict::Unconfigured),
        };
        if bytes > cfg.max_request_bytes {
            return Ok(EgressVerdict::RequestTooLarge {
                requested: bytes,
                cap: cfg.max_request_bytes,
            });
        }
        // Self-bound the record set. account() is the per-send hot path; without
        // this it appends a record on every accepted send and never trims, so a
        // long-running daemon that calls account() but forgets the separate
        // public rotate() would grow records without bound AND make
        // in_window_bytes() (a full scan) O(n) per call — O(n²) overall — on a
        // security-critical egress-budget path. rotate() drops only records
        // older than the largest configured window, which lie outside every
        // profile's per-window cutoff and so never contribute to an in_window
        // sum: verdicts are unchanged, memory and scan cost stay bounded.
        self.rotate(now_ms);
        let used = self.in_window_bytes(profile, &cfg, now_ms);
        let would = used.saturating_add(bytes);
        if would > cfg.window_budget_bytes {
            return Ok(EgressVerdict::BudgetExhausted {
                would_total: would,
                budget: cfg.window_budget_bytes,
            });
        }
        self.records.push(EgressRecord {
            ts_ms: now_ms,
            bytes,
            profile,
        });
        Ok(EgressVerdict::Accepted)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EgressError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EgressError::SchemaMismatch);
        }
        let mut last = 0u64;
        for r in &self.records {
            if r.ts_ms < last {
                return Err(EgressError::NonMonotonic {
                    prev: last,
                    new: r.ts_ms,
                });
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
        SubstrateEgressQuota::canonical().validate().unwrap();
    }

    #[test]
    fn accept_under_caps() {
        let mut q = SubstrateEgressQuota::canonical();
        assert!(matches!(
            q.account(Profile::Fast, 1 << 20, 0).unwrap(),
            EgressVerdict::Accepted
        ));
    }

    #[test]
    fn request_too_large() {
        let mut q = SubstrateEgressQuota::canonical();
        // Private max_request 1 MB.
        assert!(matches!(
            q.account(Profile::Private, 4 << 20, 0).unwrap(),
            EgressVerdict::RequestTooLarge { .. }
        ));
    }

    #[test]
    fn budget_exhausted() {
        let mut q = SubstrateEgressQuota::canonical();
        // Production 32 MB budget, 4 MB request cap. 8 × 4MB = 32MB; 9th exceeds.
        for _ in 0..8 {
            assert!(matches!(
                q.account(Profile::Production, 4 << 20, 0).unwrap(),
                EgressVerdict::Accepted
            ));
        }
        assert!(matches!(
            q.account(Profile::Production, 1, 0).unwrap(),
            EgressVerdict::BudgetExhausted { .. }
        ));
    }

    #[test]
    fn unconfigured_profile() {
        let mut q = SubstrateEgressQuota::canonical();
        q.profiles.clear();
        assert!(matches!(
            q.account(Profile::Fast, 100, 0).unwrap(),
            EgressVerdict::Unconfigured
        ));
    }

    #[test]
    fn window_slides() {
        let mut q = SubstrateEgressQuota::canonical();
        for _ in 0..8 {
            q.account(Profile::Production, 4 << 20, 0).unwrap();
        }
        // 6 minutes later, window has slid past.
        assert!(matches!(
            q.account(Profile::Production, 1, 6 * 60_000).unwrap(),
            EgressVerdict::Accepted
        ));
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut q = SubstrateEgressQuota::canonical();
        q.account(Profile::Fast, 100, 200).unwrap();
        assert!(matches!(
            q.account(Profile::Fast, 100, 100).unwrap_err(),
            EgressError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn rotate_drops_old() {
        let mut q = SubstrateEgressQuota::canonical();
        q.account(Profile::Fast, 1024, 0).unwrap();
        q.rotate(10 * 60_000);
        assert!(q.records.is_empty());
    }

    #[test]
    fn account_self_bounds_records_without_explicit_rotate() {
        // The per-send hot path must not leak: accounting repeatedly, each call
        // beyond the max window after the last, must keep records bounded even
        // though the caller never invokes rotate itself.
        let mut q = SubstrateEgressQuota::canonical();
        for i in 0..1000u64 {
            let now = i * (10 * 60_000); // 10 min apart > 5 min window
            assert!(matches!(
                q.account(Profile::Fast, 1024, now).unwrap(),
                EgressVerdict::Accepted
            ));
        }
        assert!(
            q.records.len() < 5,
            "records self-bounded by account (was {})",
            q.records.len()
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateEgressQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            EgressError::SchemaMismatch
        ));
    }

    #[test]
    fn egress_serde_roundtrip() {
        let mut q = SubstrateEgressQuota::canonical();
        q.account(Profile::Fast, 1024, 0).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateEgressQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
