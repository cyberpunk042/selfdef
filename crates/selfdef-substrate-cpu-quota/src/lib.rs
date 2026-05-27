//! `selfdef-substrate-cpu-quota` — per-profile CPU-second budget.
//!
//! Records (profile, cpu_seconds, at_unix) usage in a sliding window
//! and gates new admissions by projected total.
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

/// One usage record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct UsageRecord {
    /// At unix seconds.
    pub at_unix: u64,
    /// CPU seconds consumed.
    pub cpu_seconds: f64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubstrateCpuQuota {
    /// Schema version.
    pub schema_version: String,
    /// Window length in seconds.
    pub window_seconds: u32,
    /// Per-profile cpu_seconds_per_window cap.
    pub caps: BTreeMap<Profile, f64>,
    /// Per-profile records.
    pub records: BTreeMap<Profile, Vec<UsageRecord>>,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Allow.
    Allow,
    /// Deny.
    Deny {
        /// projected total.
        projected_total: f64,
        /// cap.
        cap: f64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum QuotaError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Window zero.
    #[error("window_seconds zero")]
    WindowZero,
    /// NaN.
    #[error("value is NaN")]
    NanValue,
    /// Negative.
    #[error("value is negative")]
    Negative,
}

impl SubstrateCpuQuota {
    /// Canonical: 60s window with Production 30s cap, lower profiles smaller.
    pub fn canonical() -> Self {
        let mut caps = BTreeMap::new();
        caps.insert(Profile::Private, 60.0);
        caps.insert(Profile::Fast, 50.0);
        caps.insert(Profile::Careful, 40.0);
        caps.insert(Profile::Autonomous, 45.0);
        caps.insert(Profile::Experimental, 60.0);
        caps.insert(Profile::Production, 30.0);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_seconds: 60,
            caps,
            records: BTreeMap::new(),
        }
    }

    /// Sum of records inside the window.
    pub fn window_total(&self, profile: Profile, now_unix: u64) -> f64 {
        self.records
            .get(&profile)
            .map(|v| {
                v.iter()
                    .filter(|r| now_unix.saturating_sub(r.at_unix) < self.window_seconds as u64)
                    .map(|r| r.cpu_seconds)
                    .sum::<f64>()
            })
            .unwrap_or(0.0)
    }

    /// Cap for a profile (defaults to f64::MAX if unconfigured).
    pub fn cap(&self, profile: Profile) -> f64 {
        *self.caps.get(&profile).unwrap_or(&f64::MAX)
    }

    /// Admit a fresh charge.
    pub fn admit(
        &mut self,
        profile: Profile,
        cpu_seconds: f64,
        now_unix: u64,
    ) -> Result<AdmitDecision, QuotaError> {
        if cpu_seconds.is_nan() {
            return Err(QuotaError::NanValue);
        }
        if cpu_seconds < 0.0 {
            return Err(QuotaError::Negative);
        }
        let cap = self.cap(profile);
        // Age out records first.
        if let Some(v) = self.records.get_mut(&profile) {
            v.retain(|r| now_unix.saturating_sub(r.at_unix) < self.window_seconds as u64);
        }
        let current = self.window_total(profile, now_unix);
        let projected = current + cpu_seconds;
        if projected > cap {
            return Ok(AdmitDecision::Deny {
                projected_total: projected,
                cap,
            });
        }
        self.records.entry(profile).or_default().push(UsageRecord {
            at_unix: now_unix,
            cpu_seconds,
        });
        Ok(AdmitDecision::Allow)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QuotaError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QuotaError::SchemaMismatch);
        }
        if self.window_seconds == 0 {
            return Err(QuotaError::WindowZero);
        }
        for v in self.caps.values() {
            if v.is_nan() {
                return Err(QuotaError::NanValue);
            }
            if *v < 0.0 {
                return Err(QuotaError::Negative);
            }
        }
        for records in self.records.values() {
            for r in records {
                if r.cpu_seconds.is_nan() {
                    return Err(QuotaError::NanValue);
                }
                if r.cpu_seconds < 0.0 {
                    return Err(QuotaError::Negative);
                }
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
        SubstrateCpuQuota::canonical().validate().unwrap();
    }

    #[test]
    fn small_admit_allowed() {
        let mut q = SubstrateCpuQuota::canonical();
        assert!(matches!(
            q.admit(Profile::Production, 5.0, 1000).unwrap(),
            AdmitDecision::Allow
        ));
    }

    #[test]
    fn cap_exceeded_denied() {
        let mut q = SubstrateCpuQuota::canonical();
        // Production cap = 30s. Submit one big charge.
        assert!(matches!(
            q.admit(Profile::Production, 50.0, 1000).unwrap(),
            AdmitDecision::Deny { .. }
        ));
    }

    #[test]
    fn window_total_ages_out() {
        let mut q = SubstrateCpuQuota::canonical();
        q.admit(Profile::Production, 5.0, 1000).unwrap();
        assert_eq!(q.window_total(Profile::Production, 1000), 5.0);
        // 70 seconds later, window=60 → aged out.
        assert_eq!(q.window_total(Profile::Production, 1070), 0.0);
    }

    #[test]
    fn nan_rejected() {
        let mut q = SubstrateCpuQuota::canonical();
        assert!(matches!(
            q.admit(Profile::Production, f64::NAN, 1000).unwrap_err(),
            QuotaError::NanValue
        ));
    }

    #[test]
    fn negative_rejected() {
        let mut q = SubstrateCpuQuota::canonical();
        assert!(matches!(
            q.admit(Profile::Production, -5.0, 1000).unwrap_err(),
            QuotaError::Negative
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateCpuQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(
            q.validate().unwrap_err(),
            QuotaError::SchemaMismatch
        ));
    }

    #[test]
    fn profile_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&Profile::Autonomous).unwrap(),
            "\"autonomous\""
        );
    }

    #[test]
    fn quota_serde_roundtrip() {
        let mut q = SubstrateCpuQuota::canonical();
        q.admit(Profile::Production, 5.0, 1000).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateCpuQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
