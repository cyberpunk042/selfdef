//! `selfdef-canary-tripwire-policy` — canary state-hash tripwires.
//!
//! Each Tripwire pins an expected state-hash for a path/key. When
//! check() observes a hash that doesn't match, a Trip record is
//! generated with the tripwire's severity. Downstream gates react
//! (Critical → kill-switch, Warn → alert, etc.).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Warn — operator should be notified.
    Warn,
    /// Critical — trigger kill switch.
    Critical,
}

/// One tripwire definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tripwire {
    /// Stable id.
    pub id: String,
    /// What's being watched (free-form path/key).
    pub watch_path: String,
    /// Expected state-hash (hex).
    pub expected_hash: String,
    /// Severity on mismatch.
    pub severity: Severity,
}

/// A trip record (mismatch).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trip {
    /// Schema version.
    pub schema_version: String,
    /// Triggering tripwire id.
    pub tripwire_id: String,
    /// Watch path.
    pub watch_path: String,
    /// Expected hash.
    pub expected_hash: String,
    /// Observed hash.
    pub observed_hash: String,
    /// Severity.
    pub severity: Severity,
    /// ISO-8601 UTC.
    pub at: String,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryTripwirePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Tripwires.
    pub tripwires: Vec<Tripwire>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CanaryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("tripwire id empty")]
    EmptyId,
    /// Empty watch path.
    #[error("tripwire {0} watch_path empty")]
    EmptyPath(String),
    /// Bad hex hash.
    #[error("tripwire {0} expected_hash not hex (or empty)")]
    BadHash(String),
    /// Duplicate id.
    #[error("duplicate tripwire id: {0}")]
    DuplicateId(String),
    /// Unknown id.
    #[error("unknown tripwire id: {0}")]
    Unknown(String),
}

impl CanaryTripwirePolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tripwires: Vec::new(),
        }
    }

    /// Add a tripwire.
    pub fn add(&mut self, t: Tripwire) -> Result<(), CanaryError> {
        check_tripwire(&t)?;
        if self.tripwires.iter().any(|x| x.id == t.id) {
            return Err(CanaryError::DuplicateId(t.id));
        }
        self.tripwires.push(t);
        Ok(())
    }

    /// Check an observed hash against the tripwire. Returns Trip if mismatch.
    pub fn check(
        &self,
        tripwire_id: &str,
        observed_hash: &str,
        at: &str,
    ) -> Result<Option<Trip>, CanaryError> {
        let t = self
            .tripwires
            .iter()
            .find(|x| x.id == tripwire_id)
            .ok_or_else(|| CanaryError::Unknown(tripwire_id.into()))?;
        if t.expected_hash.eq_ignore_ascii_case(observed_hash) {
            return Ok(None);
        }
        Ok(Some(Trip {
            schema_version: SCHEMA_VERSION.into(),
            tripwire_id: t.id.clone(),
            watch_path: t.watch_path.clone(),
            expected_hash: t.expected_hash.clone(),
            observed_hash: observed_hash.into(),
            severity: t.severity,
            at: at.into(),
        }))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CanaryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CanaryError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for t in &self.tripwires {
            check_tripwire(t)?;
            if !seen.insert(t.id.as_str()) {
                return Err(CanaryError::DuplicateId(t.id.clone()));
            }
        }
        Ok(())
    }
}

fn check_tripwire(t: &Tripwire) -> Result<(), CanaryError> {
    if t.id.is_empty() {
        return Err(CanaryError::EmptyId);
    }
    if t.watch_path.is_empty() {
        return Err(CanaryError::EmptyPath(t.id.clone()));
    }
    if t.expected_hash.is_empty() || !t.expected_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CanaryError::BadHash(t.id.clone()));
    }
    Ok(())
}

impl Default for CanaryTripwirePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, hash: &str, sev: Severity) -> Tripwire {
        Tripwire {
            id: id.into(),
            watch_path: format!("/p/{id}"),
            expected_hash: hash.into(),
            severity: sev,
        }
    }

    #[test]
    fn matching_hash_no_trip() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "abc123", Severity::Warn)).unwrap();
        assert!(p.check("a", "abc123", "now").unwrap().is_none());
    }

    #[test]
    fn case_insensitive_hash_match() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "ABC123", Severity::Warn)).unwrap();
        assert!(p.check("a", "abc123", "now").unwrap().is_none());
    }

    #[test]
    fn mismatch_emits_trip() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "abc123", Severity::Critical)).unwrap();
        let trip = p.check("a", "deadbeef", "now").unwrap().unwrap();
        assert_eq!(trip.tripwire_id, "a");
        assert_eq!(trip.severity, Severity::Critical);
        assert_eq!(trip.observed_hash, "deadbeef");
    }

    #[test]
    fn unknown_tripwire_rejected() {
        let p = CanaryTripwirePolicy::new();
        assert!(matches!(
            p.check("ghost", "x", "now").unwrap_err(),
            CanaryError::Unknown(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = CanaryTripwirePolicy::new();
        assert!(matches!(
            p.add(t("", "abc", Severity::Info)).unwrap_err(),
            CanaryError::EmptyId
        ));
    }

    #[test]
    fn empty_path_rejected() {
        let mut p = CanaryTripwirePolicy::new();
        let mut x = t("a", "abc", Severity::Info);
        x.watch_path = String::new();
        assert!(matches!(p.add(x).unwrap_err(), CanaryError::EmptyPath(_)));
    }

    #[test]
    fn bad_hash_rejected() {
        let mut p = CanaryTripwirePolicy::new();
        assert!(matches!(
            p.add(t("a", "", Severity::Info)).unwrap_err(),
            CanaryError::BadHash(_)
        ));
        assert!(matches!(
            p.add(t("a", "not-hex!", Severity::Info)).unwrap_err(),
            CanaryError::BadHash(_)
        ));
    }

    #[test]
    fn duplicate_rejected() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "abc", Severity::Info)).unwrap();
        assert!(matches!(
            p.add(t("a", "def", Severity::Info)).unwrap_err(),
            CanaryError::DuplicateId(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = CanaryTripwirePolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            CanaryError::SchemaMismatch
        ));
    }

    #[test]
    fn severity_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
    }

    #[test]
    fn trip_serde_roundtrip() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "abc", Severity::Warn)).unwrap();
        let trip = p.check("a", "def", "now").unwrap().unwrap();
        let j = serde_json::to_string(&trip).unwrap();
        let back: Trip = serde_json::from_str(&j).unwrap();
        assert_eq!(trip, back);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = CanaryTripwirePolicy::new();
        p.add(t("a", "abc", Severity::Warn)).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: CanaryTripwirePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
