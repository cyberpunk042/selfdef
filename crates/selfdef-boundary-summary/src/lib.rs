//! `selfdef-boundary-summary` — composite 5-boundary doctrine surface.
//!
//! Per R08591 the 5 IPS boundary modules form a SATURATED set:
//! - MS034 Communication boundary
//! - MS035 Capability boundary
//! - MS036 Sandbox boundary
//! - MS037 Filesystem boundary
//! - MS038 Network boundary
//!
//! This crate exposes the typed enumeration + a presence-summary so the
//! daemon can attest "all 5 boundaries are configured" at boot time.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine surface — 5-boundary saturated set per R08591.
pub const DOCTRINE_FIVE_BOUNDARIES: &str =
    "the IPS-side 5-boundary doctrine: Communication / Capability / Sandbox / Filesystem / Network";

/// The 5 canonical IPS boundary kinds per MS034-MS038.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryKind {
    /// MS034 Communication.
    Communication,
    /// MS035 Capability.
    Capability,
    /// MS036 Sandbox.
    Sandbox,
    /// MS037 Filesystem.
    Filesystem,
    /// MS038 Network.
    Network,
}

impl BoundaryKind {
    /// MS milestone id (e.g. "MS034").
    pub fn milestone_id(self) -> &'static str {
        match self {
            BoundaryKind::Communication => "MS034",
            BoundaryKind::Capability => "MS035",
            BoundaryKind::Sandbox => "MS036",
            BoundaryKind::Filesystem => "MS037",
            BoundaryKind::Network => "MS038",
        }
    }
    /// Canonical position 1..5 in the saturated set.
    pub fn position(self) -> u8 {
        match self {
            BoundaryKind::Communication => 1,
            BoundaryKind::Capability => 2,
            BoundaryKind::Sandbox => 3,
            BoundaryKind::Filesystem => 4,
            BoundaryKind::Network => 5,
        }
    }
    /// Owning crate name on disk.
    pub fn crate_name(self) -> &'static str {
        match self {
            BoundaryKind::Communication => "selfdef-communication-boundary",
            BoundaryKind::Capability => "selfdef-capability-word",
            BoundaryKind::Sandbox => "selfdef-sandbox-mirror",
            BoundaryKind::Filesystem => "selfdef-filesystem-boundary",
            BoundaryKind::Network => "selfdef-network-boundary",
        }
    }
}

/// Configuration status for one boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryStatus {
    /// Configured + healthy.
    Configured,
    /// Module present but config invalid.
    Invalid,
    /// Module missing entirely.
    Missing,
}

/// Per-boundary record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundaryRecord {
    /// Boundary discriminator.
    pub boundary: BoundaryKind,
    /// MS milestone id (must equal BoundaryKind::milestone_id()).
    pub milestone_id: String,
    /// Crate name (must equal BoundaryKind::crate_name()).
    pub crate_name: String,
    /// Current status.
    pub status: BoundaryStatus,
}

/// 5-boundary summary envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundarySummary {
    /// Schema version.
    pub schema_version: String,
    /// Doctrine surface — MUST equal [`DOCTRINE_FIVE_BOUNDARIES`].
    pub doctrine: String,
    /// 5 boundary records (exactly 5).
    pub boundaries: Vec<BoundaryRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SummaryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Doctrine tampered.
    #[error("doctrine tampered")]
    DoctrineTampered,
    /// Boundary count != 5.
    #[error("boundary count {0} != 5 saturated set")]
    BoundaryCountInvalid(usize),
    /// Required boundary missing.
    #[error("required boundary missing: {0:?}")]
    BoundaryMissing(BoundaryKind),
    /// Duplicate boundary.
    #[error("duplicate boundary: {0:?}")]
    DuplicateBoundary(BoundaryKind),
    /// Milestone-id mismatch.
    #[error("milestone_id mismatch for {boundary:?}: declared {declared}, canonical {canonical}")]
    MilestoneMismatch {
        /// Boundary.
        boundary: BoundaryKind,
        /// Declared.
        declared: String,
        /// Canonical.
        canonical: String,
    },
    /// At least one boundary is Missing — refuse daemon bring-up.
    #[error("boundary {0:?} is Missing — daemon cannot proceed (5-boundary saturated set requires all configured)")]
    BoundaryMissingStatus(BoundaryKind),
}

impl BoundarySummary {
    /// Construct canonical empty summary (all 5 Missing).
    pub fn empty_canonical() -> Self {
        let boundaries = [
            BoundaryKind::Communication, BoundaryKind::Capability,
            BoundaryKind::Sandbox, BoundaryKind::Filesystem, BoundaryKind::Network,
        ].into_iter().map(|b| BoundaryRecord {
            boundary: b,
            milestone_id: b.milestone_id().into(),
            crate_name: b.crate_name().into(),
            status: BoundaryStatus::Missing,
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            doctrine: DOCTRINE_FIVE_BOUNDARIES.into(),
            boundaries,
        }
    }

    /// Validate structural invariants (count/uniqueness/milestone-mapping).
    /// Does NOT enforce "all Configured" — that's via assert_all_configured().
    pub fn validate(&self) -> Result<(), SummaryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SummaryError::SchemaMismatch);
        }
        if self.doctrine != DOCTRINE_FIVE_BOUNDARIES {
            return Err(SummaryError::DoctrineTampered);
        }
        if self.boundaries.len() != 5 {
            return Err(SummaryError::BoundaryCountInvalid(self.boundaries.len()));
        }
        let required = [
            BoundaryKind::Communication, BoundaryKind::Capability,
            BoundaryKind::Sandbox, BoundaryKind::Filesystem, BoundaryKind::Network,
        ];
        for b in required {
            if !self.boundaries.iter().any(|r| r.boundary == b) {
                return Err(SummaryError::BoundaryMissing(b));
            }
        }
        use std::collections::HashSet;
        let mut seen: HashSet<BoundaryKind> = HashSet::new();
        for r in &self.boundaries {
            if !seen.insert(r.boundary) {
                return Err(SummaryError::DuplicateBoundary(r.boundary));
            }
            let canonical = r.boundary.milestone_id();
            if r.milestone_id != canonical {
                return Err(SummaryError::MilestoneMismatch {
                    boundary: r.boundary,
                    declared: r.milestone_id.clone(),
                    canonical: canonical.into(),
                });
            }
        }
        Ok(())
    }

    /// Daemon-boot gate — refuses to proceed unless ALL 5 boundaries Configured.
    pub fn assert_all_configured(&self) -> Result<(), SummaryError> {
        for r in &self.boundaries {
            if r.status == BoundaryStatus::Missing {
                return Err(SummaryError::BoundaryMissingStatus(r.boundary));
            }
        }
        Ok(())
    }

    /// Count of Configured boundaries.
    pub fn configured_count(&self) -> usize {
        self.boundaries.iter().filter(|r| r.status == BoundaryStatus::Configured).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_boundaries_positioned_1_to_5() {
        for (b, p) in [
            (BoundaryKind::Communication, 1), (BoundaryKind::Capability, 2),
            (BoundaryKind::Sandbox, 3), (BoundaryKind::Filesystem, 4),
            (BoundaryKind::Network, 5),
        ] {
            assert_eq!(b.position(), p);
        }
    }

    #[test]
    fn milestone_ids_match_ms034_ms038() {
        assert_eq!(BoundaryKind::Communication.milestone_id(), "MS034");
        assert_eq!(BoundaryKind::Capability.milestone_id(), "MS035");
        assert_eq!(BoundaryKind::Sandbox.milestone_id(), "MS036");
        assert_eq!(BoundaryKind::Filesystem.milestone_id(), "MS037");
        assert_eq!(BoundaryKind::Network.milestone_id(), "MS038");
    }

    #[test]
    fn crate_names_canonical() {
        assert_eq!(BoundaryKind::Communication.crate_name(), "selfdef-communication-boundary");
        assert_eq!(BoundaryKind::Capability.crate_name(), "selfdef-capability-word");
        assert_eq!(BoundaryKind::Network.crate_name(), "selfdef-network-boundary");
    }

    #[test]
    fn empty_canonical_validates_but_is_not_ready() {
        let s = BoundarySummary::empty_canonical();
        s.validate().unwrap();
        // All Missing → not all-configured
        assert!(s.assert_all_configured().is_err());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = BoundarySummary::empty_canonical();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SummaryError::SchemaMismatch));
    }

    #[test]
    fn doctrine_tamper_caught() {
        let mut s = BoundarySummary::empty_canonical();
        s.doctrine = "wrong".into();
        assert!(matches!(s.validate().unwrap_err(), SummaryError::DoctrineTampered));
    }

    #[test]
    fn boundary_count_invalid_caught() {
        let mut s = BoundarySummary::empty_canonical();
        s.boundaries.pop();
        assert!(matches!(s.validate().unwrap_err(), SummaryError::BoundaryCountInvalid(4)));
    }

    #[test]
    fn all_configured_passes() {
        let mut s = BoundarySummary::empty_canonical();
        for r in s.boundaries.iter_mut() {
            r.status = BoundaryStatus::Configured;
        }
        s.assert_all_configured().unwrap();
        assert_eq!(s.configured_count(), 5);
    }

    #[test]
    fn missing_boundary_blocks_daemon() {
        let mut s = BoundarySummary::empty_canonical();
        for r in s.boundaries.iter_mut() {
            r.status = BoundaryStatus::Configured;
        }
        // Leave one Missing
        s.boundaries[2].status = BoundaryStatus::Missing;
        match s.assert_all_configured().unwrap_err() {
            SummaryError::BoundaryMissingStatus(b) => assert_eq!(b, BoundaryKind::Sandbox),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn milestone_mismatch_caught() {
        let mut s = BoundarySummary::empty_canonical();
        s.boundaries[0].milestone_id = "MS999".into();
        match s.validate().unwrap_err() {
            SummaryError::MilestoneMismatch { boundary, declared, canonical } => {
                assert_eq!(boundary, BoundaryKind::Communication);
                assert_eq!(declared, "MS999");
                assert_eq!(canonical, "MS034");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn doctrine_verbatim() {
        assert_eq!(
            DOCTRINE_FIVE_BOUNDARIES,
            "the IPS-side 5-boundary doctrine: Communication / Capability / Sandbox / Filesystem / Network"
        );
    }

    #[test]
    fn boundary_kind_serde_kebab() {
        assert_eq!(serde_json::to_string(&BoundaryKind::Communication).unwrap(), "\"communication\"");
        assert_eq!(serde_json::to_string(&BoundaryKind::Capability).unwrap(), "\"capability\"");
    }

    #[test]
    fn boundary_summary_serde_roundtrip() {
        let s = BoundarySummary::empty_canonical();
        let j = serde_json::to_string(&s).unwrap();
        let back: BoundarySummary = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
