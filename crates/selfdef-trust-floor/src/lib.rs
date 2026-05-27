//! `selfdef-trust-floor` — per-side-effect minimum trust gates.
//!
//! Each of the 6 SideEffectClass values declares a `floor: u8` (0..=100).
//! A subject must hold `trust_score >= floor` to perform an action with
//! that side-effect — otherwise the gate's `decide_outcome` returns one
//! of (Allow / Ask / Deny) based on how far the subject is below floor.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, SideEffectClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-side-effect floor record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FloorRecord {
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// Minimum trust required (0..=100).
    pub floor: u8,
    /// Grace band (points below floor that still allow Ask rather than Deny).
    pub grace: u8,
}

/// Manifest envelope — 6 floors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustFloorManifest {
    /// Schema version.
    pub schema_version: String,
    /// 6 floors.
    pub floors: Vec<FloorRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FloorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 6.
    #[error("floor count {0} != 6 canonical")]
    CountInvalid(usize),
    /// Missing side-effect.
    #[error("missing floor for side-effect: {0:?}")]
    Missing(SideEffectClass),
    /// floor > 100.
    #[error("floor {floor} > 100 for {side_effect:?}")]
    FloorOutOfRange {
        /// side-effect.
        side_effect: SideEffectClass,
        /// floor.
        floor: u8,
    },
    /// trust > 100.
    #[error("trust {0} > 100")]
    TrustOutOfRange(u8),
}

const REQUIRED: [SideEffectClass; 6] = [
    SideEffectClass::None,
    SideEffectClass::ReadOnly,
    SideEffectClass::FsWrite,
    SideEffectClass::NetworkEgress,
    SideEffectClass::Process,
    SideEffectClass::Persistent,
];

impl TrustFloorManifest {
    /// Canonical operator-tuned defaults.
    pub fn canonical() -> Self {
        let floors = vec![
            FloorRecord {
                side_effect: SideEffectClass::None,
                floor: 0,
                grace: 0,
            },
            FloorRecord {
                side_effect: SideEffectClass::ReadOnly,
                floor: 10,
                grace: 5,
            },
            FloorRecord {
                side_effect: SideEffectClass::FsWrite,
                floor: 40,
                grace: 10,
            },
            FloorRecord {
                side_effect: SideEffectClass::NetworkEgress,
                floor: 35,
                grace: 10,
            },
            FloorRecord {
                side_effect: SideEffectClass::Process,
                floor: 60,
                grace: 15,
            },
            FloorRecord {
                side_effect: SideEffectClass::Persistent,
                floor: 80,
                grace: 10,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            floors,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FloorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FloorError::SchemaMismatch);
        }
        if self.floors.len() != 6 {
            return Err(FloorError::CountInvalid(self.floors.len()));
        }
        for s in REQUIRED {
            if !self.floors.iter().any(|r| r.side_effect == s) {
                return Err(FloorError::Missing(s));
            }
        }
        for r in &self.floors {
            if r.floor > 100 {
                return Err(FloorError::FloorOutOfRange {
                    side_effect: r.side_effect,
                    floor: r.floor,
                });
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: SideEffectClass) -> Option<&FloorRecord> {
        self.floors.iter().find(|r| r.side_effect == s)
    }

    /// Decide the outcome given the subject's trust score and the side-effect.
    /// Returns:
    /// - `Allow` if `trust >= floor`
    /// - `Ask`   if `floor - grace <= trust < floor`
    /// - `Deny`  if `trust < floor - grace`
    pub fn decide_outcome(
        &self,
        side_effect: SideEffectClass,
        trust: u8,
    ) -> Result<Outcome, FloorError> {
        if trust > 100 {
            return Err(FloorError::TrustOutOfRange(trust));
        }
        let r = self
            .get(side_effect)
            .ok_or(FloorError::Missing(side_effect))?;
        if trust >= r.floor {
            Ok(Outcome::Allow)
        } else if (r.floor as i16 - trust as i16) <= r.grace as i16 {
            Ok(Outcome::Ask)
        } else {
            Ok(Outcome::Deny)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        TrustFloorManifest::canonical().validate().unwrap();
    }

    #[test]
    fn allow_above_floor() {
        let m = TrustFloorManifest::canonical();
        // FsWrite floor=40 → trust 50 allows
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 50).unwrap(),
            Outcome::Allow
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 40).unwrap(),
            Outcome::Allow
        );
    }

    #[test]
    fn ask_within_grace() {
        let m = TrustFloorManifest::canonical();
        // FsWrite floor=40 grace=10 → 30..40 = Ask
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 35).unwrap(),
            Outcome::Ask
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 30).unwrap(),
            Outcome::Ask
        );
    }

    #[test]
    fn deny_below_grace() {
        let m = TrustFloorManifest::canonical();
        // FsWrite floor=40 grace=10 → trust<30 = Deny
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 29).unwrap(),
            Outcome::Deny
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::FsWrite, 0).unwrap(),
            Outcome::Deny
        );
    }

    #[test]
    fn persistent_requires_high_trust() {
        let m = TrustFloorManifest::canonical();
        // Persistent floor=80 grace=10 → trust=85 Allow; trust=75 Ask; trust=69 Deny
        assert_eq!(
            m.decide_outcome(SideEffectClass::Persistent, 85).unwrap(),
            Outcome::Allow
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::Persistent, 75).unwrap(),
            Outcome::Ask
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::Persistent, 69).unwrap(),
            Outcome::Deny
        );
    }

    #[test]
    fn none_floor_zero_always_allows() {
        let m = TrustFloorManifest::canonical();
        assert_eq!(
            m.decide_outcome(SideEffectClass::None, 0).unwrap(),
            Outcome::Allow
        );
        assert_eq!(
            m.decide_outcome(SideEffectClass::None, 100).unwrap(),
            Outcome::Allow
        );
    }

    #[test]
    fn trust_out_of_range_rejected() {
        let m = TrustFloorManifest::canonical();
        assert!(matches!(
            m.decide_outcome(SideEffectClass::FsWrite, 200).unwrap_err(),
            FloorError::TrustOutOfRange(200)
        ));
    }

    #[test]
    fn floor_out_of_range_caught() {
        let mut m = TrustFloorManifest::canonical();
        m.floors[0].floor = 200;
        assert!(matches!(
            m.validate().unwrap_err(),
            FloorError::FloorOutOfRange { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = TrustFloorManifest::canonical();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            FloorError::SchemaMismatch
        ));
    }

    #[test]
    fn count_invalid_caught() {
        let mut m = TrustFloorManifest::canonical();
        m.floors.pop();
        assert!(matches!(
            m.validate().unwrap_err(),
            FloorError::CountInvalid(5)
        ));
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = TrustFloorManifest::canonical();
        let j = serde_json::to_string(&m).unwrap();
        let back: TrustFloorManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
