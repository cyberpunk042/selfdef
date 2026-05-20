//! `selfdef-actor-trust-floor` — per-Profile minimum-trust-score floor.
//!
//! Each Profile has a floor in `0..=1000` (the trust-score-engine
//! domain). classify(profile, score) returns Allowed / BelowFloor{floor}
//! / Unconfigured.
//!
//! Canonical floors are strictest for Production and weakest for
//! Experimental — so that an actor with a tarnished trust score can
//! still try Experimental work while being barred from Production.
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

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorTrustFloor {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile floor (0..=1000).
    pub floors: BTreeMap<Profile, u16>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TrustVerdict {
    /// Score meets the floor.
    Allowed,
    /// Score under the floor.
    BelowFloor {
        /// floor.
        floor: u16,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FloorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Floor > 1000.
    #[error("floor {0} > 1000")]
    FloorOver1000(u16),
    /// Score > 1000.
    #[error("score {0} > 1000")]
    ScoreOver1000(u16),
}

impl ActorTrustFloor {
    /// Canonical floors.
    pub fn canonical() -> Self {
        let mut f = BTreeMap::new();
        f.insert(Profile::Private, 200);
        f.insert(Profile::Fast, 500);
        f.insert(Profile::Careful, 700);
        f.insert(Profile::Autonomous, 800);
        f.insert(Profile::Experimental, 100);
        f.insert(Profile::Production, 900);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            floors: f,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, score: u16) -> Result<TrustVerdict, FloorError> {
        if score > 1000 { return Err(FloorError::ScoreOver1000(score)); }
        let floor = match self.floors.get(&profile) {
            Some(&f) => f,
            None => return Ok(TrustVerdict::Unconfigured),
        };
        if score >= floor {
            Ok(TrustVerdict::Allowed)
        } else {
            Ok(TrustVerdict::BelowFloor { floor })
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FloorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FloorError::SchemaMismatch);
        }
        for &f in self.floors.values() {
            if f > 1000 { return Err(FloorError::FloorOver1000(f)); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ActorTrustFloor::canonical().validate().unwrap();
    }

    #[test]
    fn allowed_at_floor() {
        let f = ActorTrustFloor::canonical();
        assert_eq!(f.classify(Profile::Production, 900).unwrap(), TrustVerdict::Allowed);
    }

    #[test]
    fn below_floor_rejected() {
        let f = ActorTrustFloor::canonical();
        let v = f.classify(Profile::Production, 800).unwrap();
        assert_eq!(v, TrustVerdict::BelowFloor { floor: 900 });
    }

    #[test]
    fn experimental_admits_low_trust() {
        let f = ActorTrustFloor::canonical();
        assert_eq!(f.classify(Profile::Experimental, 150).unwrap(), TrustVerdict::Allowed);
    }

    #[test]
    fn score_over_1000_rejected() {
        let f = ActorTrustFloor::canonical();
        assert!(matches!(f.classify(Profile::Production, 1500).unwrap_err(), FloorError::ScoreOver1000(_)));
    }

    #[test]
    fn unconfigured_profile() {
        let mut f = ActorTrustFloor::canonical();
        f.floors.clear();
        assert_eq!(f.classify(Profile::Fast, 500).unwrap(), TrustVerdict::Unconfigured);
    }

    #[test]
    fn floor_over_1000_invalid() {
        let mut f = ActorTrustFloor::canonical();
        f.floors.insert(Profile::Fast, 9999);
        assert!(matches!(f.validate().unwrap_err(), FloorError::FloorOver1000(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = ActorTrustFloor::canonical();
        f.schema_version = "9.9.9".into();
        assert!(matches!(f.validate().unwrap_err(), FloorError::SchemaMismatch));
    }

    #[test]
    fn floor_serde_roundtrip() {
        let f = ActorTrustFloor::canonical();
        let j = serde_json::to_string(&f).unwrap();
        let back: ActorTrustFloor = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
