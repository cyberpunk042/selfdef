//! `selfdef-semver` — minimal semver.
//!
//! parse("1.2.3") → Version{1, 2, 3}. Comparison by tuple
//! ordering. is_compatible(a, b): same major; b.minor >=
//! a.minor; equal minor → b.patch >= a.patch. to_string emits
//! "M.N.P".
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Version.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SemverError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Parse.
    #[error("invalid semver: {0}")]
    BadVersion(String),
}

impl Version {
    /// New.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse "M.N.P".
    pub fn parse(s: &str) -> Result<Self, SemverError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(SemverError::BadVersion(s.into()));
        }
        let major: u32 = parts[0]
            .parse()
            .map_err(|_| SemverError::BadVersion(s.into()))?;
        let minor: u32 = parts[1]
            .parse()
            .map_err(|_| SemverError::BadVersion(s.into()))?;
        let patch: u32 = parts[2]
            .parse()
            .map_err(|_| SemverError::BadVersion(s.into()))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// "M.N.P" display.
    pub fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Is `other` semver-compatible with `self` (same major, >= minor.patch)?
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        if self.major != other.major {
            return false;
        }
        if other.minor > self.minor {
            return true;
        }
        if other.minor < self.minor {
            return false;
        }
        other.patch >= self.patch
    }
}

/// Versioned wrapper for state with schema-drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemverState {
    /// Schema version.
    pub schema_version: String,
    /// Last parsed.
    pub last: Option<Version>,
}

impl SemverState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: None,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SemverError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SemverError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for SemverState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v, Version::new(1, 2, 3));
    }

    #[test]
    fn parse_zero() {
        assert_eq!(Version::parse("0.0.0").unwrap(), Version::new(0, 0, 0));
    }

    #[test]
    fn parse_bad() {
        assert!(Version::parse("1.2").is_err());
        assert!(Version::parse("a.b.c").is_err());
        assert!(Version::parse("1.2.3.4").is_err());
    }

    #[test]
    fn ordering() {
        assert!(Version::new(1, 2, 3) < Version::new(1, 2, 4));
        assert!(Version::new(1, 2, 3) < Version::new(1, 3, 0));
        assert!(Version::new(1, 9, 9) < Version::new(2, 0, 0));
    }

    #[test]
    fn compat_same_major_higher_minor() {
        let req = Version::new(1, 2, 0);
        assert!(req.is_compatible_with(&Version::new(1, 5, 0)));
    }

    #[test]
    fn compat_same_major_equal_minor_higher_patch() {
        let req = Version::new(1, 2, 3);
        assert!(req.is_compatible_with(&Version::new(1, 2, 9)));
    }

    #[test]
    fn incompat_different_major() {
        let req = Version::new(1, 2, 0);
        assert!(!req.is_compatible_with(&Version::new(2, 0, 0)));
    }

    #[test]
    fn incompat_lower_minor() {
        let req = Version::new(1, 5, 0);
        assert!(!req.is_compatible_with(&Version::new(1, 4, 99)));
    }

    #[test]
    fn to_string_format() {
        assert_eq!(Version::new(1, 2, 3).to_string(), "1.2.3");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = SemverState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SemverError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = SemverState {
            schema_version: SCHEMA_VERSION.into(),
            last: Some(Version::new(1, 0, 0)),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: SemverState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
