//! `selfdef-mcp-handshake-version` — MCP version-compat gate.
//!
//! `classify(server_version, supported_range_min, supported_range_max,
//! explicit_allowlist)` returns:
//!   * `Compatible` — present in allowlist OR within [min, max].
//!   * `TooOld { min }` — server < min and not in allowlist.
//!   * `TooNew { max }` — server > max and not in allowlist.
//!   * `Unparseable` — version doesn't parse as `MAJOR.MINOR.PATCH`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Parsed semver triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Triple {
    /// major.
    pub major: u32,
    /// minor.
    pub minor: u32,
    /// patch.
    pub patch: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpHandshakeVersion {
    /// Schema version.
    pub schema_version: String,
    /// Min supported.
    pub supported_min: Triple,
    /// Max supported.
    pub supported_max: Triple,
    /// Explicit allowlist (overrides range).
    pub explicit_allowlist: BTreeSet<String>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HandshakeVerdict {
    /// Compatible.
    Compatible,
    /// Too old.
    TooOld {
        /// supported min.
        min: Triple,
    },
    /// Too new.
    TooNew {
        /// supported max.
        max: Triple,
    },
    /// Cannot parse the version string.
    Unparseable,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad range.
    #[error("supported_min > supported_max")]
    BadRange,
}

fn parse(s: &str) -> Option<Triple> {
    let mut it = s.split('.');
    let major = it.next()?.parse::<u32>().ok()?;
    let minor = it.next()?.parse::<u32>().ok()?;
    let patch = it.next()?.parse::<u32>().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(Triple {
        major,
        minor,
        patch,
    })
}

impl McpHandshakeVersion {
    /// New.
    pub fn new(min: Triple, max: Triple) -> Result<Self, HandshakeError> {
        if min > max {
            return Err(HandshakeError::BadRange);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            supported_min: min,
            supported_max: max,
            explicit_allowlist: BTreeSet::new(),
        })
    }

    /// Add an allowlist entry.
    pub fn allow(&mut self, exact_version: &str) {
        self.explicit_allowlist.insert(exact_version.into());
    }

    /// Classify.
    pub fn classify(&self, server_version: &str) -> HandshakeVerdict {
        if self.explicit_allowlist.contains(server_version) {
            return HandshakeVerdict::Compatible;
        }
        let t = match parse(server_version) {
            Some(t) => t,
            None => return HandshakeVerdict::Unparseable,
        };
        if t < self.supported_min {
            return HandshakeVerdict::TooOld {
                min: self.supported_min,
            };
        }
        if t > self.supported_max {
            return HandshakeVerdict::TooNew {
                max: self.supported_max,
            };
        }
        HandshakeVerdict::Compatible
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HandshakeError::SchemaMismatch);
        }
        if self.supported_min > self.supported_max {
            return Err(HandshakeError::BadRange);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(maj: u32, min: u32, pat: u32) -> Triple {
        Triple {
            major: maj,
            minor: min,
            patch: pat,
        }
    }

    #[test]
    fn bad_range_rejected() {
        assert!(matches!(
            McpHandshakeVersion::new(t(2, 0, 0), t(1, 0, 0)).unwrap_err(),
            HandshakeError::BadRange
        ));
    }

    #[test]
    fn in_range_compatible() {
        let h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 9, 9)).unwrap();
        assert_eq!(h.classify("1.5.0"), HandshakeVerdict::Compatible);
    }

    #[test]
    fn too_old() {
        let h = McpHandshakeVersion::new(t(1, 5, 0), t(2, 9, 9)).unwrap();
        let v = h.classify("1.0.0");
        assert_eq!(v, HandshakeVerdict::TooOld { min: t(1, 5, 0) });
    }

    #[test]
    fn too_new() {
        let h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 0, 0)).unwrap();
        let v = h.classify("3.0.0");
        assert_eq!(v, HandshakeVerdict::TooNew { max: t(2, 0, 0) });
    }

    #[test]
    fn unparseable() {
        let h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 0, 0)).unwrap();
        assert_eq!(h.classify("not-semver"), HandshakeVerdict::Unparseable);
        assert_eq!(h.classify("1.0"), HandshakeVerdict::Unparseable);
        assert_eq!(h.classify("1.0.0.0"), HandshakeVerdict::Unparseable);
    }

    #[test]
    fn allowlist_overrides_range() {
        let mut h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 0, 0)).unwrap();
        h.allow("3.5.0");
        assert_eq!(h.classify("3.5.0"), HandshakeVerdict::Compatible);
        // Another out-of-range version still rejected.
        assert!(matches!(
            h.classify("3.5.1"),
            HandshakeVerdict::TooNew { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 0, 0)).unwrap();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HandshakeError::SchemaMismatch
        ));
    }

    #[test]
    fn handshake_serde_roundtrip() {
        let mut h = McpHandshakeVersion::new(t(1, 0, 0), t(2, 0, 0)).unwrap();
        h.allow("3.5.0");
        let j = serde_json::to_string(&h).unwrap();
        let back: McpHandshakeVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
