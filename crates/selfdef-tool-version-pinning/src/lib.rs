//! `selfdef-tool-version-pinning` — tool-version pinning authority.
//!
//! Each `ToolPin` requires either an exact semver `major.minor.patch`
//! or a sha256 hex digest. admit() checks the runtime-observed
//! (version, sha256) against the pin and reports which axis
//! mismatched.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pin requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PinReq {
    /// Require exact semver.
    Semver {
        /// version.
        version: String,
    },
    /// Require exact sha256 hex digest.
    Sha256 {
        /// digest.
        digest: String,
    },
}

/// One pin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPin {
    /// Tool id (shell name or path).
    pub tool_id: String,
    /// Requirement.
    pub req: PinReq,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolVersionPinning {
    /// Schema version.
    pub schema_version: String,
    /// Pins.
    pub pins: Vec<ToolPin>,
}

/// Per-admit decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AdmitDecision {
    /// Allowed.
    Allow,
    /// Tool not pinned.
    Unknown,
    /// Semver mismatch.
    VersionMismatch {
        /// expected.
        expected: String,
        /// got.
        got: String,
    },
    /// Sha256 mismatch.
    DigestMismatch {
        /// expected.
        expected: String,
        /// got.
        got: String,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum PinError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("pin tool_id empty")]
    EmptyToolId,
    /// Duplicate tool_id.
    #[error("duplicate tool_id: {0}")]
    DuplicateToolId(String),
    /// Bad semver shape.
    #[error("invalid semver {0:?}")]
    BadSemver(String),
    /// Bad sha256 shape.
    #[error("invalid sha256 {0:?}")]
    BadSha256(String),
}

impl ToolVersionPinning {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pins: Vec::new(),
        }
    }

    /// Add a pin.
    pub fn add(&mut self, pin: ToolPin) -> Result<(), PinError> {
        check_pin(&pin)?;
        if self.pins.iter().any(|p| p.tool_id == pin.tool_id) {
            return Err(PinError::DuplicateToolId(pin.tool_id));
        }
        self.pins.push(pin);
        Ok(())
    }

    /// Admit (tool_id, observed_version, observed_sha256).
    pub fn admit(&self, tool_id: &str, version: &str, sha256: &str) -> AdmitDecision {
        let pin = match self.pins.iter().find(|p| p.tool_id == tool_id) {
            Some(p) => p,
            None => return AdmitDecision::Unknown,
        };
        match &pin.req {
            PinReq::Semver { version: required } => {
                if required == version {
                    AdmitDecision::Allow
                } else {
                    AdmitDecision::VersionMismatch {
                        expected: required.clone(),
                        got: version.into(),
                    }
                }
            }
            PinReq::Sha256 { digest: required } => {
                if required.eq_ignore_ascii_case(sha256) {
                    AdmitDecision::Allow
                } else {
                    AdmitDecision::DigestMismatch {
                        expected: required.clone(),
                        got: sha256.into(),
                    }
                }
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PinError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PinError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for p in &self.pins {
            check_pin(p)?;
            if !seen.insert(p.tool_id.as_str()) {
                return Err(PinError::DuplicateToolId(p.tool_id.clone()));
            }
        }
        Ok(())
    }
}

fn check_pin(p: &ToolPin) -> Result<(), PinError> {
    if p.tool_id.is_empty() { return Err(PinError::EmptyToolId); }
    match &p.req {
        PinReq::Semver { version } => {
            if !valid_semver(version) {
                return Err(PinError::BadSemver(version.clone()));
            }
        }
        PinReq::Sha256 { digest } => {
            if !valid_sha256(digest) {
                return Err(PinError::BadSha256(digest.clone()));
            }
        }
    }
    Ok(())
}

fn valid_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 { return false; }
    parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Default for ToolVersionPinning {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin_semver(id: &str, v: &str) -> ToolPin {
        ToolPin { tool_id: id.into(), req: PinReq::Semver { version: v.into() } }
    }

    fn pin_sha(id: &str, d: &str) -> ToolPin {
        ToolPin { tool_id: id.into(), req: PinReq::Sha256 { digest: d.into() } }
    }

    fn digest(repeat: u8) -> String {
        (0..64).map(|_| format!("{:x}", repeat)).collect()
    }

    #[test]
    fn unknown_tool_returns_unknown() {
        let v = ToolVersionPinning::new();
        assert!(matches!(v.admit("none", "1.0.0", ""), AdmitDecision::Unknown));
    }

    #[test]
    fn semver_match() {
        let mut v = ToolVersionPinning::new();
        v.add(pin_semver("git", "2.40.0")).unwrap();
        assert!(matches!(v.admit("git", "2.40.0", ""), AdmitDecision::Allow));
    }

    #[test]
    fn semver_mismatch() {
        let mut v = ToolVersionPinning::new();
        v.add(pin_semver("git", "2.40.0")).unwrap();
        let d = v.admit("git", "2.41.0", "");
        match d {
            AdmitDecision::VersionMismatch { expected, got } => {
                assert_eq!(expected, "2.40.0");
                assert_eq!(got, "2.41.0");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn sha256_match_case_insensitive() {
        let mut v = ToolVersionPinning::new();
        let d = digest(0xa);
        v.add(pin_sha("tool", &d)).unwrap();
        assert!(matches!(v.admit("tool", "", &d.to_uppercase()), AdmitDecision::Allow));
    }

    #[test]
    fn sha256_mismatch() {
        let mut v = ToolVersionPinning::new();
        v.add(pin_sha("tool", &digest(0xa))).unwrap();
        assert!(matches!(v.admit("tool", "", &digest(0xb)), AdmitDecision::DigestMismatch { .. }));
    }

    #[test]
    fn duplicate_tool_rejected() {
        let mut v = ToolVersionPinning::new();
        v.add(pin_semver("git", "1.0.0")).unwrap();
        assert!(matches!(
            v.add(pin_semver("git", "2.0.0")).unwrap_err(),
            PinError::DuplicateToolId(_)
        ));
    }

    #[test]
    fn empty_tool_id_rejected() {
        let mut v = ToolVersionPinning::new();
        assert!(matches!(v.add(pin_semver("", "1.0.0")).unwrap_err(), PinError::EmptyToolId));
    }

    #[test]
    fn bad_semver_rejected() {
        let mut v = ToolVersionPinning::new();
        assert!(matches!(v.add(pin_semver("git", "1.0")).unwrap_err(), PinError::BadSemver(_)));
        assert!(matches!(v.add(pin_semver("git", "1.0.x")).unwrap_err(), PinError::BadSemver(_)));
    }

    #[test]
    fn bad_sha256_rejected() {
        let mut v = ToolVersionPinning::new();
        assert!(matches!(v.add(pin_sha("tool", "tooshort")).unwrap_err(), PinError::BadSha256(_)));
        assert!(matches!(v.add(pin_sha("tool", &"x".repeat(64))).unwrap_err(), PinError::BadSha256(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = ToolVersionPinning::new();
        v.schema_version = "9.9.9".into();
        assert!(matches!(v.validate().unwrap_err(), PinError::SchemaMismatch));
    }

    #[test]
    fn req_serde_kebab() {
        let r = PinReq::Semver { version: "1.0.0".into() };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"kind\":\"semver\""));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut v = ToolVersionPinning::new();
        v.add(pin_semver("git", "2.40.0")).unwrap();
        v.add(pin_sha("rg", &digest(0xc))).unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let back: ToolVersionPinning = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
