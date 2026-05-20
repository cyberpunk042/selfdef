//! `selfdef-policy-version-pin` — per-actor bundle version pin.
//!
//! `pin(actor, bundle_id, version)` records a pin. `resolve(actor)`
//! returns Pinned{bundle_id, version} when present, else Unpinned.
//! `unpin(actor)` removes.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pin entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pin {
    /// Bundle id.
    pub bundle_id: String,
    /// Bundle version (e.g. "1.2.3").
    pub version: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyVersionPin {
    /// Schema version.
    pub schema_version: String,
    /// actor → pin.
    pub pins: BTreeMap<String, Pin>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PinVerdict {
    /// Pinned.
    Pinned {
        /// bundle id.
        bundle_id: String,
        /// version.
        version: String,
    },
    /// Not pinned.
    Unpinned,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PinError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty bundle id.
    #[error("bundle id empty")]
    EmptyBundle,
    /// Empty version.
    #[error("version empty")]
    EmptyVersion,
}

impl PolicyVersionPin {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            pins: BTreeMap::new(),
        }
    }

    /// Pin.
    pub fn pin(&mut self, actor: &str, bundle_id: &str, version: &str) -> Result<(), PinError> {
        if actor.is_empty() { return Err(PinError::EmptyActor); }
        if bundle_id.is_empty() { return Err(PinError::EmptyBundle); }
        if version.is_empty() { return Err(PinError::EmptyVersion); }
        self.pins.insert(actor.into(), Pin { bundle_id: bundle_id.into(), version: version.into() });
        Ok(())
    }

    /// Unpin.
    pub fn unpin(&mut self, actor: &str) -> bool {
        self.pins.remove(actor).is_some()
    }

    /// Resolve.
    pub fn resolve(&self, actor: &str) -> PinVerdict {
        match self.pins.get(actor) {
            Some(p) => PinVerdict::Pinned { bundle_id: p.bundle_id.clone(), version: p.version.clone() },
            None => PinVerdict::Unpinned,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PinError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PinError::SchemaMismatch); }
        for (a, p) in &self.pins {
            if a.is_empty() { return Err(PinError::EmptyActor); }
            if p.bundle_id.is_empty() { return Err(PinError::EmptyBundle); }
            if p.version.is_empty() { return Err(PinError::EmptyVersion); }
        }
        Ok(())
    }
}

impl Default for PolicyVersionPin {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpinned_default() {
        let p = PolicyVersionPin::new();
        assert_eq!(p.resolve("actor"), PinVerdict::Unpinned);
    }

    #[test]
    fn pin_then_resolve() {
        let mut p = PolicyVersionPin::new();
        p.pin("actor", "bundle-x", "1.2.3").unwrap();
        match p.resolve("actor") {
            PinVerdict::Pinned { bundle_id, version } => {
                assert_eq!(bundle_id, "bundle-x");
                assert_eq!(version, "1.2.3");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unpin_returns_to_unpinned() {
        let mut p = PolicyVersionPin::new();
        p.pin("actor", "bundle-x", "1.2.3").unwrap();
        assert!(p.unpin("actor"));
        assert_eq!(p.resolve("actor"), PinVerdict::Unpinned);
    }

    #[test]
    fn pin_overwrites() {
        let mut p = PolicyVersionPin::new();
        p.pin("actor", "bundle-x", "1.2.3").unwrap();
        p.pin("actor", "bundle-y", "2.0.0").unwrap();
        match p.resolve("actor") {
            PinVerdict::Pinned { bundle_id, version } => {
                assert_eq!(bundle_id, "bundle-y");
                assert_eq!(version, "2.0.0");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn empty_fields_rejected() {
        let mut p = PolicyVersionPin::new();
        assert!(matches!(p.pin("", "b", "v").unwrap_err(), PinError::EmptyActor));
        assert!(matches!(p.pin("a", "", "v").unwrap_err(), PinError::EmptyBundle));
        assert!(matches!(p.pin("a", "b", "").unwrap_err(), PinError::EmptyVersion));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicyVersionPin::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PinError::SchemaMismatch));
    }

    #[test]
    fn pin_serde_roundtrip() {
        let mut p = PolicyVersionPin::new();
        p.pin("actor", "bundle-x", "1.2.3").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicyVersionPin = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
