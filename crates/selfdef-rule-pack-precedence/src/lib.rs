//! `selfdef-rule-pack-precedence` — pack-source precedence authority.
//!
//! Each loaded RulePack declares a source. Precedence (highest first):
//! Emergency > Operator > Substrate > Vendor. resolve_order(packs)
//! returns the pack ids sorted by descending precedence, with ties
//! broken by name to keep the order deterministic.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pack source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackSource {
    /// Vendor defaults (lowest precedence).
    Vendor,
    /// Substrate (engine-shipped).
    Substrate,
    /// Operator (hand-authored / per-op).
    Operator,
    /// Emergency override (highest).
    Emergency,
}

impl PackSource {
    /// Numeric precedence (higher = wins).
    pub fn precedence(self) -> u8 {
        match self {
            PackSource::Vendor => 1,
            PackSource::Substrate => 2,
            PackSource::Operator => 3,
            PackSource::Emergency => 4,
        }
    }
}

/// One loaded rule pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePack {
    /// Pack id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Source.
    pub source: PackSource,
    /// Version (semver).
    pub version: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulePackPrecedence {
    /// Schema version.
    pub schema_version: String,
    /// Packs.
    pub packs: Vec<RulePack>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PrecedenceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty pack id.
    #[error("pack id empty")]
    EmptyId,
    /// Empty name.
    #[error("pack {0} name empty")]
    EmptyName(String),
    /// Empty version.
    #[error("pack {0} version empty")]
    EmptyVersion(String),
    /// Duplicate pack id.
    #[error("duplicate pack id: {0}")]
    DuplicateId(String),
}

impl RulePackPrecedence {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            packs: Vec::new(),
        }
    }

    /// Load a pack.
    pub fn load(&mut self, pack: RulePack) -> Result<(), PrecedenceError> {
        check_pack(&pack)?;
        if self.packs.iter().any(|p| p.id == pack.id) {
            return Err(PrecedenceError::DuplicateId(pack.id));
        }
        self.packs.push(pack);
        Ok(())
    }

    /// Resolve order: highest precedence first; tie-break by id (stable).
    pub fn resolve_order(&self) -> Vec<&RulePack> {
        let mut sorted: Vec<&RulePack> = self.packs.iter().collect();
        sorted.sort_by(|a, b| {
            b.source
                .precedence()
                .cmp(&a.source.precedence())
                .then(a.id.cmp(&b.id))
        });
        sorted
    }

    /// Top pack (highest precedence). None when empty.
    pub fn top(&self) -> Option<&RulePack> {
        self.resolve_order().into_iter().next()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PrecedenceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PrecedenceError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for p in &self.packs {
            check_pack(p)?;
            if !seen.insert(p.id.as_str()) {
                return Err(PrecedenceError::DuplicateId(p.id.clone()));
            }
        }
        Ok(())
    }
}

fn check_pack(p: &RulePack) -> Result<(), PrecedenceError> {
    if p.id.is_empty() {
        return Err(PrecedenceError::EmptyId);
    }
    if p.name.is_empty() {
        return Err(PrecedenceError::EmptyName(p.id.clone()));
    }
    if p.version.is_empty() {
        return Err(PrecedenceError::EmptyVersion(p.id.clone()));
    }
    Ok(())
}

impl Default for RulePackPrecedence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(id: &str, source: PackSource) -> RulePack {
        RulePack {
            id: id.into(),
            name: format!("N-{id}"),
            source,
            version: "1.0.0".into(),
        }
    }

    #[test]
    fn precedence_order_correct() {
        assert!(PackSource::Emergency.precedence() > PackSource::Operator.precedence());
        assert!(PackSource::Operator.precedence() > PackSource::Substrate.precedence());
        assert!(PackSource::Substrate.precedence() > PackSource::Vendor.precedence());
    }

    #[test]
    fn resolve_orders_by_precedence() {
        let mut p = RulePackPrecedence::new();
        p.load(pack("vendor-a", PackSource::Vendor)).unwrap();
        p.load(pack("op-a", PackSource::Operator)).unwrap();
        p.load(pack("sub-a", PackSource::Substrate)).unwrap();
        p.load(pack("emerg-a", PackSource::Emergency)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|x| x.id.as_str()).collect();
        assert_eq!(order, vec!["emerg-a", "op-a", "sub-a", "vendor-a"]);
    }

    #[test]
    fn tie_break_by_id() {
        let mut p = RulePackPrecedence::new();
        p.load(pack("op-b", PackSource::Operator)).unwrap();
        p.load(pack("op-a", PackSource::Operator)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|x| x.id.as_str()).collect();
        assert_eq!(order, vec!["op-a", "op-b"]);
    }

    #[test]
    fn top_is_highest() {
        let mut p = RulePackPrecedence::new();
        p.load(pack("vendor", PackSource::Vendor)).unwrap();
        p.load(pack("emerg", PackSource::Emergency)).unwrap();
        assert_eq!(p.top().unwrap().id, "emerg");
    }

    #[test]
    fn empty_has_no_top() {
        let p = RulePackPrecedence::new();
        assert!(p.top().is_none());
    }

    #[test]
    fn duplicate_rejected() {
        let mut p = RulePackPrecedence::new();
        p.load(pack("a", PackSource::Vendor)).unwrap();
        assert!(matches!(
            p.load(pack("a", PackSource::Operator)).unwrap_err(),
            PrecedenceError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = RulePackPrecedence::new();
        assert!(matches!(
            p.load(pack("", PackSource::Vendor)).unwrap_err(),
            PrecedenceError::EmptyId
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let mut p = RulePackPrecedence::new();
        let mut x = pack("a", PackSource::Vendor);
        x.name = String::new();
        assert!(matches!(
            p.load(x).unwrap_err(),
            PrecedenceError::EmptyName(_)
        ));
    }

    #[test]
    fn empty_version_rejected() {
        let mut p = RulePackPrecedence::new();
        let mut x = pack("a", PackSource::Vendor);
        x.version = String::new();
        assert!(matches!(
            p.load(x).unwrap_err(),
            PrecedenceError::EmptyVersion(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RulePackPrecedence::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PrecedenceError::SchemaMismatch
        ));
    }

    #[test]
    fn source_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PackSource::Emergency).unwrap(),
            "\"emergency\""
        );
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut p = RulePackPrecedence::new();
        p.load(pack("a", PackSource::Vendor)).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: RulePackPrecedence = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
