//! `selfdef-actor-attribute-pack` — per-actor attribute store.
//!
//! Per actor: `BTreeMap<String, String>` of key→value attributes.
//! `match_all(actor, &[(key, expected_value)])` returns Matched
//! when every (k, v) in the predicate list matches, else
//! Mismatched{ wrong: Vec<(k, expected, actual)>, missing: Vec<k> }
//! or UnknownActor.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorAttributePack {
    /// Schema version.
    pub schema_version: String,
    /// actor → key → value.
    pub attrs: BTreeMap<String, BTreeMap<String, String>>,
}

/// One mismatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrongValue {
    /// key.
    pub key: String,
    /// expected.
    pub expected: String,
    /// actual.
    pub actual: String,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MatchVerdict {
    /// All matched.
    Matched,
    /// Some keys missing or wrong.
    Mismatched {
        /// keys absent on the actor.
        missing: Vec<String>,
        /// keys present but wrong.
        wrong: Vec<WrongValue>,
    },
    /// Unknown actor.
    UnknownActor,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AttrError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty key.
    #[error("attribute key empty")]
    EmptyKey,
}

impl ActorAttributePack {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            attrs: BTreeMap::new(),
        }
    }

    /// Set.
    pub fn set(&mut self, actor: &str, key: &str, value: &str) -> Result<(), AttrError> {
        if actor.is_empty() {
            return Err(AttrError::EmptyActor);
        }
        if key.is_empty() {
            return Err(AttrError::EmptyKey);
        }
        self.attrs
            .entry(actor.into())
            .or_default()
            .insert(key.into(), value.into());
        Ok(())
    }

    /// Get.
    pub fn get(&self, actor: &str, key: &str) -> Option<&str> {
        self.attrs.get(actor)?.get(key).map(|s| s.as_str())
    }

    /// Delete a key.
    pub fn delete(&mut self, actor: &str, key: &str) -> bool {
        self.attrs
            .get_mut(actor)
            .is_some_and(|m| m.remove(key).is_some())
    }

    /// Match.
    pub fn match_all(&self, actor: &str, predicates: &[(&str, &str)]) -> MatchVerdict {
        let map = match self.attrs.get(actor) {
            Some(m) => m,
            None => return MatchVerdict::UnknownActor,
        };
        let mut missing = Vec::new();
        let mut wrong = Vec::new();
        for (k, expected) in predicates {
            match map.get(*k) {
                None => missing.push((*k).into()),
                Some(actual) if actual != expected => wrong.push(WrongValue {
                    key: (*k).into(),
                    expected: (*expected).into(),
                    actual: actual.clone(),
                }),
                _ => {}
            }
        }
        if missing.is_empty() && wrong.is_empty() {
            MatchVerdict::Matched
        } else {
            MatchVerdict::Mismatched { missing, wrong }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AttrError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AttrError::SchemaMismatch);
        }
        for (a, m) in &self.attrs {
            if a.is_empty() {
                return Err(AttrError::EmptyActor);
            }
            for k in m.keys() {
                if k.is_empty() {
                    return Err(AttrError::EmptyKey);
                }
            }
        }
        Ok(())
    }
}

impl Default for ActorAttributePack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "platform").unwrap();
        assert_eq!(p.get("actor", "team"), Some("platform"));
        assert_eq!(p.get("actor", "missing"), None);
    }

    #[test]
    fn delete_returns_true_when_existed() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "platform").unwrap();
        assert!(p.delete("actor", "team"));
        assert!(!p.delete("actor", "team"));
    }

    #[test]
    fn match_all_succeeds() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "platform").unwrap();
        p.set("actor", "region", "us-east").unwrap();
        assert_eq!(
            p.match_all("actor", &[("team", "platform"), ("region", "us-east")]),
            MatchVerdict::Matched
        );
    }

    #[test]
    fn missing_key_reported() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "platform").unwrap();
        match p.match_all("actor", &[("team", "platform"), ("region", "us-east")]) {
            MatchVerdict::Mismatched { missing, wrong } => {
                assert_eq!(missing, vec!["region"]);
                assert!(wrong.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn wrong_value_reported() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "infra").unwrap();
        match p.match_all("actor", &[("team", "platform")]) {
            MatchVerdict::Mismatched { wrong, .. } => {
                assert_eq!(wrong.len(), 1);
                assert_eq!(wrong[0].expected, "platform");
                assert_eq!(wrong[0].actual, "infra");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_actor() {
        let p = ActorAttributePack::new();
        assert_eq!(
            p.match_all("nope", &[("k", "v")]),
            MatchVerdict::UnknownActor
        );
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = ActorAttributePack::new();
        assert!(matches!(
            p.set("", "k", "v").unwrap_err(),
            AttrError::EmptyActor
        ));
        assert!(matches!(
            p.set("a", "", "v").unwrap_err(),
            AttrError::EmptyKey
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActorAttributePack::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            AttrError::SchemaMismatch
        ));
    }

    #[test]
    fn pack_serde_roundtrip() {
        let mut p = ActorAttributePack::new();
        p.set("actor", "team", "platform").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActorAttributePack = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
