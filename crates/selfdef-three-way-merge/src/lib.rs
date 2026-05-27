//! `selfdef-three-way-merge` — base/ours/theirs map merge.
//!
//! For each key in the union(base, ours, theirs):
//! - both sides unchanged from base → base value (or absent if absent)
//! - one side changed, other = base → take the changed side
//! - both sides changed to the same value → that value
//! - both sides changed to different values → Conflict
//!
//! Returns either a merged BTreeMap or a list of conflict keys.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Merge outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "outcome", content = "value")]
pub enum Outcome {
    /// Merged map.
    Merged(BTreeMap<String, String>),
    /// Conflict on these keys.
    Conflict(Vec<String>),
}

/// Versioned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreeWayMerge {
    /// Schema version.
    pub schema_version: String,
    /// Last outcome.
    pub last: Option<Outcome>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MergeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Merge.
pub fn merge(
    base: &BTreeMap<String, String>,
    ours: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
) -> Outcome {
    let mut keys: BTreeSet<&String> = BTreeSet::new();
    keys.extend(base.keys());
    keys.extend(ours.keys());
    keys.extend(theirs.keys());
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicts: Vec<String> = Vec::new();
    for k in keys {
        let b = base.get(k);
        let o = ours.get(k);
        let t = theirs.get(k);
        match (b, o, t) {
            // No changes.
            (b, o, t) if o == b && t == b => {
                if let Some(v) = b {
                    out.insert(k.clone(), v.clone());
                }
            }
            // Ours unchanged → take theirs.
            (b, o, t) if o == b => {
                if let Some(v) = t {
                    out.insert(k.clone(), v.clone());
                }
            }
            // Theirs unchanged → take ours.
            (b, o, t) if t == b => {
                if let Some(v) = o {
                    out.insert(k.clone(), v.clone());
                }
            }
            // Both changed to same value.
            (_, Some(ov), Some(tv)) if ov == tv => {
                out.insert(k.clone(), ov.clone());
            }
            // Conflict.
            _ => {
                conflicts.push(k.clone());
            }
        }
    }
    if conflicts.is_empty() {
        Outcome::Merged(out)
    } else {
        Outcome::Conflict(conflicts)
    }
}

impl ThreeWayMerge {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: None,
        }
    }

    /// Merge + store.
    pub fn merge_and_store(
        &mut self,
        base: &BTreeMap<String, String>,
        ours: &BTreeMap<String, String>,
        theirs: &BTreeMap<String, String>,
    ) -> &Outcome {
        self.last = Some(merge(base, ours, theirs));
        self.last.as_ref().unwrap()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MergeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(MergeError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for ThreeWayMerge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_changes() {
        let b = m(&[("a", "1")]);
        let r = merge(&b, &b, &b);
        match r {
            Outcome::Merged(o) => assert_eq!(o.get("a"), Some(&"1".into())),
            _ => panic!("expected merged"),
        }
    }

    #[test]
    fn ours_only_change() {
        let b = m(&[("a", "1")]);
        let o = m(&[("a", "2")]);
        let r = merge(&b, &o, &b);
        assert!(matches!(&r, Outcome::Merged(_)));
        if let Outcome::Merged(out) = r {
            assert_eq!(out.get("a"), Some(&"2".into()));
        }
    }

    #[test]
    fn theirs_only_change() {
        let b = m(&[("a", "1")]);
        let t = m(&[("a", "2")]);
        let r = merge(&b, &b, &t);
        if let Outcome::Merged(out) = r {
            assert_eq!(out.get("a"), Some(&"2".into()));
        } else {
            panic!("expected merged");
        }
    }

    #[test]
    fn same_change_both_sides() {
        let b = m(&[("a", "1")]);
        let o = m(&[("a", "2")]);
        let r = merge(&b, &o, &o);
        if let Outcome::Merged(out) = r {
            assert_eq!(out.get("a"), Some(&"2".into()));
        } else {
            panic!("expected merged");
        }
    }

    #[test]
    fn diverging_changes_conflict() {
        let b = m(&[("a", "1")]);
        let o = m(&[("a", "2")]);
        let t = m(&[("a", "3")]);
        let r = merge(&b, &o, &t);
        match r {
            Outcome::Conflict(ks) => assert_eq!(ks, vec!["a"]),
            _ => panic!("expected conflict"),
        }
    }

    #[test]
    fn delete_one_side() {
        let b = m(&[("a", "1")]);
        let o = m(&[]);
        let t = m(&[("a", "1")]);
        let r = merge(&b, &o, &t);
        if let Outcome::Merged(out) = r {
            assert!(!out.contains_key("a"));
        } else {
            panic!("expected merged");
        }
    }

    #[test]
    fn add_one_side() {
        let b = m(&[]);
        let o = m(&[("x", "1")]);
        let t = m(&[]);
        let r = merge(&b, &o, &t);
        if let Outcome::Merged(out) = r {
            assert_eq!(out.get("x"), Some(&"1".into()));
        } else {
            panic!("expected merged");
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ThreeWayMerge::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            MergeError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let mut s = ThreeWayMerge::new();
        s.merge_and_store(&m(&[("a", "1")]), &m(&[("a", "2")]), &m(&[("a", "1")]));
        let j = serde_json::to_string(&s).unwrap();
        let back: ThreeWayMerge = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
