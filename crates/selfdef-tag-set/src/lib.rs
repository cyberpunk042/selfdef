//! `selfdef-tag-set` — string tag set algebra.
//!
//! Tags are non-empty strings, kept sorted+unique. Operations:
//! add, remove, intersection, union, difference, is_subset_of,
//! is_disjoint_from. Pure data — no I/O.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagSet {
    /// Schema version.
    pub schema_version: String,
    /// Sorted unique tags.
    pub tags: BTreeSet<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TagError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("tag empty")]
    EmptyTag,
}

impl TagSet {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tags: BTreeSet::new(),
        }
    }

    /// From an iterable of tags.
    pub fn from_iter_strs<'a, I: IntoIterator<Item = &'a str>>(iter: I) -> Result<Self, TagError> {
        let mut s = Self::new();
        for t in iter {
            s.add(t)?;
        }
        Ok(s)
    }

    /// Add tag; returns true if newly inserted.
    pub fn add(&mut self, tag: &str) -> Result<bool, TagError> {
        if tag.is_empty() { return Err(TagError::EmptyTag); }
        Ok(self.tags.insert(tag.into()))
    }

    /// Remove tag; returns true if was present.
    pub fn remove(&mut self, tag: &str) -> bool {
        self.tags.remove(tag)
    }

    /// Contains?
    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Intersection.
    pub fn intersection(&self, other: &TagSet) -> TagSet {
        let tags: BTreeSet<String> = self.tags.intersection(&other.tags).cloned().collect();
        TagSet { schema_version: SCHEMA_VERSION.into(), tags }
    }

    /// Union.
    pub fn union(&self, other: &TagSet) -> TagSet {
        let tags: BTreeSet<String> = self.tags.union(&other.tags).cloned().collect();
        TagSet { schema_version: SCHEMA_VERSION.into(), tags }
    }

    /// Difference (self - other).
    pub fn difference(&self, other: &TagSet) -> TagSet {
        let tags: BTreeSet<String> = self.tags.difference(&other.tags).cloned().collect();
        TagSet { schema_version: SCHEMA_VERSION.into(), tags }
    }

    /// True iff every tag of self is in other.
    pub fn is_subset_of(&self, other: &TagSet) -> bool {
        self.tags.is_subset(&other.tags)
    }

    /// True iff no common tag.
    pub fn is_disjoint_from(&self, other: &TagSet) -> bool {
        self.tags.is_disjoint(&other.tags)
    }

    /// Size.
    pub fn len(&self) -> usize { self.tags.len() }

    /// Empty.
    pub fn is_empty(&self) -> bool { self.tags.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), TagError> {
        if self.schema_version != SCHEMA_VERSION { return Err(TagError::SchemaMismatch); }
        for t in &self.tags {
            if t.is_empty() { return Err(TagError::EmptyTag); }
        }
        Ok(())
    }
}

impl Default for TagSet {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_dedupes() {
        let mut s = TagSet::new();
        assert!(s.add("a").unwrap());
        assert!(!s.add("a").unwrap());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn intersection() {
        let a = TagSet::from_iter_strs(["x", "y", "z"]).unwrap();
        let b = TagSet::from_iter_strs(["y", "z", "w"]).unwrap();
        let i = a.intersection(&b);
        assert_eq!(i.len(), 2);
        assert!(i.contains("y"));
        assert!(i.contains("z"));
    }

    #[test]
    fn union() {
        let a = TagSet::from_iter_strs(["x", "y"]).unwrap();
        let b = TagSet::from_iter_strs(["y", "z"]).unwrap();
        let u = a.union(&b);
        assert_eq!(u.len(), 3);
    }

    #[test]
    fn difference() {
        let a = TagSet::from_iter_strs(["x", "y", "z"]).unwrap();
        let b = TagSet::from_iter_strs(["y"]).unwrap();
        let d = a.difference(&b);
        assert_eq!(d.len(), 2);
        assert!(d.contains("x"));
        assert!(d.contains("z"));
    }

    #[test]
    fn subset() {
        let a = TagSet::from_iter_strs(["x", "y"]).unwrap();
        let b = TagSet::from_iter_strs(["x", "y", "z"]).unwrap();
        assert!(a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    #[test]
    fn disjoint() {
        let a = TagSet::from_iter_strs(["x"]).unwrap();
        let b = TagSet::from_iter_strs(["y"]).unwrap();
        let c = TagSet::from_iter_strs(["x", "z"]).unwrap();
        assert!(a.is_disjoint_from(&b));
        assert!(!a.is_disjoint_from(&c));
    }

    #[test]
    fn remove() {
        let mut s = TagSet::from_iter_strs(["a", "b"]).unwrap();
        assert!(s.remove("a"));
        assert!(!s.remove("a"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn empty_tag_rejected() {
        let mut s = TagSet::new();
        assert!(matches!(s.add("").unwrap_err(), TagError::EmptyTag));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = TagSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), TagError::SchemaMismatch));
    }

    #[test]
    fn set_serde_roundtrip() {
        let s = TagSet::from_iter_strs(["a", "b", "c"]).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: TagSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
