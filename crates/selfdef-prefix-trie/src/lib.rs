//! `selfdef-prefix-trie` — string-prefix → tag lookup.
//!
//! Insert (prefix, tag): empty prefix is the root tag. lookup(k)
//! walks the input char-by-char and returns the deepest tag
//! associated with a node visited along the way (longest-prefix
//! match). Backed by a BTreeMap-based child tree for ordered,
//! deterministic serialization.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Node {
    /// Tag at this node (None = no terminal tag here).
    pub tag: Option<u32>,
    /// child char → node.
    pub children: BTreeMap<char, Node>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixTrie {
    /// Schema version.
    pub schema_version: String,
    /// Root node.
    pub root: Node,
    /// Number of distinct keys with tags.
    pub size: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TrieError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Duplicate.
    #[error("duplicate prefix: {0}")]
    DuplicatePrefix(String),
}

impl PrefixTrie {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            root: Node::default(),
            size: 0,
        }
    }

    /// Insert prefix → tag. Duplicate prefix rejected.
    pub fn insert(&mut self, prefix: &str, tag: u32) -> Result<(), TrieError> {
        let mut node = &mut self.root;
        for c in prefix.chars() {
            node = node.children.entry(c).or_default();
        }
        if node.tag.is_some() {
            return Err(TrieError::DuplicatePrefix(prefix.into()));
        }
        node.tag = Some(tag);
        self.size = self.size.saturating_add(1);
        Ok(())
    }

    /// Longest-prefix lookup. Returns the deepest tag along the path,
    /// or None if no prefix (not even root) was tagged.
    pub fn lookup(&self, key: &str) -> Option<u32> {
        let mut node = &self.root;
        let mut best = node.tag;
        for c in key.chars() {
            match node.children.get(&c) {
                Some(child) => {
                    node = child;
                    if let Some(t) = node.tag {
                        best = Some(t);
                    }
                }
                None => break,
            }
        }
        best
    }

    /// Exact prefix lookup.
    pub fn lookup_exact(&self, prefix: &str) -> Option<u32> {
        let mut node = &self.root;
        for c in prefix.chars() {
            match node.children.get(&c) {
                Some(child) => node = child,
                None => return None,
            }
        }
        node.tag
    }

    /// Number of tagged prefixes.
    pub fn len(&self) -> u32 {
        self.size
    }

    /// Empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TrieError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrieError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for PrefixTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_lookup_none() {
        let t = PrefixTrie::new();
        assert_eq!(t.lookup("anything"), None);
    }

    #[test]
    fn exact_match() {
        let mut t = PrefixTrie::new();
        t.insert("/etc/passwd", 1).unwrap();
        assert_eq!(t.lookup("/etc/passwd"), Some(1));
        assert_eq!(t.lookup_exact("/etc/passwd"), Some(1));
    }

    #[test]
    fn longest_prefix_match() {
        let mut t = PrefixTrie::new();
        t.insert("/etc", 1).unwrap();
        t.insert("/etc/secrets", 2).unwrap();
        assert_eq!(t.lookup("/etc/secrets/db.key"), Some(2));
        assert_eq!(t.lookup("/etc/passwd"), Some(1));
        assert_eq!(t.lookup("/var/log"), None);
    }

    #[test]
    fn empty_prefix_is_root_tag() {
        let mut t = PrefixTrie::new();
        t.insert("", 42).unwrap();
        assert_eq!(t.lookup("anything"), Some(42));
        assert_eq!(t.lookup(""), Some(42));
    }

    #[test]
    fn exact_misses_when_no_terminal() {
        let mut t = PrefixTrie::new();
        t.insert("/etc/passwd", 1).unwrap();
        assert_eq!(t.lookup_exact("/etc"), None);
    }

    #[test]
    fn duplicate_prefix_rejected() {
        let mut t = PrefixTrie::new();
        t.insert("/a", 1).unwrap();
        assert!(matches!(
            t.insert("/a", 2).unwrap_err(),
            TrieError::DuplicatePrefix(_)
        ));
    }

    #[test]
    fn size_tracked() {
        let mut t = PrefixTrie::new();
        t.insert("/a", 1).unwrap();
        t.insert("/b", 2).unwrap();
        t.insert("/a/b", 3).unwrap();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = PrefixTrie::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            TrieError::SchemaMismatch
        ));
    }

    #[test]
    fn trie_serde_roundtrip() {
        let mut t = PrefixTrie::new();
        t.insert("/etc", 1).unwrap();
        t.insert("/etc/secrets", 2).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: PrefixTrie = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
