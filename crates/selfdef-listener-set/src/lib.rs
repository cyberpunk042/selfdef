//! `selfdef-listener-set` — topic → listener-id set.
//!
//! subscribe(topic, listener_id) registers; unsubscribe drops.
//! listeners_for(topic) returns sorted listener ids; topics_for
//! returns sorted topics a listener subscribes to.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerSet {
    /// Schema version.
    pub schema_version: String,
    /// topic → listener_ids.
    pub by_topic: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("topic empty")]
    EmptyTopic,
    /// Empty.
    #[error("listener_id empty")]
    EmptyListener,
}

impl ListenerSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_topic: BTreeMap::new(),
        }
    }

    /// Subscribe.
    pub fn subscribe(&mut self, topic: &str, listener_id: &str) -> Result<bool, ListenerError> {
        if topic.is_empty() {
            return Err(ListenerError::EmptyTopic);
        }
        if listener_id.is_empty() {
            return Err(ListenerError::EmptyListener);
        }
        let s = self.by_topic.entry(topic.into()).or_default();
        Ok(s.insert(listener_id.into()))
    }

    /// Unsubscribe.
    pub fn unsubscribe(&mut self, topic: &str, listener_id: &str) -> bool {
        let s = match self.by_topic.get_mut(topic) {
            Some(s) => s,
            None => return false,
        };
        let removed = s.remove(listener_id);
        if s.is_empty() {
            self.by_topic.remove(topic);
        }
        removed
    }

    /// Listeners for topic.
    pub fn listeners_for(&self, topic: &str) -> Vec<&str> {
        self.by_topic
            .get(topic)
            .map(|s| s.iter().map(|k| k.as_str()).collect())
            .unwrap_or_default()
    }

    /// Topics for a listener.
    pub fn topics_for(&self, listener_id: &str) -> Vec<&str> {
        self.by_topic
            .iter()
            .filter(|(_, s)| s.contains(listener_id))
            .map(|(t, _)| t.as_str())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ListenerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ListenerError::SchemaMismatch);
        }
        for (t, s) in &self.by_topic {
            if t.is_empty() {
                return Err(ListenerError::EmptyTopic);
            }
            for id in s {
                if id.is_empty() {
                    return Err(ListenerError::EmptyListener);
                }
            }
        }
        Ok(())
    }
}

impl Default for ListenerSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_list() {
        let mut s = ListenerSet::new();
        s.subscribe("alerts", "alice").unwrap();
        s.subscribe("alerts", "bob").unwrap();
        let l = s.listeners_for("alerts");
        assert_eq!(l, vec!["alice", "bob"]);
    }

    #[test]
    fn subscribe_idempotent() {
        let mut s = ListenerSet::new();
        assert!(s.subscribe("t", "a").unwrap());
        assert!(!s.subscribe("t", "a").unwrap());
    }

    #[test]
    fn unsubscribe_works() {
        let mut s = ListenerSet::new();
        s.subscribe("t", "a").unwrap();
        assert!(s.unsubscribe("t", "a"));
        assert!(!s.unsubscribe("t", "a"));
    }

    #[test]
    fn empty_topic_dropped_after_last_unsubscribe() {
        let mut s = ListenerSet::new();
        s.subscribe("t", "a").unwrap();
        s.unsubscribe("t", "a");
        assert!(!s.by_topic.contains_key("t"));
    }

    #[test]
    fn topics_for_listener() {
        let mut s = ListenerSet::new();
        s.subscribe("a", "alice").unwrap();
        s.subscribe("b", "alice").unwrap();
        s.subscribe("a", "bob").unwrap();
        let t = s.topics_for("alice");
        assert_eq!(t, vec!["a", "b"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = ListenerSet::new();
        assert!(matches!(
            s.subscribe("", "a").unwrap_err(),
            ListenerError::EmptyTopic
        ));
        assert!(matches!(
            s.subscribe("t", "").unwrap_err(),
            ListenerError::EmptyListener
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ListenerSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            ListenerError::SchemaMismatch
        ));
    }

    #[test]
    fn set_serde_roundtrip() {
        let mut s = ListenerSet::new();
        s.subscribe("t", "a").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: ListenerSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
