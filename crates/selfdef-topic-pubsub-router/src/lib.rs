//! `selfdef-topic-pubsub-router` — topic→subscriber routing.
//!
//! Subscribers register either an exact topic match or a `*`-suffixed
//! prefix (e.g. `"audit.*"`). `match_topic(topic)` returns the set
//! of subscriber ids whose subscription matches.
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
pub struct TopicPubsubRouter {
    /// Schema version.
    pub schema_version: String,
    /// subscriber → patterns.
    pub subscriptions: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RouterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("subscriber id empty")]
    EmptySubscriber,
    /// Empty.
    #[error("topic pattern empty")]
    EmptyPattern,
}

fn pattern_matches(pattern: &str, topic: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        topic.starts_with(prefix)
    } else {
        pattern == topic
    }
}

impl TopicPubsubRouter {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            subscriptions: BTreeMap::new(),
        }
    }

    /// Subscribe.
    pub fn subscribe(&mut self, subscriber: &str, pattern: &str) -> Result<bool, RouterError> {
        if subscriber.is_empty() { return Err(RouterError::EmptySubscriber); }
        if pattern.is_empty() { return Err(RouterError::EmptyPattern); }
        Ok(self.subscriptions.entry(subscriber.into()).or_default().insert(pattern.into()))
    }

    /// Unsubscribe one pattern.
    pub fn unsubscribe(&mut self, subscriber: &str, pattern: &str) -> bool {
        let Some(set) = self.subscriptions.get_mut(subscriber) else { return false; };
        let removed = set.remove(pattern);
        if set.is_empty() { self.subscriptions.remove(subscriber); }
        removed
    }

    /// Drop a subscriber entirely.
    pub fn drop_subscriber(&mut self, subscriber: &str) -> bool {
        self.subscriptions.remove(subscriber).is_some()
    }

    /// Subscribers matching topic (sorted by id).
    pub fn match_topic(&self, topic: &str) -> Vec<String> {
        self.subscriptions.iter()
            .filter(|(_, pats)| pats.iter().any(|p| pattern_matches(p, topic)))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// All patterns for a subscriber.
    pub fn patterns_of(&self, subscriber: &str) -> Vec<String> {
        self.subscriptions.get(subscriber).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RouterError> {
        if self.schema_version != SCHEMA_VERSION { return Err(RouterError::SchemaMismatch); }
        for (sub, pats) in &self.subscriptions {
            if sub.is_empty() { return Err(RouterError::EmptySubscriber); }
            for p in pats {
                if p.is_empty() { return Err(RouterError::EmptyPattern); }
            }
        }
        Ok(())
    }
}

impl Default for TopicPubsubRouter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("s1", "audit.commit").unwrap();
        assert_eq!(r.match_topic("audit.commit"), vec!["s1"]);
        assert!(r.match_topic("audit.other").is_empty());
    }

    #[test]
    fn prefix_match() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("s1", "audit.*").unwrap();
        assert_eq!(r.match_topic("audit.x"), vec!["s1"]);
        assert_eq!(r.match_topic("audit.x.y"), vec!["s1"]);
        assert!(r.match_topic("decision.x").is_empty());
    }

    #[test]
    fn multiple_subscribers() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("a", "*").unwrap();
        r.subscribe("b", "audit.*").unwrap();
        let mut m = r.match_topic("audit.commit");
        m.sort();
        assert_eq!(m, vec!["a", "b"]);
    }

    #[test]
    fn unsubscribe_one_pattern() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("s1", "a").unwrap();
        r.subscribe("s1", "b").unwrap();
        assert!(r.unsubscribe("s1", "a"));
        assert_eq!(r.patterns_of("s1"), vec!["b"]);
    }

    #[test]
    fn drop_subscriber() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("s1", "*").unwrap();
        assert!(r.drop_subscriber("s1"));
        assert!(r.match_topic("anything").is_empty());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = TopicPubsubRouter::new();
        assert!(matches!(r.subscribe("", "x").unwrap_err(), RouterError::EmptySubscriber));
        assert!(matches!(r.subscribe("s", "").unwrap_err(), RouterError::EmptyPattern));
    }

    #[test]
    fn duplicate_subscribe_idempotent() {
        let mut r = TopicPubsubRouter::new();
        assert!(r.subscribe("s", "p").unwrap());
        assert!(!r.subscribe("s", "p").unwrap());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = TopicPubsubRouter::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), RouterError::SchemaMismatch));
    }

    #[test]
    fn pubsub_serde_roundtrip() {
        let mut r = TopicPubsubRouter::new();
        r.subscribe("s1", "audit.*").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: TopicPubsubRouter = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
