//! `selfdef-subscription-registry` — TTL-bounded subscriptions.
//!
//! Each Subscription{id, subscriber, topic, created_at_ms,
//! expires_at_ms}. subscribe takes a ttl. renew extends; expired
//! subscriptions are dropped by prune(now).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One subscription.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    /// Id.
    pub id: String,
    /// Subscriber actor.
    pub subscriber: String,
    /// Topic.
    pub topic: String,
    /// Created.
    pub created_at_ms: u64,
    /// Expires.
    pub expires_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionRegistry {
    /// Schema version.
    pub schema_version: String,
    /// id → subscription.
    pub subscriptions: BTreeMap<String, Subscription>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SubError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("subscriber empty")]
    EmptySubscriber,
    /// Empty.
    #[error("topic empty")]
    EmptyTopic,
    /// Zero ttl.
    #[error("ttl must be > 0")]
    ZeroTtl,
    /// Duplicate.
    #[error("duplicate subscription id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown subscription: {0}")]
    UnknownSubscription(String),
}

impl SubscriptionRegistry {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            subscriptions: BTreeMap::new(),
        }
    }

    /// Subscribe.
    pub fn subscribe(
        &mut self,
        id: &str,
        subscriber: &str,
        topic: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), SubError> {
        if id.is_empty() {
            return Err(SubError::EmptyId);
        }
        if subscriber.is_empty() {
            return Err(SubError::EmptySubscriber);
        }
        if topic.is_empty() {
            return Err(SubError::EmptyTopic);
        }
        if ttl_ms == 0 {
            return Err(SubError::ZeroTtl);
        }
        if self.subscriptions.contains_key(id) {
            return Err(SubError::DuplicateId(id.into()));
        }
        self.subscriptions.insert(
            id.into(),
            Subscription {
                id: id.into(),
                subscriber: subscriber.into(),
                topic: topic.into(),
                created_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            },
        );
        Ok(())
    }

    /// Renew.
    pub fn renew(&mut self, id: &str, now_ms: u64, ttl_ms: u64) -> Result<(), SubError> {
        if ttl_ms == 0 {
            return Err(SubError::ZeroTtl);
        }
        let s = self
            .subscriptions
            .get_mut(id)
            .ok_or_else(|| SubError::UnknownSubscription(id.into()))?;
        s.expires_at_ms = now_ms.saturating_add(ttl_ms);
        Ok(())
    }

    /// Unsubscribe.
    pub fn unsubscribe(&mut self, id: &str) -> bool {
        self.subscriptions.remove(id).is_some()
    }

    /// Prune expired.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let expired: Vec<String> = self
            .subscriptions
            .iter()
            .filter(|(_, s)| now_ms >= s.expires_at_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for k in expired {
            self.subscriptions.remove(&k);
        }
        n
    }

    /// Active count.
    pub fn active_count(&self, now_ms: u64) -> usize {
        self.subscriptions
            .values()
            .filter(|s| now_ms < s.expires_at_ms)
            .count()
    }

    /// Subscriptions for a topic at now.
    pub fn by_topic(&self, topic: &str, now_ms: u64) -> Vec<String> {
        self.subscriptions
            .values()
            .filter(|s| s.topic == topic && now_ms < s.expires_at_ms)
            .map(|s| s.subscriber.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SubError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SubError::SchemaMismatch);
        }
        for (id, s) in &self.subscriptions {
            if id.is_empty() {
                return Err(SubError::EmptyId);
            }
            if s.subscriber.is_empty() {
                return Err(SubError::EmptySubscriber);
            }
            if s.topic.is_empty() {
                return Err(SubError::EmptyTopic);
            }
        }
        Ok(())
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_and_query() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "audit.*", 0, 1000).unwrap();
        assert_eq!(r.active_count(500), 1);
        assert_eq!(r.by_topic("audit.*", 500), vec!["alice"]);
    }

    #[test]
    fn expired_filtered_from_active() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        assert_eq!(r.active_count(2000), 0);
    }

    #[test]
    fn renew_extends_ttl() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        r.renew("s1", 500, 5000).unwrap();
        // New expiry = 5500.
        assert_eq!(r.active_count(2000), 1);
    }

    #[test]
    fn prune_drops_expired() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        r.subscribe("s2", "bob", "t", 0, 5000).unwrap();
        assert_eq!(r.prune(2000), 1);
        assert!(r.subscriptions.contains_key("s2"));
    }

    #[test]
    fn unsubscribe_works() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        assert!(r.unsubscribe("s1"));
        assert!(!r.unsubscribe("s1"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        assert!(matches!(
            r.subscribe("s1", "bob", "t", 0, 1000).unwrap_err(),
            SubError::DuplicateId(_)
        ));
    }

    #[test]
    fn zero_ttl_rejected() {
        let mut r = SubscriptionRegistry::new();
        assert!(matches!(
            r.subscribe("s", "a", "t", 0, 0).unwrap_err(),
            SubError::ZeroTtl
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = SubscriptionRegistry::new();
        assert!(matches!(
            r.subscribe("", "a", "t", 0, 1).unwrap_err(),
            SubError::EmptyId
        ));
        assert!(matches!(
            r.subscribe("s", "", "t", 0, 1).unwrap_err(),
            SubError::EmptySubscriber
        ));
        assert!(matches!(
            r.subscribe("s", "a", "", 0, 1).unwrap_err(),
            SubError::EmptyTopic
        ));
    }

    #[test]
    fn renew_unknown_rejected() {
        let mut r = SubscriptionRegistry::new();
        assert!(matches!(
            r.renew("nope", 0, 1).unwrap_err(),
            SubError::UnknownSubscription(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = SubscriptionRegistry::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            SubError::SchemaMismatch
        ));
    }

    #[test]
    fn sub_serde_roundtrip() {
        let mut r = SubscriptionRegistry::new();
        r.subscribe("s1", "alice", "t", 0, 1000).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: SubscriptionRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
