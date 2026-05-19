//! `selfdef-bus-subscriber-registry` — 9 canonical bus subscribers.
//!
//! The IPS event bus dispatches to 9 subscribers. Each declares:
//! - `subscriber` (one of 9)
//! - `delivery`  (Broadcast / Queue / Signaled)
//! - `wired`     (true once attached at boot)
//! - `quarantined` (true if pulled off bus)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 9 canonical subscribers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Subscriber {
    /// MS016 audit-log-writer.
    AuditLog,
    /// Quarantine engine.
    Quarantine,
    /// Notifier orchestrator.
    Notifier,
    /// Evidence ledger.
    EvidenceLedger,
    /// History sink (long-term archive).
    HistorySink,
    /// Policy bus.
    PolicyBus,
    /// Trust-score engine.
    TrustScore,
    /// Profile authority gate.
    ProfileAuthority,
    /// Dashboard manifest publisher.
    DashboardManifest,
}

/// Delivery semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    /// Fan-out to every subscriber.
    Broadcast,
    /// Single-consumer FIFO.
    Queue,
    /// Wake-up signal only; subscriber polls.
    Signaled,
}

/// Per-subscriber record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberRecord {
    /// Subscriber.
    pub subscriber: Subscriber,
    /// Delivery class.
    pub delivery: Delivery,
    /// Wired at boot.
    pub wired: bool,
    /// Quarantined off bus.
    pub quarantined: bool,
}

/// Registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberRegistry {
    /// Schema version.
    pub schema_version: String,
    /// 9 entries.
    pub entries: Vec<SubscriberRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BusError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 9.
    #[error("subscriber count {0} != 9 canonical")]
    CountInvalid(usize),
    /// Missing canonical subscriber.
    #[error("missing subscriber: {0:?}")]
    Missing(Subscriber),
    /// Subscriber unwired.
    #[error("subscriber {0:?} unwired")]
    Unwired(Subscriber),
    /// Subscriber quarantined; bus refuses start.
    #[error("subscriber {0:?} quarantined")]
    Quarantined(Subscriber),
}

const REQUIRED: [Subscriber; 9] = [
    Subscriber::AuditLog, Subscriber::Quarantine, Subscriber::Notifier,
    Subscriber::EvidenceLedger, Subscriber::HistorySink, Subscriber::PolicyBus,
    Subscriber::TrustScore, Subscriber::ProfileAuthority, Subscriber::DashboardManifest,
];

impl Subscriber {
    /// Canonical delivery class for this subscriber.
    pub fn canonical_delivery(self) -> Delivery {
        match self {
            // Audit log fan-out: receives every decision.
            Subscriber::AuditLog => Delivery::Broadcast,
            // Quarantine: single-consumer queue (FIFO important).
            Subscriber::Quarantine => Delivery::Queue,
            // Notifier: single-consumer queue.
            Subscriber::Notifier => Delivery::Queue,
            // Evidence ledger: broadcast.
            Subscriber::EvidenceLedger => Delivery::Broadcast,
            // History sink: broadcast.
            Subscriber::HistorySink => Delivery::Broadcast,
            // Policy bus: broadcast (fan-out to bus consumers).
            Subscriber::PolicyBus => Delivery::Broadcast,
            // Trust score: signaled wake-up.
            Subscriber::TrustScore => Delivery::Signaled,
            // Profile authority: signaled (it queries on demand).
            Subscriber::ProfileAuthority => Delivery::Signaled,
            // Dashboard manifest: broadcast.
            Subscriber::DashboardManifest => Delivery::Broadcast,
        }
    }
}

impl SubscriberRegistry {
    /// Canonical empty (all wired, none quarantined).
    pub fn canonical() -> Self {
        let entries = REQUIRED.iter().map(|s| SubscriberRecord {
            subscriber: *s,
            delivery: s.canonical_delivery(),
            wired: true,
            quarantined: false,
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries,
        }
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<(), BusError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BusError::SchemaMismatch);
        }
        if self.entries.len() != 9 {
            return Err(BusError::CountInvalid(self.entries.len()));
        }
        for s in REQUIRED {
            if !self.entries.iter().any(|r| r.subscriber == s) {
                return Err(BusError::Missing(s));
            }
        }
        Ok(())
    }

    /// Assert ready to start the bus — every subscriber wired and not quarantined.
    pub fn assert_ready(&self) -> Result<(), BusError> {
        self.validate()?;
        for r in &self.entries {
            if !r.wired { return Err(BusError::Unwired(r.subscriber)); }
            if r.quarantined { return Err(BusError::Quarantined(r.subscriber)); }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: Subscriber) -> Option<&SubscriberRecord> {
        self.entries.iter().find(|r| r.subscriber == s)
    }

    /// Subscribers currently active (wired + not quarantined).
    pub fn active_subscribers(&self) -> Vec<Subscriber> {
        self.entries.iter().filter(|r| r.wired && !r.quarantined).map(|r| r.subscriber).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates_and_ready() {
        let r = SubscriberRegistry::canonical();
        r.validate().unwrap();
        r.assert_ready().unwrap();
    }

    #[test]
    fn nine_subscribers_present() {
        let r = SubscriberRegistry::canonical();
        for s in REQUIRED {
            assert!(r.get(s).is_some(), "missing {s:?}");
        }
    }

    #[test]
    fn canonical_delivery_map() {
        assert_eq!(Subscriber::AuditLog.canonical_delivery(), Delivery::Broadcast);
        assert_eq!(Subscriber::Quarantine.canonical_delivery(), Delivery::Queue);
        assert_eq!(Subscriber::TrustScore.canonical_delivery(), Delivery::Signaled);
        assert_eq!(Subscriber::ProfileAuthority.canonical_delivery(), Delivery::Signaled);
    }

    #[test]
    fn unwired_blocks_assert_ready() {
        let mut r = SubscriberRegistry::canonical();
        r.entries[0].wired = false;
        match r.assert_ready().unwrap_err() {
            BusError::Unwired(s) => assert_eq!(s, r.entries[0].subscriber),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quarantined_blocks_assert_ready() {
        let mut r = SubscriberRegistry::canonical();
        r.entries[1].quarantined = true;
        match r.assert_ready().unwrap_err() {
            BusError::Quarantined(s) => assert_eq!(s, r.entries[1].subscriber),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = SubscriberRegistry::canonical();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), BusError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut r = SubscriberRegistry::canonical();
        r.entries.pop();
        assert!(matches!(r.validate().unwrap_err(), BusError::CountInvalid(8)));
    }

    #[test]
    fn active_subscribers_excludes_unwired_and_quarantined() {
        let mut r = SubscriberRegistry::canonical();
        r.entries[0].wired = false;
        r.entries[1].quarantined = true;
        let active = r.active_subscribers();
        assert_eq!(active.len(), 7);
        assert!(!active.contains(&r.entries[0].subscriber));
        assert!(!active.contains(&r.entries[1].subscriber));
    }

    #[test]
    fn subscriber_serde_kebab() {
        assert_eq!(serde_json::to_string(&Subscriber::AuditLog).unwrap(), "\"audit-log\"");
        assert_eq!(serde_json::to_string(&Subscriber::EvidenceLedger).unwrap(), "\"evidence-ledger\"");
        assert_eq!(serde_json::to_string(&Subscriber::DashboardManifest).unwrap(), "\"dashboard-manifest\"");
    }

    #[test]
    fn delivery_serde_kebab() {
        assert_eq!(serde_json::to_string(&Delivery::Broadcast).unwrap(), "\"broadcast\"");
        assert_eq!(serde_json::to_string(&Delivery::Queue).unwrap(), "\"queue\"");
        assert_eq!(serde_json::to_string(&Delivery::Signaled).unwrap(), "\"signaled\"");
    }

    #[test]
    fn registry_serde_roundtrip() {
        let r = SubscriberRegistry::canonical();
        let j = serde_json::to_string(&r).unwrap();
        let back: SubscriberRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
