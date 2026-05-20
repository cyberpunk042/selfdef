//! `selfdef-alert-escalation-policy` — staged escalation.
//!
//! Each alert moves through stages in order: Notify → Page → Wake.
//! Per-stage `wait_ms` defines how long without ack before
//! escalating. `alert_at(alert_id, severity, ts)` registers a new
//! alert. `tick(now)` advances stages on any unacked alert past
//! `wait_ms`. `ack(id, ts)` stops further escalation.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Stage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Notify (low-noise channel).
    Notify,
    /// Page (high-priority).
    Page,
    /// Wake (max — phone call, etc.).
    Wake,
    /// Resolved.
    Resolved,
}

/// One alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    /// Id.
    pub id: String,
    /// Stage.
    pub stage: Stage,
    /// First raised ts.
    pub raised_at_ms: u64,
    /// Last stage entered ts.
    pub last_stage_ts_ms: u64,
    /// Severity hint.
    pub severity: String,
    /// Acked at (None = pending).
    pub acked_at_ms: Option<u64>,
}

/// Config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Waits {
    /// Notify → Page.
    pub notify_to_page_ms: u64,
    /// Page → Wake.
    pub page_to_wake_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertEscalationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Wait windows.
    pub waits: Waits,
    /// id → alert.
    pub alerts: BTreeMap<String, Alert>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AlertError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("alert id empty")]
    EmptyId,
    /// Empty severity.
    #[error("severity empty")]
    EmptySeverity,
    /// Duplicate.
    #[error("duplicate alert id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown alert: {0}")]
    UnknownAlert(String),
}

impl AlertEscalationPolicy {
    /// New.
    pub fn new(notify_to_page_ms: u64, page_to_wake_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            waits: Waits { notify_to_page_ms, page_to_wake_ms },
            alerts: BTreeMap::new(),
        }
    }

    /// Register a new alert (starts at Notify).
    pub fn alert_at(&mut self, alert_id: &str, severity: &str, ts_ms: u64) -> Result<(), AlertError> {
        if alert_id.is_empty() { return Err(AlertError::EmptyId); }
        if severity.is_empty() { return Err(AlertError::EmptySeverity); }
        if self.alerts.contains_key(alert_id) {
            return Err(AlertError::DuplicateId(alert_id.into()));
        }
        self.alerts.insert(alert_id.into(), Alert {
            id: alert_id.into(),
            stage: Stage::Notify,
            raised_at_ms: ts_ms,
            last_stage_ts_ms: ts_ms,
            severity: severity.into(),
            acked_at_ms: None,
        });
        Ok(())
    }

    /// Ack.
    pub fn ack(&mut self, alert_id: &str, ts_ms: u64) -> Result<(), AlertError> {
        let a = self.alerts.get_mut(alert_id).ok_or_else(|| AlertError::UnknownAlert(alert_id.into()))?;
        a.acked_at_ms = Some(ts_ms);
        a.stage = Stage::Resolved;
        Ok(())
    }

    /// Tick — advance any alerts past their stage's wait window.
    /// Returns ids of alerts that were escalated, with their new stage.
    pub fn tick(&mut self, now_ms: u64) -> Vec<(String, Stage)> {
        let waits = self.waits;
        let mut changes = Vec::new();
        for a in self.alerts.values_mut() {
            if a.acked_at_ms.is_some() { continue; }
            let elapsed = now_ms.saturating_sub(a.last_stage_ts_ms);
            match a.stage {
                Stage::Notify => {
                    if elapsed >= waits.notify_to_page_ms {
                        a.stage = Stage::Page;
                        a.last_stage_ts_ms = now_ms;
                        changes.push((a.id.clone(), Stage::Page));
                    }
                }
                Stage::Page => {
                    if elapsed >= waits.page_to_wake_ms {
                        a.stage = Stage::Wake;
                        a.last_stage_ts_ms = now_ms;
                        changes.push((a.id.clone(), Stage::Wake));
                    }
                }
                Stage::Wake | Stage::Resolved => {}
            }
        }
        changes
    }

    /// Pending count.
    pub fn pending_count(&self) -> usize {
        self.alerts.values().filter(|a| a.acked_at_ms.is_none()).count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AlertError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AlertError::SchemaMismatch); }
        for (id, a) in &self.alerts {
            if id.is_empty() { return Err(AlertError::EmptyId); }
            if a.severity.is_empty() { return Err(AlertError::EmptySeverity); }
        }
        Ok(())
    }
}

impl Default for AlertEscalationPolicy {
    fn default() -> Self { Self::new(300_000, 900_000) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_starts_at_notify() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a1", "warn", 0).unwrap();
        assert_eq!(p.alerts["a1"].stage, Stage::Notify);
    }

    #[test]
    fn tick_escalates_to_page() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a1", "warn", 0).unwrap();
        let c = p.tick(70_000);
        assert_eq!(c, vec![("a1".to_string(), Stage::Page)]);
        assert_eq!(p.alerts["a1"].stage, Stage::Page);
    }

    #[test]
    fn tick_escalates_to_wake() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a1", "warn", 0).unwrap();
        p.tick(70_000); // notify → page
        let c = p.tick(70_000 + 400_000); // page → wake
        assert_eq!(c, vec![("a1".to_string(), Stage::Wake)]);
    }

    #[test]
    fn wake_is_terminal() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a1", "warn", 0).unwrap();
        p.tick(70_000);
        p.tick(70_000 + 400_000);
        // Further ticks no-op.
        let c = p.tick(1_000_000_000);
        assert!(c.is_empty());
    }

    #[test]
    fn ack_stops_escalation() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a1", "warn", 0).unwrap();
        p.ack("a1", 10_000).unwrap();
        let c = p.tick(1_000_000);
        assert!(c.is_empty());
        assert_eq!(p.alerts["a1"].stage, Stage::Resolved);
    }

    #[test]
    fn pending_count_excludes_acked() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a", "x", 0).unwrap();
        p.alert_at("b", "x", 0).unwrap();
        p.ack("a", 1).unwrap();
        assert_eq!(p.pending_count(), 1);
    }

    #[test]
    fn duplicate_alert_rejected() {
        let mut p = AlertEscalationPolicy::new(1, 1);
        p.alert_at("a", "x", 0).unwrap();
        assert!(matches!(p.alert_at("a", "x", 0).unwrap_err(), AlertError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = AlertEscalationPolicy::new(1, 1);
        assert!(matches!(p.alert_at("", "x", 0).unwrap_err(), AlertError::EmptyId));
        assert!(matches!(p.alert_at("a", "", 0).unwrap_err(), AlertError::EmptySeverity));
    }

    #[test]
    fn unknown_ack_rejected() {
        let mut p = AlertEscalationPolicy::new(1, 1);
        assert!(matches!(p.ack("nope", 0).unwrap_err(), AlertError::UnknownAlert(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = AlertEscalationPolicy::new(1, 1);
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), AlertError::SchemaMismatch));
    }

    #[test]
    fn alert_serde_roundtrip() {
        let mut p = AlertEscalationPolicy::new(60_000, 300_000);
        p.alert_at("a", "warn", 0).unwrap();
        p.tick(70_000);
        let j = serde_json::to_string(&p).unwrap();
        let back: AlertEscalationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
