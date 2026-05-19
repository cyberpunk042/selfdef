//! `selfdef-policy-cooldown-window` — per-(class, key) cooldown.
//!
//! On_fire(class, key, now). next_fire_allowed(class, key, now)
//! returns true when current time exceeds last_fire + cooldown.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Policy class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyClass {
    /// Alert.
    Alert,
    /// Notification.
    Notification,
    /// Audit-log entry.
    AuditLog,
    /// Operator prompt.
    OperatorPrompt,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCooldownWindow {
    /// Schema version.
    pub schema_version: String,
    /// Per-class cooldown seconds.
    pub alert_cooldown_s: u32,
    /// Notification cooldown.
    pub notification_cooldown_s: u32,
    /// Audit-log cooldown.
    pub audit_log_cooldown_s: u32,
    /// Operator-prompt cooldown.
    pub operator_prompt_cooldown_s: u32,
    /// Last-fire timestamps keyed by (class, key).
    pub last_fires: BTreeMap<String, u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CooldownError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty key.
    #[error("key empty")]
    EmptyKey,
}

impl PolicyCooldownWindow {
    /// Canonical: Alert 60s, Notification 30s, AuditLog 1s, OperatorPrompt 300s.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            alert_cooldown_s: 60,
            notification_cooldown_s: 30,
            audit_log_cooldown_s: 1,
            operator_prompt_cooldown_s: 300,
            last_fires: BTreeMap::new(),
        }
    }

    /// Cooldown for class.
    pub fn cooldown(&self, class: PolicyClass) -> u32 {
        match class {
            PolicyClass::Alert => self.alert_cooldown_s,
            PolicyClass::Notification => self.notification_cooldown_s,
            PolicyClass::AuditLog => self.audit_log_cooldown_s,
            PolicyClass::OperatorPrompt => self.operator_prompt_cooldown_s,
        }
    }

    /// Try to fire; returns true if allowed (and records timestamp).
    pub fn try_fire(&mut self, class: PolicyClass, key: &str, now_unix: u64) -> Result<bool, CooldownError> {
        if key.is_empty() { return Err(CooldownError::EmptyKey); }
        let composite = format!("{:?}:{}", class, key);
        let last = self.last_fires.get(&composite).copied().unwrap_or(0);
        let cooldown = self.cooldown(class) as u64;
        let allowed = last == 0 || now_unix.saturating_sub(last) >= cooldown;
        if allowed {
            self.last_fires.insert(composite, now_unix);
        }
        Ok(allowed)
    }

    /// Seconds until next-allowed fire (0 = allowed now).
    pub fn seconds_to_next(&self, class: PolicyClass, key: &str, now_unix: u64) -> u64 {
        let composite = format!("{:?}:{}", class, key);
        let last = self.last_fires.get(&composite).copied().unwrap_or(0);
        if last == 0 { return 0; }
        let cooldown = self.cooldown(class) as u64;
        let next_fire = last + cooldown;
        next_fire.saturating_sub(now_unix)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CooldownError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CooldownError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_fire_allowed() {
        let mut c = PolicyCooldownWindow::canonical();
        assert!(c.try_fire(PolicyClass::Alert, "subj-a", 100).unwrap());
    }

    #[test]
    fn second_fire_within_window_denied() {
        let mut c = PolicyCooldownWindow::canonical();
        assert!(c.try_fire(PolicyClass::Alert, "subj-a", 100).unwrap());
        assert!(!c.try_fire(PolicyClass::Alert, "subj-a", 130).unwrap()); // alert cooldown 60s
    }

    #[test]
    fn second_fire_after_window_allowed() {
        let mut c = PolicyCooldownWindow::canonical();
        c.try_fire(PolicyClass::Alert, "a", 100).unwrap();
        assert!(c.try_fire(PolicyClass::Alert, "a", 200).unwrap());
    }

    #[test]
    fn different_keys_independent() {
        let mut c = PolicyCooldownWindow::canonical();
        assert!(c.try_fire(PolicyClass::Alert, "a", 100).unwrap());
        assert!(c.try_fire(PolicyClass::Alert, "b", 100).unwrap());
    }

    #[test]
    fn different_classes_independent() {
        let mut c = PolicyCooldownWindow::canonical();
        assert!(c.try_fire(PolicyClass::Alert, "a", 100).unwrap());
        assert!(c.try_fire(PolicyClass::Notification, "a", 100).unwrap());
    }

    #[test]
    fn seconds_to_next() {
        let mut c = PolicyCooldownWindow::canonical();
        c.try_fire(PolicyClass::Alert, "a", 100).unwrap();
        // alert cooldown 60s -> next at 160; at now 130 -> 30s remaining.
        assert_eq!(c.seconds_to_next(PolicyClass::Alert, "a", 130), 30);
    }

    #[test]
    fn seconds_to_next_before_first_fire_zero() {
        let c = PolicyCooldownWindow::canonical();
        assert_eq!(c.seconds_to_next(PolicyClass::Alert, "a", 100), 0);
    }

    #[test]
    fn empty_key_rejected() {
        let mut c = PolicyCooldownWindow::canonical();
        assert!(matches!(c.try_fire(PolicyClass::Alert, "", 0).unwrap_err(), CooldownError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PolicyCooldownWindow::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CooldownError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&PolicyClass::OperatorPrompt).unwrap(), "\"operator-prompt\"");
    }

    #[test]
    fn cooldown_serde_roundtrip() {
        let mut c = PolicyCooldownWindow::canonical();
        c.try_fire(PolicyClass::Alert, "a", 100).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: PolicyCooldownWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
