//! `selfdef-toggle-audit-authority` — IPS authority over operator-toggle flips.
//!
//! 5 canonical toggle scopes:
//! - `DashboardSlot`  — dashboard D-NN visibility / enabled
//! - `FeatureFlag`    — runtime feature flag
//! - `ModeBoolean`    — mode-attached boolean (e.g. live-telemetry)
//! - `NotifierChannel` — per-channel on/off
//! - `BoundaryPolicy` — boundary-rule on/off
//!
//! Every flip emits one `ToggleAuthorityEntry` with operator MS003
//! signature + trace_id + scope + key + before/after + ISO-8601 at.
//! IPS refuses entries with missing fields, unsigned, or with no-op
//! flip (before == after).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Toggle scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToggleScope {
    /// Dashboard slot.
    DashboardSlot,
    /// Feature flag.
    FeatureFlag,
    /// Mode-attached boolean.
    ModeBoolean,
    /// Notifier channel.
    NotifierChannel,
    /// Boundary policy.
    BoundaryPolicy,
}

/// Audit entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToggleAuthorityEntry {
    /// Scope.
    pub scope: ToggleScope,
    /// Toggle key (e.g. "D-13", "feature.web-fetch", "boundary.fs.write").
    pub key: String,
    /// Previous value.
    pub from: bool,
    /// New value.
    pub to: bool,
    /// Operator MS003 fingerprint.
    pub actor: String,
    /// M049 trace_id.
    pub trace_id: String,
    /// ISO-8601 UTC.
    pub at: String,
    /// MS003 signature over canonical-JSON (hex).
    pub signature: String,
}

/// Audit log envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToggleAuthorityLog {
    /// Schema version.
    pub schema_version: String,
    /// Entries in append order.
    pub entries: Vec<ToggleAuthorityEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ToggleAuthorityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty key.
    #[error("toggle key empty")]
    EmptyKey,
    /// Empty actor.
    #[error("actor missing")]
    MissingActor,
    /// Empty trace_id.
    #[error("trace_id missing")]
    MissingTraceId,
    /// Empty timestamp.
    #[error("at missing")]
    MissingTimestamp,
    /// Unsigned.
    #[error("signature missing for {key}")]
    Unsigned {
        /// key.
        key: String,
    },
    /// No-op flip.
    #[error("no-op flip on {key} (both {value})")]
    NoOpFlip {
        /// key.
        key: String,
        /// value.
        value: bool,
    },
}

impl ToggleAuthorityLog {
    /// New empty log.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }

    /// IPS-authoritative entry append. Rejects unsigned / malformed / no-op.
    pub fn record(&mut self, entry: ToggleAuthorityEntry) -> Result<(), ToggleAuthorityError> {
        check_entry(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Count flips on a key.
    pub fn count_for(&self, key: &str) -> usize {
        self.entries.iter().filter(|e| e.key == key).count()
    }

    /// Latest value on a key.
    pub fn latest(&self, key: &str) -> Option<bool> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.key == key)
            .map(|e| e.to)
    }

    /// Entries within a scope.
    pub fn in_scope(&self, scope: ToggleScope) -> Vec<&ToggleAuthorityEntry> {
        self.entries.iter().filter(|e| e.scope == scope).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ToggleAuthorityError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ToggleAuthorityError::SchemaMismatch);
        }
        for e in &self.entries {
            check_entry(e)?;
        }
        Ok(())
    }
}

fn check_entry(e: &ToggleAuthorityEntry) -> Result<(), ToggleAuthorityError> {
    if e.key.is_empty() {
        return Err(ToggleAuthorityError::EmptyKey);
    }
    if e.actor.is_empty() {
        return Err(ToggleAuthorityError::MissingActor);
    }
    if e.trace_id.is_empty() {
        return Err(ToggleAuthorityError::MissingTraceId);
    }
    if e.at.is_empty() {
        return Err(ToggleAuthorityError::MissingTimestamp);
    }
    if e.signature.is_empty() {
        return Err(ToggleAuthorityError::Unsigned { key: e.key.clone() });
    }
    if e.from == e.to {
        return Err(ToggleAuthorityError::NoOpFlip {
            key: e.key.clone(),
            value: e.from,
        });
    }
    Ok(())
}

impl Default for ToggleAuthorityLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(scope: ToggleScope, key: &str, from: bool, to: bool) -> ToggleAuthorityEntry {
        ToggleAuthorityEntry {
            scope,
            key: key.into(),
            from,
            to,
            actor: "op-fp".into(),
            trace_id: "tr-1".into(),
            at: "2026-05-19T03:00:00Z".into(),
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn empty_log_validates() {
        ToggleAuthorityLog::new().validate().unwrap();
    }

    #[test]
    fn record_and_latest() {
        let mut l = ToggleAuthorityLog::new();
        l.record(ok(ToggleScope::DashboardSlot, "D-13", false, true))
            .unwrap();
        assert_eq!(l.latest("D-13"), Some(true));
        l.record(ok(ToggleScope::DashboardSlot, "D-13", true, false))
            .unwrap();
        assert_eq!(l.latest("D-13"), Some(false));
    }

    #[test]
    fn count_for() {
        let mut l = ToggleAuthorityLog::new();
        l.record(ok(ToggleScope::FeatureFlag, "a", false, true))
            .unwrap();
        l.record(ok(ToggleScope::FeatureFlag, "a", true, false))
            .unwrap();
        l.record(ok(ToggleScope::FeatureFlag, "b", false, true))
            .unwrap();
        assert_eq!(l.count_for("a"), 2);
        assert_eq!(l.count_for("b"), 1);
    }

    #[test]
    fn in_scope_filters() {
        let mut l = ToggleAuthorityLog::new();
        l.record(ok(ToggleScope::DashboardSlot, "D-13", false, true))
            .unwrap();
        l.record(ok(ToggleScope::FeatureFlag, "a", false, true))
            .unwrap();
        l.record(ok(ToggleScope::DashboardSlot, "D-14", false, true))
            .unwrap();
        assert_eq!(l.in_scope(ToggleScope::DashboardSlot).len(), 2);
        assert_eq!(l.in_scope(ToggleScope::FeatureFlag).len(), 1);
        assert_eq!(l.in_scope(ToggleScope::BoundaryPolicy).len(), 0);
    }

    #[test]
    fn no_op_flip_rejected() {
        let mut l = ToggleAuthorityLog::new();
        let err = l
            .record(ok(ToggleScope::DashboardSlot, "D-13", true, true))
            .unwrap_err();
        assert!(matches!(err, ToggleAuthorityError::NoOpFlip { .. }));
    }

    #[test]
    fn unsigned_rejected() {
        let mut l = ToggleAuthorityLog::new();
        let mut e = ok(ToggleScope::DashboardSlot, "D-13", false, true);
        e.signature = String::new();
        let err = l.record(e).unwrap_err();
        assert!(matches!(err, ToggleAuthorityError::Unsigned { .. }));
    }

    #[test]
    fn empty_key_rejected() {
        let mut l = ToggleAuthorityLog::new();
        let err = l
            .record(ok(ToggleScope::DashboardSlot, "", false, true))
            .unwrap_err();
        assert!(matches!(err, ToggleAuthorityError::EmptyKey));
    }

    #[test]
    fn missing_actor_rejected() {
        let mut l = ToggleAuthorityLog::new();
        let mut e = ok(ToggleScope::DashboardSlot, "D-13", false, true);
        e.actor = String::new();
        let err = l.record(e).unwrap_err();
        assert!(matches!(err, ToggleAuthorityError::MissingActor));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = ToggleAuthorityLog::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            ToggleAuthorityError::SchemaMismatch
        ));
    }

    #[test]
    fn scope_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ToggleScope::DashboardSlot).unwrap(),
            "\"dashboard-slot\""
        );
        assert_eq!(
            serde_json::to_string(&ToggleScope::NotifierChannel).unwrap(),
            "\"notifier-channel\""
        );
        assert_eq!(
            serde_json::to_string(&ToggleScope::BoundaryPolicy).unwrap(),
            "\"boundary-policy\""
        );
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut l = ToggleAuthorityLog::new();
        l.record(ok(ToggleScope::DashboardSlot, "D-13", false, true))
            .unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: ToggleAuthorityLog = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
