//! `selfdef-denial-appeal-window` — appeal a recent denial.
//!
//! A denial is recorded with `record_denial(denial_id, denied_at_ms,
//! actor)`. Within `window_ms` afterwards the actor may
//! `submit_appeal(denial_id, ts_ms, justification)`. Each denial
//! accepts at most one appeal. `resolve_appeal(denial_id, ts_ms,
//! Resolution{Granted|Sustained})` records the human resolution.
//!
//! `state(denial_id)` returns:
//!   * `NotFound`.
//!   * `Pending { window_close_ms }` — no appeal yet, window open.
//!   * `WindowClosed` — no appeal, window expired.
//!   * `AppealPending` — appeal submitted, awaiting resolution.
//!   * `Granted` / `Sustained` — resolved.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Resolution outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Resolution {
    /// Granted — original denial reversed.
    Granted,
    /// Sustained — denial upheld.
    Sustained,
}

/// One appeal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Appeal {
    /// Submitted ts.
    pub submitted_at_ms: u64,
    /// Submitter justification.
    pub justification: String,
    /// Resolution (None = pending).
    pub resolution: Option<Resolution>,
    /// Resolved ts.
    pub resolved_at_ms: Option<u64>,
}

/// One denial record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Denial {
    /// Denied ts.
    pub denied_at_ms: u64,
    /// Subject actor.
    pub actor: String,
    /// Appeal (if any).
    pub appeal: Option<Appeal>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenialAppealWindow {
    /// Schema version.
    pub schema_version: String,
    /// Appeal window after denial.
    pub window_ms: u64,
    /// denial_id → denial.
    pub denials: BTreeMap<String, Denial>,
}

/// State verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AppealState {
    /// Unknown.
    NotFound,
    /// Appeal window open.
    Pending {
        /// when the window closes.
        window_close_ms: u64,
    },
    /// Window closed, no appeal.
    WindowClosed,
    /// Appeal submitted.
    AppealPending,
    /// Granted.
    Granted,
    /// Sustained.
    Sustained,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AppealError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("denial id empty")]
    EmptyDenial,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty justification.
    #[error("justification empty")]
    EmptyJustification,
    /// Duplicate denial id.
    #[error("duplicate denial id: {0}")]
    DuplicateDenial(String),
    /// Unknown denial.
    #[error("unknown denial: {0}")]
    UnknownDenial(String),
    /// Already appealed.
    #[error("already appealed: {0}")]
    AlreadyAppealed(String),
    /// Window expired.
    #[error("appeal window expired: {0}")]
    WindowExpired(String),
    /// Already resolved.
    #[error("appeal already resolved: {0}")]
    AlreadyResolved(String),
    /// No appeal yet.
    #[error("no appeal to resolve: {0}")]
    NoAppeal(String),
}

impl DenialAppealWindow {
    /// New with window length.
    pub fn new(window_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            denials: BTreeMap::new(),
        }
    }

    /// Record a denial.
    pub fn record_denial(&mut self, denial_id: &str, denied_at_ms: u64, actor: &str) -> Result<(), AppealError> {
        if denial_id.is_empty() { return Err(AppealError::EmptyDenial); }
        if actor.is_empty() { return Err(AppealError::EmptyActor); }
        if self.denials.contains_key(denial_id) {
            return Err(AppealError::DuplicateDenial(denial_id.into()));
        }
        self.denials.insert(denial_id.into(), Denial {
            denied_at_ms,
            actor: actor.into(),
            appeal: None,
        });
        Ok(())
    }

    /// Submit an appeal.
    pub fn submit_appeal(&mut self, denial_id: &str, ts_ms: u64, justification: &str) -> Result<(), AppealError> {
        if justification.is_empty() { return Err(AppealError::EmptyJustification); }
        let window = self.window_ms;
        let d = self.denials.get_mut(denial_id).ok_or_else(|| AppealError::UnknownDenial(denial_id.into()))?;
        if d.appeal.is_some() {
            return Err(AppealError::AlreadyAppealed(denial_id.into()));
        }
        let window_close = d.denied_at_ms.saturating_add(window);
        if ts_ms > window_close {
            return Err(AppealError::WindowExpired(denial_id.into()));
        }
        d.appeal = Some(Appeal {
            submitted_at_ms: ts_ms,
            justification: justification.into(),
            resolution: None,
            resolved_at_ms: None,
        });
        Ok(())
    }

    /// Resolve.
    pub fn resolve_appeal(&mut self, denial_id: &str, ts_ms: u64, resolution: Resolution) -> Result<(), AppealError> {
        let d = self.denials.get_mut(denial_id).ok_or_else(|| AppealError::UnknownDenial(denial_id.into()))?;
        let a = d.appeal.as_mut().ok_or_else(|| AppealError::NoAppeal(denial_id.into()))?;
        if a.resolution.is_some() {
            return Err(AppealError::AlreadyResolved(denial_id.into()));
        }
        a.resolution = Some(resolution);
        a.resolved_at_ms = Some(ts_ms);
        Ok(())
    }

    /// State at given moment.
    pub fn state(&self, denial_id: &str, now_ms: u64) -> AppealState {
        let Some(d) = self.denials.get(denial_id) else { return AppealState::NotFound; };
        let window_close = d.denied_at_ms.saturating_add(self.window_ms);
        match &d.appeal {
            None => {
                if now_ms > window_close { AppealState::WindowClosed }
                else { AppealState::Pending { window_close_ms: window_close } }
            }
            Some(a) => match a.resolution {
                None => AppealState::AppealPending,
                Some(Resolution::Granted) => AppealState::Granted,
                Some(Resolution::Sustained) => AppealState::Sustained,
            }
        }
    }

    /// Get.
    pub fn get(&self, denial_id: &str) -> Option<&Denial> {
        self.denials.get(denial_id)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AppealError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AppealError::SchemaMismatch); }
        for (id, d) in &self.denials {
            if id.is_empty() { return Err(AppealError::EmptyDenial); }
            if d.actor.is_empty() { return Err(AppealError::EmptyActor); }
            if let Some(a) = &d.appeal {
                if a.justification.is_empty() { return Err(AppealError::EmptyJustification); }
            }
        }
        Ok(())
    }
}

impl Default for DenialAppealWindow {
    fn default() -> Self { Self::new(86_400_000) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_in_window() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        match w.state("d1", 500) {
            AppealState::Pending { window_close_ms } => assert_eq!(window_close_ms, 1000),
            _ => panic!(),
        }
    }

    #[test]
    fn window_closed_after_expiry() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        assert_eq!(w.state("d1", 2000), AppealState::WindowClosed);
    }

    #[test]
    fn submit_within_window() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 500, "I think this was wrong").unwrap();
        assert_eq!(w.state("d1", 600), AppealState::AppealPending);
    }

    #[test]
    fn submit_outside_window_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        assert!(matches!(w.submit_appeal("d1", 2000, "x").unwrap_err(), AppealError::WindowExpired(_)));
    }

    #[test]
    fn double_appeal_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 100, "first").unwrap();
        assert!(matches!(w.submit_appeal("d1", 200, "second").unwrap_err(), AppealError::AlreadyAppealed(_)));
    }

    #[test]
    fn resolve_granted() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 100, "x").unwrap();
        w.resolve_appeal("d1", 200, Resolution::Granted).unwrap();
        assert_eq!(w.state("d1", 300), AppealState::Granted);
    }

    #[test]
    fn resolve_sustained() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 100, "x").unwrap();
        w.resolve_appeal("d1", 200, Resolution::Sustained).unwrap();
        assert_eq!(w.state("d1", 300), AppealState::Sustained);
    }

    #[test]
    fn double_resolve_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 100, "x").unwrap();
        w.resolve_appeal("d1", 200, Resolution::Granted).unwrap();
        assert!(matches!(w.resolve_appeal("d1", 300, Resolution::Sustained).unwrap_err(), AppealError::AlreadyResolved(_)));
    }

    #[test]
    fn resolve_without_appeal_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        assert!(matches!(w.resolve_appeal("d1", 200, Resolution::Granted).unwrap_err(), AppealError::NoAppeal(_)));
    }

    #[test]
    fn duplicate_denial_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        assert!(matches!(w.record_denial("d1", 0, "alice").unwrap_err(), AppealError::DuplicateDenial(_)));
    }

    #[test]
    fn not_found() {
        let w = DenialAppealWindow::new(1000);
        assert_eq!(w.state("d1", 0), AppealState::NotFound);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = DenialAppealWindow::new(1000);
        w.schema_version = "9.9.9".into();
        assert!(matches!(w.validate().unwrap_err(), AppealError::SchemaMismatch));
    }

    #[test]
    fn appeal_serde_roundtrip() {
        let mut w = DenialAppealWindow::new(1000);
        w.record_denial("d1", 0, "alice").unwrap();
        w.submit_appeal("d1", 100, "x").unwrap();
        w.resolve_appeal("d1", 200, Resolution::Granted).unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let back: DenialAppealWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
