//! `selfdef-policy-change-window` — policy-change freezes.
//!
//! Each window has a name, an `[open_ms, close_ms)` time range, an
//! optional `scope` (policy-id allowlist; empty = global), and a
//! `severity` (`Soft` warns, `Hard` blocks). `decide(policy_id,
//! now_ms)` returns:
//!   * `Permit` — no active window applies.
//!   * `SoftBlock { window }` — soft window active (caller may
//!     proceed with an explicit override).
//!   * `HardBlock { window }` — hard window active.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Severity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Warn only.
    Soft,
    /// Block.
    Hard,
}

/// One window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    /// Name.
    pub name: String,
    /// Inclusive start.
    pub open_ms: u64,
    /// Exclusive end.
    pub close_ms: u64,
    /// Scope (policy ids); empty = global.
    pub scope: Vec<String>,
    /// Severity.
    pub severity: Severity,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyChangeWindow {
    /// Schema version.
    pub schema_version: String,
    /// name → window.
    pub windows: BTreeMap<String, Window>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ChangeVerdict {
    /// Permit.
    Permit,
    /// Soft block.
    SoftBlock {
        /// Window name.
        window: String,
    },
    /// Hard block.
    HardBlock {
        /// Window name.
        window: String,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum WindowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty name.
    #[error("window name empty")]
    EmptyName,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyPolicy,
    /// Inverted range.
    #[error("close ({close}) must be > open ({open})")]
    InvertedRange {
        /// open.
        open: u64,
        /// close.
        close: u64,
    },
    /// Unknown window.
    #[error("unknown window: {0}")]
    UnknownWindow(String),
}

impl Window {
    /// Is `now_ms` inside `[open_ms, close_ms)`?
    pub fn covers(&self, now_ms: u64) -> bool {
        now_ms >= self.open_ms && now_ms < self.close_ms
    }

    /// Does this window apply to this policy id?
    pub fn applies_to(&self, policy_id: &str) -> bool {
        self.scope.is_empty() || self.scope.iter().any(|s| s == policy_id)
    }
}

impl PolicyChangeWindow {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            windows: BTreeMap::new(),
        }
    }

    /// Add.
    pub fn add(&mut self, w: Window) -> Result<(), WindowError> {
        if w.name.is_empty() {
            return Err(WindowError::EmptyName);
        }
        if w.close_ms <= w.open_ms {
            return Err(WindowError::InvertedRange {
                open: w.open_ms,
                close: w.close_ms,
            });
        }
        self.windows.insert(w.name.clone(), w);
        Ok(())
    }

    /// Remove.
    pub fn remove(&mut self, name: &str) -> bool {
        self.windows.remove(name).is_some()
    }

    /// Decide. Hard beats Soft beats Permit.
    pub fn decide(&self, policy_id: &str, now_ms: u64) -> ChangeVerdict {
        let mut soft: Option<String> = None;
        for w in self.windows.values() {
            if !w.covers(now_ms) {
                continue;
            }
            if !w.applies_to(policy_id) {
                continue;
            }
            match w.severity {
                Severity::Hard => {
                    return ChangeVerdict::HardBlock {
                        window: w.name.clone(),
                    };
                }
                Severity::Soft => {
                    if soft.is_none() {
                        soft = Some(w.name.clone());
                    }
                }
            }
        }
        match soft {
            Some(name) => ChangeVerdict::SoftBlock { window: name },
            None => ChangeVerdict::Permit,
        }
    }

    /// All windows currently active for a policy id.
    pub fn active_for(&self, policy_id: &str, now_ms: u64) -> Vec<Window> {
        self.windows
            .values()
            .filter(|w| w.covers(now_ms) && w.applies_to(policy_id))
            .cloned()
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WindowError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WindowError::SchemaMismatch);
        }
        for (name, w) in &self.windows {
            if name.is_empty() {
                return Err(WindowError::EmptyName);
            }
            if w.close_ms <= w.open_ms {
                return Err(WindowError::InvertedRange {
                    open: w.open_ms,
                    close: w.close_ms,
                });
            }
            for p in &w.scope {
                if p.is_empty() {
                    return Err(WindowError::EmptyPolicy);
                }
            }
        }
        Ok(())
    }
}

impl Default for PolicyChangeWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(name: &str, open: u64, close: u64, sev: Severity, scope: &[&str]) -> Window {
        Window {
            name: name.into(),
            open_ms: open,
            close_ms: close,
            scope: scope.iter().map(|s| (*s).into()).collect(),
            severity: sev,
        }
    }

    #[test]
    fn permit_outside_windows() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("freeze", 1000, 2000, Severity::Hard, &[])).unwrap();
        assert_eq!(c.decide("p1", 500), ChangeVerdict::Permit);
        assert_eq!(c.decide("p1", 2500), ChangeVerdict::Permit);
    }

    #[test]
    fn hard_block_inside_window() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("freeze", 1000, 2000, Severity::Hard, &[])).unwrap();
        match c.decide("p1", 1500) {
            ChangeVerdict::HardBlock { window } => assert_eq!(window, "freeze"),
            _ => panic!(),
        }
    }

    #[test]
    fn soft_block_inside_window() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("caution", 1000, 2000, Severity::Soft, &[]))
            .unwrap();
        match c.decide("p1", 1500) {
            ChangeVerdict::SoftBlock { window } => assert_eq!(window, "caution"),
            _ => panic!(),
        }
    }

    #[test]
    fn hard_beats_soft_when_both_active() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("soft", 0, 5000, Severity::Soft, &[])).unwrap();
        c.add(w("hard", 1000, 2000, Severity::Hard, &[])).unwrap();
        assert!(matches!(
            c.decide("p1", 1500),
            ChangeVerdict::HardBlock { .. }
        ));
    }

    #[test]
    fn scope_filters() {
        let mut c = PolicyChangeWindow::new();
        c.add(w(
            "freeze-routing",
            1000,
            2000,
            Severity::Hard,
            &["routing"],
        ))
        .unwrap();
        // Different policy id — permitted.
        assert_eq!(c.decide("billing", 1500), ChangeVerdict::Permit);
        // Same policy id — blocked.
        assert!(matches!(
            c.decide("routing", 1500),
            ChangeVerdict::HardBlock { .. }
        ));
    }

    #[test]
    fn close_is_exclusive() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("freeze", 1000, 2000, Severity::Hard, &[])).unwrap();
        // Right at close — outside.
        assert_eq!(c.decide("p1", 2000), ChangeVerdict::Permit);
    }

    #[test]
    fn open_is_inclusive() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("freeze", 1000, 2000, Severity::Hard, &[])).unwrap();
        assert!(matches!(
            c.decide("p1", 1000),
            ChangeVerdict::HardBlock { .. }
        ));
    }

    #[test]
    fn active_for_lists() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("a", 0, 100, Severity::Soft, &[])).unwrap();
        c.add(w("b", 50, 200, Severity::Hard, &[])).unwrap();
        let a = c.active_for("p", 75);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn inverted_range_rejected() {
        let mut c = PolicyChangeWindow::new();
        assert!(matches!(
            c.add(w("x", 2000, 1000, Severity::Hard, &[])).unwrap_err(),
            WindowError::InvertedRange { .. }
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let mut c = PolicyChangeWindow::new();
        assert!(matches!(
            c.add(w("", 0, 1, Severity::Hard, &[])).unwrap_err(),
            WindowError::EmptyName
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PolicyChangeWindow::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            WindowError::SchemaMismatch
        ));
    }

    #[test]
    fn window_serde_roundtrip() {
        let mut c = PolicyChangeWindow::new();
        c.add(w("freeze", 1000, 2000, Severity::Hard, &["p"]))
            .unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: PolicyChangeWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
