//! `selfdef-incident-record` — incident lifecycle.
//!
//! Lifecycle: Open → Triaged → Mitigated → Resolved →
//! PostmortemPending (terminal until postmortem filed).
//! Transitions are strictly forward except `reopen()` which moves
//! back to Triaged from Resolved or PostmortemPending.
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
    /// Open.
    Open,
    /// Triaged.
    Triaged,
    /// Mitigated.
    Mitigated,
    /// Resolved.
    Resolved,
    /// Postmortem pending (final stage; clears once postmortem filed).
    PostmortemPending,
}

/// One incident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    /// Id.
    pub id: String,
    /// Title.
    pub title: String,
    /// Opened.
    pub opened_at_ms: u64,
    /// Current stage.
    pub stage: Stage,
    /// Stage history.
    pub stage_log: Vec<(Stage, u64)>,
    /// Resolved at (None if not yet).
    pub resolved_at_ms: Option<u64>,
    /// Postmortem doc id (set when filed).
    pub postmortem_id: Option<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentRecord {
    /// Schema version.
    pub schema_version: String,
    /// id → incident.
    pub incidents: BTreeMap<String, Incident>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IncidentError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("title empty")]
    EmptyTitle,
    /// Empty.
    #[error("postmortem id empty")]
    EmptyPostmortem,
    /// Duplicate.
    #[error("duplicate incident id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown incident: {0}")]
    UnknownIncident(String),
    /// Invalid transition.
    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// from.
        from: Stage,
        /// to.
        to: Stage,
    },
}

fn forward_ok(from: Stage, to: Stage) -> bool {
    use Stage::*;
    matches!(
        (from, to),
        (Open, Triaged)
            | (Triaged, Mitigated)
            | (Mitigated, Resolved)
            | (Resolved, PostmortemPending)
    )
}

impl IncidentRecord {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            incidents: BTreeMap::new(),
        }
    }

    /// Open new incident.
    pub fn open(&mut self, id: &str, title: &str, ts_ms: u64) -> Result<(), IncidentError> {
        if id.is_empty() {
            return Err(IncidentError::EmptyId);
        }
        if title.is_empty() {
            return Err(IncidentError::EmptyTitle);
        }
        if self.incidents.contains_key(id) {
            return Err(IncidentError::DuplicateId(id.into()));
        }
        self.incidents.insert(
            id.into(),
            Incident {
                id: id.into(),
                title: title.into(),
                opened_at_ms: ts_ms,
                stage: Stage::Open,
                stage_log: vec![(Stage::Open, ts_ms)],
                resolved_at_ms: None,
                postmortem_id: None,
            },
        );
        Ok(())
    }

    /// Transition forward.
    pub fn transition(&mut self, id: &str, to: Stage, ts_ms: u64) -> Result<(), IncidentError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| IncidentError::UnknownIncident(id.into()))?;
        if !forward_ok(inc.stage, to) {
            return Err(IncidentError::InvalidTransition {
                from: inc.stage,
                to,
            });
        }
        inc.stage = to;
        inc.stage_log.push((to, ts_ms));
        if to == Stage::Resolved {
            inc.resolved_at_ms = Some(ts_ms);
        }
        Ok(())
    }

    /// Reopen back to Triaged from Resolved or PostmortemPending.
    pub fn reopen(&mut self, id: &str, ts_ms: u64) -> Result<(), IncidentError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| IncidentError::UnknownIncident(id.into()))?;
        if !matches!(inc.stage, Stage::Resolved | Stage::PostmortemPending) {
            return Err(IncidentError::InvalidTransition {
                from: inc.stage,
                to: Stage::Triaged,
            });
        }
        inc.stage = Stage::Triaged;
        inc.stage_log.push((Stage::Triaged, ts_ms));
        inc.resolved_at_ms = None;
        // Postmortem reference preserved as historical context.
        Ok(())
    }

    /// File postmortem (must be in PostmortemPending).
    pub fn file_postmortem(&mut self, id: &str, postmortem_id: &str) -> Result<(), IncidentError> {
        if postmortem_id.is_empty() {
            return Err(IncidentError::EmptyPostmortem);
        }
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| IncidentError::UnknownIncident(id.into()))?;
        if inc.stage != Stage::PostmortemPending {
            return Err(IncidentError::InvalidTransition {
                from: inc.stage,
                to: Stage::PostmortemPending,
            });
        }
        inc.postmortem_id = Some(postmortem_id.into());
        Ok(())
    }

    /// Time-to-resolve (None if not resolved).
    pub fn ttr_ms(&self, id: &str) -> Option<u64> {
        let inc = self.incidents.get(id)?;
        let resolved = inc.resolved_at_ms?;
        Some(resolved.saturating_sub(inc.opened_at_ms))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IncidentError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IncidentError::SchemaMismatch);
        }
        for (id, inc) in &self.incidents {
            if id.is_empty() {
                return Err(IncidentError::EmptyId);
            }
            if inc.title.is_empty() {
                return Err(IncidentError::EmptyTitle);
            }
            if let Some(p) = &inc.postmortem_id {
                if p.is_empty() {
                    return Err(IncidentError::EmptyPostmortem);
                }
            }
        }
        Ok(())
    }
}

impl Default for IncidentRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_forward() {
        let mut r = IncidentRecord::new();
        r.open("i1", "Outage", 0).unwrap();
        r.transition("i1", Stage::Triaged, 100).unwrap();
        r.transition("i1", Stage::Mitigated, 200).unwrap();
        r.transition("i1", Stage::Resolved, 300).unwrap();
        r.transition("i1", Stage::PostmortemPending, 400).unwrap();
        assert_eq!(r.incidents["i1"].stage, Stage::PostmortemPending);
    }

    #[test]
    fn ttr_set_on_resolve() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        r.transition("i1", Stage::Triaged, 100).unwrap();
        r.transition("i1", Stage::Mitigated, 200).unwrap();
        r.transition("i1", Stage::Resolved, 300).unwrap();
        assert_eq!(r.ttr_ms("i1"), Some(300));
    }

    #[test]
    fn skip_forward_rejected() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        // Skip from Open straight to Mitigated.
        assert!(matches!(
            r.transition("i1", Stage::Mitigated, 100).unwrap_err(),
            IncidentError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn reopen_from_resolved() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        r.transition("i1", Stage::Triaged, 100).unwrap();
        r.transition("i1", Stage::Mitigated, 200).unwrap();
        r.transition("i1", Stage::Resolved, 300).unwrap();
        r.reopen("i1", 400).unwrap();
        assert_eq!(r.incidents["i1"].stage, Stage::Triaged);
        assert!(r.incidents["i1"].resolved_at_ms.is_none());
    }

    #[test]
    fn reopen_from_open_rejected() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        assert!(matches!(
            r.reopen("i1", 100).unwrap_err(),
            IncidentError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn postmortem_only_in_pending() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        assert!(matches!(
            r.file_postmortem("i1", "pm-1").unwrap_err(),
            IncidentError::InvalidTransition { .. }
        ));
        r.transition("i1", Stage::Triaged, 1).unwrap();
        r.transition("i1", Stage::Mitigated, 2).unwrap();
        r.transition("i1", Stage::Resolved, 3).unwrap();
        r.transition("i1", Stage::PostmortemPending, 4).unwrap();
        r.file_postmortem("i1", "pm-1").unwrap();
        assert_eq!(r.incidents["i1"].postmortem_id.as_deref(), Some("pm-1"));
    }

    #[test]
    fn stage_log_grows() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        r.transition("i1", Stage::Triaged, 100).unwrap();
        assert_eq!(r.incidents["i1"].stage_log.len(), 2);
    }

    #[test]
    fn duplicate_open_rejected() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        assert!(matches!(
            r.open("i1", "x", 0).unwrap_err(),
            IncidentError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = IncidentRecord::new();
        assert!(matches!(
            r.open("", "x", 0).unwrap_err(),
            IncidentError::EmptyId
        ));
        assert!(matches!(
            r.open("i", "", 0).unwrap_err(),
            IncidentError::EmptyTitle
        ));
        r.open("i", "x", 0).unwrap();
        assert!(matches!(
            r.file_postmortem("i", "").unwrap_err(),
            IncidentError::EmptyPostmortem
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = IncidentRecord::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            IncidentError::SchemaMismatch
        ));
    }

    #[test]
    fn incident_serde_roundtrip() {
        let mut r = IncidentRecord::new();
        r.open("i1", "x", 0).unwrap();
        r.transition("i1", Stage::Triaged, 100).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: IncidentRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
