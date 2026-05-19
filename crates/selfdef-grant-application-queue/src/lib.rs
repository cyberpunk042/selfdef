//! `selfdef-grant-application-queue` — pending grant requests FIFO.
//!
//! Each `Application` references a `TemplateId` from
//! `selfdef-grant-template-pack`, plus operator-supplied scope override,
//! justification, submitted_at, and a state (Pending / Approved /
//! Rejected). Transitions: Pending → Approved or Pending → Rejected;
//! no reverse.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grant_template_pack::TemplateId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppState {
    /// Pending operator review.
    Pending,
    /// Approved by operator.
    Approved,
    /// Rejected by operator.
    Rejected,
}

/// One application.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Application {
    /// Application id (unique within queue).
    pub app_id: String,
    /// Subject requesting the grant.
    pub subject: String,
    /// Template the application is based on.
    pub template: TemplateId,
    /// Optional scope override (empty = use template default).
    pub scope_override: String,
    /// Operator-readable justification.
    pub justification: String,
    /// ISO-8601 UTC.
    pub submitted_at: String,
    /// Current state.
    pub state: AppState,
    /// Operator MS003 fingerprint of approver/rejecter (empty while Pending).
    pub decided_by: String,
    /// ISO-8601 UTC of decision (empty while Pending).
    pub decided_at: String,
}

/// Queue envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationQueue {
    /// Schema version.
    pub schema_version: String,
    /// Applications.
    pub applications: Vec<Application>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum QueueError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty app_id.
    #[error("app_id empty")]
    EmptyAppId,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Empty justification.
    #[error("justification empty for {0}")]
    EmptyJustification(String),
    /// Duplicate app_id.
    #[error("duplicate app_id: {0}")]
    DuplicateAppId(String),
    /// Unknown app_id.
    #[error("unknown app_id: {0}")]
    Unknown(String),
    /// Illegal state transition.
    #[error("illegal transition: {0:?} -> {1:?}")]
    IllegalTransition(AppState, AppState),
}

impl ApplicationQueue {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            applications: Vec::new(),
        }
    }

    /// Submit an application.
    pub fn submit(&mut self, mut app: Application) -> Result<(), QueueError> {
        if app.app_id.is_empty() { return Err(QueueError::EmptyAppId); }
        if app.subject.is_empty() { return Err(QueueError::EmptySubject); }
        if app.justification.is_empty() {
            return Err(QueueError::EmptyJustification(app.app_id));
        }
        if self.applications.iter().any(|a| a.app_id == app.app_id) {
            return Err(QueueError::DuplicateAppId(app.app_id));
        }
        app.state = AppState::Pending;
        app.decided_by = String::new();
        app.decided_at = String::new();
        self.applications.push(app);
        Ok(())
    }

    /// Approve an application.
    pub fn approve(&mut self, app_id: &str, actor: &str, at: &str) -> Result<(), QueueError> {
        self.decide(app_id, AppState::Approved, actor, at)
    }

    /// Reject an application.
    pub fn reject(&mut self, app_id: &str, actor: &str, at: &str) -> Result<(), QueueError> {
        self.decide(app_id, AppState::Rejected, actor, at)
    }

    fn decide(&mut self, app_id: &str, target: AppState, actor: &str, at: &str) -> Result<(), QueueError> {
        let app = self.applications.iter_mut().find(|a| a.app_id == app_id)
            .ok_or_else(|| QueueError::Unknown(app_id.into()))?;
        if app.state != AppState::Pending {
            return Err(QueueError::IllegalTransition(app.state, target));
        }
        app.state = target;
        app.decided_by = actor.into();
        app.decided_at = at.into();
        Ok(())
    }

    /// All pending applications in submit order.
    pub fn pending(&self) -> Vec<&Application> {
        self.applications.iter().filter(|a| a.state == AppState::Pending).collect()
    }

    /// Lookup.
    pub fn get(&self, app_id: &str) -> Option<&Application> {
        self.applications.iter().find(|a| a.app_id == app_id)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), QueueError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(QueueError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for a in &self.applications {
            if a.app_id.is_empty() { return Err(QueueError::EmptyAppId); }
            if a.subject.is_empty() { return Err(QueueError::EmptySubject); }
            if a.justification.is_empty() {
                return Err(QueueError::EmptyJustification(a.app_id.clone()));
            }
            if !seen.insert(a.app_id.as_str()) {
                return Err(QueueError::DuplicateAppId(a.app_id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for ApplicationQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, subject: &str, template: TemplateId) -> Application {
        Application {
            app_id: id.into(),
            subject: subject.into(),
            template,
            scope_override: String::new(),
            justification: "needed for ship".into(),
            submitted_at: "2026-05-19T03:00:00Z".into(),
            state: AppState::Pending,
            decided_by: String::new(),
            decided_at: String::new(),
        }
    }

    #[test]
    fn empty_queue_validates() {
        ApplicationQueue::new().validate().unwrap();
    }

    #[test]
    fn submit_and_approve() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap();
        q.approve("a1", "op", "2026-05-19T03:01:00Z").unwrap();
        let a = q.get("a1").unwrap();
        assert_eq!(a.state, AppState::Approved);
        assert_eq!(a.decided_by, "op");
    }

    #[test]
    fn submit_and_reject() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::SandboxTier2)).unwrap();
        q.reject("a1", "op", "t").unwrap();
        assert_eq!(q.get("a1").unwrap().state, AppState::Rejected);
    }

    #[test]
    fn double_decide_rejected() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap();
        q.approve("a1", "op", "t").unwrap();
        let err = q.reject("a1", "op", "t").unwrap_err();
        assert!(matches!(err, QueueError::IllegalTransition(AppState::Approved, AppState::Rejected)));
    }

    #[test]
    fn duplicate_submit_rejected() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap();
        let err = q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap_err();
        assert!(matches!(err, QueueError::DuplicateAppId(_)));
    }

    #[test]
    fn unknown_app_rejected_on_decide() {
        let mut q = ApplicationQueue::new();
        let err = q.approve("none", "op", "t").unwrap_err();
        assert!(matches!(err, QueueError::Unknown(_)));
    }

    #[test]
    fn empty_app_id_rejected() {
        let mut q = ApplicationQueue::new();
        let err = q.submit(app("", "alice", TemplateId::ReadWorkspace)).unwrap_err();
        assert!(matches!(err, QueueError::EmptyAppId));
    }

    #[test]
    fn empty_subject_rejected() {
        let mut q = ApplicationQueue::new();
        let err = q.submit(app("a1", "", TemplateId::ReadWorkspace)).unwrap_err();
        assert!(matches!(err, QueueError::EmptySubject));
    }

    #[test]
    fn empty_justification_rejected() {
        let mut q = ApplicationQueue::new();
        let mut a = app("a1", "alice", TemplateId::ReadWorkspace);
        a.justification = String::new();
        let err = q.submit(a).unwrap_err();
        assert!(matches!(err, QueueError::EmptyJustification(_)));
    }

    #[test]
    fn pending_returns_only_pending() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap();
        q.submit(app("a2", "alice", TemplateId::ReadWorkspace)).unwrap();
        q.submit(app("a3", "alice", TemplateId::ReadWorkspace)).unwrap();
        q.approve("a2", "op", "t").unwrap();
        let v = q.pending();
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|a| a.app_id == "a1"));
        assert!(v.iter().any(|a| a.app_id == "a3"));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = ApplicationQueue::new();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), QueueError::SchemaMismatch));
    }

    #[test]
    fn state_serde_kebab() {
        assert_eq!(serde_json::to_string(&AppState::Pending).unwrap(), "\"pending\"");
        assert_eq!(serde_json::to_string(&AppState::Approved).unwrap(), "\"approved\"");
        assert_eq!(serde_json::to_string(&AppState::Rejected).unwrap(), "\"rejected\"");
    }

    #[test]
    fn queue_serde_roundtrip() {
        let mut q = ApplicationQueue::new();
        q.submit(app("a1", "alice", TemplateId::ReadWorkspace)).unwrap();
        let j = serde_json::to_string(&q).unwrap();
        let back: ApplicationQueue = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
