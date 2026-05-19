//! `selfdef-replay-source-authority` — IPS gate for Replay mode entry.
//!
//! Before the daemon enters `ExecutionMode::Replay`, the operator must
//! present a `ReplaySource` declaration the IPS authority validates:
//!
//! - non-empty operator MS003 signature
//! - non-empty trace_id
//! - non-empty path (absolute, ending in `.jsonl`)
//! - declared source kind matches per-kind invariants (e.g. canary kind
//!   requires `canary_id` field)
//!
//! Approved sources are entered into a registry the daemon hands to
//! the replay subsystem; rejected sources block mode entry.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 3 canonical replay source kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Live capture (events recorded from production).
    LiveCapture,
    /// Synthetic canary (operator-fabricated test fixture).
    SyntheticCanary,
    /// Archived history (older live capture pulled from cold storage).
    ArchivedHistory,
}

/// One replay source declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaySource {
    /// Operator-readable label.
    pub label: String,
    /// Absolute JSONL path.
    pub path: String,
    /// Source kind.
    pub kind: SourceKind,
    /// M049 trace_id binding the replay session to its origin.
    pub trace_id: String,
    /// Canary id (only for SyntheticCanary; empty otherwise).
    pub canary_id: String,
    /// ISO-8601 UTC original capture window start.
    pub captured_from: String,
    /// ISO-8601 UTC original capture window end.
    pub captured_to: String,
    /// MS003 signature over canonical-JSON (non-empty when authorized).
    pub signature: String,
}

/// Approved-sources registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovedSources {
    /// Schema version.
    pub schema_version: String,
    /// Approved sources.
    pub sources: Vec<ReplaySource>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReplaySourceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty label.
    #[error("source label empty")]
    EmptyLabel,
    /// Empty path.
    #[error("source path empty")]
    EmptyPath,
    /// Path not absolute.
    #[error("source path {0} not absolute")]
    NotAbsolute(String),
    /// Path not JSONL.
    #[error("source path {0} not .jsonl")]
    NotJsonl(String),
    /// Empty trace_id.
    #[error("trace_id missing")]
    MissingTraceId,
    /// Unsigned.
    #[error("source {0} unsigned")]
    Unsigned(String),
    /// Window timestamps inverted.
    #[error("captured_to {to} precedes captured_from {from}")]
    WindowInverted {
        /// from.
        from: String,
        /// to.
        to: String,
    },
    /// Missing canary_id when kind is SyntheticCanary.
    #[error("synthetic-canary kind requires canary_id")]
    CanaryIdMissing,
    /// Stray canary_id on non-canary kind.
    #[error("canary_id should be empty for kind {0:?}")]
    StrayCanaryId(SourceKind),
}

/// Authority check.
pub fn approve(source: &ReplaySource) -> Result<(), ReplaySourceError> {
    if source.label.is_empty() { return Err(ReplaySourceError::EmptyLabel); }
    if source.path.is_empty() { return Err(ReplaySourceError::EmptyPath); }
    if !source.path.starts_with('/') {
        return Err(ReplaySourceError::NotAbsolute(source.path.clone()));
    }
    if !source.path.ends_with(".jsonl") {
        return Err(ReplaySourceError::NotJsonl(source.path.clone()));
    }
    if source.trace_id.is_empty() { return Err(ReplaySourceError::MissingTraceId); }
    if source.signature.is_empty() { return Err(ReplaySourceError::Unsigned(source.label.clone())); }
    if !source.captured_from.is_empty() && !source.captured_to.is_empty()
        && source.captured_to < source.captured_from
    {
        return Err(ReplaySourceError::WindowInverted {
            from: source.captured_from.clone(),
            to: source.captured_to.clone(),
        });
    }
    match source.kind {
        SourceKind::SyntheticCanary => {
            if source.canary_id.is_empty() {
                return Err(ReplaySourceError::CanaryIdMissing);
            }
        }
        other => {
            if !source.canary_id.is_empty() {
                return Err(ReplaySourceError::StrayCanaryId(other));
            }
        }
    }
    Ok(())
}

impl ApprovedSources {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            sources: Vec::new(),
        }
    }

    /// Authorize + admit a source.
    pub fn admit(&mut self, source: ReplaySource) -> Result<(), ReplaySourceError> {
        approve(&source)?;
        self.sources.push(source);
        Ok(())
    }

    /// Validate the registry.
    pub fn validate(&self) -> Result<(), ReplaySourceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReplaySourceError::SchemaMismatch);
        }
        for s in &self.sources {
            approve(s)?;
        }
        Ok(())
    }
}

impl Default for ApprovedSources {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_source(kind: SourceKind) -> ReplaySource {
        ReplaySource {
            label: "morning capture".into(),
            path: "/var/lib/selfdef/replay/2026-05-19.jsonl".into(),
            kind,
            trace_id: "tr-1".into(),
            canary_id: if kind == SourceKind::SyntheticCanary { "canary-007".into() } else { String::new() },
            captured_from: "2026-05-19T01:00:00Z".into(),
            captured_to: "2026-05-19T02:00:00Z".into(),
            signature: "ms003-hex".into(),
        }
    }

    #[test]
    fn ok_live_capture_approves() {
        approve(&ok_source(SourceKind::LiveCapture)).unwrap();
    }

    #[test]
    fn ok_synthetic_canary_approves() {
        approve(&ok_source(SourceKind::SyntheticCanary)).unwrap();
    }

    #[test]
    fn empty_label_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.label = String::new();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::EmptyLabel));
    }

    #[test]
    fn non_absolute_path_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.path = "relative/x.jsonl".into();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::NotAbsolute(_)));
    }

    #[test]
    fn non_jsonl_path_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.path = "/var/replay.txt".into();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::NotJsonl(_)));
    }

    #[test]
    fn unsigned_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.signature = String::new();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::Unsigned(_)));
    }

    #[test]
    fn empty_trace_id_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.trace_id = String::new();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::MissingTraceId));
    }

    #[test]
    fn window_inverted_rejected() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.captured_from = "2026-05-19T05:00:00Z".into();
        s.captured_to = "2026-05-19T01:00:00Z".into();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::WindowInverted { .. }));
    }

    #[test]
    fn canary_id_required_for_canary_kind() {
        let mut s = ok_source(SourceKind::SyntheticCanary);
        s.canary_id = String::new();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::CanaryIdMissing));
    }

    #[test]
    fn canary_id_forbidden_on_non_canary_kind() {
        let mut s = ok_source(SourceKind::LiveCapture);
        s.canary_id = "canary-007".into();
        assert!(matches!(approve(&s).unwrap_err(), ReplaySourceError::StrayCanaryId(SourceKind::LiveCapture)));
    }

    #[test]
    fn admit_appends() {
        let mut r = ApprovedSources::new();
        r.admit(ok_source(SourceKind::LiveCapture)).unwrap();
        r.admit(ok_source(SourceKind::ArchivedHistory)).unwrap();
        assert_eq!(r.sources.len(), 2);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ApprovedSources::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), ReplaySourceError::SchemaMismatch));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(serde_json::to_string(&SourceKind::LiveCapture).unwrap(), "\"live-capture\"");
        assert_eq!(serde_json::to_string(&SourceKind::SyntheticCanary).unwrap(), "\"synthetic-canary\"");
        assert_eq!(serde_json::to_string(&SourceKind::ArchivedHistory).unwrap(), "\"archived-history\"");
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = ApprovedSources::new();
        r.admit(ok_source(SourceKind::LiveCapture)).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ApprovedSources = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
