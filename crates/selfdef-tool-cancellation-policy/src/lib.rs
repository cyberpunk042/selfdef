//! `selfdef-tool-cancellation-policy` — per-tool cancel gate.
//!
//! CancelMode {Never, SafeOnly, Anytime}. ExecPhase {Prepare,
//! Streaming, Commit, Finalize}. cancel(tool, phase) returns Allow /
//! Denied (with reason class).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Cancel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancelMode {
    /// Never cancellable (atomic).
    Never,
    /// Cancellable only in safe phases (Prepare).
    SafeOnly,
    /// Cancellable in any phase.
    Anytime,
}

/// Execution phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecPhase {
    /// Prepare (no side effects yet).
    Prepare,
    /// Streaming (output in flight).
    Streaming,
    /// Commit (writing).
    Commit,
    /// Finalize (cleanup).
    Finalize,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CancelDecision {
    /// Allow.
    Allow,
    /// Tool refuses to be cancelled at all.
    DeniedTool,
    /// Phase too unsafe to cancel.
    DeniedPhase,
    /// Unknown tool.
    DeniedUnknown,
}

/// One tool's policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCancelPolicy {
    /// Stable tool id.
    pub tool_id: String,
    /// Cancel mode.
    pub mode: CancelMode,
}

/// Registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCancellationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Tools.
    pub tools: Vec<ToolCancelPolicy>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CancelError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("tool id empty")]
    EmptyToolId,
    /// Duplicate.
    #[error("duplicate tool id: {0}")]
    DuplicateToolId(String),
}

impl ToolCancellationPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tools: Vec::new(),
        }
    }

    /// Register a tool with its CancelMode.
    pub fn register(&mut self, tool_id: &str, mode: CancelMode) -> Result<(), CancelError> {
        if tool_id.is_empty() { return Err(CancelError::EmptyToolId); }
        if self.tools.iter().any(|t| t.tool_id == tool_id) {
            return Err(CancelError::DuplicateToolId(tool_id.into()));
        }
        self.tools.push(ToolCancelPolicy { tool_id: tool_id.into(), mode });
        Ok(())
    }

    /// Decide.
    pub fn cancel(&self, tool_id: &str, phase: ExecPhase) -> CancelDecision {
        let t = match self.tools.iter().find(|t| t.tool_id == tool_id) {
            Some(t) => t,
            None => return CancelDecision::DeniedUnknown,
        };
        match t.mode {
            CancelMode::Never => CancelDecision::DeniedTool,
            CancelMode::Anytime => CancelDecision::Allow,
            CancelMode::SafeOnly => {
                if phase == ExecPhase::Prepare { CancelDecision::Allow } else { CancelDecision::DeniedPhase }
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CancelError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CancelError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for t in &self.tools {
            if t.tool_id.is_empty() { return Err(CancelError::EmptyToolId); }
            if !seen.insert(t.tool_id.as_str()) {
                return Err(CancelError::DuplicateToolId(t.tool_id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for ToolCancellationPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tool_denied() {
        let p = ToolCancellationPolicy::new();
        assert_eq!(p.cancel("ghost", ExecPhase::Prepare), CancelDecision::DeniedUnknown);
    }

    #[test]
    fn never_always_denied() {
        let mut p = ToolCancellationPolicy::new();
        p.register("commit", CancelMode::Never).unwrap();
        for ph in [ExecPhase::Prepare, ExecPhase::Streaming, ExecPhase::Commit, ExecPhase::Finalize] {
            assert_eq!(p.cancel("commit", ph), CancelDecision::DeniedTool);
        }
    }

    #[test]
    fn anytime_always_allow() {
        let mut p = ToolCancellationPolicy::new();
        p.register("search", CancelMode::Anytime).unwrap();
        for ph in [ExecPhase::Prepare, ExecPhase::Streaming, ExecPhase::Commit, ExecPhase::Finalize] {
            assert_eq!(p.cancel("search", ph), CancelDecision::Allow);
        }
    }

    #[test]
    fn safe_only_prepare_ok_rest_denied() {
        let mut p = ToolCancellationPolicy::new();
        p.register("upload", CancelMode::SafeOnly).unwrap();
        assert_eq!(p.cancel("upload", ExecPhase::Prepare), CancelDecision::Allow);
        assert_eq!(p.cancel("upload", ExecPhase::Streaming), CancelDecision::DeniedPhase);
        assert_eq!(p.cancel("upload", ExecPhase::Commit), CancelDecision::DeniedPhase);
    }

    #[test]
    fn duplicate_rejected() {
        let mut p = ToolCancellationPolicy::new();
        p.register("a", CancelMode::Never).unwrap();
        assert!(matches!(p.register("a", CancelMode::Anytime).unwrap_err(), CancelError::DuplicateToolId(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = ToolCancellationPolicy::new();
        assert!(matches!(p.register("", CancelMode::Never).unwrap_err(), CancelError::EmptyToolId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ToolCancellationPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), CancelError::SchemaMismatch));
    }

    #[test]
    fn mode_serde_kebab() {
        assert_eq!(serde_json::to_string(&CancelMode::SafeOnly).unwrap(), "\"safe-only\"");
    }

    #[test]
    fn phase_serde_kebab() {
        assert_eq!(serde_json::to_string(&ExecPhase::Streaming).unwrap(), "\"streaming\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = ToolCancellationPolicy::new();
        p.register("a", CancelMode::SafeOnly).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ToolCancellationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
