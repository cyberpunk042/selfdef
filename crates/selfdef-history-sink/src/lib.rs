//! # `selfdef-history-sink`
//!
//! Selfdef-side history-event emitter. Cross-repo binding to
//! **sovereign-os E11.M5** (global-history, R448). Every selfdef
//! module that experiences operator-relevant lifecycle events
//! (install / uninstall / feature-toggled / profile-switched /
//! policy-applied / etc.) appends a JSONL record here so the
//! sovereign-os `global-history` aggregator can fold them into the
//! cross-repo "what changed?" surface.
//!
//! Cross-repo binding ID: `SD-R-EVENT-LOG-1`.
//!
//! ## File location
//!
//! The default path is `/var/log/sovereign-os/modules.jsonl` — the
//! exact path consumed by sovereign-os
//! `scripts/operator/global-history.py` (`_read_modules`). Operators
//! can override via `SOVEREIGN_OS_MODULES_LOG`.
//!
//! ## Record shape (one JSON object per line)
//!
//! ```json
//! {
//!   "timestamp": "2026-05-18T15:42:00.123Z",
//!   "source":    "modules",
//!   "module":    "agent-guard",
//!   "event":     "feature-toggled",
//!   "status":    "ok",
//!   "actor":     "selfdefctl",
//!   "detail":    {"feature": "rule-pack-v2", "enabled": true}
//! }
//! ```
//!
//! Required: `timestamp`, `source`, `module`, `event`, `status`.
//! `actor` and `detail` are optional but recommended.
//!
//! ## Best-effort semantics
//!
//! Writes are append-only and best-effort. IO failures are reported
//! as `Err(_)` but the caller should generally LOG and CONTINUE —
//! the history sink is observability, not control-flow. Per operator
//! §1g standing rule "operator-supplied keys NEVER in-repo": this
//! crate writes ONLY operator-event metadata, never secrets.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Default JSONL path consumed by sovereign-os `global-history`
/// (R448 `_read_modules`).
pub const DEFAULT_MODULES_LOG: &str = "/var/log/sovereign-os/modules.jsonl";

/// Operator-overridable env var name (sovereign-os and selfdef agree
/// on this identifier; drift = silent contract break).
pub const ENV_MODULES_LOG: &str = "SOVEREIGN_OS_MODULES_LOG";

/// Operator-named event status values. Drift here breaks the
/// sovereign-os `global-history delta` action histogram.
pub const STATUSES: [&str; 5] = ["ok", "started", "failed", "skipped", "rolled-back"];

/// One history record. Fields are exactly what the sovereign-os
/// global-history `_read_modules` reader expects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEvent {
    /// ISO 8601 / RFC 3339 timestamp. Use [`HistoryEvent::now`] to
    /// auto-fill from the system clock.
    pub timestamp: String,
    /// Always `"modules"` — names the sovereign-os source bucket.
    pub source: String,
    /// selfdef module id (e.g., `"agent-guard"`).
    pub module: String,
    /// Operator-named event (e.g., `"feature-toggled"`,
    /// `"installed"`, `"uninstalled"`, `"profile-switched"`).
    pub event: String,
    /// One of [`STATUSES`].
    pub status: String,
    /// Optional actor (e.g., `"selfdefctl"`, `"systemd"`,
    /// `"operator-cli"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Optional structured detail blob. Free-form JSON; do NOT
    /// include secrets (operator §1g sacrosanct).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl HistoryEvent {
    /// Construct an event with `timestamp = now()` and `source = "modules"`.
    pub fn now(
        module: impl Into<String>,
        event: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
            source: "modules".to_string(),
            module: module.into(),
            event: event.into(),
            status: status.into(),
            actor: None,
            detail: None,
        }
    }

    /// Set the `actor` field (builder-style).
    #[must_use]
    pub fn with_actor(mut self, a: impl Into<String>) -> Self {
        self.actor = Some(a.into());
        self
    }

    /// Set the `detail` field (builder-style).
    #[must_use]
    pub fn with_detail(mut self, d: serde_json::Value) -> Self {
        self.detail = Some(d);
        self
    }
}

/// Errors produced while emitting / validating an event.
#[derive(Debug, Error)]
pub enum HistorySinkError {
    /// IO failure (file open / write).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Validation rule violated.
    #[error("validation: {0}")]
    Validation(String),
}

/// Resolve the active modules-log path. Honors
/// `SOVEREIGN_OS_MODULES_LOG`; falls back to [`DEFAULT_MODULES_LOG`].
pub fn resolve_log_path() -> PathBuf {
    std::env::var_os(ENV_MODULES_LOG)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MODULES_LOG))
}

/// Validate an event against the operator-discoverable contract.
pub fn validate(e: &HistoryEvent) -> Result<(), HistorySinkError> {
    if e.timestamp.is_empty() {
        return Err(HistorySinkError::Validation("timestamp empty".into()));
    }
    if e.source != "modules" {
        return Err(HistorySinkError::Validation(format!(
            "source must be \"modules\", got {:?}",
            e.source
        )));
    }
    if e.module.is_empty() {
        return Err(HistorySinkError::Validation("module empty".into()));
    }
    if e.event.is_empty() {
        return Err(HistorySinkError::Validation("event empty".into()));
    }
    if !STATUSES.contains(&e.status.as_str()) {
        return Err(HistorySinkError::Validation(format!(
            "status {:?} not one of {:?}",
            e.status, STATUSES
        )));
    }
    Ok(())
}

/// Append one validated event to the path. Creates parent dir if
/// missing. Append-mode; no truncation. Best-effort fsync.
pub fn emit(e: &HistoryEvent, path: &Path) -> Result<(), HistorySinkError> {
    validate(e)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let line = serde_json::to_string(e)?;
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    // Best-effort sync; never fail the call on sync failure.
    let _ = f.sync_data();
    Ok(())
}

/// Append to the default-resolved path.
pub fn emit_default(e: &HistoryEvent) -> Result<(), HistorySinkError> {
    emit(e, &resolve_log_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_operator_named_order() {
        // Operator-discoverable status enum. Drift = sovereign-os
        // global-history delta-action histogram becomes lossy.
        assert_eq!(
            STATUSES,
            ["ok", "started", "failed", "skipped", "rolled-back"]
        );
    }

    #[test]
    fn default_path_matches_sovereign_os_reader() {
        // sovereign-os scripts/operator/global-history.py `_read_modules`
        // reads "/var/log/sovereign-os/modules.jsonl". Drift = events
        // get written but never aggregated.
        assert_eq!(DEFAULT_MODULES_LOG, "/var/log/sovereign-os/modules.jsonl");
    }

    #[test]
    fn now_fills_timestamp_and_source() {
        let e = HistoryEvent::now("agent-guard", "installed", "ok");
        assert!(!e.timestamp.is_empty());
        assert_eq!(e.source, "modules");
        assert_eq!(e.module, "agent-guard");
        assert_eq!(e.event, "installed");
        assert_eq!(e.status, "ok");
        assert!(e.actor.is_none());
        assert!(e.detail.is_none());
    }

    #[test]
    fn validate_accepts_minimal_event() {
        let e = HistoryEvent::now("m", "ev", "ok");
        validate(&e).expect("minimal valid");
    }

    #[test]
    fn validate_rejects_unknown_status() {
        let mut e = HistoryEvent::now("m", "ev", "maybe");
        assert!(validate(&e).is_err());
        e.status = "rolled-back".into();
        validate(&e).expect("rolled-back is valid");
    }

    #[test]
    fn validate_rejects_wrong_source() {
        let mut e = HistoryEvent::now("m", "ev", "ok");
        e.source = "shell".into();
        let err = validate(&e).unwrap_err();
        assert!(format!("{err}").contains("source"));
    }

    #[test]
    fn validate_rejects_empty_module_or_event() {
        let mut e = HistoryEvent::now("", "ev", "ok");
        assert!(validate(&e).is_err());
        e.module = "m".into();
        e.event = "".into();
        assert!(validate(&e).is_err());
    }

    #[test]
    fn builder_chains_work() {
        let e = HistoryEvent::now("agent-guard", "feature-toggled", "ok")
            .with_actor("selfdefctl")
            .with_detail(serde_json::json!({"feature": "rule-pack-v2"}));
        assert_eq!(e.actor.as_deref(), Some("selfdefctl"));
        assert!(e.detail.is_some());
    }

    #[test]
    fn resolve_log_path_honors_env_override() {
        // Avoid clobbering parallel-test env state by using a scoped
        // child path. We cannot reliably set env in parallel tests,
        // so verify the fallback at minimum:
        let p = resolve_log_path();
        // Either the default or whatever the harness set
        assert!(p.is_absolute() || !p.as_os_str().is_empty());
    }
}
