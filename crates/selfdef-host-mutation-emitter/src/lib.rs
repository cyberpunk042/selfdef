//! `selfdef-host-mutation-emitter` — structured event for watched-path changes.
//!
//! For each fsnotify event the daemon's watcher detected, the emitter
//! produces a `HostMutationEvent` carrying (path, kind, owner, at,
//! trace_id). The bus broadcasts it; subscribers correlate against
//! their grant/decision history.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_host_watcher_channel::WatcherChannel;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Kind of mutation observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationKind {
    /// File or directory created.
    Created,
    /// Modified in place.
    Modified,
    /// Deleted.
    Deleted,
    /// Renamed (from another path).
    Renamed,
    /// Permissions / ACL changed.
    PermChanged,
}

/// One mutation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostMutationEvent {
    /// Schema version.
    pub schema_version: String,
    /// Path that changed.
    pub path: String,
    /// Owner subsystem (looked up from watcher channel).
    pub owner: String,
    /// Mutation kind.
    pub kind: MutationKind,
    /// ISO-8601 UTC.
    pub at: String,
    /// M049 trace_id.
    pub trace_id: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EmitterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Path not in watcher channel.
    #[error("path {0} not registered with any watcher")]
    UnknownPath(String),
    /// Empty timestamp.
    #[error("at missing")]
    MissingTimestamp,
    /// Empty trace_id.
    #[error("trace_id missing")]
    MissingTraceId,
}

/// Build a `HostMutationEvent` if the path is registered.
pub fn emit(
    channel: &WatcherChannel,
    path: &str,
    kind: MutationKind,
    at: &str,
    trace_id: &str,
) -> Result<HostMutationEvent, EmitterError> {
    if at.is_empty() {
        return Err(EmitterError::MissingTimestamp);
    }
    if trace_id.is_empty() {
        return Err(EmitterError::MissingTraceId);
    }
    let watcher = channel
        .get(path)
        .ok_or_else(|| EmitterError::UnknownPath(path.into()))?;
    Ok(HostMutationEvent {
        schema_version: SCHEMA_VERSION.into(),
        path: path.into(),
        owner: watcher.owner.clone(),
        kind,
        at: at.into(),
        trace_id: trace_id.into(),
    })
}

impl HostMutationEvent {
    /// Validate.
    pub fn validate(&self) -> Result<(), EmitterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EmitterError::SchemaMismatch);
        }
        if self.at.is_empty() {
            return Err(EmitterError::MissingTimestamp);
        }
        if self.trace_id.is_empty() {
            return Err(EmitterError::MissingTraceId);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_host_watcher_channel::{WatchKind, WatcherEntry};

    fn channel_with_one(path: &str, owner: &str) -> WatcherChannel {
        let mut c = WatcherChannel::new();
        c.register(WatcherEntry {
            path: path.into(),
            kind: WatchKind::File,
            recursive: false,
            owner: owner.into(),
        })
        .unwrap();
        c
    }

    #[test]
    fn emit_known_path() {
        let c = channel_with_one("/etc/x.toml", "policy-bus");
        let e = emit(
            &c,
            "/etc/x.toml",
            MutationKind::Modified,
            "2026-05-19T03:00:00Z",
            "tr-1",
        )
        .unwrap();
        assert_eq!(e.owner, "policy-bus");
        assert_eq!(e.kind, MutationKind::Modified);
        e.validate().unwrap();
    }

    #[test]
    fn emit_unknown_path_rejected() {
        let c = channel_with_one("/etc/x.toml", "p");
        let err = emit(&c, "/other", MutationKind::Modified, "t", "tr").unwrap_err();
        assert!(matches!(err, EmitterError::UnknownPath(_)));
    }

    #[test]
    fn missing_timestamp_rejected() {
        let c = channel_with_one("/etc/x.toml", "p");
        assert!(matches!(
            emit(&c, "/etc/x.toml", MutationKind::Modified, "", "tr").unwrap_err(),
            EmitterError::MissingTimestamp
        ));
    }

    #[test]
    fn missing_trace_id_rejected() {
        let c = channel_with_one("/etc/x.toml", "p");
        assert!(matches!(
            emit(&c, "/etc/x.toml", MutationKind::Modified, "t", "").unwrap_err(),
            EmitterError::MissingTraceId
        ));
    }

    #[test]
    fn validate_schema_drift_rejected() {
        let c = channel_with_one("/etc/x.toml", "p");
        let mut e = emit(&c, "/etc/x.toml", MutationKind::Modified, "t", "tr").unwrap();
        e.schema_version = "9.9.9".into();
        assert!(matches!(
            e.validate().unwrap_err(),
            EmitterError::SchemaMismatch
        ));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&MutationKind::Created).unwrap(),
            "\"created\""
        );
        assert_eq!(
            serde_json::to_string(&MutationKind::Modified).unwrap(),
            "\"modified\""
        );
        assert_eq!(
            serde_json::to_string(&MutationKind::Deleted).unwrap(),
            "\"deleted\""
        );
        assert_eq!(
            serde_json::to_string(&MutationKind::Renamed).unwrap(),
            "\"renamed\""
        );
        assert_eq!(
            serde_json::to_string(&MutationKind::PermChanged).unwrap(),
            "\"perm-changed\""
        );
    }

    #[test]
    fn event_serde_roundtrip() {
        let c = channel_with_one("/etc/x.toml", "p");
        let e = emit(&c, "/etc/x.toml", MutationKind::Created, "t", "tr").unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: HostMutationEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
