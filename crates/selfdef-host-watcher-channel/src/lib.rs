//! `selfdef-host-watcher-channel` — registry of host paths/sockets watched.
//!
//! Each `WatcherEntry` declares (path, kind, recursive, owner). The
//! daemon (or eBPF helper) attaches fsnotify watches and emits one
//! `HostMutation` event per detected change.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// What is being watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchKind {
    /// Regular file.
    File,
    /// Directory (recursive flag separate).
    Directory,
    /// Unix socket.
    UnixSocket,
    /// FIFO.
    Fifo,
}

/// Per-watcher entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherEntry {
    /// Absolute path or socket address.
    pub path: String,
    /// Kind.
    pub kind: WatchKind,
    /// Recursive (only meaningful for Directory).
    pub recursive: bool,
    /// Owning subsystem ("policy-bus", "audit-log", …).
    pub owner: String,
}

/// Mutation event the channel emits when a watched path changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostMutation {
    /// Path that changed.
    pub path: String,
    /// Owner subsystem.
    pub owner: String,
    /// "created" / "modified" / "deleted" / "renamed".
    pub event: String,
    /// ISO-8601 UTC.
    pub at: String,
}

/// Channel envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherChannel {
    /// Schema version.
    pub schema_version: String,
    /// Watchers.
    pub watchers: Vec<WatcherEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WatcherError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty path.
    #[error("watcher path empty")]
    EmptyPath,
    /// Non-absolute path on a File/Directory watcher.
    #[error("non-absolute path: {0}")]
    NotAbsolute(String),
    /// Recursive set on a non-Directory watcher.
    #[error("recursive=true only valid on Directory; got {kind:?} for {path}")]
    RecursiveOnNonDir {
        /// path.
        path: String,
        /// kind.
        kind: WatchKind,
    },
    /// Empty owner.
    #[error("watcher {0} owner empty")]
    EmptyOwner(String),
    /// Duplicate.
    #[error("duplicate watcher path: {0}")]
    DuplicatePath(String),
}

impl WatcherChannel {
    /// New empty channel.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            watchers: Vec::new(),
        }
    }

    /// Register a watcher.
    pub fn register(&mut self, w: WatcherEntry) -> Result<(), WatcherError> {
        if w.path.is_empty() { return Err(WatcherError::EmptyPath); }
        if matches!(w.kind, WatchKind::File | WatchKind::Directory) && !w.path.starts_with('/') {
            return Err(WatcherError::NotAbsolute(w.path));
        }
        if w.recursive && w.kind != WatchKind::Directory {
            return Err(WatcherError::RecursiveOnNonDir { path: w.path, kind: w.kind });
        }
        if w.owner.is_empty() { return Err(WatcherError::EmptyOwner(w.path)); }
        if self.watchers.iter().any(|x| x.path == w.path) {
            return Err(WatcherError::DuplicatePath(w.path));
        }
        self.watchers.push(w);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WatcherError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WatcherError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for w in &self.watchers {
            if w.path.is_empty() { return Err(WatcherError::EmptyPath); }
            if matches!(w.kind, WatchKind::File | WatchKind::Directory) && !w.path.starts_with('/') {
                return Err(WatcherError::NotAbsolute(w.path.clone()));
            }
            if w.recursive && w.kind != WatchKind::Directory {
                return Err(WatcherError::RecursiveOnNonDir { path: w.path.clone(), kind: w.kind });
            }
            if w.owner.is_empty() { return Err(WatcherError::EmptyOwner(w.path.clone())); }
            if !seen.insert(w.path.as_str()) {
                return Err(WatcherError::DuplicatePath(w.path.clone()));
            }
        }
        Ok(())
    }

    /// Lookup by path.
    pub fn get(&self, path: &str) -> Option<&WatcherEntry> {
        self.watchers.iter().find(|w| w.path == path)
    }

    /// All watchers owned by a subsystem.
    pub fn owned_by(&self, owner: &str) -> Vec<&WatcherEntry> {
        self.watchers.iter().filter(|w| w.owner == owner).collect()
    }
}

impl Default for WatcherChannel {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(path: &str, kind: WatchKind, recursive: bool, owner: &str) -> WatcherEntry {
        WatcherEntry { path: path.into(), kind, recursive, owner: owner.into() }
    }

    #[test]
    fn empty_validates() {
        WatcherChannel::new().validate().unwrap();
    }

    #[test]
    fn register_file_watch() {
        let mut c = WatcherChannel::new();
        c.register(w("/etc/sovereign/config.toml", WatchKind::File, false, "policy-bus")).unwrap();
        assert!(c.get("/etc/sovereign/config.toml").is_some());
    }

    #[test]
    fn directory_recursive_ok() {
        let mut c = WatcherChannel::new();
        c.register(w("/workspace", WatchKind::Directory, true, "audit-log")).unwrap();
    }

    #[test]
    fn recursive_on_file_rejected() {
        let mut c = WatcherChannel::new();
        let err = c.register(w("/etc/x.toml", WatchKind::File, true, "p")).unwrap_err();
        assert!(matches!(err, WatcherError::RecursiveOnNonDir { .. }));
    }

    #[test]
    fn non_absolute_path_rejected_for_file_dir() {
        let mut c = WatcherChannel::new();
        let err = c.register(w("relative/path", WatchKind::File, false, "p")).unwrap_err();
        assert!(matches!(err, WatcherError::NotAbsolute(_)));
    }

    #[test]
    fn socket_path_can_be_non_absolute() {
        let mut c = WatcherChannel::new();
        c.register(w("@abstract-socket", WatchKind::UnixSocket, false, "p")).unwrap();
    }

    #[test]
    fn empty_path_rejected() {
        let mut c = WatcherChannel::new();
        let err = c.register(w("", WatchKind::File, false, "p")).unwrap_err();
        assert!(matches!(err, WatcherError::EmptyPath));
    }

    #[test]
    fn empty_owner_rejected() {
        let mut c = WatcherChannel::new();
        let err = c.register(w("/x", WatchKind::File, false, "")).unwrap_err();
        assert!(matches!(err, WatcherError::EmptyOwner(_)));
    }

    #[test]
    fn duplicate_path_rejected() {
        let mut c = WatcherChannel::new();
        c.register(w("/x", WatchKind::File, false, "p")).unwrap();
        let err = c.register(w("/x", WatchKind::File, false, "q")).unwrap_err();
        assert!(matches!(err, WatcherError::DuplicatePath(_)));
    }

    #[test]
    fn owned_by_filters() {
        let mut c = WatcherChannel::new();
        c.register(w("/a", WatchKind::File, false, "p")).unwrap();
        c.register(w("/b", WatchKind::File, false, "q")).unwrap();
        c.register(w("/c", WatchKind::File, false, "p")).unwrap();
        assert_eq!(c.owned_by("p").len(), 2);
        assert_eq!(c.owned_by("q").len(), 1);
        assert_eq!(c.owned_by("z").len(), 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = WatcherChannel::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), WatcherError::SchemaMismatch));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(serde_json::to_string(&WatchKind::Directory).unwrap(), "\"directory\"");
        assert_eq!(serde_json::to_string(&WatchKind::UnixSocket).unwrap(), "\"unix-socket\"");
        assert_eq!(serde_json::to_string(&WatchKind::Fifo).unwrap(), "\"fifo\"");
    }

    #[test]
    fn channel_serde_roundtrip() {
        let mut c = WatcherChannel::new();
        c.register(w("/etc/x.toml", WatchKind::File, false, "p")).unwrap();
        c.register(w("/workspace", WatchKind::Directory, true, "q")).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: WatcherChannel = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
