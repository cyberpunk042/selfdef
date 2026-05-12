//! Honeytoken (canary file) collector.
//!
//! Watches a list of paths with inotify. Any access (open/read/write/attrib
//! change) emits a `DETECTION_FINDING` event with `Severity::Critical`.
//!
//! Inotify alone doesn't carry process identity — only file events. The
//! emitted finding includes the file path and event kind; correlating to
//! a process is done downstream by joining with Tetragon's `process_kprobe`
//! observations of the same path.
//!
//! Operational note: watches are installed once at startup. If a canary
//! file is deleted and recreated, the watch is lost. Pin canaries to paths
//! you don't intend to legitimately mutate.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::StreamExt;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use selfdef_bus::Publisher;
use selfdef_core::attack::{Tactic, TechniqueRef};
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const FINDING_CREATE: u32 = 1;

#[derive(Debug, Error)]
pub enum CanaryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct CanaryCollector {
    paths: Vec<PathBuf>,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
}

impl CanaryCollector {
    #[must_use]
    pub fn new(paths: Vec<PathBuf>, publisher: Publisher, host_tag: String) -> Self {
        Self {
            paths,
            publisher,
            host_tag,
            sequence: AtomicU64::new(0),
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), CanaryError> {
        if self.paths.is_empty() {
            info!("canary collector: no paths configured; idle");
            shutdown.cancelled().await;
            return Ok(());
        }

        let inotify = Inotify::init()?;
        let mut watches = inotify.watches();
        let mut wd_to_path: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        let mask = WatchMask::ACCESS
            | WatchMask::OPEN
            | WatchMask::MODIFY
            | WatchMask::ATTRIB
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF;

        for path in &self.paths {
            match watches.add(path, mask) {
                Ok(wd) => {
                    info!(path = %path.display(), "canary watch installed");
                    wd_to_path.insert(wd, path.clone());
                }
                Err(e) => warn!(path = %path.display(), error = %e, "failed to watch canary"),
            }
        }

        if wd_to_path.is_empty() {
            warn!("canary collector: no watches were installed; idle");
            shutdown.cancelled().await;
            return Ok(());
        }

        let buffer = [0u8; 4096];
        let mut stream = inotify.into_event_stream(buffer)?;

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    debug!("canary collector shutdown requested");
                    return Ok(());
                }
                next = stream.next() => match next {
                    Some(Ok(event)) => {
                        if let Some(path) = wd_to_path.get(&event.wd) {
                            self.emit_finding(path, &event);
                        }
                    }
                    Some(Err(e)) => warn!(error = %e, "inotify error"),
                    None => {
                        warn!("inotify stream ended");
                        return Ok(());
                    }
                }
            }
        }
    }

    fn next_seq(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn emit_finding(&self, path: &std::path::Path, ev: &inotify::Event<std::ffi::OsString>) {
        let mask = ev.mask;
        let kind = if mask.contains(inotify::EventMask::ACCESS) {
            "read"
        } else if mask.contains(inotify::EventMask::OPEN) {
            "open"
        } else if mask.contains(inotify::EventMask::MODIFY) {
            "modify"
        } else if mask.contains(inotify::EventMask::ATTRIB) {
            "attrib"
        } else if mask.contains(inotify::EventMask::DELETE_SELF) {
            "delete"
        } else if mask.contains(inotify::EventMask::MOVE_SELF) {
            "move"
        } else {
            "touch"
        };

        let finding = Event::new(
            ClassUid::DETECTION_FINDING,
            FINDING_CREATE,
            SeverityId::Critical,
            &self.host_tag,
            "selfdef.canary",
            self.next_seq(),
        )
        .with_message(format!("Canary {kind}: {}", path.display()))
        .with_file(File::at_path(path.display().to_string()))
        .with_attack(TechniqueRef::new(
            "T1552.001",
            "Unsecured Credentials: Credentials In Files",
            Tactic::CredentialAccess,
        ))
        .with_raw(serde_json::json!({
            "canary_path": path.display().to_string(),
            "inotify_mask": format!("{:?}", mask),
            "event_kind": kind,
        }));

        self.publisher.publish_lossy(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[tokio::test(flavor = "current_thread")]
    async fn opening_a_canary_fires_critical_finding() {
        let mut canary = NamedTempFile::new().unwrap();
        writeln!(canary, "definitely-not-real-credentials").unwrap();
        let canary_path = canary.path().to_path_buf();

        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();

        let collector = CanaryCollector::new(vec![canary_path.clone()], pub_, "test-host".into());
        let shutdown = CancellationToken::new();
        let sd = shutdown.clone();
        let task = tokio::spawn(async move { collector.run(sd).await });

        // Give inotify a moment to install the watch.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger an access.
        let _ = std::fs::read(&canary_path).unwrap();

        let finding = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("recv timeout")
            .expect("recv error");

        assert_eq!(finding.severity_id, SeverityId::Critical);
        assert_eq!(finding.class_uid, ClassUid::DETECTION_FINDING);
        assert_eq!(finding.source, "selfdef.canary");
        let f = finding.file.unwrap();
        assert_eq!(f.path.as_deref(), Some(canary_path.to_str().unwrap()));
        assert!(!finding.attack.is_empty());
        assert_eq!(finding.attack[0].id, "T1552.001");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}
