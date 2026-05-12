//! External event stream collector.
//!
//! Reads a JSONL file where every line is a pre-formed selfdef [`Event`]
//! (same shape as the bus carries internally) and republishes onto the
//! bus. Used by the `selfdef-ssh-wrap` binary and any other tool that
//! wants to inject events without writing to the bus directly.
//!
//! The collector trusts the on-disk events to be well-formed — the writer
//! and the daemon typically share the same `selfdef-core` version, and
//! the schema is forward-compatible (non-exhaustive Event struct). Bad
//! lines are logged and skipped, never crash the collector.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::Event;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    Start,
    End,
}

impl ReadFrom {
    pub fn parse(s: &str) -> Self {
        match s {
            "start" => Self::Start,
            _ => Self::End,
        }
    }
}

#[derive(Debug, Error)]
pub enum EventstreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct EventstreamCollector {
    input_path: PathBuf,
    read_from: ReadFrom,
    publisher: Publisher,
}

impl EventstreamCollector {
    #[must_use]
    pub fn new(input_path: PathBuf, read_from: ReadFrom, publisher: Publisher) -> Self {
        Self {
            input_path,
            read_from,
            publisher,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), EventstreamError> {
        info!(path = %self.input_path.display(), "eventstream collector starting");
        wait_for_file(&self.input_path, &shutdown).await;

        let mut file = tokio::fs::File::open(&self.input_path).await?;
        if self.read_from == ReadFrom::End {
            file.seek(std::io::SeekFrom::End(0)).await?;
        }
        let mut reader = BufReader::new(file);
        let mut buf = String::new();

        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            buf.clear();
            let n = tokio::select! {
                r = reader.read_line(&mut buf) => r?,
                () = shutdown.cancelled() => return Ok(()),
            };
            if n == 0 {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line) {
                Ok(event) => self.publisher.publish_lossy(event),
                Err(e) => debug!(error = %e, "skipping malformed eventstream line"),
            }
        }
    }
}

async fn wait_for_file(path: &Path, shutdown: &CancellationToken) {
    for _ in 0..40 {
        if path.exists() {
            return;
        }
        if shutdown.is_cancelled() {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test(flavor = "current_thread")]
    async fn tails_event_file_and_republishes() {
        let mut file = NamedTempFile::new().unwrap();

        // Pre-write one event so we know it's seen on Start mode.
        let event = Event::new(
            ClassUid::SSH_ACTIVITY,
            1,
            SeverityId::Informational,
            "test-host",
            "selfdef.ssh-wrap",
            0,
        );
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        file.flush().unwrap();

        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();

        let collector = EventstreamCollector::new(file.path().to_path_buf(), ReadFrom::Start, pub_);
        let shutdown = CancellationToken::new();
        let sd = shutdown.clone();
        let task = tokio::spawn(async move { collector.run(sd).await });

        let received = tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("timeout")
            .expect("recv error");
        assert_eq!(received.source, "selfdef.ssh-wrap");
        assert_eq!(received.class_uid, ClassUid::SSH_ACTIVITY);

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}
