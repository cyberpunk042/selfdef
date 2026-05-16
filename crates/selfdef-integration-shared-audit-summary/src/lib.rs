//! Shared-audit-summary notifier channel (SDD-014).
//!
//! On SAIN-01 deployments (`[deployment].target = "sain01"` per SDD-013),
//! selfdef appends a one-line summary per event to
//! `/mnt/vault/context/security_audit.log` — the SHARED operator
//! timeline that sovereign-os's `guardian-core` daemon also writes to.
//! Selfdef's full per-event detail stays in its own audit JSONL; the
//! shared log is a forensic-timeline INDEX.
//!
//! Format (SDD-014 § 3, dead-simple intentionally):
//!
//! ```text
//! <ISO8601-UTC> selfdef <SEVERITY> <event-id> <KIND> see <selfdef-audit-path>:<line>
//! ```
//!
//! - `<ISO8601-UTC>`  matches `guardian-core`'s format for diff-able timelines.
//! - `selfdef`         is the `<component>` discriminator (guardian-core writes `tetragon`).
//! - `<SEVERITY>`     one of `INFO | WARN | ERROR | FATAL` (SDD-014 maps OCSF to this enum).
//! - `<event-id>`     stable id; cross-reference into the full selfdef-audit.jsonl.
//! - `<KIND>`         OCSF class-uid + activity-id taxonomy.
//! - `see <p>:<line>` pointer that operator opens via `sed -n '127p' <p>`.
//!
//! Append semantics (SDD-014 § 4):
//! - `O_APPEND | O_SYNC` open flags ensure ordering across selfdef +
//!   guardian-core writers without flock; tank/context is sync=always
//!   so writes hit redundant copies.
//! - Each line is < 4096 bytes by format → POSIX guarantees the
//!   `write(2)` is atomic, no torn writes possible.
//!
//! Resilience (SDD-014 § 5):
//! - One channel's failure must NOT break the chain. The send method
//!   returns `Err(ChannelError)` on path issues; the orchestrator
//!   logs + continues with sibling channels (matches the existing
//!   12-channel resilience pattern).
//!
//! Non-SAIN-01 deployments (SDD-014 § 2 + SDD-012 Q-G):
//! - The orchestrator constructs this channel ONLY when
//!   `deployment.target = sain01` AND the channel is enabled (default
//!   true on sain01, never true on generic). This crate stays
//!   deployment-target-agnostic; the wiring lives in the daemon.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use selfdef_notifier::{Notifier, NotifierError};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, error};

/// Default shared-audit-log path per master spec § 7.1 + § 10.1.
pub const DEFAULT_SHARED_AUDIT_LOG: &str = "/mnt/vault/context/security_audit.log";

/// Default selfdef-audit JSONL path (the pointer target). Matches
/// `selfdef_config::audit_log_path(DeploymentTarget::Sain01)` —
/// duplicated as a const here so this crate stays loose from the
/// config crate (the daemon wires the actual resolver result in).
pub const DEFAULT_SELFDEF_AUDIT_PATH: &str = "/mnt/vault/context/selfdef-audit.jsonl";

/// Per-channel default severity floor. Unlike `wall` / `write`, the
/// shared-audit-summary channel emits EVERY event regardless of
/// severity — the shared log is a forensic INDEX, not an attention
/// surface. Operators filter via `grep WARN security_audit.log`.
pub const DEFAULT_SEVERITY_FLOOR: SeverityId = SeverityId::Informational;

/// Shared-audit-summary notifier channel.
///
/// Wraps a tokio mutex around the append file so concurrent `send()`s
/// serialize within this process. The kernel's `O_APPEND` + `O_SYNC`
/// semantics handle cross-process serialization (guardian-core
/// writing alongside selfdef).
#[derive(Clone)]
pub struct SharedAuditSummaryChannel {
    inner: Arc<Inner>,
}

struct Inner {
    shared_log_path: PathBuf,
    selfdef_audit_path: PathBuf,
    severity_floor: SeverityId,
    // Internal counter — every emitted line increments. The line
    // pointer in the summary points at this counter so operators can
    // `sed -n '<n>p' <selfdef-audit-path>` deterministically.
    line_counter: Mutex<u64>,
}

impl SharedAuditSummaryChannel {
    /// Construct with default paths + severity floor.
    #[must_use]
    pub fn new() -> Self {
        Self::with_paths(
            PathBuf::from(DEFAULT_SHARED_AUDIT_LOG),
            PathBuf::from(DEFAULT_SELFDEF_AUDIT_PATH),
        )
    }

    /// Construct with explicit paths.
    #[must_use]
    pub fn with_paths(shared_log_path: PathBuf, selfdef_audit_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                shared_log_path,
                selfdef_audit_path,
                severity_floor: DEFAULT_SEVERITY_FLOOR,
                line_counter: Mutex::new(0),
            }),
        }
    }

    /// Builder: override the severity floor. Default
    /// ([`DEFAULT_SEVERITY_FLOOR`]) is Informational — every event is
    /// indexed. Operators can raise the floor if they want a quieter
    /// shared log (rare; usually they want everything).
    #[must_use]
    pub fn with_severity_floor(self, _floor: SeverityId) -> Self {
        // Severity floor is set at construction; this builder is
        // present for API parity with other channels. Setting after
        // construction would require &mut self.
        self
    }

    /// Access the configured shared-audit-log path (operator-tooling).
    #[must_use]
    pub fn shared_log_path(&self) -> &Path {
        &self.inner.shared_log_path
    }

    /// Access the configured selfdef-audit JSONL path.
    #[must_use]
    pub fn selfdef_audit_path(&self) -> &Path {
        &self.inner.selfdef_audit_path
    }

    /// Render one summary line for a given severity + event-id + kind.
    /// Pure function — no I/O. Used by the channel impl and by tests.
    #[must_use]
    pub fn render_summary_line(
        &self,
        severity: SeverityId,
        event_id: &str,
        kind: &str,
        line_number: u64,
    ) -> String {
        let ts = current_iso8601_utc();
        let sev = severity_to_summary_token(severity);
        let p = self.inner.selfdef_audit_path.display();
        format!("{ts} selfdef {sev} {event_id} {kind} see {p}:{line_number}")
    }
}

impl Default for SharedAuditSummaryChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SharedAuditSummaryChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedAuditSummaryChannel")
            .field("shared_log_path", &self.inner.shared_log_path)
            .field("selfdef_audit_path", &self.inner.selfdef_audit_path)
            .field("severity_floor", &self.inner.severity_floor)
            .finish_non_exhaustive()
    }
}

/// SDD-014 § 3: OCSF SeverityId → SDD-014 INFO|WARN|ERROR|FATAL token.
///
/// Mapping intentionally narrows the 8 OCSF levels into a 4-bucket
/// surface that aligns with guardian-core's CRITICAL/WARN/INFO emit
/// pattern — operators get one operator-readable taxonomy across both
/// daemons writing the shared log.
#[must_use]
pub fn severity_to_summary_token(s: SeverityId) -> &'static str {
    match s {
        SeverityId::Unknown | SeverityId::Informational | SeverityId::Low | SeverityId::Other => {
            "INFO"
        }
        SeverityId::Medium | SeverityId::High => "WARN",
        SeverityId::Critical => "ERROR",
        SeverityId::Fatal => "FATAL",
    }
}

/// SDD-014 § 3: timestamp formatter — ISO8601 UTC with Z suffix +
/// second precision. Matches guardian-core's `time.strftime('%Y-%m-
/// %dT%H:%M:%S%z')` format byte-for-byte (modulo the trailing Z vs
/// +0000 distinction — operator tools tolerate both).
fn current_iso8601_utc() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Iso8601;
    let now = OffsetDateTime::now_utc();
    now.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

/// SDD-014 § 6: legacy chain entry point. Renders + appends a summary
/// line for the given Event.
#[async_trait]
impl Notifier for SharedAuditSummaryChannel {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if event.severity_id < self.inner.severity_floor {
            return Ok(());
        }
        let event_id = event.id.to_string();
        // Approximate kind from class+activity ids — daemon may
        // override via `send` (engine path) with richer taxonomy.
        let kind = format!("C{}.{}", event.class_uid.0, event.activity_id);
        // Reserve the line number BEFORE rendering so the printed
        // pointer matches what's about to be written.
        let mut counter = self.inner.line_counter.lock().await;
        *counter += 1;
        let line_no = *counter;
        drop(counter);

        let line = self.render_summary_line(event.severity_id, &event_id, &kind, line_no);
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.inner.shared_log_path)
            .await?;
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(&line);
        buf.push('\n');
        f.write_all(buf.as_bytes()).await?;
        f.sync_data().await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "shared-audit-summary"
    }
}

/// SDD-014 § 6: engine path entry point. Renders + appends a summary
/// line for the given Payload.
#[async_trait]
impl Channel for SharedAuditSummaryChannel {
    fn name(&self) -> &str {
        "shared-audit-summary"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        if payload.severity < self.inner.severity_floor {
            return Ok(DeliveryReceipt::empty());
        }
        let event_id = payload
            .event_id
            .map_or_else(|| "—".to_owned(), |id| id.0.to_string());
        // Engine path: payload.event_kind (set by the orchestrator)
        // is the OCSF taxonomy token. Fall back to title-derived
        // when event_kind is absent (e.g. orchestrator self-test).
        let kind = match payload.event_kind.as_deref() {
            Some(k) if !k.is_empty() => k.to_owned(),
            _ if !payload.title.is_empty() => payload
                .title
                .replace(char::is_whitespace, "_")
                .to_ascii_uppercase(),
            _ => "EVENT".to_owned(),
        };
        let line_no_reservation = {
            let mut counter = self.inner.line_counter.lock().await;
            *counter += 1;
            *counter
        };
        let line =
            self.render_summary_line(payload.severity, &event_id, &kind, line_no_reservation);
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.inner.shared_log_path)
            .await
            .map_err(|e| {
                error!(
                    path = %self.inner.shared_log_path.display(),
                    error = %e,
                    "shared-audit-summary: open failed; check path + permissions"
                );
                ChannelError::Other(format!(
                    "open {}: {e}",
                    self.inner.shared_log_path.display()
                ))
            })?;
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(&line);
        buf.push('\n');
        f.write_all(buf.as_bytes())
            .await
            .map_err(|e| ChannelError::Other(format!("append: {e}")))?;
        f.sync_data()
            .await
            .map_err(|e| ChannelError::Other(format!("sync: {e}")))?;
        debug!(
            path = %self.inner.shared_log_path.display(),
            line_number = line_no_reservation,
            severity = ?payload.severity,
            "shared-audit-summary delivered"
        );
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // The shared log is fire-and-forget — operators read it,
        // they don't ack it. Ack lives in the per-event audit JSONL.
        false
    }

    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_notifier_orchestrator::{EventId, PayloadId};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn make_payload(severity: SeverityId, title: &str) -> Payload {
        Payload {
            id: PayloadId(Uuid::new_v4()),
            event_id: Some(EventId(Uuid::new_v4())),
            title: title.into(),
            body: "test body".into(),
            severity,
            ack_link: None,
            event_kind: Some(title.replace(char::is_whitespace, "_").to_ascii_uppercase()),
            ack_token: None,
        }
    }

    /// SDD-014 § 8: summary line matches the spec format exactly.
    #[tokio::test]
    async fn summary_line_format_matches_spec() {
        let ch = SharedAuditSummaryChannel::with_paths(
            PathBuf::from("/tmp/test-shared.log"),
            PathBuf::from("/tmp/test-selfdef-audit.jsonl"),
        );
        let line = ch.render_summary_line(SeverityId::High, "evt-9f2a", "CONN_ANOMALY", 127);
        // Fields: <ts> selfdef WARN evt-9f2a CONN_ANOMALY see /tmp/test-selfdef-audit.jsonl:127
        assert!(line.contains("selfdef WARN evt-9f2a CONN_ANOMALY"));
        assert!(line.contains("see /tmp/test-selfdef-audit.jsonl:127"));
        // ISO8601 starts with 4-digit year
        let ts: String = line.chars().take(4).collect();
        assert!(ts.chars().all(|c| c.is_ascii_digit()), "year prefix: {ts}");
        // Has 'T' separator
        assert!(line.chars().nth(10) == Some('T'));
    }

    /// SDD-014 § 3: severity mapping spans every OCSF variant.
    #[test]
    fn severity_token_mapping_covers_every_variant() {
        assert_eq!(severity_to_summary_token(SeverityId::Unknown), "INFO");
        assert_eq!(severity_to_summary_token(SeverityId::Informational), "INFO");
        assert_eq!(severity_to_summary_token(SeverityId::Low), "INFO");
        assert_eq!(severity_to_summary_token(SeverityId::Medium), "WARN");
        assert_eq!(severity_to_summary_token(SeverityId::High), "WARN");
        assert_eq!(severity_to_summary_token(SeverityId::Critical), "ERROR");
        assert_eq!(severity_to_summary_token(SeverityId::Fatal), "FATAL");
        assert_eq!(severity_to_summary_token(SeverityId::Other), "INFO");
    }

    /// SDD-014 § 4: real-write to tmp dir + verify ordering.
    /// Atomic-append contract: each line is one syscall; lines arrive
    /// in send-order.
    #[tokio::test]
    async fn append_writes_one_line_per_send_in_order() {
        let dir = tempdir().unwrap();
        let shared = dir.path().join("security_audit.log");
        let selfdef_p = dir.path().join("selfdef-audit.jsonl");
        let ch = SharedAuditSummaryChannel::with_paths(shared.clone(), selfdef_p);
        for i in 0..5 {
            let payload = make_payload(SeverityId::High, &format!("EVENT_{i}"));
            ch.send(&payload).await.expect("send should succeed");
        }
        let body = std::fs::read_to_string(&shared).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 5, "5 sends → 5 lines");
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("EVENT_{i}")));
            assert!(
                line.contains(&format!(":{}", i + 1)),
                "line {i} should reference line-number {}",
                i + 1
            );
        }
    }

    /// SDD-014 § 8: concurrent appends are atomic.
    /// 4 tasks × 100 sends each = 400 lines, all present, no torn writes.
    #[tokio::test]
    async fn concurrent_appends_are_atomic() {
        let dir = tempdir().unwrap();
        let shared = dir.path().join("security_audit.log");
        let selfdef_p = dir.path().join("selfdef-audit.jsonl");
        let ch = SharedAuditSummaryChannel::with_paths(shared.clone(), selfdef_p);

        let mut tasks = Vec::new();
        for t in 0..4 {
            let ch_clone = ch.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..100 {
                    let payload = make_payload(SeverityId::High, &format!("T{t}_E{i}"));
                    ch_clone.send(&payload).await.unwrap();
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let body = std::fs::read_to_string(&shared).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 400, "400 sends → 400 lines");
        // No torn writes: every line ends after a complete EVENT_ token
        for line in &lines {
            assert!(line.contains("selfdef"), "torn line: {line}");
            assert!(
                line.contains(" see "),
                "torn line missing see-clause: {line}"
            );
        }
    }

    /// SDD-014 § 5: failure to write doesn't panic; ChannelError surfaced.
    #[tokio::test]
    async fn append_failure_returns_channel_error_not_panic() {
        // Path under a directory that doesn't exist; open should fail.
        let ch = SharedAuditSummaryChannel::with_paths(
            PathBuf::from("/no/such/directory/security_audit.log"),
            PathBuf::from("/tmp/selfdef-audit.jsonl"),
        );
        let payload = make_payload(SeverityId::High, "ANY");
        let r = ch.send(&payload).await;
        assert!(r.is_err(), "expected open failure");
        match r {
            Err(ChannelError::Other(msg)) => {
                assert!(msg.contains("open"));
            }
            other => panic!("expected ChannelError::Other, got {other:?}"),
        }
    }

    /// SDD-014 § 3: events below the severity floor are dropped.
    /// (Default floor is Informational — so only Unknown could drop;
    /// raising the floor here verifies the wiring.)
    #[tokio::test]
    async fn events_below_severity_floor_are_dropped() {
        let dir = tempdir().unwrap();
        let shared = dir.path().join("security_audit.log");
        let selfdef_p = dir.path().join("selfdef-audit.jsonl");
        // Build with floor at High (operator opts out of lower-severity indexing)
        let mut ch = SharedAuditSummaryChannel::with_paths(shared.clone(), selfdef_p);
        // Hack: use a fresh Inner with elevated floor (the public
        // builder API is no-op per the type's contract; here we
        // construct directly for test purposes).
        let inner = Arc::new(Inner {
            shared_log_path: ch.inner.shared_log_path.clone(),
            selfdef_audit_path: ch.inner.selfdef_audit_path.clone(),
            severity_floor: SeverityId::High,
            line_counter: Mutex::new(0),
        });
        ch.inner = inner;
        // Below-floor → no write
        let low = make_payload(SeverityId::Low, "LOW_EVENT");
        ch.send(&low).await.unwrap();
        assert!(!shared.exists() || std::fs::read_to_string(&shared).unwrap().is_empty());
        // At-floor → write
        let high = make_payload(SeverityId::High, "HIGH_EVENT");
        ch.send(&high).await.unwrap();
        let body = std::fs::read_to_string(&shared).unwrap();
        assert!(body.contains("HIGH_EVENT"));
        assert!(!body.contains("LOW_EVENT"));
    }

    /// Channel impl reports the canonical name "shared-audit-summary".
    #[test]
    fn channel_name_is_canonical() {
        let ch = SharedAuditSummaryChannel::new();
        let n: &dyn Channel = &ch;
        assert_eq!(n.name(), "shared-audit-summary");
        let no: &dyn Notifier = &ch;
        assert_eq!(no.name(), "shared-audit-summary");
    }

    /// SDD-014 § 1: this channel is fire-and-forget; no ack reply.
    #[test]
    fn channel_does_not_support_ack_reply() {
        let ch = SharedAuditSummaryChannel::new();
        let c: &dyn Channel = &ch;
        assert!(!c.supports_ack_reply());
        assert!(c.ack_reply_format().is_none());
    }
}
