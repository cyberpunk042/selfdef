//! `wall(1)` session-attention channel — SDD-008 D-8.
//!
//! The operator's original ask was "talk to the bash session when
//! the user doesn't notice" — wake the on-call who's at the
//! terminal, not just their phone. This crate implements that
//! against the venerable Unix [`wall(1)`] broadcast: every
//! logged-in TTY receives a one-line attention message prefixed
//! with the severity emoji.
//!
//! Per the SDD-008 charter, session-attention is conceptually a
//! responder (it mutates local host state — writes to TTY
//! devices — rather than an external service). For the v1
//! implementation we leverage the [`Channel`] trait the
//! orchestrator already plumbs through; the taxonomy distinction
//! can be refactored once we add a second session-attention
//! transport (e.g. `write(1)` for per-user targeting).
//!
//! Defaults that matter:
//!
//! - **Severity floor = `SeverityId::High`** — wall is loud-by-
//!   design and bothering every TTY for an Informational event is
//!   wrong. The operator can tune this knob downward but the
//!   built-in default refuses to broadcast on routine events.
//! - **Binary path = `/usr/bin/wall`** — the standard Linux path.
//!   Configurable for unit tests + non-FHS systems.
//! - **Empty binary path → NotConfigured** — daemon startup never
//!   silently wires up a wall channel without an explicit binary.
//!
//! [`wall(1)`]: https://man7.org/linux/man-pages/man1/wall.1.html

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};

/// Default binary path. Tests + non-FHS systems override via
/// [`WallChannel::with_binary`].
pub const DEFAULT_WALL_BINARY: &str = "/usr/bin/wall";

/// Default severity floor. Events below this severity quietly
/// skip wall — wall is system-wide broadcast, bothering every TTY
/// for an Informational event is wrong.
pub const DEFAULT_SEVERITY_FLOOR: SeverityId = SeverityId::High;

/// wall(1) session-attention channel.
#[derive(Debug, Clone)]
pub struct WallChannel {
    binary: PathBuf,
    severity_floor: SeverityId,
}

impl WallChannel {
    /// Construct with the default binary path
    /// ([`DEFAULT_WALL_BINARY`]) and the default severity floor
    /// ([`DEFAULT_SEVERITY_FLOOR`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_WALL_BINARY),
            severity_floor: DEFAULT_SEVERITY_FLOOR,
        }
    }

    /// Builder: override the `wall` binary path. Use for tests
    /// (point at `/bin/true` to assert success without spamming
    /// every TTY on the build host) or non-FHS systems.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Builder: override the severity floor. Events below this
    /// severity quietly skip wall (return `Ok` without spawning).
    /// Operators MAY lower this knob, but the default already
    /// refuses to broadcast on Low / Medium / Informational.
    #[must_use]
    pub fn with_severity_floor(mut self, floor: SeverityId) -> Self {
        self.severity_floor = floor;
        self
    }

    /// Build from config-shaped inputs. `binary.is_empty()` =
    /// not-configured (refuses); empty severity_floor string =
    /// default ([`DEFAULT_SEVERITY_FLOOR`]).
    pub fn from_config(
        binary: &Path,
        severity_floor: Option<&str>,
    ) -> Result<Self, WallBuildError> {
        if binary.as_os_str().is_empty() {
            return Err(WallBuildError::EmptyBinary);
        }
        let floor = match severity_floor {
            None | Some("") => DEFAULT_SEVERITY_FLOOR,
            Some(s) => {
                severity_from_str(s).ok_or_else(|| WallBuildError::UnknownSeverity(s.to_owned()))?
            }
        };
        Ok(Self {
            binary: binary.to_path_buf(),
            severity_floor: floor,
        })
    }

    /// Shared core for both trait impls. Skips below-floor events
    /// quietly; pipes the rendered message into the binary's stdin
    /// (the way `wall` accepts a body without command-line args).
    async fn broadcast(
        &self,
        severity: SeverityId,
        message: &str,
    ) -> Result<bool, WallDeliveryError> {
        if (severity as u32) < (self.severity_floor as u32) {
            return Ok(false); // below floor → quietly skipped
        }
        use tokio::io::AsyncWriteExt as _;
        let mut child = tokio::process::Command::new(&self.binary)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| WallDeliveryError::Spawn(e.to_string()))?;
        if let Some(stdin) = child.stdin.as_mut() {
            // EPIPE on write means the child has already exited (or
            // closed its stdin) before we finished delivering the
            // message. Don't fail eagerly — the wait below will
            // surface the child's actual exit status, which is what
            // callers act on. A real wall(1) with no logged-in TTYs
            // can plausibly hit this path; in tests, fast stand-ins
            // like /bin/true and /bin/false exhibit the same race.
            if let Err(e) = stdin.write_all(message.as_bytes()).await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(WallDeliveryError::WriteStdin(e.to_string()));
            }
            // Drop stdin so wall sees EOF and starts broadcasting.
            // Same EPIPE tolerance as the write above.
            if let Err(e) = stdin.shutdown().await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(WallDeliveryError::WriteStdin(e.to_string()));
            }
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| WallDeliveryError::Wait(e.to_string()))?;
        if output.status.success() {
            Ok(true)
        } else {
            Err(WallDeliveryError::Subprocess {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }
}

impl Default for WallChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from constructing a [`WallChannel`] via
/// [`WallChannel::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum WallBuildError {
    #[error("wall binary path is empty")]
    EmptyBinary,
    #[error(
        "wall severity_floor must be one of informational|low|medium|high|critical|fatal; got {0:?}"
    )]
    UnknownSeverity(String),
}

/// Internal delivery error; bridged into [`NotifierError`] /
/// [`ChannelError`] at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum WallDeliveryError {
    #[error("wall spawn failed: {0}")]
    Spawn(String),
    #[error("wall write-to-stdin failed: {0}")]
    WriteStdin(String),
    #[error("wall wait failed: {0}")]
    Wait(String),
    #[error("wall exited with status {status}: {stderr}")]
    Subprocess { status: i32, stderr: String },
}

impl From<WallDeliveryError> for NotifierError {
    fn from(e: WallDeliveryError) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<WallDeliveryError> for ChannelError {
    fn from(e: WallDeliveryError) -> Self {
        match e {
            WallDeliveryError::Subprocess { status, stderr } => Self::Remote {
                status: status.unsigned_abs() as u16,
                body: stderr,
            },
            other => Self::Transport(other.to_string()),
        }
    }
}

/// Parse the operator-facing severity string (case-insensitive).
fn severity_from_str(s: &str) -> Option<SeverityId> {
    match s.to_ascii_lowercase().as_str() {
        "info" | "informational" => Some(SeverityId::Informational),
        "low" => Some(SeverityId::Low),
        "medium" | "med" => Some(SeverityId::Medium),
        "high" => Some(SeverityId::High),
        "critical" | "crit" => Some(SeverityId::Critical),
        "fatal" => Some(SeverityId::Fatal),
        _ => None,
    }
}

/// Render a single-line attention banner suitable for the wall
/// broadcast. Prefixed with a severity emoji + the originating
/// event id (so an operator at the terminal sees enough to find
/// the event in `selfdefctl notify list`).
fn render_attention_banner(severity: SeverityId, title: &str, event_id: &str) -> String {
    let emoji = severity_emoji(severity);
    format!("{emoji} [selfdef] {severity} — {title}  (event {event_id})\n")
}

/// Single emoji per severity. Matches the conventions of the
/// other integration crates (Slack / Discord / CLI list).
fn severity_emoji(severity: SeverityId) -> &'static str {
    match severity {
        SeverityId::Unknown | SeverityId::Informational => "ℹ️",
        SeverityId::Low => "🔹",
        SeverityId::Medium => "⚠️",
        SeverityId::High => "🚨",
        SeverityId::Critical | SeverityId::Fatal => "🔥",
        SeverityId::Other => "❓",
    }
}

#[async_trait]
impl Notifier for WallChannel {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.binary.as_os_str().is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        let title = render_title(event);
        // Legacy path: include the full body. wall renders newlines
        // as wall does — most terminals get one line per body line.
        let body = render_body(event);
        let banner = render_attention_banner(event.severity_id, &title, &event.id.to_string());
        let message = format!("{banner}{body}");
        self.broadcast(event.severity_id, &message).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "wall"
    }
}

#[async_trait]
impl Channel for WallChannel {
    fn name(&self) -> &str {
        "wall"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        if self.binary.as_os_str().is_empty() {
            return Err(ChannelError::Other("wall not configured".into()));
        }
        let event_str = payload
            .event_id
            .map_or_else(|| "—".to_owned(), |id| id.to_string());
        let banner = render_attention_banner(payload.severity, &payload.title, &event_str);
        let message = match &payload.ack_link {
            Some(link) => format!("{banner}{}\nAck: {link}\n", payload.body),
            None => format!("{banner}{}\n", payload.body),
        };
        self.broadcast(payload.severity, &message).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // wall is one-way broadcast; no ack channel exists.
        // Operators ack via `selfdefctl notify ack <id>` from any
        // shell on the same host.
        false
    }

    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_notifier_orchestrator::{EventId, PayloadId};
    use uuid::Uuid;

    fn finding_event() -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::High,
            "test-host",
            "selfdef.correlator.test",
            0,
        )
        .with_message("Possible SSH brute force")
    }

    fn mk_payload_with_severity(severity: SeverityId) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId(Uuid::now_v7())),
            title: "alert".into(),
            body: "body".into(),
            severity,
            ack_link: None,
        }
    }

    #[test]
    fn default_severity_floor_is_high() {
        assert_eq!(DEFAULT_SEVERITY_FLOOR, SeverityId::High);
    }

    #[test]
    fn default_constructor_uses_built_in_defaults() {
        let w = WallChannel::new();
        assert_eq!(w.binary, PathBuf::from(DEFAULT_WALL_BINARY));
        assert_eq!(w.severity_floor, DEFAULT_SEVERITY_FLOOR);
    }

    #[test]
    fn from_config_rejects_empty_binary() {
        let err =
            WallChannel::from_config(&PathBuf::new(), None).expect_err("empty binary must fail");
        assert!(matches!(err, WallBuildError::EmptyBinary));
    }

    #[test]
    fn from_config_rejects_unknown_severity() {
        let err = WallChannel::from_config(&PathBuf::from("/bin/true"), Some("yolo"))
            .expect_err("unknown severity must fail");
        assert!(matches!(err, WallBuildError::UnknownSeverity(_)));
    }

    #[test]
    fn from_config_accepts_empty_severity_string_as_default() {
        let w = WallChannel::from_config(&PathBuf::from("/bin/true"), Some(""))
            .expect("empty severity → default");
        assert_eq!(w.severity_floor, DEFAULT_SEVERITY_FLOOR);
    }

    #[test]
    fn from_config_parses_severity_case_insensitive() {
        let w =
            WallChannel::from_config(&PathBuf::from("/bin/true"), Some("CRITICAL")).expect("ok");
        assert_eq!(w.severity_floor, SeverityId::Critical);
    }

    #[test]
    fn severity_emoji_maps_consistently() {
        assert_eq!(severity_emoji(SeverityId::High), "🚨");
        assert_eq!(severity_emoji(SeverityId::Critical), "🔥");
        assert_eq!(severity_emoji(SeverityId::Informational), "ℹ️");
    }

    #[test]
    fn render_attention_banner_has_severity_event_id_title() {
        let banner = render_attention_banner(SeverityId::High, "ssh brute", "abc-123");
        assert!(banner.starts_with("🚨"));
        assert!(banner.contains("High"));
        assert!(banner.contains("ssh brute"));
        assert!(banner.contains("event abc-123"));
        assert!(banner.ends_with('\n'));
    }

    #[test]
    fn name_parity() {
        let w = WallChannel::new();
        assert_eq!(<WallChannel as Notifier>::name(&w), "wall");
        assert_eq!(<WallChannel as Channel>::name(&w), "wall");
    }

    #[tokio::test]
    async fn notify_with_empty_binary_returns_not_configured() {
        let w = WallChannel {
            binary: PathBuf::new(),
            severity_floor: SeverityId::High,
        };
        let e = finding_event();
        assert!(matches!(
            <WallChannel as Notifier>::notify(&w, &e).await,
            Err(NotifierError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn channel_send_with_empty_binary_returns_other() {
        let w = WallChannel {
            binary: PathBuf::new(),
            severity_floor: SeverityId::High,
        };
        let p = mk_payload_with_severity(SeverityId::High);
        match <WallChannel as Channel>::send(&w, &p).await {
            Err(ChannelError::Other(_)) => {}
            other => panic!("expected ChannelError::Other, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn below_severity_floor_is_a_noop_via_notifier() {
        // /bin/false would fail if spawned, but the below-floor
        // event MUST short-circuit before the spawn.
        let w = WallChannel::new()
            .with_binary("/bin/false")
            .with_severity_floor(SeverityId::Critical);
        let mut e = finding_event();
        e.severity_id = SeverityId::High; // below the Critical floor
        let result = <WallChannel as Notifier>::notify(&w, &e).await;
        assert!(
            result.is_ok(),
            "below-floor event must not spawn /bin/false; got {result:?}",
        );
    }

    #[tokio::test]
    async fn below_severity_floor_is_a_noop_via_channel() {
        let w = WallChannel::new()
            .with_binary("/bin/false")
            .with_severity_floor(SeverityId::Critical);
        let p = mk_payload_with_severity(SeverityId::High);
        let result = <WallChannel as Channel>::send(&w, &p).await;
        assert!(result.is_ok(), "below-floor must not spawn; got {result:?}");
    }

    #[tokio::test]
    async fn at_or_above_floor_spawns_and_uses_exit_status() {
        // /bin/true accepts piped stdin and exits 0.
        let w = WallChannel::new()
            .with_binary("/bin/true")
            .with_severity_floor(SeverityId::High);
        let e = finding_event(); // High → at floor
        let result = <WallChannel as Notifier>::notify(&w, &e).await;
        assert!(result.is_ok(), "/bin/true must succeed; got {result:?}");
    }

    #[tokio::test]
    async fn nonzero_exit_surfaces_as_remote_error_via_channel() {
        let w = WallChannel::new()
            .with_binary("/bin/false")
            .with_severity_floor(SeverityId::High);
        let p = mk_payload_with_severity(SeverityId::High); // at-floor → spawn
        let result = <WallChannel as Channel>::send(&w, &p).await;
        match result {
            Err(ChannelError::Remote { status, .. }) => {
                // /bin/false exits 1; we cast to u16 → 1.
                assert_eq!(status, 1);
            }
            other => panic!("expected ChannelError::Remote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_binary_surfaces_as_transport_error() {
        // Path that exists in the type system but not on disk.
        let w = WallChannel::new()
            .with_binary("/nonexistent/wall-binary")
            .with_severity_floor(SeverityId::High);
        let p = mk_payload_with_severity(SeverityId::High);
        let result = <WallChannel as Channel>::send(&w, &p).await;
        match result {
            Err(ChannelError::Transport(_)) => {} // spawn fails
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
