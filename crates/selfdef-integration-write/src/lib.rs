//! `write(1)` per-user session-attention channel — D-004 realization.
//!
//! Sibling of [`selfdef-integration-wall`] for **per-user** TTY
//! delivery. Where `wall(1)` broadcasts to every logged-in TTY,
//! `write(1)` targets one user at a time. This crate ships the
//! per-user transport that decisions-log D-004 calls for: operators
//! who want session-attention only on a specific allowlist of
//! operator accounts wire up this channel instead of (or alongside)
//! `wall`.
//!
//! Mechanism: for each configured target user, spawn
//! `write <username>` and pipe the rendered attention message into
//! stdin. Per-user spawns are issued sequentially; a failure for one
//! user does not abort delivery to the others (best-effort).
//! `write(1)` exits non-zero when the target user is not logged in
//! — that's expected, not an error worth surfacing to the operator
//! (operators in vim / not at a session shouldn't fail an
//! escalation). Bona fide failures (binary missing, spawn errored)
//! still surface.
//!
//! Defaults that matter:
//!
//! - **Severity floor = `SeverityId::High`** — same posture as wall:
//!   loud-by-design, don't bother any TTY for routine events.
//! - **Binary path = `/usr/bin/write`** — the standard Linux path.
//!   Configurable for unit tests + non-FHS systems.
//! - **Users list non-empty** — required. Empty users = nothing to
//!   target = `NotConfigured`. Operators wanting broadcast-all use
//!   the `wall` channel instead.
//!
//! [`selfdef-integration-wall`]: ../selfdef_integration_wall/index.html

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use tracing::warn;

/// Default binary path. Tests + non-FHS systems override via
/// [`WriteChannel::with_binary`].
pub const DEFAULT_WRITE_BINARY: &str = "/usr/bin/write";

/// Default severity floor. Events below this severity quietly skip
/// write — same posture as wall.
pub const DEFAULT_SEVERITY_FLOOR: SeverityId = SeverityId::High;

/// Hard ceiling on one per-user write(1) invocation. write(2) to a
/// flow-controlled TTY (the target user pressed Ctrl-S — the classic
/// jam) blocks INDEFINITELY, and the notifier chain awaits channels
/// sequentially — one jammed terminal would silence every later
/// channel. On expiry the child is killed (`kill_on_drop`) and the
/// per-user loop continues to the remaining users (same posture as a
/// non-zero exit). Worst case is users × timeout, which stays bounded.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// `write(1)` per-user session-attention channel.
#[derive(Debug, Clone)]
pub struct WriteChannel {
    binary: PathBuf,
    severity_floor: SeverityId,
    users: Vec<String>,
    send_timeout: Duration,
}

impl WriteChannel {
    /// Construct with the default binary path
    /// ([`DEFAULT_WRITE_BINARY`]) and the default severity floor
    /// ([`DEFAULT_SEVERITY_FLOOR`]). The users list starts empty
    /// — set it via [`Self::with_users`] before invoking `notify` /
    /// `send`, otherwise the channel reports `NotConfigured`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_WRITE_BINARY),
            severity_floor: DEFAULT_SEVERITY_FLOOR,
            users: Vec::new(),
            send_timeout: DEFAULT_SEND_TIMEOUT,
        }
    }

    /// Builder: override the per-user write(1) deadline
    /// ([`DEFAULT_SEND_TIMEOUT`]). Tests use a short value with a slow
    /// stand-in binary to lock the no-hang contract.
    #[must_use]
    pub fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Builder: override the `write` binary path.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Builder: override the severity floor.
    #[must_use]
    pub fn with_severity_floor(mut self, floor: SeverityId) -> Self {
        self.severity_floor = floor;
        self
    }

    /// Builder: set the target user list. An empty users list will
    /// cause subsequent `notify` / `send` calls to return
    /// `NotConfigured`.
    #[must_use]
    pub fn with_users<I, S>(mut self, users: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.users = users.into_iter().map(Into::into).collect();
        self
    }

    /// Build from config-shaped inputs. `binary.is_empty()` or
    /// `users.is_empty()` = not-configured (refuses); empty
    /// severity_floor string = default ([`DEFAULT_SEVERITY_FLOOR`]).
    pub fn from_config(
        binary: &Path,
        severity_floor: Option<&str>,
        users: &[String],
    ) -> Result<Self, WriteBuildError> {
        if binary.as_os_str().is_empty() {
            return Err(WriteBuildError::EmptyBinary);
        }
        if users.is_empty() {
            return Err(WriteBuildError::EmptyUsers);
        }
        // Defense in depth: usernames are command-line args to write(1).
        // Reject any entry that contains shell-metacharacter-shaped chars
        // even though we use the no-shell exec path. Allowed shape is
        // the POSIX username set + a small safe extension.
        for u in users {
            if !is_safe_username(u) {
                return Err(WriteBuildError::UnsafeUsername(u.clone()));
            }
        }
        let floor = match severity_floor {
            None | Some("") => DEFAULT_SEVERITY_FLOOR,
            Some(s) => severity_from_str(s)
                .ok_or_else(|| WriteBuildError::UnknownSeverity(s.to_owned()))?,
        };
        Ok(Self {
            binary: binary.to_path_buf(),
            severity_floor: floor,
            users: users.to_vec(),
            send_timeout: DEFAULT_SEND_TIMEOUT,
        })
    }

    /// Read the configured user list (for tests + introspection).
    #[must_use]
    pub fn users(&self) -> &[String] {
        &self.users
    }

    /// Shared core: per-user `write(1)` invocations. Returns `Ok(true)`
    /// if at least one user write completed cleanly (or none were
    /// attempted because the event is below the severity floor).
    /// Per-user write failures (write(1) exits non-zero when the
    /// target user is not logged in) are logged at warn but do not
    /// abort delivery to the remaining users. Spawn-time failures
    /// (binary missing) surface eagerly.
    async fn deliver_to_users(
        &self,
        severity: SeverityId,
        message: &str,
    ) -> Result<bool, WriteDeliveryError> {
        if (severity as u32) < (self.severity_floor as u32) {
            return Ok(false); // below floor → quietly skipped
        }
        if self.users.is_empty() {
            // Defense-in-depth — from_config refuses this; this guard
            // catches direct struct construction in tests.
            return Err(WriteDeliveryError::NoUsers);
        }
        let mut delivered_any = false;
        let mut last_spawn_err: Option<String> = None;
        for user in &self.users {
            match write_to_user(&self.binary, user, message, self.send_timeout).await {
                Ok(true) => delivered_any = true,
                Ok(false) => {
                    // write(1) exited non-zero (user not logged in,
                    // mesg disabled, etc.). Not a failure of the
                    // channel — log and continue.
                    warn!(
                        channel = "write",
                        target_user = %user,
                        "write(1) exited non-zero (user not logged in or mesg disabled); skipping",
                    );
                }
                Err(e) => {
                    // Spawn-time failure (binary missing, EACCES).
                    // Record but try the rest of the list — if every
                    // user errors, we surface the last error to caller.
                    last_spawn_err = Some(e.to_string());
                    warn!(
                        channel = "write",
                        target_user = %user,
                        error = %e,
                        "write(1) spawn failed",
                    );
                }
            }
        }
        if delivered_any {
            Ok(true)
        } else if let Some(err) = last_spawn_err {
            Err(WriteDeliveryError::Spawn(err))
        } else {
            // Every user write(1) exited non-zero (none of the
            // targets were logged in). Treat as a soft success — the
            // channel ran, no one was reachable, nothing more to do.
            Ok(false)
        }
    }
}

impl Default for WriteChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from constructing a [`WriteChannel`] via
/// [`WriteChannel::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum WriteBuildError {
    #[error("write binary path is empty")]
    EmptyBinary,
    #[error("write users list is empty — at least one target user required")]
    EmptyUsers,
    #[error(
        "write severity_floor must be one of informational|low|medium|high|critical|fatal; got {0:?}"
    )]
    UnknownSeverity(String),
    #[error("write target username contains disallowed characters: {0:?}")]
    UnsafeUsername(String),
}

/// Internal delivery error; bridged into [`NotifierError`] /
/// [`ChannelError`] at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum WriteDeliveryError {
    #[error("write users list is empty")]
    NoUsers,
    #[error("write spawn failed: {0}")]
    Spawn(String),
}

impl From<WriteDeliveryError> for NotifierError {
    fn from(e: WriteDeliveryError) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<WriteDeliveryError> for ChannelError {
    fn from(e: WriteDeliveryError) -> Self {
        Self::Transport(e.to_string())
    }
}

/// Spawn `write(1) <user>` and pipe the message body via stdin.
/// Returns `Ok(true)` on a clean exit (status 0); `Ok(false)` if the
/// child exits non-zero (e.g. user not logged in / mesg disabled);
/// `Err` on spawn-time errors only (binary missing, permission
/// denied at exec time).
async fn write_to_user(
    binary: &Path,
    user: &str,
    message: &str,
    send_timeout: Duration,
) -> Result<bool, std::io::Error> {
    use tokio::io::AsyncWriteExt as _;
    // kill_on_drop: when the deadline below fires, the dropped future takes
    // the child with it instead of leaking a write(1) wedged on a
    // flow-controlled TTY.
    let mut child = tokio::process::Command::new(binary)
        .arg(user)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    // Stdin writes AND the wait sit inside the deadline: a jammed TTY can
    // park the child (and, through the full pipe, our writes) at any point.
    let work = async move {
        if let Some(stdin) = child.stdin.as_mut() {
            // EPIPE tolerance per the wall(1) precedent: the child may
            // close stdin (or exit entirely) before we finish writing.
            // Don't error eagerly — the wait below surfaces the real
            // exit status.
            if let Err(e) = stdin.write_all(message.as_bytes()).await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
            if let Err(e) = stdin.shutdown().await
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
        }
        let output = child.wait_with_output().await?;
        Ok(output.status.success())
    };
    match tokio::time::timeout(send_timeout, work).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "write(1) to user {user:?} timed out after {}s (child killed; jammed TTY?)",
                send_timeout.as_secs_f64()
            ),
        )),
    }
}

/// POSIX-ish username allowlist. Rejects anything outside
/// `[a-zA-Z0-9._-]` — wider than strict POSIX but matches what
/// modern Linux distros accept. No shell metacharacters.
fn is_safe_username(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
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

/// Render the per-user attention banner. Same shape as wall's banner
/// so operators recognise the format across both transports.
fn render_attention_banner(severity: SeverityId, title: &str, event_id: &str) -> String {
    let emoji = severity_emoji(severity);
    format!("{emoji} [selfdef] {severity} — {title}  (event {event_id})\n")
}

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
impl Notifier for WriteChannel {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.binary.as_os_str().is_empty() || self.users.is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        let title = render_title(event);
        let body = render_body(event);
        let banner = render_attention_banner(event.severity_id, &title, &event.id.to_string());
        let message = format!("{banner}{body}");
        self.deliver_to_users(event.severity_id, &message).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "write"
    }
}

#[async_trait]
impl Channel for WriteChannel {
    fn name(&self) -> &str {
        "write"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        if self.binary.as_os_str().is_empty() || self.users.is_empty() {
            return Err(ChannelError::Other("write not configured".into()));
        }
        let event_str = payload
            .event_id
            .map_or_else(|| "—".to_owned(), |id| id.to_string());
        let banner = render_attention_banner(payload.severity, &payload.title, &event_str);
        let message = match &payload.ack_link {
            Some(link) => format!("{banner}{}\nAck: {link}\n", payload.body),
            None => format!("{banner}{}\n", payload.body),
        };
        self.deliver_to_users(payload.severity, &message).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // write(1) is one-way; operators ack via
        // `selfdefctl notify ack <id>` from any shell on the host.
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
            event_kind: None,
            ack_token: None,
        }
    }

    #[test]
    fn default_severity_floor_is_high() {
        assert_eq!(DEFAULT_SEVERITY_FLOOR, SeverityId::High);
    }

    #[test]
    fn default_constructor_uses_built_in_defaults() {
        let w = WriteChannel::new();
        assert_eq!(w.binary, PathBuf::from(DEFAULT_WRITE_BINARY));
        assert_eq!(w.severity_floor, DEFAULT_SEVERITY_FLOOR);
        assert!(w.users.is_empty());
    }

    #[test]
    fn from_config_rejects_empty_binary() {
        let err = WriteChannel::from_config(&PathBuf::new(), None, &["alice".to_owned()])
            .expect_err("empty binary must fail");
        assert!(matches!(err, WriteBuildError::EmptyBinary));
    }

    #[test]
    fn from_config_rejects_empty_users() {
        let err = WriteChannel::from_config(&PathBuf::from("/bin/true"), None, &[])
            .expect_err("empty users must fail");
        assert!(matches!(err, WriteBuildError::EmptyUsers));
    }

    #[test]
    fn from_config_rejects_unknown_severity() {
        let err = WriteChannel::from_config(
            &PathBuf::from("/bin/true"),
            Some("yolo"),
            &["alice".to_owned()],
        )
        .expect_err("unknown severity must fail");
        assert!(matches!(err, WriteBuildError::UnknownSeverity(_)));
    }

    #[test]
    fn from_config_rejects_unsafe_username() {
        let bad = ["alice; rm -rf /".to_owned()];
        let err = WriteChannel::from_config(&PathBuf::from("/bin/true"), None, &bad)
            .expect_err("unsafe username must fail");
        assert!(matches!(err, WriteBuildError::UnsafeUsername(_)));
    }

    #[test]
    fn from_config_accepts_empty_severity_string_as_default() {
        let w =
            WriteChannel::from_config(&PathBuf::from("/bin/true"), Some(""), &["alice".to_owned()])
                .expect("empty severity → default");
        assert_eq!(w.severity_floor, DEFAULT_SEVERITY_FLOOR);
    }

    #[test]
    fn from_config_parses_severity_case_insensitive() {
        let w = WriteChannel::from_config(
            &PathBuf::from("/bin/true"),
            Some("CRITICAL"),
            &["alice".to_owned()],
        )
        .expect("ok");
        assert_eq!(w.severity_floor, SeverityId::Critical);
    }

    #[test]
    fn safe_username_accepts_standard_shapes() {
        assert!(is_safe_username("alice"));
        assert!(is_safe_username("ops_team_member"));
        assert!(is_safe_username("user.name"));
        assert!(is_safe_username("user-name-42"));
    }

    #[test]
    fn safe_username_rejects_shell_meta() {
        assert!(!is_safe_username(""));
        assert!(!is_safe_username("alice; rm -rf /"));
        assert!(!is_safe_username("alice $bob"));
        assert!(!is_safe_username("alice`cmd`"));
        assert!(!is_safe_username("alice|cmd"));
        assert!(!is_safe_username("alice/bob"));
    }

    #[test]
    fn severity_emoji_maps_consistently() {
        assert_eq!(severity_emoji(SeverityId::High), "🚨");
        assert_eq!(severity_emoji(SeverityId::Critical), "🔥");
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
        let w = WriteChannel::new();
        assert_eq!(<WriteChannel as Notifier>::name(&w), "write");
        assert_eq!(<WriteChannel as Channel>::name(&w), "write");
    }

    #[tokio::test]
    async fn notify_with_empty_users_returns_not_configured() {
        let w = WriteChannel::new(); // users empty by default
        let e = finding_event();
        assert!(matches!(
            <WriteChannel as Notifier>::notify(&w, &e).await,
            Err(NotifierError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn channel_send_with_empty_users_returns_other() {
        let w = WriteChannel::new();
        let p = mk_payload_with_severity(SeverityId::High);
        match <WriteChannel as Channel>::send(&w, &p).await {
            Err(ChannelError::Other(_)) => {}
            other => panic!("expected ChannelError::Other, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn below_severity_floor_is_a_noop() {
        // /bin/false would fail if spawned, but the below-floor
        // event MUST short-circuit before the spawn.
        let w = WriteChannel::new()
            .with_binary("/bin/false")
            .with_severity_floor(SeverityId::Critical)
            .with_users(["alice"]);
        let mut e = finding_event();
        e.severity_id = SeverityId::High; // below the Critical floor
        let result = <WriteChannel as Notifier>::notify(&w, &e).await;
        assert!(
            result.is_ok(),
            "below-floor event must not spawn /bin/false; got {result:?}",
        );
    }

    #[tokio::test]
    async fn at_or_above_floor_spawns_and_uses_exit_status() {
        // /bin/true accepts piped stdin and exits 0 → success.
        let w = WriteChannel::new()
            .with_binary("/bin/true")
            .with_severity_floor(SeverityId::High)
            .with_users(["alice"]);
        let e = finding_event();
        let result = <WriteChannel as Notifier>::notify(&w, &e).await;
        assert!(result.is_ok(), "/bin/true must succeed; got {result:?}");
    }

    #[tokio::test]
    async fn write_exits_nonzero_when_no_user_logged_in_is_soft_success() {
        // /bin/false exits 1 — simulates "user not logged in".
        // Channel should return Ok (soft success), not Err.
        let w = WriteChannel::new()
            .with_binary("/bin/false")
            .with_severity_floor(SeverityId::High)
            .with_users(["alice"]);
        let p = mk_payload_with_severity(SeverityId::High);
        let result = <WriteChannel as Channel>::send(&w, &p).await;
        assert!(
            result.is_ok(),
            "write exits nonzero for not-logged-in user must be soft success; got {result:?}",
        );
    }

    #[tokio::test]
    async fn missing_binary_surfaces_as_transport_error() {
        let w = WriteChannel::new()
            .with_binary("/nonexistent/write-binary")
            .with_severity_floor(SeverityId::High)
            .with_users(["alice"]);
        let p = mk_payload_with_severity(SeverityId::High);
        let result = <WriteChannel as Channel>::send(&w, &p).await;
        match result {
            Err(ChannelError::Transport(_)) => {} // spawn fails
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delivers_to_all_users_in_order() {
        // /bin/true succeeds for both users; we just assert no error.
        let w = WriteChannel::new()
            .with_binary("/bin/true")
            .with_severity_floor(SeverityId::High)
            .with_users(["alice", "bob", "charlie"]);
        let p = mk_payload_with_severity(SeverityId::High);
        let result = <WriteChannel as Channel>::send(&w, &p).await;
        assert!(
            result.is_ok(),
            "multi-user delivery should succeed; got {result:?}"
        );
    }

    /// The no-hang contract: a write(1) wedged on a flow-controlled TTY
    /// (stand-in: a script that swallows stdin then sleeps past the
    /// deadline) must time out per-user and let the loop continue — NOT
    /// hang the sequential notifier chain. Worst case stays bounded at
    /// users × timeout.
    #[tokio::test]
    async fn jammed_write_times_out_instead_of_blocking_forever() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("jammed-write");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            f.write_all(b"#!/bin/sh\ncat >/dev/null\nsleep 60\n")
                .unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let w = WriteChannel::new()
            .with_binary(&script)
            .with_users(["alice"])
            .with_severity_floor(SeverityId::High)
            .with_send_timeout(std::time::Duration::from_millis(200));

        let start = std::time::Instant::now();
        let result = <WriteChannel as Notifier>::notify(&w, &finding_event()).await;
        let elapsed = start.elapsed();

        // Every target timed out → surfaces as the channel's error path.
        assert!(result.is_err(), "jammed write must error, got {result:?}");
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("timed out"), "expected timeout error: {msg}");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "must return promptly after the deadline, took {elapsed:?}"
        );
    }
}
