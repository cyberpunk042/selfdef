//! signal-cli outbound channel for the selfdef notifier.
//!
//! SDD-008 D-2c: graduated out of `selfdef-notifier` into its own
//! integration crate, following the pattern D-2b set for ntfy. The
//! struct implements **both** the legacy
//! [`selfdef_notifier::Notifier`] trait and the forward-looking
//! [`selfdef_notifier_orchestrator::Channel`] trait so existing M4
//! callers and the future orchestrator (D-5+) both consume the same
//! impl through their respective ABIs.
//!
//! Behaviour is unchanged from the M4 implementation: spawns
//! `signal-cli -a <account> send -m <message> <recipient>` via
//! `tokio::process::Command`. Useful as a fallback channel when the
//! network ntfy path is down.
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the taxonomy + acknowledgement model and
//! [`docs/dev/integrations.md`](../../../docs/dev/integrations.md) for
//! the contributor-facing crate template this implements.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};

/// Hard ceiling on one signal-cli send. signal-cli is a network-touching
/// JVM process: on a black-holed network (or a wedged JVM) it can hang
/// indefinitely, and the notifier chain awaits channels SEQUENTIALLY — one
/// hung send would block every later channel, defeating the chain's whole
/// failover purpose on the path that must never go dark. 30s allows JVM
/// startup plus a slow send; on expiry the child is killed (`kill_on_drop`)
/// and the error lets the chain move to the next channel.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// signal-cli outbound channel.
#[derive(Debug)]
pub struct SignalCliNotifier {
    binary: PathBuf,
    account: String,
    recipient: String,
    send_timeout: Duration,
}

impl SignalCliNotifier {
    /// Construct from an explicit binary path + sender account + recipient.
    #[must_use]
    pub fn new(binary: PathBuf, account: String, recipient: String) -> Self {
        Self {
            binary,
            account,
            recipient,
            send_timeout: DEFAULT_SEND_TIMEOUT,
        }
    }

    /// Builder: override the per-send subprocess deadline
    /// ([`DEFAULT_SEND_TIMEOUT`]). Tests use a short value with a slow
    /// stand-in binary to lock the no-hang contract.
    #[must_use]
    pub fn with_send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Shared core: shell out to `signal-cli` with the rendered
    /// message. Used by both trait impls so wire behaviour stays
    /// byte-identical regardless of caller path.
    async fn run(&self, message: &str) -> Result<(), SignalDeliveryError> {
        if self.account.is_empty() || self.recipient.is_empty() {
            return Err(SignalDeliveryError::NotConfigured);
        }
        // kill_on_drop: when the timeout below fires, the dropped future
        // takes the child with it instead of leaking a wedged JVM.
        let pending = tokio::process::Command::new(&self.binary)
            .arg("-a")
            .arg(&self.account)
            .arg("send")
            .arg("-m")
            .arg(message)
            .arg(&self.recipient)
            .kill_on_drop(true)
            .output();
        let output = match tokio::time::timeout(self.send_timeout, pending).await {
            Ok(r) => r.map_err(SignalDeliveryError::Io)?,
            Err(_) => {
                return Err(SignalDeliveryError::Timeout {
                    secs: self.send_timeout.as_secs_f64(),
                });
            }
        };
        if output.status.success() {
            Ok(())
        } else {
            Err(SignalDeliveryError::Subprocess {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }
}

/// Internal delivery error; bridged into [`NotifierError`] (legacy)
/// and [`ChannelError`] (orchestrator) at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum SignalDeliveryError {
    #[error("signal-cli not configured (empty account or recipient)")]
    NotConfigured,
    #[error("signal-cli io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signal-cli exited with status {status}: {stderr}")]
    Subprocess { status: i32, stderr: String },
    #[error("signal-cli send timed out after {secs}s (child killed)")]
    Timeout { secs: f64 },
}

impl From<SignalDeliveryError> for NotifierError {
    fn from(e: SignalDeliveryError) -> Self {
        match e {
            SignalDeliveryError::NotConfigured => Self::NotConfigured,
            SignalDeliveryError::Io(err) => Self::Io(err),
            SignalDeliveryError::Subprocess { status, stderr } => {
                Self::SignalCli { status, stderr }
            }
            SignalDeliveryError::Timeout { secs } => Self::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("signal-cli send timed out after {secs}s (child killed)"),
            )),
        }
    }
}

impl From<SignalDeliveryError> for ChannelError {
    fn from(e: SignalDeliveryError) -> Self {
        match e {
            SignalDeliveryError::NotConfigured => {
                Self::Other("signal-cli not configured (empty account or recipient)".into())
            }
            SignalDeliveryError::Io(err) => Self::Transport(err.to_string()),
            SignalDeliveryError::Subprocess { status, stderr } => {
                // Subprocess exit codes don't naturally map to HTTP-style
                // statuses; cast into the Remote variant's u16 with a
                // documented caveat — orchestrator-side handling treats
                // any non-success as a terminal attempt either way.
                Self::Remote {
                    status: status.unsigned_abs() as u16,
                    body: stderr,
                }
            }
            SignalDeliveryError::Timeout { secs } => Self::Transport(format!(
                "signal-cli send timed out after {secs}s (child killed)"
            )),
        }
    }
}

#[async_trait]
impl Notifier for SignalCliNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let message = format!("{}\n\n{}", render_title(event), render_body(event));
        self.run(&message).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "signal"
    }
}

#[async_trait]
impl Channel for SignalCliNotifier {
    fn name(&self) -> &str {
        "signal"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        // Orchestrator-mode payloads carry pre-rendered title/body.
        // We concatenate them in the same shape the legacy path uses
        // so the recipient sees identical message bodies regardless
        // of which trait the caller went through.
        let message = format!("{}\n\n{}", payload.title, payload.body);
        self.run(&message).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // Per SDD-008 Q-B working assumption: v1 of the orchestrator
        // skips channel-native Signal ack (would require running
        // signal-cli in daemon-mode and parsing JSONRPC replies).
        // Acks come through the CLI / HTTP click-link path instead.
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
    use selfdef_core::prelude::SeverityId;
    use selfdef_notifier_orchestrator::PayloadId;

    fn finding_event() -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::High,
            "test-host",
            "selfdef.correlator.test",
            0,
        )
        .with_message("Possible SSH brute force from 192.0.2.5")
    }

    #[tokio::test]
    async fn notify_returns_not_configured_when_account_empty() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/false"),
            String::new(),
            "+15551234567".into(),
        );
        let e = finding_event();
        assert!(matches!(
            <SignalCliNotifier as Notifier>::notify(&n, &e).await,
            Err(NotifierError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_recipient_empty() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/false"),
            "+15550000000".into(),
            String::new(),
        );
        let payload = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
            ack_token: None,
        };
        let result = <SignalCliNotifier as Channel>::send(&n, &payload).await;
        assert!(matches!(result, Err(ChannelError::Other(_))));
    }

    #[test]
    fn channel_name_matches_notifier_name() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/false"),
            "+15550000000".into(),
            "+15551234567".into(),
        );
        assert_eq!(<SignalCliNotifier as Notifier>::name(&n), "signal");
        assert_eq!(<SignalCliNotifier as Channel>::name(&n), "signal");
    }

    // Subprocess-exec tests use coreutils `/bin/true` and `/bin/false`
    // which are universally available on the daemon's target platforms
    // (Linux). They exercise the three terminal outcomes of `run()`
    // (success, non-zero exit, exec failure) without requiring the
    // real `signal-cli` binary.

    fn payload() -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "alert title".into(),
            body: "alert body".into(),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
            ack_token: None,
        }
    }

    #[tokio::test]
    async fn run_succeeds_when_binary_exits_zero() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/true"),
            "+15550000000".into(),
            "+15551234567".into(),
        );
        let r = <SignalCliNotifier as Channel>::send(&n, &payload()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn run_maps_nonzero_exit_to_remote_error() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/false"),
            "+15550000000".into(),
            "+15551234567".into(),
        );
        let r = <SignalCliNotifier as Channel>::send(&n, &payload()).await;
        match r {
            Err(ChannelError::Remote { status, .. }) => {
                assert_eq!(status, 1, "/bin/false exits 1");
            }
            other => panic!("expected Remote(1), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_maps_missing_binary_to_transport_error() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/nonexistent/path/to/signal-cli"),
            "+15550000000".into(),
            "+15551234567".into(),
        );
        let r = <SignalCliNotifier as Channel>::send(&n, &payload()).await;
        match r {
            Err(ChannelError::Transport(_)) => {}
            other => panic!("expected Transport(io), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn legacy_notify_succeeds_when_binary_exits_zero() {
        let n = SignalCliNotifier::new(
            PathBuf::from("/bin/true"),
            "+15550000000".into(),
            "+15551234567".into(),
        );
        let r = <SignalCliNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    /// The no-hang contract: a wedged signal-cli (stand-in: a script that
    /// sleeps far past the deadline) must surface a timeout error within the
    /// configured send deadline — NOT hang. The notifier chain awaits
    /// channels sequentially, so a hang here would block every later
    /// channel and silence ALL alerting.
    #[tokio::test]
    async fn hung_signal_cli_times_out_instead_of_blocking_forever() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hung-signal-cli");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            // Ignores the notifier's args and wedges; `--probe` is the fast
            // liveness path used below to clear the ETXTBSY window.
            f.write_all(b"#!/bin/sh\nif [ \"$1\" = \"--probe\" ]; then exit 0; fi\nsleep 60\n")
                .unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Writing an executable and exec'ing it inside a multi-threaded test
        // binary races with other threads' fork()/exec(): a concurrent fork can
        // momentarily hold our write fd, so the exec returns `ETXTBSY`
        // ("Text file busy") instead of running the script. That surfaced as a
        // non-timeout io error and made this test flaky under the parallel
        // `cargo test --workspace` run (green in isolation, red under load).
        // Probe the script with the fast `--probe` path until it runs cleanly,
        // waiting out the transient window BEFORE the timed measurement, so the
        // test genuinely exercises the timeout path every time.
        for _ in 0..200 {
            match std::process::Command::new(&script).arg("--probe").output() {
                Ok(_) => break,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("probe failed for an unexpected reason: {e}"),
            }
        }

        let n = SignalCliNotifier::new(script, "+15550000000".into(), "+15551234567".into())
            .with_send_timeout(Duration::from_millis(500));

        let start = std::time::Instant::now();
        let r = <SignalCliNotifier as Notifier>::notify(&n, &finding_event()).await;
        let elapsed = start.elapsed();

        assert!(r.is_err(), "hung child must surface an error, got {r:?}");
        let msg = format!("{}", r.unwrap_err());
        assert!(msg.contains("timed out"), "expected timeout error: {msg}");
        // The contract is "does NOT hang for the child's full 60s sleep" — the
        // deadline fired and returned. The bound only has to sit comfortably
        // below 60s; a tight wall-clock assertion would re-introduce load
        // flakiness (scheduler delay after the logical 500ms deadline under a
        // saturated workspace run), so 30s proves no-hang without racing.
        assert!(
            elapsed < Duration::from_secs(30),
            "must return after the deadline rather than hanging the full 60s child sleep, took {elapsed:?}"
        );
    }
}
