//! SMTP outbound channel for the selfdef notifier.
//!
//! SDD-008 D-7 Q-E: first **new** integration crate (not a refactor),
//! built against the [`docs/dev/integrations.md`](../../../docs/dev/integrations.md)
//! template established by D-1. Validates that the template carries
//! a fresh service from zero without scope creep.
//!
//! Behaviour: connects to an operator-supplied SMTP relay over
//! STARTTLS or implicit-TLS, authenticates with PLAIN, and emits one
//! email per [`Payload`] or [`selfdef_core::Event`]. The struct
//! implements **both** the legacy [`Notifier`] trait and the
//! forward-looking [`selfdef_notifier_orchestrator::Channel`] trait
//! so existing M4 callers (none today; this is net-new) and the
//! orchestrator (D-5+) both consume the same impl through their
//! respective ABIs.
//!
//! Q-D / Q-F deliberately deferred: this channel ships
//! `supports_ack_reply = false` for v1; ack arrives through the
//! orchestrator's HTTP click-link path (D-4) which the channel
//! threads into [`Payload::ack_link`].
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the taxonomy and acknowledgement model.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use selfdef_core::Event;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use tracing::warn;

/// TLS profile for the SMTP transport.
#[derive(Copy, Clone, Debug, Default)]
pub enum TlsProfile {
    /// STARTTLS on a plain port (typically 587). Required by most
    /// public SMTP relays.
    #[default]
    StartTls,
    /// Implicit TLS from the connect (typically 465).
    ImplicitTls,
    /// Plaintext — only for an in-network testing relay; refused for
    /// any auth-bearing send.
    Plain,
}

/// SMTP outbound channel.
pub struct SmtpNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
}

impl std::fmt::Debug for SmtpNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately elide the transport (which carries the
        // credentials secret) and the recipient list (which could
        // include personal email addresses) from the Debug output.
        f.debug_struct("SmtpNotifier")
            .field("from_domain", &self.from.email.domain())
            .field("to_count", &self.to.len())
            .finish_non_exhaustive()
    }
}

impl SmtpNotifier {
    /// Construct from an already-built transport + sender + recipient
    /// list. Useful for tests and for callers that want full control
    /// over the lettre transport configuration.
    #[must_use]
    pub fn new(
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
        to: Vec<Mailbox>,
    ) -> Self {
        Self {
            transport,
            from,
            to,
        }
    }

    /// Construct from config-shaped inputs: relay host/port, TLS
    /// profile, optional username, optional path to a password file
    /// (read on construction; mode-check is the operator's concern
    /// today and the orchestrator's concern at D-5+), sender +
    /// recipient list. Returns an error if the recipients list is
    /// empty or if the from address fails to parse.
    ///
    /// Eight parameters earns one `too_many_arguments` allow. A
    /// config-struct refactor is reasonable at D-3 / D-6 when the
    /// orchestrator's typed config layer lands and integration crates
    /// all stop carrying their own constructors with primitive args.
    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        relay_host: &str,
        relay_port: u16,
        tls: TlsProfile,
        username: Option<&str>,
        password_file: Option<&PathBuf>,
        from: &str,
        to: &[String],
        timeout: Duration,
    ) -> Result<Self, SmtpBuildError> {
        if relay_host.is_empty() {
            return Err(SmtpBuildError::EmptyRelayHost);
        }
        if to.is_empty() {
            return Err(SmtpBuildError::EmptyRecipientList);
        }
        let from_mbox: Mailbox = from.parse().map_err(|e: lettre::address::AddressError| {
            SmtpBuildError::InvalidAddress(format!("from: {e}"))
        })?;
        let mut to_mboxes = Vec::with_capacity(to.len());
        for r in to {
            let m: Mailbox = r.parse().map_err(|e: lettre::address::AddressError| {
                SmtpBuildError::InvalidAddress(format!("to {r:?}: {e}"))
            })?;
            to_mboxes.push(m);
        }

        let mut builder: lettre::transport::smtp::AsyncSmtpTransportBuilder = match tls {
            TlsProfile::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(relay_host)
                    .map_err(|e| SmtpBuildError::Transport(e.to_string()))?
            }
            TlsProfile::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(relay_host)
                .map_err(|e| SmtpBuildError::Transport(e.to_string()))?,
            TlsProfile::Plain => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(relay_host)
            }
        };
        builder = builder.port(relay_port).timeout(Some(timeout));

        if let (Some(user), Some(path)) = (username, password_file) {
            let password = std::fs::read_to_string(path)
                .map_err(|e| SmtpBuildError::PasswordFileUnreadable(e.to_string()))?
                .trim()
                .to_owned();
            if password.is_empty() {
                return Err(SmtpBuildError::EmptyPasswordFile);
            }
            if matches!(tls, TlsProfile::Plain) {
                return Err(SmtpBuildError::AuthOverPlain);
            }
            builder = builder.credentials(Credentials::new(user.to_owned(), password));
        }

        Ok(Self::new(builder.build(), from_mbox, to_mboxes))
    }

    /// Shared core used by both trait impls. Builds the lettre
    /// `Message`, dispatches over the transport, surfaces a typed
    /// internal error that the two `From` impls map to
    /// [`NotifierError`] / [`ChannelError`].
    async fn dispatch(
        &self,
        subject: &str,
        body: &str,
    ) -> Result<lettre::transport::smtp::response::Response, SmtpDeliveryError> {
        let mut builder = Message::builder().from(self.from.clone()).subject(subject);
        for recipient in &self.to {
            builder = builder.to(recipient.clone());
        }
        let message = builder
            .body(body.to_owned())
            .map_err(|e| SmtpDeliveryError::Build(e.to_string()))?;
        let response = self
            .transport
            .send(message)
            .await
            .map_err(|e| SmtpDeliveryError::Send(e.to_string()))?;
        Ok(response)
    }
}

/// Errors from constructing an [`SmtpNotifier`] via
/// [`SmtpNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum SmtpBuildError {
    #[error("smtp relay host is empty")]
    EmptyRelayHost,
    #[error("smtp recipient list is empty")]
    EmptyRecipientList,
    #[error("smtp address parse error: {0}")]
    InvalidAddress(String),
    #[error("smtp transport construction failed: {0}")]
    Transport(String),
    #[error("smtp password file unreadable: {0}")]
    PasswordFileUnreadable(String),
    #[error("smtp password file is empty after trim")]
    EmptyPasswordFile,
    #[error("smtp auth requested with plaintext TLS profile; refuse")]
    AuthOverPlain,
}

/// Internal delivery error; bridged into [`NotifierError`] (legacy)
/// and [`ChannelError`] (orchestrator) at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum SmtpDeliveryError {
    #[error("smtp message build error: {0}")]
    Build(String),
    #[error("smtp send error: {0}")]
    Send(String),
}

impl From<SmtpDeliveryError> for NotifierError {
    fn from(e: SmtpDeliveryError) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<SmtpDeliveryError> for ChannelError {
    fn from(e: SmtpDeliveryError) -> Self {
        match e {
            SmtpDeliveryError::Build(msg) => Self::Other(format!("smtp build: {msg}")),
            SmtpDeliveryError::Send(msg) => Self::Transport(msg),
        }
    }
}

#[async_trait]
impl Notifier for SmtpNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let subject = render_title(event);
        let body = render_body(event);
        match self.dispatch(&subject, &body).await {
            Ok(resp) => {
                if resp.is_positive() {
                    Ok(())
                } else {
                    warn!(code = ?resp.code(), "smtp non-positive response");
                    Err(NotifierError::Http(format!(
                        "smtp non-positive response: {:?}",
                        resp.code()
                    )))
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    fn name(&self) -> &'static str {
        "smtp"
    }
}

#[async_trait]
impl Channel for SmtpNotifier {
    fn name(&self) -> &str {
        "smtp"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        // The orchestrator hands us a pre-rendered Payload. If the
        // operator opted into HTTP click-link acks (D-4), the link
        // is embedded into the body separator below so the recipient
        // sees both the event content and the one-tap ack URL.
        let body = match &payload.ack_link {
            Some(link) => format!(
                "{}\n\nAck: {link}\n(or run `selfdefctl notify ack {}`)",
                payload.body,
                payload.id.as_short_str()
            ),
            None => payload.body.clone(),
        };
        let response = self.dispatch(&payload.title, &body).await?;
        if !response.is_positive() {
            warn!(code = ?response.code(), "smtp non-positive response");
            return Err(ChannelError::Remote {
                status: u16::from(response.code().severity as u8) * 100
                    + u16::from(response.code().category as u8) * 10
                    + u16::from(response.code().detail as u8),
                body: format!("smtp non-positive response: {:?}", response.code()),
            });
        }
        // Lettre's `Response` exposes `first_line()` as the canonical
        // server reply. Surface it as the native message id so the
        // orchestrator's ack-correlation path has something stable to
        // log.
        let native_id = response
            .first_line()
            .map(|s| s.to_owned())
            .unwrap_or_default();
        Ok(if native_id.is_empty() {
            DeliveryReceipt::empty()
        } else {
            DeliveryReceipt::native(native_id)
        })
    }

    fn supports_ack_reply(&self) -> bool {
        // v1: HTTP click-link only (orchestrator's D-4 path).
        // Inbound reply parsing (IMAP polling, plus-addressing,
        // VERP) is a follow-up D if operators ask.
        false
    }

    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn ok_transport() -> AsyncSmtpTransport<Tokio1Executor> {
        // A "dangerous" plaintext transport pointed at a TCP port
        // nothing is listening on. We rely on the from_config
        // *validation* path for negative tests; tests for actual
        // SMTP send would need a real catcher (e.g. mailpit) which
        // is out of scope for unit tests.
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
            .port(2)
            .build()
    }

    #[test]
    fn from_config_rejects_empty_relay_host() {
        let err = SmtpNotifier::from_config(
            "",
            587,
            TlsProfile::StartTls,
            None,
            None,
            "alerts@example.org",
            &["op@example.org".to_owned()],
            Duration::from_secs(5),
        )
        .expect_err("empty relay host must fail");
        assert!(matches!(err, SmtpBuildError::EmptyRelayHost));
    }

    #[test]
    fn from_config_rejects_empty_recipient_list() {
        let err = SmtpNotifier::from_config(
            "smtp.example.org",
            587,
            TlsProfile::StartTls,
            None,
            None,
            "alerts@example.org",
            &[],
            Duration::from_secs(5),
        )
        .expect_err("empty recipients must fail");
        assert!(matches!(err, SmtpBuildError::EmptyRecipientList));
    }

    #[test]
    fn from_config_rejects_malformed_address() {
        let err = SmtpNotifier::from_config(
            "smtp.example.org",
            587,
            TlsProfile::StartTls,
            None,
            None,
            "not a valid address!",
            &["op@example.org".to_owned()],
            Duration::from_secs(5),
        )
        .expect_err("invalid from must fail");
        assert!(matches!(err, SmtpBuildError::InvalidAddress(_)));
    }

    #[test]
    fn from_config_rejects_auth_over_plain() {
        let mut pw = tempfile::NamedTempFile::new().unwrap();
        writeln!(pw, "hunter2").unwrap();
        let err = SmtpNotifier::from_config(
            "smtp.example.org",
            25,
            TlsProfile::Plain,
            Some("alerts"),
            Some(&pw.path().to_owned()),
            "alerts@example.org",
            &["op@example.org".to_owned()],
            Duration::from_secs(5),
        )
        .expect_err("plaintext + auth must fail");
        assert!(matches!(err, SmtpBuildError::AuthOverPlain));
    }

    #[test]
    fn from_config_rejects_empty_password_file() {
        let pw = tempfile::NamedTempFile::new().unwrap();
        // file exists but is empty after trim
        let err = SmtpNotifier::from_config(
            "smtp.example.org",
            587,
            TlsProfile::StartTls,
            Some("alerts"),
            Some(&pw.path().to_owned()),
            "alerts@example.org",
            &["op@example.org".to_owned()],
            Duration::from_secs(5),
        )
        .expect_err("empty password file must fail");
        assert!(matches!(err, SmtpBuildError::EmptyPasswordFile));
    }

    #[test]
    fn name_parity() {
        let n = SmtpNotifier::new(
            ok_transport(),
            "alerts@example.org".parse().unwrap(),
            vec!["op@example.org".parse().unwrap()],
        );
        assert_eq!(<SmtpNotifier as Notifier>::name(&n), "smtp");
        assert_eq!(<SmtpNotifier as Channel>::name(&n), "smtp");
    }

    #[test]
    fn debug_elides_credentials_and_recipients() {
        let n = SmtpNotifier::new(
            ok_transport(),
            "alerts@example.org".parse().unwrap(),
            vec![
                "op@example.org".parse().unwrap(),
                "sre@example.org".parse().unwrap(),
            ],
        );
        let s = format!("{n:?}");
        assert!(s.contains("SmtpNotifier"), "{s}");
        assert!(s.contains("from_domain"), "{s}");
        assert!(s.contains("\"example.org\""), "{s}");
        assert!(s.contains("to_count"), "{s}");
        assert!(s.contains("2"), "{s}");
        // explicit anti-coverage: no full recipient address leaks
        assert!(!s.contains("op@example.org"), "leaks recipient: {s}");
        assert!(!s.contains("sre@example.org"), "leaks recipient: {s}");
    }
}
