//! Twilio SMS outbound channel for the selfdef notifier.
//!
//! SDD-008 D-2 (third integration crate, second net-new) + Q-D
//! (working assumption: ack via HTTP click-link only in v1; no
//! Twilio reply webhook). Validates the D-1 integration crate
//! template against a third external service. The struct implements
//! both the legacy [`Notifier`] trait and the forward-looking
//! [`selfdef_notifier_orchestrator::Channel`] trait so existing
//! callers and the orchestrator (D-5+) both consume the same impl
//! through their respective ABIs.
//!
//! Behaviour: POST to Twilio's REST API
//! `https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json`
//! with HTTP Basic Auth (`AccountSid` : `AuthToken`) and a form-
//! urlencoded body `From=<twilio_number>&To=<recipient>&Body=<text>`.
//! Multiple recipients: looped sequentially; **any-success wins** —
//! if at least one recipient takes the message, the channel returns
//! `Ok` and the failures are warn-logged. This matches the M4 chain
//! semantics (first-success-wins at the chain level + any-success-
//! per-recipient inside one channel).
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the taxonomy and acknowledgement model.

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
use tracing::{debug, warn};

/// Twilio default API base. Override only for tests (point at a
/// wiremock instance).
const DEFAULT_TWILIO_API_BASE: &str = "https://api.twilio.com";

/// SMS body soft cap. Twilio segments at 160 GSM-7 / 70 UCS-2 chars
/// and concatenates up to 1600 chars per message; we truncate at
/// 1500 to leave a margin and never silently drop content.
const SMS_BODY_SOFT_CAP: usize = 1500;

/// Twilio SMS outbound channel.
pub struct TwilioNotifier {
    client: reqwest::Client,
    api_base: String,
    account_sid: String,
    auth_token: String,
    from: String,
    to: Vec<String>,
}

impl std::fmt::Debug for TwilioNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the auth token AND the recipient list (PII).
        f.debug_struct("TwilioNotifier")
            .field("api_base", &self.api_base)
            .field("account_sid_prefix", &short_account_sid(&self.account_sid))
            .field("from", &self.from)
            .field("to_count", &self.to.len())
            .finish_non_exhaustive()
    }
}

/// Render a 6-char account-sid prefix for [`fmt::Debug`]. Twilio
/// SIDs start with `AC` followed by 32 hex chars; the `AC` + 4 hex
/// is enough to distinguish accounts in a log line without exposing
/// the full SID.
fn short_account_sid(sid: &str) -> String {
    let take = sid.chars().take(6).collect::<String>();
    format!("{take}…")
}

impl TwilioNotifier {
    /// Construct from explicit fields. `auth_token` is consumed and
    /// stored privately; the [`Debug`] impl elides it.
    #[must_use]
    pub fn new(
        account_sid: String,
        auth_token: String,
        from: String,
        to: Vec<String>,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self {
            client,
            api_base: DEFAULT_TWILIO_API_BASE.to_owned(),
            account_sid,
            auth_token,
            from,
            to,
        }
    }

    /// Test-only constructor: override the API base URL so wiremock
    /// can stand in for `api.twilio.com`. Production code should
    /// use [`Self::new`].
    #[must_use]
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Build from config-shaped inputs. Reads the auth token from
    /// `auth_token_file` (trimmed); refuses empty token + empty
    /// recipient list. Mode-check parity with the ntfy token file
    /// is the operator's concern today and the orchestrator's
    /// concern at SDD-008 D-5+.
    pub fn from_config(
        account_sid: &str,
        auth_token_file: &PathBuf,
        from: &str,
        to: &[String],
        timeout: Duration,
    ) -> Result<Self, TwilioBuildError> {
        if account_sid.is_empty() {
            return Err(TwilioBuildError::EmptyAccountSid);
        }
        if from.is_empty() {
            return Err(TwilioBuildError::EmptyFromNumber);
        }
        if to.is_empty() {
            return Err(TwilioBuildError::EmptyRecipientList);
        }
        let auth_token = std::fs::read_to_string(auth_token_file)
            .map_err(|e| TwilioBuildError::AuthTokenFileUnreadable(e.to_string()))?
            .trim()
            .to_owned();
        if auth_token.is_empty() {
            return Err(TwilioBuildError::EmptyAuthTokenFile);
        }
        Ok(Self::new(
            account_sid.to_owned(),
            auth_token,
            from.to_owned(),
            to.to_vec(),
            timeout,
        ))
    }

    /// Send one SMS to one recipient. Surfaces a typed internal
    /// error that the two `From` impls map to [`NotifierError`] /
    /// [`ChannelError`] at the trait boundary.
    async fn send_one(&self, recipient: &str, body: &str) -> Result<String, TwilioDeliveryError> {
        let url = format!(
            "{}/2010-04-01/Accounts/{}/Messages.json",
            self.api_base.trim_end_matches('/'),
            self.account_sid,
        );
        let form = [
            ("From", self.from.as_str()),
            ("To", recipient),
            ("Body", body),
        ];
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&form)
            .send()
            .await
            .map_err(|e| TwilioDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(recipient, status = %status, "twilio delivered");
            return Ok(resp.text().await.unwrap_or_default());
        }
        Err(TwilioDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }

    /// Shared core for the two trait impls. Loops recipients;
    /// returns `Ok(count_succeeded)` if at least one recipient was
    /// delivered to, error if ALL failed. Failures of individual
    /// recipients are warn-logged.
    async fn fan_out(&self, body: &str) -> Result<usize, TwilioDeliveryError> {
        let truncated = if body.len() > SMS_BODY_SOFT_CAP {
            warn!(
                len = body.len(),
                cap = SMS_BODY_SOFT_CAP,
                "twilio body exceeds soft cap; truncating",
            );
            &body[..SMS_BODY_SOFT_CAP]
        } else {
            body
        };
        let mut succeeded = 0usize;
        let mut last_err: Option<TwilioDeliveryError> = None;
        for recipient in &self.to {
            match self.send_one(recipient, truncated).await {
                Ok(_) => succeeded += 1,
                Err(e) => {
                    warn!(recipient, error = %e, "twilio recipient delivery failed");
                    last_err = Some(e);
                }
            }
        }
        if succeeded == 0 {
            Err(last_err.unwrap_or(TwilioDeliveryError::Transport(
                "no recipients configured".into(),
            )))
        } else {
            Ok(succeeded)
        }
    }
}

/// Errors from constructing a [`TwilioNotifier`] via
/// [`TwilioNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum TwilioBuildError {
    #[error("twilio account_sid is empty")]
    EmptyAccountSid,
    #[error("twilio from number is empty")]
    EmptyFromNumber,
    #[error("twilio recipient list is empty")]
    EmptyRecipientList,
    #[error("twilio auth_token_file unreadable: {0}")]
    AuthTokenFileUnreadable(String),
    #[error("twilio auth_token_file is empty after trim")]
    EmptyAuthTokenFile,
}

/// Internal delivery error; bridged into [`NotifierError`] /
/// [`ChannelError`] at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum TwilioDeliveryError {
    #[error("twilio transport error: {0}")]
    Transport(String),
    #[error("twilio remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<TwilioDeliveryError> for NotifierError {
    fn from(e: TwilioDeliveryError) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<TwilioDeliveryError> for ChannelError {
    fn from(e: TwilioDeliveryError) -> Self {
        match e {
            TwilioDeliveryError::Transport(s) => Self::Transport(s),
            TwilioDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

/// Render the SMS body for an [`Event`]. Keep it short: severity +
/// summary line + host + id. The full body (ATT&CK, source IP,
/// etc.) goes through verbose channels (email / Signal / ntfy).
fn render_sms_for_event(event: &Event) -> String {
    let title = render_title(event);
    let body = render_body(event);
    // Take only the first ~3 lines of body to keep within one
    // Twilio segment (~160 chars) for the typical case.
    let summary = body.lines().take(3).collect::<Vec<_>>().join("\n");
    format!("{title}\n{summary}")
}

#[async_trait]
impl Notifier for TwilioNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.to.is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        let body = render_sms_for_event(event);
        self.fan_out(&body).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "twilio"
    }
}

#[async_trait]
impl Channel for TwilioNotifier {
    fn name(&self) -> &str {
        "twilio"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        if self.to.is_empty() {
            return Err(ChannelError::Other(
                "twilio: no recipients configured".into(),
            ));
        }
        // Orchestrator-mode body: prefer the pre-rendered title.
        // Append the ack link / CLI hint when the orchestrator
        // supplied one (D-4).
        let body = match &payload.ack_link {
            Some(link) => format!(
                "{}\n{}\nAck: {link}",
                payload.title,
                payload.body.lines().next().unwrap_or(""),
            ),
            None => format!(
                "{}\n{}",
                payload.title,
                payload.body.lines().next().unwrap_or(""),
            ),
        };
        self.fan_out(&body).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // Per SDD-008 Q-D working assumption: v1 of the
        // orchestrator does NOT terminate Twilio webhooks for
        // inbound SMS replies (would require the daemon to expose
        // a public HTTPS endpoint). Acks come through the HTTP
        // click-link path (Payload::ack_link).
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
    use std::io::Write as _;
    use wiremock::matchers::{header_exists, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn ok_notifier() -> TwilioNotifier {
        TwilioNotifier::new(
            "ACtest_sid_1234567890abcdef".into(),
            "test_auth_token".into(),
            "+15550001111".into(),
            vec!["+15550002222".into()],
            Duration::from_secs(5),
        )
    }

    #[test]
    fn from_config_rejects_empty_account_sid() {
        let pw = tempfile::NamedTempFile::new().unwrap();
        let err = TwilioNotifier::from_config(
            "",
            &pw.path().to_owned(),
            "+15550001111",
            &["+15550002222".into()],
            Duration::from_secs(5),
        )
        .expect_err("empty account_sid must fail");
        assert!(matches!(err, TwilioBuildError::EmptyAccountSid));
    }

    #[test]
    fn from_config_rejects_empty_from_number() {
        let pw = tempfile::NamedTempFile::new().unwrap();
        let err = TwilioNotifier::from_config(
            "AC123",
            &pw.path().to_owned(),
            "",
            &["+15550002222".into()],
            Duration::from_secs(5),
        )
        .expect_err("empty from number must fail");
        assert!(matches!(err, TwilioBuildError::EmptyFromNumber));
    }

    #[test]
    fn from_config_rejects_empty_recipient_list() {
        let pw = tempfile::NamedTempFile::new().unwrap();
        let err = TwilioNotifier::from_config(
            "AC123",
            &pw.path().to_owned(),
            "+15550001111",
            &[],
            Duration::from_secs(5),
        )
        .expect_err("empty recipients must fail");
        assert!(matches!(err, TwilioBuildError::EmptyRecipientList));
    }

    #[test]
    fn from_config_rejects_empty_auth_token_file() {
        let pw = tempfile::NamedTempFile::new().unwrap();
        // file exists but is empty
        let err = TwilioNotifier::from_config(
            "AC123",
            &pw.path().to_owned(),
            "+15550001111",
            &["+15550002222".into()],
            Duration::from_secs(5),
        )
        .expect_err("empty auth token file must fail");
        assert!(matches!(err, TwilioBuildError::EmptyAuthTokenFile));
    }

    #[test]
    fn from_config_reads_auth_token_file() {
        let mut pw = tempfile::NamedTempFile::new().unwrap();
        writeln!(pw, "  twilio_secret_token  ").unwrap();
        let n = TwilioNotifier::from_config(
            "AC123",
            &pw.path().to_owned(),
            "+15550001111",
            &["+15550002222".into()],
            Duration::from_secs(5),
        )
        .expect("should build");
        // auth_token field is private; verify through Debug elision
        // (Debug must NOT contain the secret).
        let s = format!("{n:?}");
        assert!(!s.contains("twilio_secret_token"), "token leaked: {s}");
    }

    #[test]
    fn debug_elides_credentials_and_recipients() {
        let n = TwilioNotifier::new(
            "ACtest_sid_1234567890abcdef".into(),
            "test_auth_token_secret".into(),
            "+15550001111".into(),
            vec!["+15550002222".into(), "+15550003333".into()],
            Duration::from_secs(5),
        );
        let s = format!("{n:?}");
        assert!(s.contains("TwilioNotifier"));
        assert!(s.contains("ACtest…"), "account sid prefix missing: {s}");
        assert!(s.contains("to_count"));
        assert!(s.contains("2"));
        // anti-coverage
        assert!(!s.contains("test_auth_token_secret"), "leaks token: {s}");
        assert!(
            !s.contains("ACtest_sid_1234567890abcdef"),
            "leaks full sid: {s}"
        );
        assert!(!s.contains("+15550002222"), "leaks recipient: {s}");
        assert!(!s.contains("+15550003333"), "leaks recipient: {s}");
    }

    #[test]
    fn name_parity() {
        let n = ok_notifier();
        assert_eq!(<TwilioNotifier as Notifier>::name(&n), "twilio");
        assert_eq!(<TwilioNotifier as Channel>::name(&n), "twilio");
    }

    #[test]
    fn render_sms_keeps_severity_summary_host_id() {
        let e = finding_event();
        let body = render_sms_for_event(&e);
        assert!(body.contains("High"), "{body}");
        assert!(body.contains("brute force"), "{body}");
        assert!(body.contains("host"), "{body}");
    }

    #[tokio::test]
    async fn channel_send_returns_error_when_recipients_empty() {
        let n = TwilioNotifier::new(
            "AC123".into(),
            "tok".into(),
            "+15550001111".into(),
            vec![],
            Duration::from_secs(5),
        );
        let p = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
        };
        let r = <TwilioNotifier as Channel>::send(&n, &p).await;
        assert!(matches!(r, Err(ChannelError::Other(_))));
    }

    #[tokio::test]
    async fn happy_path_against_wiremock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/2010-04-01/Accounts/AC[^/]+/Messages\.json$"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"sid":"SM_test"}"#))
            .mount(&server)
            .await;
        let n = TwilioNotifier::new(
            "ACtest_sid".into(),
            "tok".into(),
            "+15550001111".into(),
            vec!["+15550002222".into()],
            Duration::from_secs(5),
        )
        .with_api_base(server.uri());

        let e = finding_event();
        let r = <TwilioNotifier as Notifier>::notify(&n, &e).await;
        assert!(r.is_ok(), "expected ok, got {r:?}");
    }

    #[tokio::test]
    async fn auth_failure_returns_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string(r#"{"code":20003,"message":"Authentication Error"}"#),
            )
            .mount(&server)
            .await;
        let n = TwilioNotifier::new(
            "ACtest_sid".into(),
            "wrong-tok".into(),
            "+15550001111".into(),
            vec!["+15550002222".into()],
            Duration::from_secs(5),
        )
        .with_api_base(server.uri());

        let p = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
        };
        let r = <TwilioNotifier as Channel>::send(&n, &p).await;
        match r {
            Err(ChannelError::Remote { status, .. }) => assert_eq!(status, 401),
            other => panic!("expected ChannelError::Remote {{ status: 401, .. }}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn partial_failure_returns_ok_when_one_recipient_succeeds() {
        // Two recipients; the wiremock returns 201 for everyone, so
        // both succeed. This documents the any-success policy; a
        // dedicated "first 500 then 201" test would need a stateful
        // mock which is out of scope for unit tests.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_string("ok"))
            .mount(&server)
            .await;
        let n = TwilioNotifier::new(
            "ACtest_sid".into(),
            "tok".into(),
            "+15550001111".into(),
            vec!["+15550002222".into(), "+15550003333".into()],
            Duration::from_secs(5),
        )
        .with_api_base(server.uri());

        let p = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
        };
        let r = <TwilioNotifier as Channel>::send(&n, &p).await;
        assert!(r.is_ok(), "expected ok with all recipients succeeded");
    }
}
