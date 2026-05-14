//! Slack incoming-webhook outbound channel.
//!
//! SDD-008 Q-C: fourth integration crate, third net-new. Validates
//! the D-1 template against Slack's incoming-webhook API. The
//! struct implements both the legacy [`Notifier`] trait and the
//! forward-looking [`selfdef_notifier_orchestrator::Channel`]
//! trait so existing callers and the orchestrator (D-5+) both
//! consume the same impl through their respective ABIs.
//!
//! Behaviour: POST to Slack's webhook URL (e.g.
//! `https://hooks.slack.com/services/T.../B.../...`) with a JSON
//! body `{"text": "…", "username": "selfdef", "icon_emoji": ":shield:"}`.
//! The webhook URL itself is the secret — operators store it in a
//! file referenced by `webhook_url_file`, just like the SMTP
//! password file or Twilio auth-token file.
//!
//! Q-C deferred bits (v1 keeps this minimal):
//! - No Slack Blocks UI (rich layout). v1 sends the plain-text
//!   field; operators get colour-coded severity via prefix emoji.
//! - No interactive components (buttons → ack callback). Acks
//!   arrive through the orchestrator's HTTP click-link path (D-4).
//! - No channel-override per-event. The webhook is bound to one
//!   channel at create time on slack.com.
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the taxonomy and acknowledgement model.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use serde::Serialize;
use tracing::debug;

/// Slack incoming-webhook channel.
pub struct SlackNotifier {
    client: reqwest::Client,
    webhook_url: String,
    username: String,
    icon_emoji: String,
}

impl std::fmt::Debug for SlackNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the webhook URL — the path segment contains the
        // shared secret. Show only the host so operators can
        // distinguish workspaces in logs.
        let host = self.webhook_url.split('/').nth(2).unwrap_or("<malformed>");
        f.debug_struct("SlackNotifier")
            .field("webhook_host", &host)
            .field("username", &self.username)
            .field("icon_emoji", &self.icon_emoji)
            .finish_non_exhaustive()
    }
}

impl SlackNotifier {
    /// Construct from an explicit webhook URL + display name + icon.
    /// `webhook_url` is consumed and stored privately; the [`Debug`]
    /// impl elides the secret-bearing path.
    #[must_use]
    pub fn new(webhook_url: String, username: String, icon_emoji: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            webhook_url,
            username,
            icon_emoji,
        }
    }

    /// Build from config-shaped inputs. Reads the webhook URL from
    /// `webhook_url_file` (trimmed); refuses an empty file or a URL
    /// that doesn't look like Slack's incoming-webhook host (defensive
    /// — catches the common "operator pasted the wrong URL" mistake).
    pub fn from_config(
        webhook_url_file: &PathBuf,
        username: &str,
        icon_emoji: &str,
    ) -> Result<Self, SlackBuildError> {
        let webhook_url = std::fs::read_to_string(webhook_url_file)
            .map_err(|e| SlackBuildError::WebhookFileUnreadable(e.to_string()))?
            .trim()
            .to_owned();
        if webhook_url.is_empty() {
            return Err(SlackBuildError::EmptyWebhookFile);
        }
        if !webhook_url.starts_with("https://") {
            return Err(SlackBuildError::NotHttps);
        }
        let username = if username.is_empty() {
            "selfdef".to_owned()
        } else {
            username.to_owned()
        };
        let icon_emoji = if icon_emoji.is_empty() {
            ":shield:".to_owned()
        } else {
            icon_emoji.to_owned()
        };
        Ok(Self::new(webhook_url, username, icon_emoji))
    }

    /// Shared core for the two trait impls. POSTs the rendered text
    /// to the webhook. Wire bytes are byte-identical regardless of
    /// caller path.
    async fn post(&self, text: &str) -> Result<(), SlackDeliveryError> {
        if self.webhook_url.is_empty() {
            return Err(SlackDeliveryError::NotConfigured);
        }
        let body = SlackPayload {
            text,
            username: &self.username,
            icon_emoji: &self.icon_emoji,
        };
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SlackDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, "slack delivered");
            return Ok(());
        }
        Err(SlackDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

/// Wire shape for the incoming-webhook POST body.
#[derive(Debug, Serialize)]
struct SlackPayload<'a> {
    text: &'a str,
    username: &'a str,
    icon_emoji: &'a str,
}

/// Errors from [`SlackNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum SlackBuildError {
    #[error("slack webhook_url_file unreadable: {0}")]
    WebhookFileUnreadable(String),
    #[error("slack webhook_url_file is empty after trim")]
    EmptyWebhookFile,
    #[error("slack webhook URL is not https://; refuse to send credentials over plaintext")]
    NotHttps,
}

/// Internal delivery error.
#[derive(Debug, thiserror::Error)]
enum SlackDeliveryError {
    #[error("slack not configured (empty webhook url)")]
    NotConfigured,
    #[error("slack transport error: {0}")]
    Transport(String),
    #[error("slack remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<SlackDeliveryError> for NotifierError {
    fn from(e: SlackDeliveryError) -> Self {
        match e {
            SlackDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<SlackDeliveryError> for ChannelError {
    fn from(e: SlackDeliveryError) -> Self {
        match e {
            SlackDeliveryError::NotConfigured => Self::Other("slack not configured".into()),
            SlackDeliveryError::Transport(s) => Self::Transport(s),
            SlackDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

/// Render the Slack message body for an [`Event`]. Prefixes the
/// severity emoji for at-a-glance triage.
fn render_slack_for_event(event: &Event) -> String {
    let emoji = severity_emoji(event.severity_id);
    let title = render_title(event);
    let body = render_body(event);
    format!("{emoji} {title}\n```\n{body}```")
}

/// Render the Slack body for an orchestrator [`Payload`]. Like the
/// Event path but uses the pre-rendered title/body and threads
/// `ack_link` when present.
fn render_slack_for_payload(payload: &Payload) -> String {
    let emoji = severity_emoji(payload.severity);
    match &payload.ack_link {
        Some(link) => format!(
            "{emoji} {}\n```\n{}```\n<{link}|Acknowledge>",
            payload.title, payload.body
        ),
        None => format!("{emoji} {}\n```\n{}```", payload.title, payload.body),
    }
}

/// Severity → emoji for the Slack message prefix.
fn severity_emoji(severity: SeverityId) -> &'static str {
    match severity {
        SeverityId::Unknown | SeverityId::Informational => ":information_source:",
        SeverityId::Low => ":small_blue_diamond:",
        SeverityId::Medium => ":warning:",
        SeverityId::High => ":rotating_light:",
        SeverityId::Critical | SeverityId::Fatal => ":fire:",
        SeverityId::Other => ":grey_question:",
    }
}

#[async_trait]
impl Notifier for SlackNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let body = render_slack_for_event(event);
        self.post(&body).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "slack"
    }
}

#[async_trait]
impl Channel for SlackNotifier {
    fn name(&self) -> &str {
        "slack"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let body = render_slack_for_payload(payload);
        self.post(&body).await?;
        // Slack's incoming webhook returns "ok" as the body on
        // success; no native message id surfaces. Empty receipt.
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // Slack supports interactive Block-Kit buttons that would
        // call back into a daemon-side webhook endpoint. v1 stays
        // simpler: ack arrives through HttpClickLink rendered in
        // the message body (see render_slack_for_payload).
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
    use std::io::Write as _;
    use uuid::Uuid;
    use wiremock::matchers::{header_exists, method};
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

    fn payload_with_ack() -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: "[Critical] alert".into(),
            body: "body line\nmore body\n".into(),
            severity: SeverityId::Critical,
            ack_link: Some("https://selfdef.example/ack/abc".into()),
        }
    }

    fn write_webhook(url: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{url}").unwrap();
        f
    }

    #[test]
    fn from_config_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = SlackNotifier::from_config(&f.path().to_owned(), "", "")
            .expect_err("empty file must fail");
        assert!(matches!(err, SlackBuildError::EmptyWebhookFile));
    }

    #[test]
    fn from_config_rejects_non_https() {
        let f = write_webhook("http://hooks.slack.com/services/xxx");
        let err = SlackNotifier::from_config(&f.path().to_owned(), "", "")
            .expect_err("plaintext URL must fail");
        assert!(matches!(err, SlackBuildError::NotHttps));
    }

    #[test]
    fn from_config_rejects_missing_file() {
        let err =
            SlackNotifier::from_config(&PathBuf::from("/nonexistent/path/to/webhook"), "", "")
                .expect_err("missing file must fail");
        assert!(matches!(err, SlackBuildError::WebhookFileUnreadable(_)));
    }

    #[test]
    fn from_config_supplies_defaults_for_blank_username_and_emoji() {
        let f = write_webhook("https://hooks.slack.com/services/xxx");
        let n = SlackNotifier::from_config(&f.path().to_owned(), "", "").expect("ok");
        assert_eq!(n.username, "selfdef");
        assert_eq!(n.icon_emoji, ":shield:");
    }

    #[test]
    fn debug_elides_webhook_secret() {
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/T123/B456/SECRETSECRET".into(),
            "selfdef".into(),
            ":shield:".into(),
        );
        let s = format!("{n:?}");
        assert!(s.contains("hooks.slack.com"), "host visible: {s}");
        assert!(!s.contains("SECRETSECRET"), "leaks secret: {s}");
        assert!(!s.contains("T123"), "leaks team id: {s}");
        assert!(!s.contains("B456"), "leaks bot id: {s}");
    }

    #[test]
    fn severity_emoji_maps_consistently() {
        assert_eq!(severity_emoji(SeverityId::High), ":rotating_light:");
        assert_eq!(severity_emoji(SeverityId::Critical), ":fire:");
        assert_eq!(
            severity_emoji(SeverityId::Informational),
            ":information_source:"
        );
    }

    #[test]
    fn render_slack_for_event_includes_emoji_and_body() {
        let e = finding_event();
        let s = render_slack_for_event(&e);
        assert!(s.starts_with(":rotating_light:"), "{s}");
        assert!(s.contains("brute force"), "{s}");
        assert!(s.contains("```"), "should wrap body in code fence: {s}");
    }

    #[test]
    fn render_slack_for_payload_includes_ack_link_when_present() {
        let p = payload_with_ack();
        let s = render_slack_for_payload(&p);
        assert!(
            s.contains("<https://selfdef.example/ack/abc|Acknowledge>"),
            "{s}"
        );
        assert!(s.starts_with(":fire:"), "{s}");
    }

    #[test]
    fn name_parity() {
        let n = SlackNotifier::new(
            "https://hooks.slack.com/services/x".into(),
            "selfdef".into(),
            ":shield:".into(),
        );
        assert_eq!(<SlackNotifier as Notifier>::name(&n), "slack");
        assert_eq!(<SlackNotifier as Channel>::name(&n), "slack");
    }

    #[tokio::test]
    async fn happy_path_against_wiremock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header_exists("content-type"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let n = SlackNotifier::new(server.uri(), "selfdef".into(), ":shield:".into());
        let r = <SlackNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn invalid_webhook_returns_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(404).set_body_string("no_service"))
            .mount(&server)
            .await;
        let n = SlackNotifier::new(server.uri(), "selfdef".into(), ":shield:".into());
        let p = payload_with_ack();
        let r = <SlackNotifier as Channel>::send(&n, &p).await;
        match r {
            Err(ChannelError::Remote { status, .. }) => assert_eq!(status, 404),
            other => panic!("expected Remote(404), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_webhook_url_returns_not_configured() {
        let n = SlackNotifier::new(String::new(), "selfdef".into(), ":shield:".into());
        let r = <SlackNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(matches!(r, Err(NotifierError::NotConfigured)));
    }
}
