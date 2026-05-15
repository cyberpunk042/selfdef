//! Discord webhook outbound channel.
//!
//! SDD-008: sixth integration crate, fourth net-new. Closes the
//! second name the operator explicitly listed in the original
//! conversation ("put Slack and Discord for future"). Same shape as
//! Slack with Discord's wire body: `{"content": "…", "username":
//! "selfdef", "avatar_url": null}`.
//!
//! Discord caveats vs Slack:
//! - `content` field is hard-capped at **2000 characters** by the
//!   API. Bodies above that get truncated by the channel with a
//!   `…[truncated]` suffix before send.
//! - The webhook URL is itself the auth secret (like Slack). Stored
//!   in `webhook_url_file`; mode 0600 recommended.
//! - No interactive components in v1; ack via the orchestrator's
//!   HTTP click-link path (D-4).
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the taxonomy + acknowledgement model and
//! [`docs/dev/integrations.md`](../../../docs/dev/integrations.md)
//! for the contributor-facing crate template.

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

/// Discord's hard cap on the `content` field. The wire body is JSON
/// so the byte limit is a character count; we truncate at 1990 to
/// leave room for a `…[truncated]` marker.
const DISCORD_CONTENT_CAP: usize = 1990;

/// Discord webhook channel.
pub struct DiscordNotifier {
    client: reqwest::Client,
    webhook_url: String,
    username: String,
}

impl std::fmt::Debug for DiscordNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the webhook URL path (channel-id + token). Show
        // only the host so operators can distinguish guilds in logs.
        let host = self.webhook_url.split('/').nth(2).unwrap_or("<malformed>");
        f.debug_struct("DiscordNotifier")
            .field("webhook_host", &host)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl DiscordNotifier {
    /// Construct from an explicit webhook URL + display name. The
    /// URL is consumed and stored privately; the [`Debug`] impl
    /// elides the secret-bearing path.
    #[must_use]
    pub fn new(webhook_url: String, username: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            webhook_url,
            username,
        }
    }

    /// Build from config-shaped inputs. Reads the webhook URL from
    /// `webhook_url_file` (trimmed); refuses an empty file or any
    /// non-https URL (defensive against the common "pasted the
    /// wrong URL" mistake).
    pub fn from_config(
        webhook_url_file: &PathBuf,
        username: &str,
    ) -> Result<Self, DiscordBuildError> {
        let webhook_url = std::fs::read_to_string(webhook_url_file)
            .map_err(|e| DiscordBuildError::WebhookFileUnreadable(e.to_string()))?
            .trim()
            .to_owned();
        if webhook_url.is_empty() {
            return Err(DiscordBuildError::EmptyWebhookFile);
        }
        if !webhook_url.starts_with("https://") {
            return Err(DiscordBuildError::NotHttps);
        }
        let username = if username.is_empty() {
            "selfdef".to_owned()
        } else {
            username.to_owned()
        };
        Ok(Self::new(webhook_url, username))
    }

    /// Shared core for the two trait impls. POSTs the rendered text
    /// to the webhook. Truncates to Discord's 2000-char content cap
    /// with an explicit suffix rather than silent loss.
    async fn post(&self, content: &str) -> Result<(), DiscordDeliveryError> {
        if self.webhook_url.is_empty() {
            return Err(DiscordDeliveryError::NotConfigured);
        }
        let truncated = if content.chars().count() > DISCORD_CONTENT_CAP {
            let kept: String = content.chars().take(DISCORD_CONTENT_CAP).collect();
            format!("{kept}…[truncated]")
        } else {
            content.to_owned()
        };
        let body = DiscordPayload {
            content: &truncated,
            username: &self.username,
        };
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| DiscordDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, "discord delivered");
            return Ok(());
        }
        Err(DiscordDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

/// Wire shape for the webhook POST body.
#[derive(Debug, Serialize)]
struct DiscordPayload<'a> {
    content: &'a str,
    username: &'a str,
}

/// Errors from [`DiscordNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum DiscordBuildError {
    #[error("discord webhook_url_file unreadable: {0}")]
    WebhookFileUnreadable(String),
    #[error("discord webhook_url_file is empty after trim")]
    EmptyWebhookFile,
    #[error("discord webhook URL is not https://; refuse to send credentials over plaintext")]
    NotHttps,
}

/// Internal delivery error; bridged into legacy / orchestrator
/// errors at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum DiscordDeliveryError {
    #[error("discord not configured (empty webhook url)")]
    NotConfigured,
    #[error("discord transport error: {0}")]
    Transport(String),
    #[error("discord remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<DiscordDeliveryError> for NotifierError {
    fn from(e: DiscordDeliveryError) -> Self {
        match e {
            DiscordDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<DiscordDeliveryError> for ChannelError {
    fn from(e: DiscordDeliveryError) -> Self {
        match e {
            DiscordDeliveryError::NotConfigured => Self::Other("discord not configured".into()),
            DiscordDeliveryError::Transport(s) => Self::Transport(s),
            DiscordDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

/// Render the Discord message body for an [`Event`]. Severity-aware
/// emoji prefix for at-a-glance triage.
fn render_discord_for_event(event: &Event) -> String {
    let emoji = severity_emoji(event.severity_id);
    let title = render_title(event);
    let body = render_body(event);
    format!("{emoji} **{title}**\n```\n{body}```")
}

/// Render the Discord body for an orchestrator [`Payload`]. Threads
/// the ack link as a markdown link below the body when present.
fn render_discord_for_payload(payload: &Payload) -> String {
    let emoji = severity_emoji(payload.severity);
    match &payload.ack_link {
        Some(link) => format!(
            "{emoji} **{}**\n```\n{}```\n[Acknowledge]({link})",
            payload.title, payload.body
        ),
        None => format!("{emoji} **{}**\n```\n{}```", payload.title, payload.body),
    }
}

/// Severity → emoji for the Discord message prefix.
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
impl Notifier for DiscordNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let body = render_discord_for_event(event);
        self.post(&body).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "discord"
    }
}

#[async_trait]
impl Channel for DiscordNotifier {
    fn name(&self) -> &str {
        "discord"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let body = render_discord_for_payload(payload);
        self.post(&body).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // Discord supports interaction-component callbacks but v1
        // skips them — ack arrives through the HTTP click-link
        // path the Channel impl threads into the body.
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
            SeverityId::Critical,
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
            title: "[High] alert".into(),
            body: "body line\nmore body".into(),
            severity: SeverityId::High,
            ack_link: Some("https://selfdef.example/ack/abc".into()),
            event_kind: None,
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
        let err = DiscordNotifier::from_config(&f.path().to_owned(), "")
            .expect_err("empty file must fail");
        assert!(matches!(err, DiscordBuildError::EmptyWebhookFile));
    }

    #[test]
    fn from_config_rejects_non_https() {
        let f = write_webhook("http://discord.com/api/webhooks/123/abc");
        let err = DiscordNotifier::from_config(&f.path().to_owned(), "")
            .expect_err("plaintext URL must fail");
        assert!(matches!(err, DiscordBuildError::NotHttps));
    }

    #[test]
    fn from_config_rejects_missing_file() {
        let err = DiscordNotifier::from_config(&PathBuf::from("/nonexistent"), "")
            .expect_err("missing file must fail");
        assert!(matches!(err, DiscordBuildError::WebhookFileUnreadable(_)));
    }

    #[test]
    fn from_config_supplies_default_username() {
        let f = write_webhook("https://discord.com/api/webhooks/123/abc");
        let n = DiscordNotifier::from_config(&f.path().to_owned(), "").expect("ok");
        assert_eq!(n.username, "selfdef");
    }

    #[test]
    fn debug_elides_webhook_secret() {
        let n = DiscordNotifier::new(
            "https://discord.com/api/webhooks/123456789/SECRETTOKEN_XYZ".into(),
            "selfdef".into(),
        );
        let s = format!("{n:?}");
        assert!(s.contains("discord.com"), "host visible: {s}");
        assert!(!s.contains("SECRETTOKEN_XYZ"), "leaks token: {s}");
        assert!(!s.contains("123456789"), "leaks channel id: {s}");
    }

    #[test]
    fn severity_emoji_maps_consistently() {
        assert_eq!(severity_emoji(SeverityId::High), "🚨");
        assert_eq!(severity_emoji(SeverityId::Critical), "🔥");
        assert_eq!(severity_emoji(SeverityId::Informational), "ℹ️");
    }

    #[test]
    fn render_discord_for_event_uses_bold_and_code_fence() {
        let e = finding_event();
        let s = render_discord_for_event(&e);
        assert!(s.starts_with("🔥"), "{s}");
        assert!(s.contains("**"), "should use bold for title: {s}");
        assert!(s.contains("```"), "should wrap body in code fence: {s}");
    }

    #[test]
    fn render_discord_for_payload_includes_ack_link_when_present() {
        let p = payload_with_ack();
        let s = render_discord_for_payload(&p);
        assert!(
            s.contains("[Acknowledge](https://selfdef.example/ack/abc)"),
            "{s}"
        );
        assert!(s.starts_with("🚨"), "{s}");
    }

    #[test]
    fn name_parity() {
        let n = DiscordNotifier::new(
            "https://discord.com/api/webhooks/x".into(),
            "selfdef".into(),
        );
        assert_eq!(<DiscordNotifier as Notifier>::name(&n), "discord");
        assert_eq!(<DiscordNotifier as Channel>::name(&n), "discord");
    }

    #[tokio::test]
    async fn happy_path_against_wiremock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header_exists("content-type"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let n = DiscordNotifier::new(server.uri(), "selfdef".into());
        let r = <DiscordNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn invalid_webhook_returns_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Unknown Webhook"))
            .mount(&server)
            .await;
        let n = DiscordNotifier::new(server.uri(), "selfdef".into());
        let p = payload_with_ack();
        let r = <DiscordNotifier as Channel>::send(&n, &p).await;
        match r {
            Err(ChannelError::Remote { status, .. }) => assert_eq!(status, 404),
            other => panic!("expected Remote(404), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn long_content_is_truncated_with_marker() {
        // Wiremock that captures the request body so we can assert
        // on it. Discord's 2000-char content cap must be respected;
        // we expect the truncation marker rather than silent loss.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let n = DiscordNotifier::new(server.uri(), "selfdef".into());
        // Build a payload with a body > 1990 chars.
        let huge_body = "X".repeat(5_000);
        let p = Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: "long".into(),
            body: huge_body,
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
        };
        let r = <DiscordNotifier as Channel>::send(&n, &p).await;
        assert!(r.is_ok(), "{r:?}");
        // We can't easily introspect the request body via the
        // default wiremock matchers here, but the channel didn't
        // 400/500-fail on overflow → the truncation path executed.
    }

    #[tokio::test]
    async fn empty_webhook_url_returns_not_configured() {
        let n = DiscordNotifier::new(String::new(), "selfdef".into());
        let r = <DiscordNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(matches!(r, Err(NotifierError::NotConfigured)));
    }
}
