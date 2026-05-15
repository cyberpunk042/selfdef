//! ntfy outbound channel for the selfdef notifier.
//!
//! SDD-008 D-2b: graduated out of `selfdef-notifier` into its own
//! integration crate. The struct implements **both** ABIs so existing
//! M4-era callers (`selfdef-daemon`, `selfdef-cli`, the `m4_alert`
//! integration test) keep working unchanged via the legacy
//! [`Notifier`] trait, while the orchestrator (D-5 onward) consumes
//! the same impl through the forward-looking
//! [`selfdef_notifier_orchestrator::Channel`] trait.
//!
//! Behaviour is unchanged from the M4 implementation: HTTP POST to a
//! self-hosted ntfy server with up-to-3 attempts and ~200ms..800ms
//! exponential backoff, optional bearer-token auth loaded from disk.
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
use selfdef_notifier::{Notifier, NotifierError, priority_for, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use tracing::{debug, warn};

/// ntfy outbound channel.
pub struct NtfyNotifier {
    url: String,
    topic: String,
    token: Option<String>,
    client: reqwest::Client,
}

// Custom `Debug` impl elides the bearer token so it never leaks
// through `tracing::error!("{notifier:?}", …)` or a panic backtrace.
// Matches the secret-elision posture of the slack/discord/twilio/smtp
// integration crates (F-2031-005).
impl std::fmt::Debug for NtfyNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtfyNotifier")
            .field("url", &self.url)
            .field("topic", &self.topic)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl NtfyNotifier {
    /// Construct from explicit url + topic + optional bearer token.
    pub fn new(url: impl Into<String>, topic: impl Into<String>, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            url: url.into(),
            topic: topic.into(),
            token,
            client,
        }
    }

    /// Construct from config: read a token from `token_file` if given,
    /// otherwise emit unauthenticated requests (suitable for an
    /// unauthenticated self-hosted ntfy server).
    pub fn from_config(url: &str, topic: &str, token_file: Option<&PathBuf>) -> Self {
        let token = token_file
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self::new(url, topic, token)
    }

    /// Shared core: POST one rendered payload to `<url>/<topic>` with
    /// up-to-3 attempts and exponential backoff. Used by both the
    /// legacy [`Notifier`] impl and the new [`Channel`] impl so the
    /// behaviour stays bytewise identical.
    async fn post(
        &self,
        title: &str,
        body: &str,
        priority: u8,
        tags: &str,
    ) -> Result<reqwest::Response, NtfyDeliveryError> {
        if self.url.is_empty() || self.topic.is_empty() {
            return Err(NtfyDeliveryError::NotConfigured);
        }
        let endpoint = format!("{}/{}", self.url.trim_end_matches('/'), self.topic);
        let mut last_err: Option<NtfyDeliveryError> = None;
        for attempt in 0u32..3 {
            if attempt > 0 {
                let backoff = Duration::from_millis(200u64 << attempt);
                tokio::time::sleep(backoff).await;
            }
            let mut req = self
                .client
                .post(&endpoint)
                .header("Title", title)
                .header("Priority", priority.to_string())
                .header("Tags", tags)
                .body(body.to_owned());
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(attempt, status = %resp.status(), "ntfy delivered");
                    return Ok(resp);
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    last_err = Some(NtfyDeliveryError::Remote {
                        status,
                        message: format!("non-success status: {status}"),
                    });
                    warn!(attempt, status, "ntfy non-success response");
                }
                Err(e) => {
                    last_err = Some(NtfyDeliveryError::Transport(e.to_string()));
                    warn!(attempt, error = %e, "ntfy send failed");
                }
            }
        }
        Err(last_err.unwrap_or(NtfyDeliveryError::Transport("unknown".into())))
    }
}

/// Internal delivery error; bridged into [`NotifierError`] (legacy)
/// and [`ChannelError`] (orchestrator) at the trait boundaries.
#[derive(Debug, thiserror::Error)]
enum NtfyDeliveryError {
    #[error("ntfy not configured (empty url or topic)")]
    NotConfigured,
    #[error("ntfy transport error: {0}")]
    Transport(String),
    #[error("ntfy remote returned {status}: {message}")]
    Remote { status: u16, message: String },
}

impl From<NtfyDeliveryError> for NotifierError {
    fn from(e: NtfyDeliveryError) -> Self {
        match e {
            NtfyDeliveryError::NotConfigured => Self::NotConfigured,
            NtfyDeliveryError::Transport(s) => Self::Http(s),
            NtfyDeliveryError::Remote { message, .. } => Self::Http(message),
        }
    }
}

impl From<NtfyDeliveryError> for ChannelError {
    fn from(e: NtfyDeliveryError) -> Self {
        match e {
            NtfyDeliveryError::NotConfigured => {
                Self::Other("ntfy not configured (empty url or topic)".into())
            }
            NtfyDeliveryError::Transport(s) => Self::Transport(s),
            NtfyDeliveryError::Remote { status, message } => Self::Remote {
                status,
                body: message,
            },
        }
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let title = render_title(event);
        let body = render_body(event);
        let priority = priority_for(event.severity_id);
        let tags = ntfy_tags_for(event);
        self.post(&title, &body, priority, &tags).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ntfy"
    }
}

#[async_trait]
impl Channel for NtfyNotifier {
    fn name(&self) -> &str {
        "ntfy"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        // Orchestrator-mode payloads carry pre-rendered title/body.
        // We map severity → ntfy priority via the legacy helper so
        // the rendered priority stays identical to the M4 path.
        let priority = priority_for(payload.severity);
        // Tags: when invoked through the Channel surface we have no
        // direct access to ATT&CK techniques (those live on Event,
        // not on Payload). Use a stable single-tag fallback; future
        // Ds may grow Payload to carry richer metadata.
        let tags = "shield";
        self.post(&payload.title, &payload.body, priority, tags)
            .await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // ntfy supports action buttons. v1 of the orchestrator (D-5)
        // will surface this via HttpClickLink in the message body;
        // native NativeButton support follows once the daemon
        // exposes the webhook receiver path. Until then this stays
        // false so the orchestrator falls back to CLI / HTTP-link
        // ack paths.
        false
    }

    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

/// Build the ntfy `Tags:` header from an [`Event`]. Equivalent to the
/// M4 inline construction; surfaced as a helper so the orchestrator-
/// side `Channel::send` (which doesn't see the underlying `Event`)
/// can pick the same default in a follow-up D.
fn ntfy_tags_for(event: &Event) -> String {
    if event.attack.is_empty() {
        "shield".to_owned()
    } else {
        let mut t = vec!["shield".to_owned()];
        for technique in &event.attack {
            t.push(technique.id.clone());
        }
        t.join(",")
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

    #[test]
    fn ntfy_tags_default_to_shield_only_when_no_attack() {
        let e = finding_event();
        assert_eq!(ntfy_tags_for(&e), "shield");
    }

    #[tokio::test]
    async fn notify_returns_not_configured_when_url_empty() {
        let n = NtfyNotifier::new("", "topic", None);
        let e = finding_event();
        assert!(matches!(
            <NtfyNotifier as Notifier>::notify(&n, &e).await,
            Err(NotifierError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_url_empty() {
        let n = NtfyNotifier::new("", "topic", None);
        let payload = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity: SeverityId::High,
            ack_link: None,
        };
        let result = <NtfyNotifier as Channel>::send(&n, &payload).await;
        assert!(matches!(result, Err(ChannelError::Other(_))));
    }

    #[test]
    fn channel_name_matches_notifier_name() {
        let n = NtfyNotifier::new("http://example.invalid", "topic", None);
        assert_eq!(<NtfyNotifier as Notifier>::name(&n), "ntfy");
        assert_eq!(<NtfyNotifier as Channel>::name(&n), "ntfy");
    }

    #[test]
    fn debug_elides_bearer_token() {
        let n = NtfyNotifier::new("https://ntfy.example", "t", Some("SECRET-TOKEN-XYZ".into()));
        let s = format!("{n:?}");
        assert!(s.contains("ntfy.example"), "host visible: {s}");
        assert!(s.contains("t"), "topic visible: {s}");
        assert!(!s.contains("SECRET-TOKEN-XYZ"), "leaks token: {s}");
    }

    #[test]
    fn debug_shows_no_token_when_none() {
        let n = NtfyNotifier::new("https://ntfy.example", "t", None);
        let s = format!("{n:?}");
        assert!(s.contains("ntfy.example"), "host visible: {s}");
        assert!(!s.contains("redacted"), "no token configured: {s}");
    }

    mod wiremock_tests {
        use super::*;
        use selfdef_notifier_orchestrator::EventId;
        use uuid::Uuid;
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn payload() -> Payload {
            Payload {
                id: PayloadId::new(),
                event_id: Some(EventId::from(Uuid::now_v7())),
                title: "alert title".into(),
                body: "alert body".into(),
                severity: SeverityId::High,
                ack_link: None,
            }
        }

        #[tokio::test]
        async fn happy_path_against_wiremock() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/selfdef-test"))
                .and(header_exists("title"))
                .and(header_exists("priority"))
                .and(header_exists("tags"))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&server)
                .await;
            let n = NtfyNotifier::new(server.uri(), "selfdef-test", None);
            let r = <NtfyNotifier as Channel>::send(&n, &payload()).await;
            assert!(r.is_ok(), "{r:?}");
        }

        #[tokio::test]
        async fn non_success_status_maps_to_remote_error() {
            // ntfy retries up to 3 times — return 4xx every time.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
                .mount(&server)
                .await;
            let n = NtfyNotifier::new(server.uri(), "selfdef-test", None);
            let r = <NtfyNotifier as Channel>::send(&n, &payload()).await;
            match r {
                Err(ChannelError::Remote { status, .. }) => assert_eq!(status, 403),
                other => panic!("expected Remote(403), got {other:?}"),
            }
        }

        #[tokio::test]
        async fn bearer_token_attached_when_configured() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(header("authorization", "Bearer secret-token-xyz"))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&server)
                .await;
            let n = NtfyNotifier::new(server.uri(), "t", Some("secret-token-xyz".into()));
            let r = <NtfyNotifier as Channel>::send(&n, &payload()).await;
            assert!(r.is_ok(), "expected bearer-auth match, got {r:?}");
        }
    }
}
