//! PagerDuty Events API v2 outbound channel.
//!
//! SDD-008 Q-G adapter: pattern-instance of the integration crate
//! template ([`docs/dev/integrations.md`]). The struct implements
//! both the legacy [`Notifier`] trait and the forward-looking
//! [`selfdef_notifier_orchestrator::Channel`] trait.
//!
//! Behaviour: POST to PagerDuty's Events API v2 endpoint
//! (`https://events.pagerduty.com/v2/enqueue` by default) with a
//! JSON body shaped per the [Events API v2 spec][spec]:
//!
//! ```json
//! {
//!   "routing_key": "<32-char hex integration key>",
//!   "event_action": "trigger",
//!   "dedup_key": "<event_id>",
//!   "payload": {
//!     "summary":   "<title>",
//!     "severity":  "critical" | "error" | "warning" | "info",
//!     "source":    "<host>",
//!     "custom_details": { "body": "<full rendered body>" }
//!   }
//! }
//! ```
//!
//! The routing key IS the auth — store it in a file referenced by
//! `routing_key_file`, mode `0600`. PagerDuty's Events API doesn't
//! require any other authentication.
//!
//! ## Deduplication
//!
//! v1 sends every payload as a `"trigger"` action with `dedup_key`
//! set to the orchestrator-supplied `PayloadId` (engine path) or
//! to a freshly-minted UUID (legacy chain path). This means
//! re-fires from the wake task's escalation rungs land on
//! PagerDuty as **new** incidents (operator gets paged again on
//! each rung). That matches what SDD-008's escalation semantics
//! want — "an unacked alert pages louder" — but is a deliberate
//! choice over PagerDuty's native deduplication (where a stable
//! `dedup_key` would update the existing incident in place).
//!
//! A future revision could thread `EventId` as the `dedup_key` and
//! switch to PagerDuty-native incident updates. That's a richer
//! integration; v1 ships the simpler shape.
//!
//! ## Q-G deferred bits
//!
//! - No `acknowledge` / `resolve` event_action flows. The
//!   orchestrator's CLI / HTTP click-link ack paths suffice for
//!   v1; bidirectional PagerDuty ack (operator acks on PagerDuty
//!   → selfdef notices) ships under a future SDD when the daemon
//!   exposes the webhook receiver pattern.
//! - No service-routing per event. v1 binds the channel to one
//!   integration key (one PagerDuty service); operators wanting
//!   per-severity routing can wire multiple PagerDuty services
//!   via per-channel subscription filters (D-3 / D-5e).
//!
//! [spec]: https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event
//! [`docs/dev/integrations.md`]: ../../../docs/dev/integrations.md

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

/// Default PagerDuty Events API v2 endpoint. Override via
/// [`PagerDutyNotifier::with_endpoint`] for staging / EU-only PD
/// instances. The default is the global US endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://events.pagerduty.com/v2/enqueue";

/// PagerDuty Events API v2 channel.
pub struct PagerDutyNotifier {
    client: reqwest::Client,
    endpoint: String,
    routing_key: String,
    source: String,
}

impl std::fmt::Debug for PagerDutyNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the routing_key — it's the integration secret.
        // Show its prefix only so operators can disambiguate
        // multiple PagerDuty services in logs.
        let prefix = self
            .routing_key
            .get(..8)
            .map(str::to_string)
            .unwrap_or_default();
        f.debug_struct("PagerDutyNotifier")
            .field("endpoint", &self.endpoint)
            .field("routing_key_prefix", &format!("{prefix}…"))
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl PagerDutyNotifier {
    /// Construct from explicit values. `routing_key` is consumed
    /// and stored privately; the [`Debug`] impl elides the secret.
    /// `source` is the OCSF event source / hostname surfaced in
    /// the PagerDuty UI as the alerting entity.
    #[must_use]
    pub fn new(routing_key: String, source: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            routing_key,
            source,
        }
    }

    /// Override the API endpoint (staging, EU-only, in-process
    /// wiremock for tests). Builder-style so daemon wiring can
    /// keep [`Self::new`] tidy.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Build from config-shaped inputs. Reads the 32-char routing
    /// key from `routing_key_file` (trimmed); refuses an empty
    /// file. `endpoint` overrides the default (use `""` to mean
    /// "use the default global US endpoint"). `source` defaults to
    /// `"selfdef"` when empty.
    pub fn from_config(
        routing_key_file: &PathBuf,
        endpoint: &str,
        source: &str,
    ) -> Result<Self, PagerDutyBuildError> {
        let routing_key = std::fs::read_to_string(routing_key_file)
            .map_err(|e| PagerDutyBuildError::RoutingKeyFileUnreadable(e.to_string()))?
            .trim()
            .to_owned();
        if routing_key.is_empty() {
            return Err(PagerDutyBuildError::EmptyRoutingKeyFile);
        }
        let endpoint = if endpoint.is_empty() {
            DEFAULT_ENDPOINT.to_string()
        } else {
            if !endpoint.starts_with("https://") {
                return Err(PagerDutyBuildError::EndpointNotHttps);
            }
            endpoint.to_owned()
        };
        let source = if source.is_empty() {
            "selfdef".to_owned()
        } else {
            source.to_owned()
        };
        // Route through `Self::new` so the reqwest::Client::builder
        // shape stays in one place (F-2032-004 closure: was a
        // duplicated block, drifted from the other Q-G adapters that
        // all go through their `new`).
        Ok(Self::new(routing_key, source).with_endpoint(endpoint))
    }

    /// Shared core for the two trait impls. POSTs the rendered
    /// event payload. Wire bytes are byte-identical regardless of
    /// caller path.
    async fn post(
        &self,
        summary: &str,
        severity: PdSeverity,
        body: &str,
        dedup_key: &str,
    ) -> Result<(), PagerDutyDeliveryError> {
        if self.routing_key.is_empty() {
            return Err(PagerDutyDeliveryError::NotConfigured);
        }
        let payload = PdPayloadField {
            summary,
            severity: severity.as_str(),
            source: &self.source,
            custom_details: PdCustomDetails { body },
        };
        let wire = PdEvent {
            routing_key: &self.routing_key,
            event_action: "trigger",
            dedup_key,
            payload,
        };
        let resp = self
            .client
            .post(&self.endpoint)
            .json(&wire)
            .send()
            .await
            .map_err(|e| PagerDutyDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, "pagerduty delivered");
            return Ok(());
        }
        Err(PagerDutyDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

/// Wire shape for the Events API v2 POST body.
#[derive(Debug, Serialize)]
struct PdEvent<'a> {
    routing_key: &'a str,
    event_action: &'a str,
    dedup_key: &'a str,
    payload: PdPayloadField<'a>,
}

#[derive(Debug, Serialize)]
struct PdPayloadField<'a> {
    summary: &'a str,
    severity: &'a str,
    source: &'a str,
    custom_details: PdCustomDetails<'a>,
}

#[derive(Debug, Serialize)]
struct PdCustomDetails<'a> {
    body: &'a str,
}

/// PagerDuty's four-level severity scale (matches Events API v2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PdSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl PdSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Map OCSF severity → PagerDuty severity. PD's four levels are
/// coarser than OCSF's six, so we collapse:
/// `Informational/Low → info`,
/// `Medium → warning`,
/// `High → error`,
/// `Critical/Fatal → critical`.
fn map_severity(s: SeverityId) -> PdSeverity {
    match s {
        SeverityId::Unknown | SeverityId::Other | SeverityId::Informational => PdSeverity::Info,
        SeverityId::Low => PdSeverity::Info,
        SeverityId::Medium => PdSeverity::Warning,
        SeverityId::High => PdSeverity::Error,
        SeverityId::Critical | SeverityId::Fatal => PdSeverity::Critical,
    }
}

/// Errors from [`PagerDutyNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum PagerDutyBuildError {
    #[error("pagerduty routing_key_file unreadable: {0}")]
    RoutingKeyFileUnreadable(String),
    #[error("pagerduty routing_key_file is empty after trim")]
    EmptyRoutingKeyFile,
    #[error("pagerduty endpoint must be https://; refuse to send credentials over plaintext")]
    EndpointNotHttps,
}

/// Internal delivery error.
#[derive(Debug, thiserror::Error)]
enum PagerDutyDeliveryError {
    #[error("pagerduty not configured (empty routing key)")]
    NotConfigured,
    #[error("pagerduty transport error: {0}")]
    Transport(String),
    #[error("pagerduty remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<PagerDutyDeliveryError> for NotifierError {
    fn from(e: PagerDutyDeliveryError) -> Self {
        match e {
            PagerDutyDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<PagerDutyDeliveryError> for ChannelError {
    fn from(e: PagerDutyDeliveryError) -> Self {
        match e {
            PagerDutyDeliveryError::NotConfigured => Self::Other("pagerduty not configured".into()),
            PagerDutyDeliveryError::Transport(s) => Self::Transport(s),
            PagerDutyDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

#[async_trait]
impl Notifier for PagerDutyNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let summary = render_title(event);
        let body = render_body(event);
        let severity = map_severity(event.severity_id);
        // Legacy chain path: no orchestrator-supplied dedup_key.
        // Use the Event's own id so the responder re-firing twice
        // for the same Event deduplicates on PD's side. (This
        // differs from the Channel path's per-PayloadId behaviour
        // — see module rustdoc.)
        let dedup_key = event.id.simple().to_string();
        self.post(&summary, severity, &body, &dedup_key).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "pagerduty"
    }
}

#[async_trait]
impl Channel for PagerDutyNotifier {
    fn name(&self) -> &str {
        "pagerduty"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let severity = map_severity(payload.severity);
        // Engine path: each rung-fire mints a fresh PayloadId, so
        // using it as dedup_key produces one incident per rung.
        // That's by design — SDD-008's escalation semantics want
        // "an unacked alert pages louder" — see module rustdoc.
        let dedup_key = payload.id.0.simple().to_string();
        self.post(&payload.title, severity, &payload.body, &dedup_key)
            .await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // PagerDuty supports `acknowledge` / `resolve` event_action
        // flows that would close an incident in-place when the
        // operator acks on the PD UI. v1 doesn't wire the inbound
        // webhook receiver to learn about those — operator acks
        // through selfdef's CLI / HTTP click-link paths instead.
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
    use wiremock::matchers::{body_partial_json, header, method, path};
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
        .with_message("ssh brute force from 192.0.2.5")
    }

    fn write_key(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{content}").unwrap();
        f
    }

    fn payload(severity: SeverityId) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: Some(EventId::from(Uuid::now_v7())),
            title: "alert title".into(),
            body: "alert body".into(),
            severity,
            ack_link: None,
            event_kind: None,
            ack_token: None,
        }
    }

    #[test]
    fn from_config_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = PagerDutyNotifier::from_config(&f.path().to_owned(), "", "")
            .expect_err("empty file must fail");
        assert!(matches!(err, PagerDutyBuildError::EmptyRoutingKeyFile));
    }

    #[test]
    fn from_config_rejects_missing_file() {
        let err = PagerDutyNotifier::from_config(
            &PathBuf::from("/nonexistent/path/to/routing-key"),
            "",
            "",
        )
        .expect_err("missing file must fail");
        assert!(matches!(
            err,
            PagerDutyBuildError::RoutingKeyFileUnreadable(_)
        ));
    }

    #[test]
    fn from_config_rejects_http_endpoint() {
        let f = write_key("0123456789abcdef0123456789abcdef");
        let err = PagerDutyNotifier::from_config(
            &f.path().to_owned(),
            "http://events.pagerduty.example/",
            "",
        )
        .expect_err("plaintext endpoint must fail");
        assert!(matches!(err, PagerDutyBuildError::EndpointNotHttps));
    }

    #[test]
    fn from_config_supplies_default_source() {
        let f = write_key("0123456789abcdef0123456789abcdef");
        let n = PagerDutyNotifier::from_config(&f.path().to_owned(), "", "").expect("ok");
        assert_eq!(n.source, "selfdef");
    }

    #[test]
    fn from_config_uses_default_endpoint_when_empty() {
        let f = write_key("0123456789abcdef0123456789abcdef");
        let n =
            PagerDutyNotifier::from_config(&f.path().to_owned(), "", "test-source").expect("ok");
        assert_eq!(n.endpoint, DEFAULT_ENDPOINT);
        assert_eq!(n.source, "test-source");
    }

    #[test]
    fn debug_elides_routing_key() {
        let n = PagerDutyNotifier::new("SECRET-ROUTING-KEY-NEVER-PRINTED".into(), "host".into());
        let s = format!("{n:?}");
        assert!(!s.contains("ROUTING-KEY-NEVER-PRINTED"), "leaks: {s}");
        assert!(s.contains("SECRET-R"), "prefix shown for triage: {s}");
    }

    #[test]
    fn severity_map_collapses_six_to_four() {
        assert_eq!(map_severity(SeverityId::Informational), PdSeverity::Info);
        assert_eq!(map_severity(SeverityId::Low), PdSeverity::Info);
        assert_eq!(map_severity(SeverityId::Medium), PdSeverity::Warning);
        assert_eq!(map_severity(SeverityId::High), PdSeverity::Error);
        assert_eq!(map_severity(SeverityId::Critical), PdSeverity::Critical);
        assert_eq!(map_severity(SeverityId::Fatal), PdSeverity::Critical);
    }

    #[test]
    fn name_parity() {
        let n = PagerDutyNotifier::new("k".into(), "h".into());
        assert_eq!(<PagerDutyNotifier as Notifier>::name(&n), "pagerduty");
        assert_eq!(<PagerDutyNotifier as Channel>::name(&n), "pagerduty");
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_unconfigured() {
        let n = PagerDutyNotifier::new(String::new(), "h".into());
        let r = <PagerDutyNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        assert!(matches!(r, Err(ChannelError::Other(_))));
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "routing_key": "test-key",
                "event_action": "trigger",
                "payload": {
                    "severity": "error",
                    "source": "selfdef",
                }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_string(r#"{"status":"success"}"#))
            .mount(&server)
            .await;
        let n = PagerDutyNotifier::new("test-key".into(), "selfdef".into())
            .with_endpoint(format!("{}/v2/enqueue", server.uri()));
        let r = <PagerDutyNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .and(body_partial_json(serde_json::json!({
                "event_action": "trigger",
                "payload": {
                    "severity": "critical",
                }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_string(r#"{"status":"success"}"#))
            .mount(&server)
            .await;
        let n = PagerDutyNotifier::new("test-key".into(), "selfdef".into())
            .with_endpoint(format!("{}/v2/enqueue", server.uri()));
        let r = <PagerDutyNotifier as Channel>::send(&n, &payload(SeverityId::Critical)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn non_success_status_maps_to_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(429).set_body_string(r#"{"status":"rate_limited"}"#),
            )
            .mount(&server)
            .await;
        let n = PagerDutyNotifier::new("test-key".into(), "selfdef".into())
            .with_endpoint(format!("{}/v2/enqueue", server.uri()));
        let r = <PagerDutyNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        match r {
            Err(ChannelError::Remote { status, body }) => {
                assert_eq!(status, 429);
                assert!(body.contains("rate_limited"), "body: {body}");
            }
            other => panic!("expected Remote(429), got {other:?}"),
        }
    }
}
