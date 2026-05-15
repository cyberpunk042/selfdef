//! Grafana Loki push-API outbound channel.
//!
//! SDD-008 Q-G adapter (Loki). Pattern-instance of the integration
//! crate template (`docs/dev/integrations.md`). Implements both the
//! legacy [`Notifier`] trait and the forward-looking
//! [`selfdef_notifier_orchestrator::Channel`] trait.
//!
//! ## Wire shape
//!
//! POST to Loki's `/loki/api/v1/push` endpoint with a body shaped
//! per the [Loki push API spec][spec]:
//!
//! ```json
//! {
//!   "streams": [
//!     {
//!       "stream": {
//!         "service":  "selfdef",
//!         "severity": "high",
//!         "host":     "<source>",
//!         "kind":     "<event_kind>"
//!       },
//!       "values": [["<unix_ns>", "<one-line title — body>"]]
//!     }
//!   ]
//! }
//! ```
//!
//! ## Auth model
//!
//! Loki's deployment landscape is plural:
//!
//! - **Self-hosted single-tenant**: no auth, no `tenant_id`. Just an
//!   endpoint.
//! - **Self-hosted multi-tenant**: `X-Scope-OrgID: <tenant>`. No
//!   bearer secret.
//! - **Grafana Cloud Loki**: Basic auth with `tenant_id` as the
//!   user and a Grafana Cloud API key as the password.
//!
//! v1 supports the union via two optional fields:
//!
//! - `tenant_id: Option<String>` → sent as `X-Scope-OrgID`.
//! - `auth_token_file: Option<PathBuf>` → contents become the
//!   bearer token via `Authorization: Bearer <token>` (the most
//!   common shape; Grafana Cloud's Basic-auth pattern works too
//!   when the operator base64-encodes `tenant_id:apikey` into the
//!   token file with `Authorization: Basic` rewrite via reverse
//!   proxy — we keep this layer simple).
//!
//! ## Q-G deferred bits
//!
//! - No label-template expansion. v1 uses a small fixed label set
//!   (`service`, `severity`, `host`, `kind`); operators wanting
//!   per-rule labels can land that under a future SDD that grows
//!   `Payload` with an `extra_labels` field.
//! - No batching. v1 sends one push per event. Loki accepts this
//!   (the `streams` array has length 1); selfdef's emit cadence
//!   is finding-shaped, not log-shaped, so batching wouldn't pay
//!   off until the daemon grows a higher-throughput collector.
//! - No bidirectional ack. Loki is one-way; ack stays on the
//!   orchestrator's CLI / HTTP click-link paths.
//!
//! [spec]: https://grafana.com/docs/loki/latest/reference/loki-http-api/#push-log-entries-to-loki

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use selfdef_notifier::{Notifier, NotifierError, render_body, render_title};
use selfdef_notifier_orchestrator::{
    AckReplyHint, Channel, ChannelError, DeliveryReceipt, Payload,
};
use serde::Serialize;
use std::collections::BTreeMap;
use tracing::debug;

/// Loki push channel.
pub struct LokiNotifier {
    client: reqwest::Client,
    endpoint: String,
    tenant_id: Option<String>,
    token: Option<String>,
    source: String,
}

impl std::fmt::Debug for LokiNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the bearer token if present; show tenant_id +
        // endpoint freely (those are operator-visible config).
        f.debug_struct("LokiNotifier")
            .field("endpoint", &self.endpoint)
            .field("tenant_id", &self.tenant_id)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl LokiNotifier {
    /// Construct from explicit endpoint + optional tenant + optional
    /// bearer token. `token` is consumed and stored privately; the
    /// [`Debug`] impl elides it.
    #[must_use]
    pub fn new(
        endpoint: String,
        tenant_id: Option<String>,
        token: Option<String>,
        source: String,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            endpoint,
            tenant_id,
            token,
            source,
        }
    }

    /// Build from config-shaped inputs.
    /// - `endpoint`: required; must be `https://` (defensive — we
    ///   refuse to send bearer tokens over plaintext).
    /// - `tenant_id`: optional `X-Scope-OrgID`. Empty = no header.
    /// - `auth_token_file`: optional path to a file containing the
    ///   bearer token. Empty = no `Authorization` header.
    /// - `source`: hostname / source identifier surfaced as the
    ///   `host` label in Loki. Defaults to `"selfdef"` when blank.
    pub fn from_config(
        endpoint: &str,
        tenant_id: &str,
        auth_token_file: Option<&PathBuf>,
        source: &str,
    ) -> Result<Self, LokiBuildError> {
        if endpoint.is_empty() {
            return Err(LokiBuildError::EmptyEndpoint);
        }
        if !endpoint.starts_with("https://") {
            return Err(LokiBuildError::EndpointNotHttps);
        }
        let tenant_id = if tenant_id.is_empty() {
            None
        } else {
            Some(tenant_id.to_owned())
        };
        let token = match auth_token_file {
            None => None,
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .map_err(|e| LokiBuildError::TokenFileUnreadable(e.to_string()))?
                    .trim()
                    .to_owned();
                if raw.is_empty() {
                    return Err(LokiBuildError::EmptyTokenFile);
                }
                Some(raw)
            }
        };
        let source = if source.is_empty() {
            "selfdef".to_owned()
        } else {
            source.to_owned()
        };
        Ok(Self::new(endpoint.to_owned(), tenant_id, token, source))
    }

    /// Shared core for the two trait impls. Renders one Loki push
    /// body and POSTs it.
    async fn push(
        &self,
        labels: BTreeMap<&str, String>,
        line: &str,
    ) -> Result<(), LokiDeliveryError> {
        if self.endpoint.is_empty() {
            return Err(LokiDeliveryError::NotConfigured);
        }
        let ts_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Loki's protocol pins the value as a (string-ns, string-line)
        // 2-tuple. Stringify both sides exactly to avoid the
        // float-precision pitfall some clients hit when serializing
        // u128 timestamps as JSON numbers.
        let wire = LokiPush {
            streams: vec![LokiStream {
                stream: &labels,
                values: vec![[ts_ns.to_string(), line.to_owned()]],
            }],
        };
        let mut req = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .json(&wire);
        if let Some(tid) = &self.tenant_id {
            req = req.header("X-Scope-OrgID", tid.as_str());
        }
        if let Some(tok) = &self.token {
            req = req.bearer_auth(tok);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| LokiDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, "loki delivered");
            return Ok(());
        }
        Err(LokiDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

/// Wire shape: top-level push body.
#[derive(Debug, Serialize)]
struct LokiPush<'a> {
    streams: Vec<LokiStream<'a>>,
}

/// One stream entry. Loki expects an arbitrary label-set object
/// plus a vector of `[ts_ns_string, line]` 2-tuples. `Vec<[String;
/// 2]>` serializes as a JSON array of 2-element arrays — exactly
/// what Loki wants.
#[derive(Debug, Serialize)]
struct LokiStream<'a> {
    stream: &'a BTreeMap<&'a str, String>,
    values: Vec<[String; 2]>,
}

/// Map OCSF severity → the string label Loki sees. Stable lowercase
/// labels match standard log-pipeline conventions.
fn severity_label(s: SeverityId) -> &'static str {
    match s {
        SeverityId::Unknown | SeverityId::Other => "unknown",
        SeverityId::Informational => "informational",
        SeverityId::Low => "low",
        SeverityId::Medium => "medium",
        SeverityId::High => "high",
        SeverityId::Critical => "critical",
        SeverityId::Fatal => "fatal",
    }
}

/// Errors from [`LokiNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum LokiBuildError {
    #[error("loki endpoint is empty (set [notifier.loki].endpoint)")]
    EmptyEndpoint,
    #[error("loki endpoint must be https://; refuse to send bearer over plaintext")]
    EndpointNotHttps,
    #[error("loki auth_token_file unreadable: {0}")]
    TokenFileUnreadable(String),
    #[error("loki auth_token_file is empty after trim")]
    EmptyTokenFile,
}

/// Internal delivery error.
#[derive(Debug, thiserror::Error)]
enum LokiDeliveryError {
    #[error("loki not configured (empty endpoint)")]
    NotConfigured,
    #[error("loki transport error: {0}")]
    Transport(String),
    #[error("loki remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<LokiDeliveryError> for NotifierError {
    fn from(e: LokiDeliveryError) -> Self {
        match e {
            LokiDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<LokiDeliveryError> for ChannelError {
    fn from(e: LokiDeliveryError) -> Self {
        match e {
            LokiDeliveryError::NotConfigured => Self::Other("loki not configured".into()),
            LokiDeliveryError::Transport(s) => Self::Transport(s),
            LokiDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

/// Compose the single one-line log entry Loki receives.
fn render_line(title: &str, body: &str) -> String {
    // Loki rejects newlines in a single value's line component
    // (the protocol expects one "log line" per (ts, line) tuple).
    // Collapse newlines to ` · ` so the title + body stays
    // grepable while remaining one logical entry.
    let raw = if body.is_empty() {
        title.to_string()
    } else {
        format!("{title} · {body}")
    };
    raw.replace(['\n', '\r'], " · ")
}

#[async_trait]
impl Notifier for LokiNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let mut labels = BTreeMap::new();
        labels.insert("service", "selfdef".to_string());
        labels.insert("severity", severity_label(event.severity_id).to_string());
        labels.insert("host", self.source.clone());
        labels.insert("kind", event.class_uid.name().to_string());
        let title = render_title(event);
        let body = render_body(event);
        let line = render_line(&title, &body);
        self.push(labels, &line).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "loki"
    }
}

#[async_trait]
impl Channel for LokiNotifier {
    fn name(&self) -> &str {
        "loki"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let mut labels = BTreeMap::new();
        labels.insert("service", "selfdef".to_string());
        labels.insert("severity", severity_label(payload.severity).to_string());
        labels.insert("host", self.source.clone());
        if let Some(kind) = &payload.event_kind {
            labels.insert("kind", kind.clone());
        }
        let line = render_line(&payload.title, &payload.body);
        self.push(labels, &line).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // Loki is one-way push-only.
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

    fn write_file(content: &str) -> tempfile::NamedTempFile {
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
            event_kind: Some("Detection Finding".into()),
            ack_token: None,
        }
    }

    #[test]
    fn from_config_rejects_empty_endpoint() {
        let err =
            LokiNotifier::from_config("", "", None, "").expect_err("empty endpoint must fail");
        assert!(matches!(err, LokiBuildError::EmptyEndpoint));
    }

    #[test]
    fn from_config_rejects_http_endpoint() {
        let err = LokiNotifier::from_config("http://loki.example", "", None, "")
            .expect_err("plaintext endpoint must fail");
        assert!(matches!(err, LokiBuildError::EndpointNotHttps));
    }

    #[test]
    fn from_config_rejects_empty_token_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = LokiNotifier::from_config(
            "https://loki.example/loki/api/v1/push",
            "",
            Some(&f.path().to_owned()),
            "",
        )
        .expect_err("empty token file must fail");
        assert!(matches!(err, LokiBuildError::EmptyTokenFile));
    }

    #[test]
    fn from_config_rejects_missing_token_file() {
        let err = LokiNotifier::from_config(
            "https://loki.example/loki/api/v1/push",
            "",
            Some(&PathBuf::from("/nonexistent/path/to/loki-token")),
            "",
        )
        .expect_err("missing token file must fail");
        assert!(matches!(err, LokiBuildError::TokenFileUnreadable(_)));
    }

    #[test]
    fn from_config_supplies_default_source() {
        let n = LokiNotifier::from_config("https://loki.example/loki/api/v1/push", "", None, "")
            .unwrap();
        assert_eq!(n.source, "selfdef");
        assert!(n.tenant_id.is_none());
        assert!(n.token.is_none());
    }

    #[test]
    fn from_config_well_formed_round_trip() {
        let tok = write_file("the-token-value");
        let n = LokiNotifier::from_config(
            "https://logs-prod.grafana.net/loki/api/v1/push",
            "12345",
            Some(&tok.path().to_owned()),
            "my-host",
        )
        .unwrap();
        assert_eq!(n.tenant_id.as_deref(), Some("12345"));
        assert_eq!(n.token.as_deref(), Some("the-token-value"));
        assert_eq!(n.source, "my-host");
    }

    #[test]
    fn debug_elides_token() {
        let n = LokiNotifier::new(
            "https://loki.example".into(),
            Some("tenant-42".into()),
            Some("SECRET-LOKI-TOKEN".into()),
            "h".into(),
        );
        let s = format!("{n:?}");
        assert!(!s.contains("SECRET-LOKI-TOKEN"), "leaks: {s}");
        assert!(s.contains("tenant-42"), "tenant visible: {s}");
        assert!(s.contains("redacted"), "token marker: {s}");
    }

    #[test]
    fn debug_shows_no_token_when_none() {
        let n = LokiNotifier::new("https://loki.example".into(), None, None, "h".into());
        let s = format!("{n:?}");
        assert!(!s.contains("redacted"));
    }

    #[test]
    fn severity_label_round_trips_every_variant() {
        assert_eq!(severity_label(SeverityId::Informational), "informational");
        assert_eq!(severity_label(SeverityId::Low), "low");
        assert_eq!(severity_label(SeverityId::Medium), "medium");
        assert_eq!(severity_label(SeverityId::High), "high");
        assert_eq!(severity_label(SeverityId::Critical), "critical");
        assert_eq!(severity_label(SeverityId::Fatal), "fatal");
        assert_eq!(severity_label(SeverityId::Unknown), "unknown");
        assert_eq!(severity_label(SeverityId::Other), "unknown");
    }

    #[test]
    fn render_line_collapses_newlines() {
        let line = render_line(
            "title here",
            "body line one\nbody line two\r\nbody line three",
        );
        assert!(!line.contains('\n'), "no raw newline: {line}");
        assert!(!line.contains('\r'), "no raw CR: {line}");
        assert!(line.contains("body line one"));
        assert!(line.contains("body line two"));
        assert!(line.contains("body line three"));
    }

    #[test]
    fn render_line_handles_empty_body() {
        let line = render_line("just a title", "");
        assert_eq!(line, "just a title");
    }

    #[test]
    fn name_parity() {
        let n = LokiNotifier::new("https://x".into(), None, None, "h".into());
        assert_eq!(<LokiNotifier as Notifier>::name(&n), "loki");
        assert_eq!(<LokiNotifier as Channel>::name(&n), "loki");
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_unconfigured() {
        let n = LokiNotifier::new(String::new(), None, None, "h".into());
        let r = <LokiNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        assert!(matches!(r, Err(ChannelError::Other(_))));
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/loki/api/v1/push"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "streams": [{
                    "stream": {
                        "service": "selfdef",
                        "severity": "high",
                    }
                }]
            })))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let n = LokiNotifier::new(
            format!("{}/loki/api/v1/push", server.uri()),
            None,
            None,
            "selfdef".into(),
        );
        let r = <LokiNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn tenant_and_bearer_headers_attached_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/loki/api/v1/push"))
            .and(header("x-scope-orgid", "tenant-99"))
            .and(header("authorization", "Bearer the-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let n = LokiNotifier::new(
            format!("{}/loki/api/v1/push", server.uri()),
            Some("tenant-99".into()),
            Some("the-token".into()),
            "selfdef".into(),
        );
        let r = <LokiNotifier as Channel>::send(&n, &payload(SeverityId::Critical)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn non_success_status_maps_to_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(r#"{"error":"internal"}"#))
            .mount(&server)
            .await;
        let n = LokiNotifier::new(
            format!("{}/loki/api/v1/push", server.uri()),
            None,
            None,
            "selfdef".into(),
        );
        let r = <LokiNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        match r {
            Err(ChannelError::Remote { status, body }) => {
                assert_eq!(status, 500);
                assert!(body.contains("internal"), "body: {body}");
            }
            other => panic!("expected Remote(500), got {other:?}"),
        }
    }
}
