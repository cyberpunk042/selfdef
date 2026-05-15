//! OpenSearch / Elasticsearch document-index outbound channel.
//!
//! SDD-008 Q-G adapter (OpenSearch). Pattern-instance of the
//! integration crate template (`docs/dev/integrations.md`).
//! Implements both the legacy [`Notifier`] trait and the forward-
//! looking [`selfdef_notifier_orchestrator::Channel`] trait.
//!
//! ## Wire shape
//!
//! POST to `<endpoint>/<index>/_doc` with a JSON document:
//!
//! ```json
//! {
//!   "@timestamp": "2026-05-15T12:00:00Z",
//!   "service":    "selfdef",
//!   "host":       "<source>",
//!   "severity":   "high",
//!   "kind":       "Detection Finding",
//!   "title":      "<rendered title>",
//!   "body":       "<rendered body>",
//!   "event_id":   "<uuid, when available>",
//!   "payload_id": "<uuid, engine path only>"
//! }
//! ```
//!
//! The compatible Elasticsearch v7+ document-index API is identical
//! (`/<index>/_doc` POST + JSON body), so this channel works against
//! any OS/ES cluster reachable from the daemon.
//!
//! ## Auth model
//!
//! Two operator-configurable paths:
//!
//! - **Basic auth**: set `username` + `auth_token_file` (the latter
//!   contains the password). Most common for self-hosted clusters
//!   guarded by an OS Security plugin.
//! - **API key**: set `auth_token_file` without `username` and
//!   `auth_kind = "api_key"`. The token contents are sent as
//!   `Authorization: ApiKey <token>` per the AWS-OpenSearch /
//!   Elastic Cloud convention.
//!
//! Empty `auth_token_file` and empty `username` produce an
//! unauthenticated client — fine against a self-hosted cluster
//! protected by network ACLs alone.
//!
//! ## Q-G deferred bits
//!
//! - No `_bulk` batching. v1 sends one POST per event. selfdef's
//!   finding cadence is too sparse for bulk to pay off; high-
//!   throughput collectors can add batching under a future SDD.
//! - No mapping templates. v1 trusts the cluster's default dynamic
//!   mapping; operators wanting strict typing pre-create the
//!   index with a template on the OS side.
//! - No bidirectional ack. OpenSearch is a one-way data store.

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
use time::OffsetDateTime;
use tracing::debug;

/// Auth shape for the OpenSearch channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthKind {
    /// No `Authorization` header. Network-ACL-only clusters.
    #[default]
    None,
    /// HTTP Basic: `Authorization: Basic <base64(user:pass)>`.
    Basic,
    /// AWS-OpenSearch / Elastic Cloud API key:
    /// `Authorization: ApiKey <token>`.
    ApiKey,
}

impl AuthKind {
    /// Parse the operator-facing string form. Returns `None` for
    /// unknown strings; the daemon logs a warn and falls back to
    /// [`Self::default`] (no auth).
    #[must_use]
    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "none" => Some(Self::None),
            "basic" => Some(Self::Basic),
            "apikey" | "api_key" | "api-key" => Some(Self::ApiKey),
            _ => None,
        }
    }
}

/// OpenSearch document-index channel.
pub struct OpenSearchNotifier {
    client: reqwest::Client,
    endpoint: String,
    index: String,
    auth_kind: AuthKind,
    username: Option<String>,
    token: Option<String>,
    source: String,
}

impl std::fmt::Debug for OpenSearchNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the auth token. Show username + endpoint + index
        // freely (operator config).
        f.debug_struct("OpenSearchNotifier")
            .field("endpoint", &self.endpoint)
            .field("index", &self.index)
            .field("auth_kind", &self.auth_kind)
            .field("username", &self.username)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl OpenSearchNotifier {
    /// Explicit constructor. `token` is consumed and stored privately.
    #[must_use]
    pub fn new(
        endpoint: String,
        index: String,
        auth_kind: AuthKind,
        username: Option<String>,
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
            index,
            auth_kind,
            username,
            token,
            source,
        }
    }

    /// Build from config-shaped inputs.
    /// - `endpoint`: required, must be `https://`. Trailing slash
    ///   is stripped.
    /// - `index`: required, non-empty (e.g. `"selfdef-events"`).
    /// - `auth_kind`: `"none"` / `"basic"` / `"apikey"`. Empty =
    ///   `none`. Unknown strings are rejected so misconfigs surface
    ///   loudly rather than silently sending unauthenticated.
    /// - `username`: required for Basic; ignored for ApiKey / None.
    /// - `auth_token_file`: required for Basic + ApiKey; ignored
    ///   for None.
    /// - `source`: surfaced as the `host` field on each document.
    ///   Defaults to `"selfdef"` when empty.
    pub fn from_config(
        endpoint: &str,
        index: &str,
        auth_kind: &str,
        username: &str,
        auth_token_file: Option<&PathBuf>,
        source: &str,
    ) -> Result<Self, OpenSearchBuildError> {
        if endpoint.is_empty() {
            return Err(OpenSearchBuildError::EmptyEndpoint);
        }
        if !endpoint.starts_with("https://") {
            return Err(OpenSearchBuildError::EndpointNotHttps);
        }
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        if index.is_empty() {
            return Err(OpenSearchBuildError::EmptyIndex);
        }
        let auth_kind = AuthKind::from_str_ci(auth_kind)
            .ok_or_else(|| OpenSearchBuildError::UnknownAuthKind(auth_kind.to_owned()))?;
        let (username_opt, token_opt) = match auth_kind {
            AuthKind::None => (None, None),
            AuthKind::Basic => {
                if username.is_empty() {
                    return Err(OpenSearchBuildError::BasicMissingUsername);
                }
                let Some(path) = auth_token_file else {
                    return Err(OpenSearchBuildError::BasicMissingTokenFile);
                };
                let token = read_token(path)?;
                (Some(username.to_owned()), Some(token))
            }
            AuthKind::ApiKey => {
                let Some(path) = auth_token_file else {
                    return Err(OpenSearchBuildError::ApiKeyMissingTokenFile);
                };
                let token = read_token(path)?;
                (None, Some(token))
            }
        };
        let source = if source.is_empty() {
            "selfdef".to_owned()
        } else {
            source.to_owned()
        };
        Ok(Self::new(
            endpoint,
            index.to_owned(),
            auth_kind,
            username_opt,
            token_opt,
            source,
        ))
    }

    /// Shared POST core. Builds the JSON document and indexes it.
    async fn index_document(
        &self,
        doc: &OpenSearchDocument<'_>,
    ) -> Result<(), OpenSearchDeliveryError> {
        if self.endpoint.is_empty() || self.index.is_empty() {
            return Err(OpenSearchDeliveryError::NotConfigured);
        }
        let url = format!("{}/{}/_doc", self.endpoint, self.index);
        let mut req = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(doc);
        match (self.auth_kind, &self.username, &self.token) {
            (AuthKind::Basic, Some(user), Some(pass)) => {
                req = req.basic_auth(user, Some(pass));
            }
            (AuthKind::ApiKey, _, Some(tok)) => {
                req = req.header("authorization", format!("ApiKey {tok}"));
            }
            _ => {}
        }
        let resp = req
            .send()
            .await
            .map_err(|e| OpenSearchDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, index = %self.index, "opensearch delivered");
            return Ok(());
        }
        Err(OpenSearchDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

fn read_token(path: &PathBuf) -> Result<String, OpenSearchBuildError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| OpenSearchBuildError::TokenFileUnreadable(e.to_string()))?
        .trim()
        .to_owned();
    if raw.is_empty() {
        return Err(OpenSearchBuildError::EmptyTokenFile);
    }
    Ok(raw)
}

/// Wire shape for the indexed document.
#[derive(Debug, Serialize)]
struct OpenSearchDocument<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    service: &'static str,
    host: &'a str,
    severity: &'static str,
    kind: Option<&'a str>,
    title: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_id: Option<String>,
}

/// Map OCSF severity → the string label OpenSearch sees.
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

/// RFC-3339 timestamp for the `@timestamp` field. Falls back to a
/// zero-epoch string on the (impossible) clock-before-epoch case.
fn iso8601_now() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// Errors from [`OpenSearchNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum OpenSearchBuildError {
    #[error("opensearch endpoint is empty (set [notifier.opensearch].endpoint)")]
    EmptyEndpoint,
    #[error("opensearch endpoint must be https://; refuse to send credentials over plaintext")]
    EndpointNotHttps,
    #[error("opensearch index is empty (set [notifier.opensearch].index)")]
    EmptyIndex,
    #[error("opensearch auth_kind must be one of: none|basic|apikey; got {0:?}")]
    UnknownAuthKind(String),
    #[error("opensearch auth_kind = basic requires a non-empty username")]
    BasicMissingUsername,
    #[error("opensearch auth_kind = basic requires auth_token_file (password)")]
    BasicMissingTokenFile,
    #[error("opensearch auth_kind = apikey requires auth_token_file")]
    ApiKeyMissingTokenFile,
    #[error("opensearch auth_token_file unreadable: {0}")]
    TokenFileUnreadable(String),
    #[error("opensearch auth_token_file is empty after trim")]
    EmptyTokenFile,
}

/// Internal delivery error.
#[derive(Debug, thiserror::Error)]
enum OpenSearchDeliveryError {
    #[error("opensearch not configured (empty endpoint or index)")]
    NotConfigured,
    #[error("opensearch transport error: {0}")]
    Transport(String),
    #[error("opensearch remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<OpenSearchDeliveryError> for NotifierError {
    fn from(e: OpenSearchDeliveryError) -> Self {
        match e {
            OpenSearchDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<OpenSearchDeliveryError> for ChannelError {
    fn from(e: OpenSearchDeliveryError) -> Self {
        match e {
            OpenSearchDeliveryError::NotConfigured => {
                Self::Other("opensearch not configured".into())
            }
            OpenSearchDeliveryError::Transport(s) => Self::Transport(s),
            OpenSearchDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

#[async_trait]
impl Notifier for OpenSearchNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let title = render_title(event);
        let body = render_body(event);
        let kind = event.class_uid.name();
        let doc = OpenSearchDocument {
            timestamp: iso8601_now(),
            service: "selfdef",
            host: &self.source,
            severity: severity_label(event.severity_id),
            kind: Some(kind),
            title: &title,
            body: &body,
            event_id: Some(event.id.simple().to_string()),
            payload_id: None,
        };
        self.index_document(&doc).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "opensearch"
    }
}

#[async_trait]
impl Channel for OpenSearchNotifier {
    fn name(&self) -> &str {
        "opensearch"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let doc = OpenSearchDocument {
            timestamp: iso8601_now(),
            service: "selfdef",
            host: &self.source,
            severity: severity_label(payload.severity),
            kind: payload.event_kind.as_deref(),
            title: &payload.title,
            body: &payload.body,
            event_id: payload.event_id.map(|e| e.0.simple().to_string()),
            payload_id: Some(payload.id.0.simple().to_string()),
        };
        self.index_document(&doc).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
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
    fn auth_kind_parse_round_trips() {
        assert_eq!(AuthKind::from_str_ci(""), Some(AuthKind::None));
        assert_eq!(AuthKind::from_str_ci("none"), Some(AuthKind::None));
        assert_eq!(AuthKind::from_str_ci("Basic"), Some(AuthKind::Basic));
        assert_eq!(AuthKind::from_str_ci("APIKEY"), Some(AuthKind::ApiKey));
        assert_eq!(AuthKind::from_str_ci("api-key"), Some(AuthKind::ApiKey));
        assert_eq!(AuthKind::from_str_ci("api_key"), Some(AuthKind::ApiKey));
        assert_eq!(AuthKind::from_str_ci("oauth"), None);
    }

    #[test]
    fn from_config_rejects_empty_endpoint() {
        let err = OpenSearchNotifier::from_config("", "idx", "", "", None, "")
            .expect_err("empty endpoint must fail");
        assert!(matches!(err, OpenSearchBuildError::EmptyEndpoint));
    }

    #[test]
    fn from_config_rejects_http_endpoint() {
        let err = OpenSearchNotifier::from_config("http://os.example", "idx", "", "", None, "")
            .expect_err("plaintext endpoint must fail");
        assert!(matches!(err, OpenSearchBuildError::EndpointNotHttps));
    }

    #[test]
    fn from_config_rejects_empty_index() {
        let err = OpenSearchNotifier::from_config("https://os.example", "", "", "", None, "")
            .expect_err("empty index must fail");
        assert!(matches!(err, OpenSearchBuildError::EmptyIndex));
    }

    #[test]
    fn from_config_rejects_unknown_auth_kind() {
        let err =
            OpenSearchNotifier::from_config("https://os.example", "idx", "oauth", "", None, "")
                .expect_err("unknown auth must fail");
        assert!(matches!(err, OpenSearchBuildError::UnknownAuthKind(_)));
    }

    #[test]
    fn from_config_basic_requires_username() {
        let f = write_file("pw");
        let err = OpenSearchNotifier::from_config(
            "https://os.example",
            "idx",
            "basic",
            "",
            Some(&f.path().to_owned()),
            "",
        )
        .expect_err("basic without user must fail");
        assert!(matches!(err, OpenSearchBuildError::BasicMissingUsername));
    }

    #[test]
    fn from_config_basic_requires_token_file() {
        let err = OpenSearchNotifier::from_config(
            "https://os.example",
            "idx",
            "basic",
            "admin",
            None,
            "",
        )
        .expect_err("basic without token must fail");
        assert!(matches!(err, OpenSearchBuildError::BasicMissingTokenFile));
    }

    #[test]
    fn from_config_apikey_requires_token_file() {
        let err =
            OpenSearchNotifier::from_config("https://os.example", "idx", "apikey", "", None, "")
                .expect_err("apikey without token must fail");
        assert!(matches!(err, OpenSearchBuildError::ApiKeyMissingTokenFile));
    }

    #[test]
    fn from_config_rejects_empty_token_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = OpenSearchNotifier::from_config(
            "https://os.example",
            "idx",
            "apikey",
            "",
            Some(&f.path().to_owned()),
            "",
        )
        .expect_err("empty token must fail");
        assert!(matches!(err, OpenSearchBuildError::EmptyTokenFile));
    }

    #[test]
    fn from_config_unauth_round_trip() {
        let n = OpenSearchNotifier::from_config(
            "https://os.example/",
            "selfdef-events",
            "",
            "",
            None,
            "",
        )
        .unwrap();
        assert_eq!(n.endpoint, "https://os.example"); // trailing slash stripped
        assert_eq!(n.index, "selfdef-events");
        assert_eq!(n.auth_kind, AuthKind::None);
        assert!(n.username.is_none());
        assert!(n.token.is_none());
        assert_eq!(n.source, "selfdef");
    }

    #[test]
    fn from_config_basic_round_trip() {
        let f = write_file("the-password");
        let n = OpenSearchNotifier::from_config(
            "https://os.example",
            "selfdef-events",
            "basic",
            "admin",
            Some(&f.path().to_owned()),
            "my-host",
        )
        .unwrap();
        assert_eq!(n.auth_kind, AuthKind::Basic);
        assert_eq!(n.username.as_deref(), Some("admin"));
        assert_eq!(n.token.as_deref(), Some("the-password"));
        assert_eq!(n.source, "my-host");
    }

    #[test]
    fn from_config_apikey_round_trip() {
        let f = write_file("the-api-key");
        let n = OpenSearchNotifier::from_config(
            "https://os.example",
            "selfdef-events",
            "apikey",
            "",
            Some(&f.path().to_owned()),
            "",
        )
        .unwrap();
        assert_eq!(n.auth_kind, AuthKind::ApiKey);
        assert!(n.username.is_none());
        assert_eq!(n.token.as_deref(), Some("the-api-key"));
    }

    #[test]
    fn debug_elides_token() {
        let n = OpenSearchNotifier::new(
            "https://os.example".into(),
            "idx".into(),
            AuthKind::Basic,
            Some("admin".into()),
            Some("SECRET-PASSWORD".into()),
            "h".into(),
        );
        let s = format!("{n:?}");
        assert!(!s.contains("SECRET-PASSWORD"), "leaks: {s}");
        assert!(s.contains("admin"), "user visible: {s}");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn severity_labels_complete() {
        for s in [
            SeverityId::Informational,
            SeverityId::Low,
            SeverityId::Medium,
            SeverityId::High,
            SeverityId::Critical,
            SeverityId::Fatal,
        ] {
            assert!(!severity_label(s).is_empty(), "severity {s:?} unmapped");
        }
    }

    #[test]
    fn iso8601_now_emits_rfc3339() {
        let s = iso8601_now();
        // RFC-3339 looks like 2026-05-15T12:00:00.123456789Z
        assert!(s.ends_with('Z'), "got: {s}");
        assert!(s.contains('T'), "got: {s}");
        assert!(s.len() >= 20, "got: {s}");
    }

    #[test]
    fn name_parity() {
        let n = OpenSearchNotifier::new(
            "https://x".into(),
            "idx".into(),
            AuthKind::None,
            None,
            None,
            "h".into(),
        );
        assert_eq!(<OpenSearchNotifier as Notifier>::name(&n), "opensearch");
        assert_eq!(<OpenSearchNotifier as Channel>::name(&n), "opensearch");
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_unconfigured() {
        let n = OpenSearchNotifier::new(
            String::new(),
            "idx".into(),
            AuthKind::None,
            None,
            None,
            "h".into(),
        );
        let r = <OpenSearchNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        assert!(matches!(r, Err(ChannelError::Other(_))));
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/selfdef-events/_doc"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "service":  "selfdef",
                "severity": "high",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"result":"created"}"#))
            .mount(&server)
            .await;
        let n = OpenSearchNotifier::new(
            server.uri(),
            "selfdef-events".into(),
            AuthKind::None,
            None,
            None,
            "selfdef".into(),
        );
        let r = <OpenSearchNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/selfdef-events/_doc"))
            .and(body_partial_json(serde_json::json!({
                "service":  "selfdef",
                "severity": "critical",
                "kind":     "Detection Finding",
            })))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let n = OpenSearchNotifier::new(
            server.uri(),
            "selfdef-events".into(),
            AuthKind::None,
            None,
            None,
            "selfdef".into(),
        );
        let r = <OpenSearchNotifier as Channel>::send(&n, &payload(SeverityId::Critical)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn basic_auth_header_attached_when_configured() {
        let server = MockServer::start().await;
        // base64("admin:the-pass") = YWRtaW46dGhlLXBhc3M=
        Mock::given(method("POST"))
            .and(header("authorization", "Basic YWRtaW46dGhlLXBhc3M="))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let n = OpenSearchNotifier::new(
            server.uri(),
            "idx".into(),
            AuthKind::Basic,
            Some("admin".into()),
            Some("the-pass".into()),
            "h".into(),
        );
        let r = <OpenSearchNotifier as Channel>::send(&n, &payload(SeverityId::Low)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn apikey_header_attached_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "ApiKey the-api-key"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let n = OpenSearchNotifier::new(
            server.uri(),
            "idx".into(),
            AuthKind::ApiKey,
            None,
            Some("the-api-key".into()),
            "h".into(),
        );
        let r = <OpenSearchNotifier as Channel>::send(&n, &payload(SeverityId::Medium)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn non_success_status_maps_to_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"error":{"type":"security_exception"}}"#),
            )
            .mount(&server)
            .await;
        let n = OpenSearchNotifier::new(
            server.uri(),
            "idx".into(),
            AuthKind::None,
            None,
            None,
            "h".into(),
        );
        let r = <OpenSearchNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        match r {
            Err(ChannelError::Remote { status, body }) => {
                assert_eq!(status, 403);
                assert!(body.contains("security_exception"), "body: {body}");
            }
            other => panic!("expected Remote(403), got {other:?}"),
        }
    }
}
