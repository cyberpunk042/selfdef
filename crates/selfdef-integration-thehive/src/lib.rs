//! TheHive incident-management alert-API outbound channel.
//!
//! SDD-008 Q-G adapter (TheHive). Pattern-instance of the
//! integration crate template (`docs/dev/integrations.md`). Each
//! selfdef event becomes a TheHive Alert via the
//! `POST /api/v1/alert` endpoint, ready for an analyst to triage
//! or promote into a Case.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "type":          "selfdef",
//!   "source":        "<host>",
//!   "sourceRef":     "<event_id>",
//!   "title":         "<rendered title>",
//!   "description":   "<rendered body>",
//!   "severity":      2,
//!   "tlp":           2,
//!   "tags":          ["selfdef", "selfdef:high", "kind:Detection Finding"]
//! }
//! ```
//!
//! TheHive's `severity` is a 1-4 integer (`1=Low, 2=Medium,
//! 3=High, 4=Critical`); OCSF's six levels collapse as follows:
//!
//! | OCSF | TheHive |
//! | --- | --- |
//! | Unknown / Other / Informational / Low | 1 (Low) |
//! | Medium | 2 (Medium) |
//! | High | 3 (High) |
//! | Critical / Fatal | 4 (Critical) |
//!
//! TLP is `Amber` (2) by default — Selfdef-style detection
//! findings often contain hostnames / paths / IPs the operator
//! shouldn't broadcast outside the SOC.
//!
//! ## Auth model
//!
//! TheHive uses Bearer API keys in `Authorization: Bearer <key>`.
//! Operator stores the key in `api_key_file` (one line, no
//! trailing whitespace), mode `0600`. The key IS the auth — there
//! is no orchestrator-level username concept.
//!
//! ## Q-G deferred bits
//!
//! - **No observable attachment**. v1 ships title + body + tags
//!   only. TheHive supports rich observables (IPs, file hashes,
//!   URLs) that the operator can pivot on; surfacing those would
//!   need `Payload` to carry IOC metadata. Future SDD.
//! - **No `sourceRef` dedup**. v1 generates a new alert per fire
//!   (the engine path's PayloadId differs per rung; the legacy
//!   chain path uses the Event id). TheHive's native dedup-by-
//!   sourceRef is therefore opt-out, not opt-in. SDD-008's "an
//!   unacked alert pages louder" semantics + the fact that
//!   TheHive *also* has its own state machine means this is
//!   defensible; a future revision can thread EventId as a stable
//!   sourceRef and switch to the update-existing flow.
//! - **No case promotion**. v1 always posts Alerts (analyst
//!   decides case promotion). A future revision could pre-promote
//!   based on severity threshold.

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

/// TheHive default TLP (Traffic Light Protocol) for selfdef
/// alerts. `Amber` = "limited disclosure, restricted to
/// participants' organizations" — appropriate for SOC-internal
/// detection findings. Operators can override at a future
/// `with_tlp` builder once we surface this knob.
pub const DEFAULT_TLP: u8 = 2;

/// TheHive alert channel.
pub struct TheHiveNotifier {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    source: String,
    alert_type: String,
}

impl std::fmt::Debug for TheHiveNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the api_key entirely — its prefix is shown so
        // operators can disambiguate multiple TheHive instances
        // in logs.
        let prefix = self
            .api_key
            .get(..8)
            .map(str::to_string)
            .unwrap_or_default();
        f.debug_struct("TheHiveNotifier")
            .field("endpoint", &self.endpoint)
            .field("api_key_prefix", &format!("{prefix}…"))
            .field("source", &self.source)
            .field("alert_type", &self.alert_type)
            .finish_non_exhaustive()
    }
}

impl TheHiveNotifier {
    /// Explicit constructor.
    #[must_use]
    pub fn new(endpoint: String, api_key: String, source: String, alert_type: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            endpoint,
            api_key,
            source,
            alert_type,
        }
    }

    /// Build from config-shaped inputs.
    /// - `endpoint`: required, must be `https://`. Trailing slash
    ///   is stripped.
    /// - `api_key_file`: required; one-line file containing the
    ///   Bearer API key.
    /// - `source`: alert `source` field. Defaults to `"selfdef"`.
    /// - `alert_type`: alert `type` field. Defaults to `"selfdef"`.
    pub fn from_config(
        endpoint: &str,
        api_key_file: &PathBuf,
        source: &str,
        alert_type: &str,
    ) -> Result<Self, TheHiveBuildError> {
        if endpoint.is_empty() {
            return Err(TheHiveBuildError::EmptyEndpoint);
        }
        if !endpoint.starts_with("https://") {
            return Err(TheHiveBuildError::EndpointNotHttps);
        }
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        let api_key = std::fs::read_to_string(api_key_file)
            .map_err(|e| TheHiveBuildError::ApiKeyFileUnreadable(e.to_string()))?
            .trim()
            .to_owned();
        if api_key.is_empty() {
            return Err(TheHiveBuildError::EmptyApiKeyFile);
        }
        let source = if source.is_empty() {
            "selfdef".to_owned()
        } else {
            source.to_owned()
        };
        let alert_type = if alert_type.is_empty() {
            "selfdef".to_owned()
        } else {
            alert_type.to_owned()
        };
        Ok(Self::new(endpoint, api_key, source, alert_type))
    }

    /// Shared POST core. Posts to `<endpoint>/api/v1/alert`.
    async fn post_alert(&self, alert: &TheHiveAlert<'_>) -> Result<(), TheHiveDeliveryError> {
        if self.endpoint.is_empty() || self.api_key.is_empty() {
            return Err(TheHiveDeliveryError::NotConfigured);
        }
        let url = format!("{}/api/v1/alert", self.endpoint);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(alert)
            .send()
            .await
            .map_err(|e| TheHiveDeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            debug!(status = %status, "thehive delivered");
            return Ok(());
        }
        Err(TheHiveDeliveryError::Remote {
            status: status.as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

/// Wire shape for the TheHive alert POST body.
#[derive(Debug, Serialize)]
struct TheHiveAlert<'a> {
    #[serde(rename = "type")]
    alert_type: &'a str,
    source: &'a str,
    #[serde(rename = "sourceRef")]
    source_ref: String,
    title: &'a str,
    description: &'a str,
    severity: u8,
    tlp: u8,
    tags: Vec<String>,
}

/// Map OCSF severity → TheHive 1-4 scale.
fn map_severity(s: SeverityId) -> u8 {
    match s {
        SeverityId::Unknown | SeverityId::Other | SeverityId::Informational | SeverityId::Low => 1,
        SeverityId::Medium => 2,
        SeverityId::High => 3,
        SeverityId::Critical | SeverityId::Fatal => 4,
    }
}

/// Stable lowercase severity label for tag composition.
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

fn compose_tags(severity: SeverityId, kind: Option<&str>) -> Vec<String> {
    let mut tags = vec![
        "selfdef".to_string(),
        format!("selfdef:{}", severity_label(severity)),
    ];
    if let Some(k) = kind {
        tags.push(format!("kind:{k}"));
    }
    tags
}

/// Errors from [`TheHiveNotifier::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum TheHiveBuildError {
    #[error("thehive endpoint is empty (set [notifier.thehive].endpoint)")]
    EmptyEndpoint,
    #[error("thehive endpoint must be https://; refuse to send credentials over plaintext")]
    EndpointNotHttps,
    #[error("thehive api_key_file unreadable: {0}")]
    ApiKeyFileUnreadable(String),
    #[error("thehive api_key_file is empty after trim")]
    EmptyApiKeyFile,
}

/// Internal delivery error.
#[derive(Debug, thiserror::Error)]
enum TheHiveDeliveryError {
    #[error("thehive not configured (empty endpoint or api_key)")]
    NotConfigured,
    #[error("thehive transport error: {0}")]
    Transport(String),
    #[error("thehive remote returned {status}: {body}")]
    Remote { status: u16, body: String },
}

impl From<TheHiveDeliveryError> for NotifierError {
    fn from(e: TheHiveDeliveryError) -> Self {
        match e {
            TheHiveDeliveryError::NotConfigured => Self::NotConfigured,
            other => Self::Http(other.to_string()),
        }
    }
}

impl From<TheHiveDeliveryError> for ChannelError {
    fn from(e: TheHiveDeliveryError) -> Self {
        match e {
            TheHiveDeliveryError::NotConfigured => Self::Other("thehive not configured".into()),
            TheHiveDeliveryError::Transport(s) => Self::Transport(s),
            TheHiveDeliveryError::Remote { status, body } => Self::Remote { status, body },
        }
    }
}

#[async_trait]
impl Notifier for TheHiveNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        let title = render_title(event);
        let body = render_body(event);
        let kind = event.class_uid.name();
        let alert = TheHiveAlert {
            alert_type: &self.alert_type,
            source: &self.source,
            source_ref: event.id.simple().to_string(),
            title: &title,
            description: &body,
            severity: map_severity(event.severity_id),
            tlp: DEFAULT_TLP,
            tags: compose_tags(event.severity_id, Some(kind)),
        };
        self.post_alert(&alert).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "thehive"
    }
}

#[async_trait]
impl Channel for TheHiveNotifier {
    fn name(&self) -> &str {
        "thehive"
    }

    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
        let source_ref = payload.id.0.simple().to_string();
        let alert = TheHiveAlert {
            alert_type: &self.alert_type,
            source: &self.source,
            source_ref,
            title: &payload.title,
            description: &payload.body,
            severity: map_severity(payload.severity),
            tlp: DEFAULT_TLP,
            tags: compose_tags(payload.severity, payload.event_kind.as_deref()),
        };
        self.post_alert(&alert).await?;
        Ok(DeliveryReceipt::empty())
    }

    fn supports_ack_reply(&self) -> bool {
        // TheHive has its own alert state machine; v1 doesn't wire
        // the inbound webhook receiver for analyst-side acks.
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
    fn severity_map_collapses_six_to_four() {
        assert_eq!(map_severity(SeverityId::Informational), 1);
        assert_eq!(map_severity(SeverityId::Low), 1);
        assert_eq!(map_severity(SeverityId::Medium), 2);
        assert_eq!(map_severity(SeverityId::High), 3);
        assert_eq!(map_severity(SeverityId::Critical), 4);
        assert_eq!(map_severity(SeverityId::Fatal), 4);
        assert_eq!(map_severity(SeverityId::Unknown), 1);
    }

    #[test]
    fn compose_tags_builds_expected_set() {
        let tags = compose_tags(SeverityId::Critical, Some("Security Finding"));
        assert!(tags.contains(&"selfdef".to_string()));
        assert!(tags.contains(&"selfdef:critical".to_string()));
        assert!(tags.contains(&"kind:Security Finding".to_string()));
    }

    #[test]
    fn compose_tags_omits_kind_when_none() {
        let tags = compose_tags(SeverityId::High, None);
        assert!(tags.iter().all(|t| !t.starts_with("kind:")));
    }

    #[test]
    fn from_config_rejects_empty_endpoint() {
        let f = write_file("k");
        let err = TheHiveNotifier::from_config("", &f.path().to_owned(), "", "")
            .expect_err("empty endpoint must fail");
        assert!(matches!(err, TheHiveBuildError::EmptyEndpoint));
    }

    #[test]
    fn from_config_rejects_http_endpoint() {
        let f = write_file("k");
        let err = TheHiveNotifier::from_config("http://hive.example", &f.path().to_owned(), "", "")
            .expect_err("plaintext endpoint must fail");
        assert!(matches!(err, TheHiveBuildError::EndpointNotHttps));
    }

    #[test]
    fn from_config_rejects_empty_api_key_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err =
            TheHiveNotifier::from_config("https://hive.example", &f.path().to_owned(), "", "")
                .expect_err("empty file must fail");
        assert!(matches!(err, TheHiveBuildError::EmptyApiKeyFile));
    }

    #[test]
    fn from_config_rejects_missing_api_key_file() {
        let err = TheHiveNotifier::from_config(
            "https://hive.example",
            &PathBuf::from("/nonexistent/path/to/key"),
            "",
            "",
        )
        .expect_err("missing file must fail");
        assert!(matches!(err, TheHiveBuildError::ApiKeyFileUnreadable(_)));
    }

    #[test]
    fn from_config_strips_trailing_slash() {
        let f = write_file("the-key");
        let n = TheHiveNotifier::from_config("https://hive.example/", &f.path().to_owned(), "", "")
            .unwrap();
        assert_eq!(n.endpoint, "https://hive.example");
    }

    #[test]
    fn from_config_supplies_defaults() {
        let f = write_file("the-key");
        let n = TheHiveNotifier::from_config("https://hive.example", &f.path().to_owned(), "", "")
            .unwrap();
        assert_eq!(n.source, "selfdef");
        assert_eq!(n.alert_type, "selfdef");
        assert_eq!(n.api_key, "the-key");
    }

    #[test]
    fn from_config_round_trips_explicit_values() {
        let f = write_file("the-key");
        let n = TheHiveNotifier::from_config(
            "https://hive.example",
            &f.path().to_owned(),
            "my-host",
            "selfdef-detection",
        )
        .unwrap();
        assert_eq!(n.source, "my-host");
        assert_eq!(n.alert_type, "selfdef-detection");
    }

    #[test]
    fn debug_elides_api_key() {
        let n = TheHiveNotifier::new(
            "https://hive.example".into(),
            "SECRET-HIVE-API-KEY-NEVER-PRINTED".into(),
            "host".into(),
            "selfdef".into(),
        );
        let s = format!("{n:?}");
        assert!(!s.contains("NEVER-PRINTED"), "leaks: {s}");
        assert!(s.contains("SECRET-H"), "prefix shown for triage: {s}");
    }

    #[test]
    fn name_parity() {
        let n = TheHiveNotifier::new("https://x".into(), "k".into(), "h".into(), "selfdef".into());
        assert_eq!(<TheHiveNotifier as Notifier>::name(&n), "thehive");
        assert_eq!(<TheHiveNotifier as Channel>::name(&n), "thehive");
    }

    #[tokio::test]
    async fn channel_send_returns_channel_error_when_unconfigured() {
        let n = TheHiveNotifier::new(String::new(), "k".into(), "h".into(), "selfdef".into());
        let r = <TheHiveNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        assert!(matches!(r, Err(ChannelError::Other(_))));
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/alert"))
            .and(header("authorization", "Bearer test-key"))
            .and(body_partial_json(serde_json::json!({
                "type":     "selfdef",
                "source":   "selfdef",
                "severity": 3,
                "tlp":      2,
            })))
            .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"_id":"~123"}"#))
            .mount(&server)
            .await;
        let n = TheHiveNotifier::new(
            server.uri(),
            "test-key".into(),
            "selfdef".into(),
            "selfdef".into(),
        );
        let r = <TheHiveNotifier as Notifier>::notify(&n, &finding_event()).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn happy_path_against_wiremock_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/alert"))
            .and(body_partial_json(serde_json::json!({
                "severity": 4,
                "tlp":      2,
            })))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let n = TheHiveNotifier::new(
            server.uri(),
            "test-key".into(),
            "selfdef".into(),
            "selfdef".into(),
        );
        let r = <TheHiveNotifier as Channel>::send(&n, &payload(SeverityId::Critical)).await;
        assert!(r.is_ok(), "{r:?}");
    }

    #[tokio::test]
    async fn non_success_status_maps_to_remote_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"type":"AuthErr"}"#))
            .mount(&server)
            .await;
        let n = TheHiveNotifier::new(
            server.uri(),
            "test-key".into(),
            "selfdef".into(),
            "selfdef".into(),
        );
        let r = <TheHiveNotifier as Channel>::send(&n, &payload(SeverityId::High)).await;
        match r {
            Err(ChannelError::Remote { status, body }) => {
                assert_eq!(status, 401);
                assert!(body.contains("AuthErr"), "body: {body}");
            }
            other => panic!("expected Remote(401), got {other:?}"),
        }
    }
}
