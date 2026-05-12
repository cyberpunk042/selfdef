//! Outbound notification channels.
//!
//! M4 ships two implementations of the [`Notifier`] trait:
//! - [`NtfyNotifier`] — HTTP POST to a self-hosted ntfy server. Optional
//!   bearer token loaded from disk.
//! - [`SignalCliNotifier`] — subprocess call to `signal-cli`. Useful as a
//!   fallback channel when the network ntfy path is down.
//!
//! [`NotifierChain`] composes a list of notifiers and tries them in order;
//! the first success wins. The chain itself implements [`Notifier`] so it
//! drops into anywhere a single notifier fits.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum NotifierError {
    #[error("http error: {0}")]
    Http(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signal-cli failed: exit={status}, stderr={stderr}")]
    SignalCli { status: i32, stderr: String },
    #[error("all notification channels failed")]
    AllChannelsFailed,
    #[error("notifier is not configured")]
    NotConfigured,
}

/// Outbound notification channel.
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError>;
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------- shared helpers

/// Title rendered into notifications. e.g. `[HIGH] Possible SSH brute force from …`
#[must_use]
pub fn render_title(event: &Event) -> String {
    let summary = event
        .message
        .as_deref()
        .unwrap_or("Detection")
        .lines()
        .next()
        .unwrap_or("Detection");
    format!("[{}] {summary}", event.severity_id)
}

/// Body rendered into notifications. Includes ATT&CK tags, src endpoint,
/// message — anything we have.
#[must_use]
pub fn render_body(event: &Event) -> String {
    let mut out = String::new();
    if let Some(msg) = &event.message {
        out.push_str(msg);
        out.push('\n');
    }
    if let Some(src) = event
        .src_endpoint
        .as_ref()
        .and_then(|e| e.ip.map(|ip| ip.to_string()))
    {
        out.push_str(&format!("source: {src}\n"));
    }
    if !event.attack.is_empty() {
        let ids: Vec<&str> = event.attack.iter().map(|t| t.id.as_str()).collect();
        out.push_str(&format!("att&ck: {}\n", ids.join(", ")));
    }
    out.push_str(&format!("class: {}\n", event.class_uid.name()));
    out.push_str(&format!("host:  {}\n", event.host_tag));
    out.push_str(&format!("id:    {}\n", event.id));
    out
}

/// ntfy priority 1..=5 from OCSF severity_id.
#[must_use]
pub const fn priority_for(severity: SeverityId) -> u8 {
    match severity {
        SeverityId::Unknown | SeverityId::Informational => 2,
        SeverityId::Low => 3,
        SeverityId::Medium => 4,
        SeverityId::High | SeverityId::Critical | SeverityId::Fatal | SeverityId::Other => 5,
    }
}

// ---------------------------------------------------------------- NtfyNotifier

#[derive(Debug)]
pub struct NtfyNotifier {
    url: String,
    topic: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl NtfyNotifier {
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

    /// Construct from a token file. If `token_file` is None or unreadable,
    /// authentication is omitted (suitable for unauthenticated ntfy servers).
    pub fn from_config(url: &str, topic: &str, token_file: Option<&PathBuf>) -> Self {
        let token = token_file
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self::new(url, topic, token)
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.url.is_empty() || self.topic.is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        let endpoint = format!("{}/{}", self.url.trim_end_matches('/'), self.topic);
        let title = render_title(event);
        let body = render_body(event);
        let priority = priority_for(event.severity_id);
        let tags = if event.attack.is_empty() {
            "shield".to_string()
        } else {
            let mut t = vec!["shield".to_string()];
            for technique in &event.attack {
                t.push(technique.id.clone());
            }
            t.join(",")
        };

        // Up to 3 attempts with light backoff. ntfy is single-POST, no streaming.
        let mut last_err: Option<NotifierError> = None;
        for attempt in 0u32..3 {
            if attempt > 0 {
                let backoff = Duration::from_millis(200u64 << attempt);
                tokio::time::sleep(backoff).await;
            }
            let mut req = self
                .client
                .post(&endpoint)
                .header("Title", &title)
                .header("Priority", priority.to_string())
                .header("Tags", &tags)
                .body(body.clone());
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(attempt, status = %resp.status(), "ntfy delivered");
                    return Ok(());
                }
                Ok(resp) => {
                    let status = resp.status();
                    last_err = Some(NotifierError::Http(format!("non-success status: {status}")));
                    warn!(attempt, %status, "ntfy non-success response");
                }
                Err(e) => {
                    last_err = Some(NotifierError::Http(e.to_string()));
                    warn!(attempt, error = %e, "ntfy send failed");
                }
            }
        }
        Err(last_err.unwrap_or_else(|| NotifierError::Http("unknown".into())))
    }

    fn name(&self) -> &'static str {
        "ntfy"
    }
}

// ---------------------------------------------------------------- SignalCliNotifier

#[derive(Debug)]
pub struct SignalCliNotifier {
    binary: PathBuf,
    account: String,
    recipient: String,
}

impl SignalCliNotifier {
    pub fn new(binary: PathBuf, account: String, recipient: String) -> Self {
        Self {
            binary,
            account,
            recipient,
        }
    }
}

#[async_trait]
impl Notifier for SignalCliNotifier {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.account.is_empty() || self.recipient.is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        let message = format!("{}\n\n{}", render_title(event), render_body(event));

        let output = tokio::process::Command::new(&self.binary)
            .arg("-a")
            .arg(&self.account)
            .arg("send")
            .arg("-m")
            .arg(&message)
            .arg(&self.recipient)
            .output()
            .await?;

        if output.status.success() {
            Ok(())
        } else {
            Err(NotifierError::SignalCli {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    fn name(&self) -> &'static str {
        "signal"
    }
}

// ---------------------------------------------------------------- NotifierChain

/// Tries notifiers in order, returning on the first success.
pub struct NotifierChain {
    inner: Vec<Box<dyn Notifier>>,
}

impl std::fmt::Debug for NotifierChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifierChain")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl NotifierChain {
    #[must_use]
    pub fn new(inner: Vec<Box<dyn Notifier>>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[async_trait]
impl Notifier for NotifierChain {
    async fn notify(&self, event: &Event) -> Result<(), NotifierError> {
        if self.inner.is_empty() {
            return Err(NotifierError::NotConfigured);
        }
        for n in &self.inner {
            match n.notify(event).await {
                Ok(()) => return Ok(()),
                Err(e) => warn!(channel = n.name(), error = %e, "channel failed, trying next"),
            }
        }
        Err(NotifierError::AllChannelsFailed)
    }

    fn name(&self) -> &'static str {
        "chain"
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::SeverityId;

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
    fn render_title_includes_severity_and_summary() {
        let e = finding_event();
        let t = render_title(&e);
        assert!(t.contains("High"));
        assert!(t.contains("brute force"));
    }

    #[test]
    fn priority_mapping() {
        assert_eq!(priority_for(SeverityId::Informational), 2);
        assert_eq!(priority_for(SeverityId::Low), 3);
        assert_eq!(priority_for(SeverityId::Medium), 4);
        assert_eq!(priority_for(SeverityId::High), 5);
        assert_eq!(priority_for(SeverityId::Critical), 5);
    }

    #[tokio::test]
    async fn empty_chain_returns_not_configured() {
        let chain = NotifierChain::new(vec![]);
        let e = finding_event();
        assert!(matches!(
            chain.notify(&e).await,
            Err(NotifierError::NotConfigured)
        ));
    }
}
