//! Notifier trait + shared helpers + chain composer.
//!
//! Crate trajectory (SDD-008):
//! - M4 shipped `NtfyNotifier` + `SignalCliNotifier` inside this crate.
//! - **D-2b** moved `NtfyNotifier` into
//!   [`selfdef_integration_ntfy`](https://docs.rs/selfdef-integration-ntfy).
//! - **D-2c** moved `SignalCliNotifier` into
//!   [`selfdef_integration_signal`](https://docs.rs/selfdef-integration-signal).
//!
//! What remains here is the legacy ABI surface every channel still
//! plugs into: the [`Notifier`] trait, the [`NotifierError`] type,
//! the shared rendering helpers ([`render_title`], [`render_body`],
//! [`priority_for`]), and the [`NotifierChain`] composer. The new
//! orchestrator ABI is [`selfdef_notifier_orchestrator::Channel`];
//! integration crates implement **both** so existing M4 callers keep
//! working through the legacy trait while the orchestrator (D-5+)
//! consumes the same impl through `Channel`.
//!
//! [`NotifierChain`] tries notifiers in order; the first success
//! wins. The chain itself implements [`Notifier`] so it drops into
//! anywhere a single notifier fits.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_core::severity::SeverityId;
use thiserror::Error;
use tracing::warn;

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
