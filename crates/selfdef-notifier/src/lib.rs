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

// ---------------------------------------------------------------- Subscription (D-3)

/// SDD-008 D-3: per-channel subscription filter.
///
/// Operators configure these per channel via
/// `[notifier.subscriptions.<channel_name>]`. A channel without an
/// explicit subscription uses [`Subscription::default`] which
/// accepts every event.
///
/// v1 ships two filters; the charter's full set
/// (severity_floor / event_kinds / quiet_hours / device_hint) lands
/// incrementally — quiet_hours + device_hint follow once TZ +
/// channel-routing semantics are scoped.
#[derive(Debug, Clone, Default)]
pub struct Subscription {
    /// Minimum severity to forward. Events below this are dropped
    /// before the channel sees them. `None` = accept all severities.
    pub severity_floor: Option<SeverityId>,
    /// Allowed event-kind substrings (matched case-insensitively
    /// against `Event::class_uid::name()`). Empty = accept all kinds.
    /// e.g. `["security", "detection"]` matches both "Security
    /// Finding" and "Detection Finding".
    pub event_kinds: Vec<String>,
}

impl Subscription {
    /// Returns `true` when this event should be forwarded to the
    /// channel under this subscription.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(floor) = self.severity_floor
            && (event.severity_id as u32) < (floor as u32)
        {
            return false;
        }
        if !self.event_kinds.is_empty() {
            let class = event.class_uid.name().to_ascii_lowercase();
            if !self
                .event_kinds
                .iter()
                .any(|k| class.contains(&k.to_ascii_lowercase()))
            {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------- NotifierChain

/// Tries notifiers in order, returning on the first success. Each
/// notifier carries a [`Subscription`] filter (SDD-008 D-3); events
/// that fail the subscription skip the channel before any I/O. A
/// chain in which every channel filters the event out returns
/// `Ok(())` — that's "operator chose silence", not a failure.
pub struct NotifierChain {
    inner: Vec<(Box<dyn Notifier>, Subscription)>,
}

impl std::fmt::Debug for NotifierChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifierChain")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl NotifierChain {
    /// Construct with default (accept-all) subscriptions on every
    /// channel. Pre-D-3 callers keep working unchanged.
    #[must_use]
    pub fn new(inner: Vec<Box<dyn Notifier>>) -> Self {
        Self {
            inner: inner
                .into_iter()
                .map(|n| (n, Subscription::default()))
                .collect(),
        }
    }

    /// SDD-008 D-3: construct from explicit (notifier, subscription)
    /// pairs. Each pair's subscription gates whether that channel
    /// sees an event.
    #[must_use]
    pub fn with_subscriptions(inner: Vec<(Box<dyn Notifier>, Subscription)>) -> Self {
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
        let mut tried = 0usize;
        for (n, sub) in &self.inner {
            if !sub.matches(event) {
                continue;
            }
            tried += 1;
            match n.notify(event).await {
                Ok(()) => return Ok(()),
                Err(e) => warn!(channel = n.name(), error = %e, "channel failed, trying next"),
            }
        }
        if tried == 0 {
            // Operator filtered every channel out for this event.
            // That's intentional silence, not a failure.
            return Ok(());
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

    fn low_event() -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Low,
            "test-host",
            "selfdef.correlator.test",
            0,
        )
    }

    fn process_event() -> Event {
        Event::new(
            ClassUid(1007), // "Process Activity"
            1,
            SeverityId::High,
            "test-host",
            "selfdef.correlator.test",
            0,
        )
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

    #[test]
    fn subscription_default_matches_every_event() {
        let s = Subscription::default();
        assert!(s.matches(&finding_event()));
        assert!(s.matches(&low_event()));
        assert!(s.matches(&process_event()));
    }

    #[test]
    fn subscription_severity_floor_blocks_below() {
        let s = Subscription {
            severity_floor: Some(SeverityId::High),
            ..Subscription::default()
        };
        assert!(s.matches(&finding_event())); // High
        assert!(!s.matches(&low_event())); // Low
    }

    #[test]
    fn subscription_severity_floor_passes_at_and_above() {
        let s = Subscription {
            severity_floor: Some(SeverityId::Medium),
            ..Subscription::default()
        };
        // High >= Medium → pass
        let mut e = low_event();
        e.severity_id = SeverityId::Medium;
        assert!(s.matches(&e));
        e.severity_id = SeverityId::Critical;
        assert!(s.matches(&e));
        e.severity_id = SeverityId::Low;
        assert!(!s.matches(&e));
    }

    #[test]
    fn subscription_event_kinds_substring_case_insensitive() {
        let s = Subscription {
            event_kinds: vec!["detection".to_owned()],
            ..Subscription::default()
        };
        assert!(s.matches(&finding_event())); // "Detection Finding" contains "detection"
        assert!(!s.matches(&process_event())); // "Process Activity" doesn't
    }

    #[test]
    fn subscription_empty_event_kinds_accepts_all() {
        let s = Subscription {
            event_kinds: vec![],
            ..Subscription::default()
        };
        assert!(s.matches(&finding_event()));
        assert!(s.matches(&process_event()));
    }

    #[test]
    fn subscription_multi_kind_any_match_passes() {
        let s = Subscription {
            event_kinds: vec!["security".to_owned(), "detection".to_owned()],
            ..Subscription::default()
        };
        assert!(s.matches(&finding_event()));
    }

    /// A tiny stub Notifier that always succeeds, records the
    /// invocation in an atomic counter, and exposes a name.
    struct StubNotifier {
        name: &'static str,
        sent: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl Notifier for StubNotifier {
        async fn notify(&self, _event: &Event) -> Result<(), NotifierError> {
            self.sent.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(())
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn stub(
        name: &'static str,
    ) -> (
        Box<dyn Notifier>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Box::new(StubNotifier {
                name,
                sent: std::sync::Arc::clone(&counter),
            }),
            counter,
        )
    }

    #[tokio::test]
    async fn chain_with_subscriptions_filters_per_channel() {
        let (n_high, c_high) = stub("high-only");
        let (n_all, c_all) = stub("accept-all");
        let chain = NotifierChain::with_subscriptions(vec![
            (
                n_high,
                Subscription {
                    severity_floor: Some(SeverityId::High),
                    ..Subscription::default()
                },
            ),
            (n_all, Subscription::default()),
        ]);

        // Low event: high-only filters out, accept-all wins.
        chain.notify(&low_event()).await.expect("ok");
        assert_eq!(c_high.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(c_all.load(std::sync::atomic::Ordering::Acquire), 1);

        // High event: high-only fires first, accept-all never sees it.
        chain.notify(&finding_event()).await.expect("ok");
        assert_eq!(c_high.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(c_all.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn chain_with_subscriptions_all_filtered_returns_ok() {
        // Two channels both with severity_floor = Critical; a Low
        // event is filtered by both. The chain returns Ok because
        // "everyone filtered" is operator-intended silence.
        let (n1, c1) = stub("crit-1");
        let (n2, c2) = stub("crit-2");
        let chain = NotifierChain::with_subscriptions(vec![
            (
                n1,
                Subscription {
                    severity_floor: Some(SeverityId::Critical),
                    ..Subscription::default()
                },
            ),
            (
                n2,
                Subscription {
                    severity_floor: Some(SeverityId::Critical),
                    ..Subscription::default()
                },
            ),
        ]);
        chain.notify(&low_event()).await.expect("ok");
        assert_eq!(c1.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(c2.load(std::sync::atomic::Ordering::Acquire), 0);
    }
}
