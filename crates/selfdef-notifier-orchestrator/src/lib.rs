//! Notifier orchestrator — trait + payload types.
//!
//! SDD-008 D-2a: this crate is the load-bearing ABI between the
//! orchestrator (escalation, persistence, profile selection — D-5
//! onward) and the per-service integration crates
//! (`crates/selfdef-integration-<service>`, D-1).
//!
//! Today the crate ships **only** the trait + types. The engine,
//! the SQLite persistence layer, the profile loader, and the ack
//! tracker land in subsequent Ds. Channel implementations now live
//! in their respective integration crates:
//! `crates/selfdef-integration-ntfy` (D-2b) and
//! `crates/selfdef-integration-signal` (D-2c). Future channels
//! (smtp / twilio / slack / discord) follow the same pattern.
//!
//! See [`docs/sdd/008-notifications-orchestration.md`](../../../docs/sdd/008-notifications-orchestration.md)
//! for the full design and
//! [`docs/dev/integrations.md`](../../../docs/dev/integrations.md)
//! for the contributor-facing crate template.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

pub use selfdef_core::severity::SeverityId;

/// Stable id for one notification *attempt*.
///
/// Distinct from [`EventId`]: a single triggering event may produce
/// multiple `PayloadId`s as the escalation engine fans out across
/// rungs. The orchestrator mints these via `Uuid::now_v7()` so they
/// sort by issuance time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayloadId(pub Uuid);

impl PayloadId {
    /// Mint a fresh `PayloadId` (UUIDv7, monotonic in issuance time).
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Render the id as a short ASCII string for inclusion in
    /// outbound headers / message-ids.
    #[must_use]
    pub fn as_short_str(&self) -> String {
        self.0.simple().to_string()
    }
}

impl Default for PayloadId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PayloadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Reference to an originating event in the bus / store.
///
/// Newtype over [`Uuid`] to match `selfdef_core::Event::id`. Wrapping
/// is structural: it keeps a `PayloadId` from being passed where an
/// `EventId` is expected at compile-time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventId(pub Uuid);

impl From<Uuid> for EventId {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// A typed notification payload handed to a [`Channel`] for delivery.
///
/// Construction is straightforward `Payload { id, event_id, … }`; the
/// orchestrator owns the population. Integration crates treat
/// `Payload` as read-only.
#[derive(Clone, Debug)]
pub struct Payload {
    /// Per-attempt id, mint via [`PayloadId::new`].
    pub id: PayloadId,
    /// Originating event reference; `None` for orchestrator-internal
    /// payloads (e.g. self-test pings).
    pub event_id: Option<EventId>,
    /// One-line title, suitable for SMS / push notification subjects.
    /// Must fit within the most-restrictive channel's limit (Twilio
    /// SMS: ~160 chars). Long content goes in [`Self::body`].
    pub title: String,
    /// Multi-line human-readable body. Channels render this verbatim;
    /// formatting beyond plain text is the channel's concern.
    pub body: String,
    /// Severity of the underlying event. Drives DEFCON mapping and
    /// the orchestrator's panic-floor logic.
    pub severity: SeverityId,
    /// Optional pre-rendered HTTP click-link the channel may include
    /// for ack purposes. `None` for channels that handle acks via
    /// native replies (Signal text, Slack button) or that don't
    /// support acks at all.
    pub ack_link: Option<String>,
    /// Event-kind name (e.g. `"Security Finding"`, `"Detection
    /// Finding"`), copied from the originating
    /// `Event::class_uid::name()`. SDD-008 D-5e:
    /// [`Subscription::matches`] consults this together with
    /// `severity` to gate per-channel filtering on the engine path.
    /// `None` for orchestrator-internal payloads with no
    /// originating event.
    pub event_kind: Option<String>,
}

/// Per-channel subscription filter — SDD-008 D-3 + D-5e.
///
/// Operators express filters as `[notifier.subscriptions.<channel>]`
/// in `selfdef.toml`. The daemon converts each
/// `selfdef_config::SubscriptionConfig` into one of these and hands
/// the resulting `HashMap<channel_name, Subscription>` to
/// [`PayloadDispatcher::with_subscriptions`].
///
/// `Default` accepts every event (no filtering); a channel without
/// a `[notifier.subscriptions.<channel>]` entry runs unfiltered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscription {
    /// Minimum severity to forward. Events below this are dropped
    /// before the channel sees them. `None` = accept all severities.
    pub severity_floor: Option<SeverityId>,
    /// Allowed event-kind substrings (matched case-insensitively
    /// against [`Payload::event_kind`]). Empty = accept all kinds.
    /// e.g. `["security", "detection"]` matches both "Security
    /// Finding" and "Detection Finding".
    pub event_kinds: Vec<String>,
}

impl Subscription {
    /// Returns `true` when `payload` should be forwarded to the
    /// channel under this subscription. Conservative on missing
    /// metadata: a payload with `event_kind = None` passes the
    /// `event_kinds` filter only if the filter is empty (operator
    /// asked for "any kind"); otherwise it's dropped because we
    /// can't prove it matches.
    #[must_use]
    pub fn matches(&self, payload: &Payload) -> bool {
        if let Some(floor) = self.severity_floor
            && (payload.severity as u32) < (floor as u32)
        {
            return false;
        }
        if !self.event_kinds.is_empty() {
            let Some(kind) = payload.event_kind.as_ref() else {
                return false;
            };
            let class = kind.to_ascii_lowercase();
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

/// What a [`Channel::send`] hands back on successful delivery.
#[derive(Clone, Debug, Default)]
pub struct DeliveryReceipt {
    /// Channel-native message id (e.g. Twilio SID, ntfy message id,
    /// signal-cli timestamp). `None` for channels that don't surface
    /// one. Used by the ack-correlation path to match channel-native
    /// replies back to the originating [`PayloadId`].
    pub native_message_id: Option<String>,
}

impl DeliveryReceipt {
    /// Construct a receipt carrying the channel's native message id.
    #[must_use]
    pub fn native(id: impl Into<String>) -> Self {
        Self {
            native_message_id: Some(id.into()),
        }
    }

    /// Empty receipt — successful delivery, no native id surfaced.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Errors a [`Channel`] may return from [`Channel::send`].
#[derive(Error, Debug)]
pub enum ChannelError {
    /// Transport-level failure: socket reset, DNS failure, malformed
    /// TLS handshake. Retriable in principle.
    #[error("transport error: {0}")]
    Transport(String),
    /// External service returned a non-success HTTP status (or
    /// subprocess exited non-zero). The `status` is HTTP-shaped for
    /// HTTP channels and an arbitrary `u16` (typically `exit_code as
    /// u16`) for subprocess channels.
    #[error("remote returned {status}: {body}")]
    Remote {
        /// HTTP status code (or subprocess exit code cast to u16).
        status: u16,
        /// Response body / stderr fragment, truncated to a reasonable
        /// length before logging.
        body: String,
    },
    /// Operation exceeded the channel's per-call timeout. Not
    /// automatically retried; orchestrator decides whether to
    /// re-attempt.
    #[error("operation timed out")]
    Timeout,
    /// Channel-specific failure mode not covered by the above. The
    /// orchestrator treats this as terminal for the current attempt.
    #[error("channel error: {0}")]
    Other(String),
}

impl ChannelError {
    /// Convenience constructor for transport errors that wrap a
    /// `Display`-able cause.
    pub fn transport(cause: impl std::fmt::Display) -> Self {
        Self::Transport(cause.to_string())
    }

    /// Convenience constructor for remote / non-success-status
    /// errors.
    pub fn remote(status: u16, body: impl Into<String>) -> Self {
        Self::Remote {
            status,
            body: body.into(),
        }
    }
}

/// Hint to the orchestrator about how acknowledgements arrive on this
/// channel, when [`Channel::supports_ack_reply`] returns `true`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AckReplyHint {
    /// User clicks an HTTP link (the [`Payload::ack_link`] value)
    /// rendered into the message body. Daemon-side endpoint receives
    /// the click.
    HttpClickLink,
    /// Channel supports a native action button (ntfy actions, Slack
    /// interactive component). Daemon receives a webhook callback
    /// carrying the [`PayloadId`].
    NativeButton,
    /// User replies with a text token (Signal text reply, Twilio SMS
    /// inbound). Daemon parses the token from the reply body.
    TextReply,
    /// User invokes a chat slash command (`/selfdef-ack <id>`).
    SlashCommand,
}

/// One outbound notification channel.
///
/// Implementations live in `crates/selfdef-integration-<service>`.
/// They are pure adapters: take a [`Payload`], emit it to one
/// external service, return a [`DeliveryReceipt`] or
/// [`ChannelError`]. They MUST NOT:
///
/// - install anything on the host
/// - mutate host topology (files outside their credentials path,
///   sockets, kernel state)
/// - own escalation, subscription filtering, or persistence — those
///   live in the orchestrator
///
/// See [`docs/dev/integrations.md`](../../../docs/dev/integrations.md)
/// for the full contributor contract.
#[async_trait]
pub trait Channel: Send + Sync {
    /// Stable lowercase slug identifying this channel
    /// (`"ntfy"`, `"signal"`, `"smtp"`, …). Used for operator config
    /// lookup (`[notifications.channels.<slug>]`) and for the
    /// `name` field in [`tracing`] spans.
    fn name(&self) -> &str;

    /// Emit `payload` to the external service. Implementations MUST
    /// set a per-call timeout on the underlying transport; the
    /// orchestrator relies on `Channel::send` returning within
    /// bounded time so its escalation timers stay accurate.
    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError>;

    /// Whether this channel can return acknowledgements via a
    /// channel-native path (button click, text reply, slash command).
    /// Defaults to `false`; channels without native ack still benefit
    /// from the orchestrator's CLI / HTTP click-link paths.
    fn supports_ack_reply(&self) -> bool {
        false
    }

    /// When [`Self::supports_ack_reply`] returns `true`, this returns
    /// the shape of the expected reply. The orchestrator uses this to
    /// decide how to render ack instructions in the outbound message
    /// body. `None` when the channel does not support native acks.
    fn ack_reply_format(&self) -> Option<AckReplyHint> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn payload_id_new_is_unique() {
        let a = PayloadId::new();
        let b = PayloadId::new();
        assert_ne!(a, b, "two consecutive PayloadId::new must differ");
    }

    #[test]
    fn payload_id_short_str_is_32_hex_chars() {
        let id = PayloadId::new();
        let s = id.as_short_str();
        assert_eq!(s.len(), 32, "uuid simple form is 32 hex chars; got {s}");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "must be hex: {s}");
    }

    #[test]
    fn event_id_from_uuid_round_trip() {
        let u = Uuid::now_v7();
        let e = EventId::from(u);
        assert_eq!(e.0, u);
    }

    #[test]
    fn delivery_receipt_native_carries_id() {
        let r = DeliveryReceipt::native("twilio-SID-12345");
        assert_eq!(r.native_message_id.as_deref(), Some("twilio-SID-12345"));
    }

    #[test]
    fn delivery_receipt_empty_has_no_id() {
        let r = DeliveryReceipt::empty();
        assert!(r.native_message_id.is_none());
    }

    #[test]
    fn channel_error_transport_constructor() {
        let e = ChannelError::transport("connection refused");
        match e {
            ChannelError::Transport(s) => assert_eq!(s, "connection refused"),
            _ => panic!("expected Transport variant"),
        }
    }

    #[test]
    fn channel_error_remote_constructor() {
        let e = ChannelError::remote(503, "service unavailable");
        match e {
            ChannelError::Remote { status, body } => {
                assert_eq!(status, 503);
                assert_eq!(body, "service unavailable");
            }
            _ => panic!("expected Remote variant"),
        }
    }

    /// Compile-time check: a minimal `Channel` impl wires up cleanly.
    /// Catches accidental trait-shape changes that would break every
    /// downstream integration crate.
    struct StubChannel;

    #[async_trait]
    impl Channel for StubChannel {
        fn name(&self) -> &str {
            "stub"
        }

        async fn send(&self, _payload: &Payload) -> Result<DeliveryReceipt, ChannelError> {
            Ok(DeliveryReceipt::empty())
        }
    }

    #[tokio::test]
    async fn stub_channel_compiles_and_sends() {
        let ch = StubChannel;
        let payload = Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "test".into(),
            body: "test body".into(),
            severity: SeverityId::Informational,
            ack_link: None,
            event_kind: None,
        };
        let receipt = ch.send(&payload).await.expect("stub send succeeds");
        assert!(receipt.native_message_id.is_none());
        assert!(!ch.supports_ack_reply());
        assert!(ch.ack_reply_format().is_none());
        assert_eq!(ch.name(), "stub");
    }

    fn mk_payload(severity: SeverityId, event_kind: Option<&str>) -> Payload {
        Payload {
            id: PayloadId::new(),
            event_id: None,
            title: "t".into(),
            body: "b".into(),
            severity,
            ack_link: None,
            event_kind: event_kind.map(str::to_owned),
        }
    }

    #[test]
    fn subscription_default_accepts_everything() {
        let s = Subscription::default();
        assert!(s.matches(&mk_payload(SeverityId::Informational, None)));
        assert!(s.matches(&mk_payload(SeverityId::Critical, Some("Security Finding"))));
    }

    #[test]
    fn subscription_severity_floor_blocks_below() {
        let s = Subscription {
            severity_floor: Some(SeverityId::High),
            event_kinds: vec![],
        };
        assert!(!s.matches(&mk_payload(SeverityId::Medium, None)));
        assert!(s.matches(&mk_payload(SeverityId::High, None)));
        assert!(s.matches(&mk_payload(SeverityId::Critical, None)));
    }

    #[test]
    fn subscription_event_kinds_substring_case_insensitive() {
        let s = Subscription {
            severity_floor: None,
            event_kinds: vec!["security".into(), "detection".into()],
        };
        assert!(s.matches(&mk_payload(SeverityId::Low, Some("Security Finding"))));
        assert!(s.matches(&mk_payload(SeverityId::Low, Some("DETECTION finding"))));
        assert!(!s.matches(&mk_payload(SeverityId::Low, Some("Process Activity"))));
    }

    #[test]
    fn subscription_event_kinds_with_none_payload_kind_drops_when_filter_present() {
        let s = Subscription {
            severity_floor: None,
            event_kinds: vec!["security".into()],
        };
        // Conservative: missing metadata + non-empty filter → drop.
        assert!(!s.matches(&mk_payload(SeverityId::Low, None)));
    }

    #[test]
    fn subscription_event_kinds_with_none_payload_kind_passes_when_filter_empty() {
        let s = Subscription::default();
        assert!(s.matches(&mk_payload(SeverityId::Low, None)));
    }

    #[test]
    fn subscription_combined_severity_and_kind_must_both_pass() {
        let s = Subscription {
            severity_floor: Some(SeverityId::High),
            event_kinds: vec!["security".into()],
        };
        assert!(s.matches(&mk_payload(SeverityId::High, Some("Security Finding"))));
        // High but wrong kind → drop.
        assert!(!s.matches(&mk_payload(SeverityId::High, Some("Process Activity"))));
        // Right kind but low severity → drop.
        assert!(!s.matches(&mk_payload(SeverityId::Low, Some("Security Finding"))));
    }
}
