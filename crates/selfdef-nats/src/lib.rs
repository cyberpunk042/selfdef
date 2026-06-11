//! NATS bridge for the selfdef event bus.
//!
//! Forwards events between hosts. The single local in-proc bus
//! ([`selfdef_bus::Bus`]) stays the source of truth for collectors,
//! correlator, and responder; the NATS bridge runs alongside as a
//! two-way pump:
//!
//! - **Outbound**: subscribes to the local bus and publishes every
//!   *locally-originated* event to `<subject_prefix>.<host_tag>`.
//! - **Inbound**: subscribes to `<subject_prefix>.>` and republishes
//!   every received event onto the local bus — *except* messages
//!   carrying our own [`host_tag`](selfdef_core::Event::host_tag),
//!   which we drop to avoid the obvious echo loop.
//!
//! ## Two modes
//!
//! The bridge runs in one of two modes, picked by config:
//!
//! - **Core (default).** Fire-and-forget pub/sub. Lowest latency, no
//!   durability. A daemon that's offline while a publish happens
//!   misses that message forever. Good for live multi-host correlation
//!   on a stable LAN.
//! - **JetStream.** Outbound publishes go to a JetStream stream;
//!   inbound reads from a durable pull consumer. A daemon that
//!   restarts resumes from its last acked message, so reboots and
//!   short network blips don't drop events.
//!
//! Both modes share the same loop-avoidance and subject layout — only
//! the wire-level publish/subscribe machinery differs.
//!
//! ## Loop avoidance
//!
//! Outbound filters by `event.host_tag == local`. Inbound drops the
//! mirror (`event.host_tag == local`) so a daemon's own messages
//! coming back through NATS don't re-enter the local bus. The local
//! UUIDv7 on each event also lets downstream sinks dedupe, but the
//! bridge doesn't rely on that — the host_tag check is sufficient and
//! O(1).
//!
//! ## What it isn't
//!
//! This is a **bridge**, not a replacement for the in-proc bus. The
//! local bus is still the trait-less, low-latency broadcast every
//! subscriber reads from. NATS is glue between daemons. No built-in
//! auth — operators bring NATS mTLS / NKey / JWT as needed.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::AckPolicy;
use async_nats::jetstream::consumer::pull::Config as PullConsumerConfig;
use async_nats::jetstream::stream::Config as StreamConfig;
use futures::StreamExt as _;
use selfdef_bus::{BusError, Publisher, Subscriber};
use selfdef_core::Event;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
pub enum NatsError {
    #[error("connect: {0}")]
    Connect(#[from] async_nats::ConnectError),
    #[error("subscribe: {0}")]
    Subscribe(#[from] async_nats::SubscribeError),
    #[error("publish: {0}")]
    Publish(#[from] async_nats::PublishError),
    #[error("jetstream stream: {0}")]
    Stream(String),
    #[error("jetstream consumer: {0}")]
    Consumer(String),
    #[error("jetstream publish: {0}")]
    JsPublish(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Bridge configuration. Mirrors `[bus.nats]` in `selfdef.toml`.
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// `nats://host:port` or `tls://host:port`. Multiple servers can be
    /// comma-separated per the async-nats URL grammar.
    pub url: String,
    /// Subject prefix. Outbound publishes go to `<prefix>.<host_tag>`;
    /// inbound subscribes to `<prefix>.>`. Default `selfdef.events`.
    pub subject_prefix: String,
    /// Optional JetStream durability. When disabled the bridge uses
    /// plain NATS Core pub/sub (the default since M15).
    pub jetstream: JetStreamConfig,
}

/// JetStream durability options.
///
/// When `enabled`, the bridge ensures a stream (`stream_name` capturing
/// `<subject_prefix>.>`) and a durable pull consumer named
/// `<durable_consumer_prefix>-<host_tag>`. A restarting daemon picks
/// up from the last acked message rather than starting from "now".
#[derive(Debug, Clone)]
pub struct JetStreamConfig {
    pub enabled: bool,
    /// Stream name. JetStream stream names must be alphanumeric, `-`,
    /// or `_`. Default `selfdef-events`.
    pub stream_name: String,
    /// Per-daemon durable consumer name. The actual durable name is
    /// `<prefix>-<sanitized_host_tag>` so each host tracks its own
    /// progress independently. Default `selfdef-bridge`.
    pub durable_consumer_prefix: String,
    /// Retain messages no older than this many seconds. `0` = unlimited.
    /// Default 7 days.
    pub max_age_secs: u64,
    /// Cap on stream bytes. `-1` = unlimited (default).
    pub max_bytes: i64,
    /// Cap on stream message count. `-1` = unlimited (default).
    pub max_msgs: i64,
}

impl Default for JetStreamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stream_name: "selfdef-events".into(),
            durable_consumer_prefix: "selfdef-bridge".into(),
            // 7 days. Tune to your retention story; selfdef itself
            // re-stores everything in SQLite as the events arrive.
            max_age_secs: 7 * 24 * 3600,
            max_bytes: -1,
            max_msgs: -1,
        }
    }
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            subject_prefix: "selfdef.events".into(),
            jetstream: JetStreamConfig::default(),
        }
    }
}

/// Build the outbound subject for a given local host tag.
#[must_use]
pub fn outbound_subject(prefix: &str, host_tag: &str) -> String {
    // NATS subject grammar: dot-separated tokens, no whitespace, `>` and
    // `*` are reserved as wildcards. Daemon host_tags should be plain
    // hostnames, but normalize defensively.
    let safe = host_tag.replace(
        |c: char| c.is_whitespace() || c == '.' || c == '>' || c == '*',
        "-",
    );
    format!("{prefix}.{safe}")
}

/// The wildcard inbound subject `<prefix>.>` that catches every host's
/// publishes under this prefix.
#[must_use]
pub fn inbound_subject(prefix: &str) -> String {
    format!("{prefix}.>")
}

/// Whether the bridge should forward this event onto NATS. Skips
/// events from other hosts that we've already received via the inbound
/// path (and would otherwise echo back).
#[must_use]
pub fn is_local_originated(event: &Event, local_host_tag: &str) -> bool {
    event.host_tag == local_host_tag
}

/// Build the per-host durable consumer name for JetStream mode.
///
/// JetStream durable names must be alphanumeric, `-`, or `_`. We sanitize
/// the host_tag the same way we sanitize subjects and join with `-`.
#[must_use]
pub fn durable_consumer_name(prefix: &str, host_tag: &str) -> String {
    let safe = host_tag.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "-",
    );
    format!("{prefix}-{safe}")
}

/// Run the NATS bridge until `shutdown` is cancelled. Dispatches to
/// core pub/sub or the JetStream durable path based on
/// `cfg.jetstream.enabled`.
pub async fn run_bridge(
    cfg: NatsConfig,
    host_tag: String,
    publisher: Publisher,
    subscriber: Subscriber,
    shutdown: CancellationToken,
    federated_inbound: Option<Arc<AtomicU64>>,
) -> Result<(), NatsError> {
    let client = async_nats::connect(&cfg.url).await?;
    info!(url = %cfg.url, prefix = %cfg.subject_prefix, "nats: connected");

    if cfg.jetstream.enabled {
        run_jetstream_bridge(client, cfg, host_tag, publisher, subscriber, shutdown, federated_inbound).await
    } else {
        run_core_bridge(client, cfg, host_tag, publisher, subscriber, shutdown, federated_inbound).await
    }
}

async fn run_core_bridge(
    client: async_nats::Client,
    cfg: NatsConfig,
    host_tag: String,
    publisher: Publisher,
    subscriber: Subscriber,
    shutdown: CancellationToken,
    federated_inbound: Option<Arc<AtomicU64>>,
) -> Result<(), NatsError> {
    let out_subject = outbound_subject(&cfg.subject_prefix, &host_tag);
    let in_subject = inbound_subject(&cfg.subject_prefix);

    let mut inbound_sub = client.subscribe(in_subject.clone()).await?;
    info!(subject = %in_subject, "nats core: subscribed");

    let client = Arc::new(client);

    // Outbound task — drains the local bus, filters, publishes.
    let out_task = {
        let client = Arc::clone(&client);
        let host_tag = host_tag.clone();
        let out_subject = out_subject.clone();
        let sd = shutdown.clone();
        tokio::spawn(async move {
            run_outbound(client, subscriber, host_tag, out_subject, sd).await;
        })
    };

    // Inbound task — drains the NATS subscription, deserializes,
    // republishes onto the local bus, drops local-tag echoes.
    let in_task = {
        let host_tag = host_tag.clone();
        let sd = shutdown.clone();
        let federated_inbound = federated_inbound.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = sd.cancelled() => {
                        debug!("nats inbound: shutdown");
                        return;
                    }
                    msg = inbound_sub.next() => {
                        let Some(msg) = msg else {
                            warn!("nats inbound: subscription ended");
                            return;
                        };
                        republish_inbound(
                            &msg.payload,
                            &host_tag,
                            &publisher,
                            federated_inbound.as_deref(),
                        );
                    }
                }
            }
        })
    };

    // Wait for shutdown, then await both tasks.
    shutdown.cancelled().await;
    let _ = out_task.await;
    let _ = in_task.await;
    info!("nats core bridge stopped");
    Ok(())
}

async fn run_jetstream_bridge(
    client: async_nats::Client,
    cfg: NatsConfig,
    host_tag: String,
    publisher: Publisher,
    subscriber: Subscriber,
    shutdown: CancellationToken,
    federated_inbound: Option<Arc<AtomicU64>>,
) -> Result<(), NatsError> {
    let js = jetstream::new(client);

    // Ensure the stream. get_or_create_stream is idempotent — first
    // caller wins on stream config, later callers get the same stream
    // back. Operators who want to change retention later can
    // `nats stream edit` it directly; we don't reconcile here.
    let subjects = vec![inbound_subject(&cfg.subject_prefix)];
    let stream_cfg = StreamConfig {
        name: cfg.jetstream.stream_name.clone(),
        subjects,
        max_age: if cfg.jetstream.max_age_secs == 0 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs(cfg.jetstream.max_age_secs)
        },
        max_bytes: cfg.jetstream.max_bytes,
        max_messages: cfg.jetstream.max_msgs,
        ..Default::default()
    };
    let stream = js
        .get_or_create_stream(stream_cfg)
        .await
        .map_err(|e| NatsError::Stream(e.to_string()))?;
    info!(
        stream = %cfg.jetstream.stream_name,
        max_age_secs = cfg.jetstream.max_age_secs,
        "jetstream: stream ready"
    );

    // Durable pull consumer keyed on the host_tag. Each daemon tracks
    // its own ack progress so a reboot resumes mid-stream.
    let durable = durable_consumer_name(&cfg.jetstream.durable_consumer_prefix, &host_tag);
    let consumer_cfg = PullConsumerConfig {
        durable_name: Some(durable.clone()),
        filter_subject: inbound_subject(&cfg.subject_prefix),
        ack_policy: AckPolicy::Explicit,
        ..Default::default()
    };
    let consumer = stream
        .get_or_create_consumer(&durable, consumer_cfg)
        .await
        .map_err(|e| NatsError::Consumer(e.to_string()))?;
    info!(durable = %durable, "jetstream: consumer ready");

    // Outbound task — publishes locally-originated events via JetStream
    // (which writes them into the stream and returns an ack).
    let out_subject = outbound_subject(&cfg.subject_prefix, &host_tag);
    let js_for_out = js.clone();
    let out_task = {
        let host_tag = host_tag.clone();
        let out_subject = out_subject.clone();
        let sd = shutdown.clone();
        tokio::spawn(async move {
            run_jetstream_outbound(js_for_out, subscriber, host_tag, out_subject, sd).await;
        })
    };

    // Inbound task — pulls from the durable consumer, decodes, drops
    // self-echo, republishes locally, acks.
    let in_task = {
        let host_tag = host_tag.clone();
        let sd = shutdown.clone();
        let federated_inbound = federated_inbound.clone();
        tokio::spawn(async move {
            let mut messages = match consumer.messages().await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "jetstream inbound: messages() failed");
                    return;
                }
            };
            loop {
                tokio::select! {
                    () = sd.cancelled() => {
                        debug!("jetstream inbound: shutdown");
                        return;
                    }
                    msg = messages.next() => {
                        let Some(msg) = msg else {
                            warn!("jetstream inbound: message stream ended");
                            return;
                        };
                        let msg = match msg {
                            Ok(m) => m,
                            Err(e) => {
                                warn!(error = %e, "jetstream inbound: recv error");
                                continue;
                            }
                        };
                        republish_inbound(
                            &msg.payload,
                            &host_tag,
                            &publisher,
                            federated_inbound.as_deref(),
                        );
                        // Ack regardless of local outcome. publish_lossy
                        // never fails; a redelivery would just re-push
                        // the same event id and the store sink dedups.
                        if let Err(e) = msg.ack().await {
                            warn!(error = %e, "jetstream inbound: ack failed");
                        }
                    }
                }
            }
        })
    };

    shutdown.cancelled().await;
    let _ = out_task.await;
    let _ = in_task.await;
    info!("jetstream bridge stopped");
    Ok(())
}

async fn run_jetstream_outbound(
    js: jetstream::Context,
    mut subscriber: Subscriber,
    host_tag: String,
    subject: String,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                debug!("jetstream outbound: shutdown");
                return;
            }
            res = subscriber.recv() => match res {
                Ok(event) => {
                    if !is_local_originated(&event, &host_tag) {
                        continue;
                    }
                    let bytes = match serde_json::to_vec(&event) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "jetstream outbound: serialize failed");
                            continue;
                        }
                    };
                    // Wait for the server ack so an outage stalls
                    // publishes rather than silently dropping them.
                    // Operators who want fire-and-forget should use the
                    // core mode.
                    match js.publish(subject.clone(), bytes.into()).await {
                        Ok(ack_fut) => {
                            if let Err(e) = ack_fut.await {
                                warn!(error = %e, "jetstream outbound: ack failed");
                            }
                        }
                        Err(e) => warn!(error = %e, "jetstream outbound: publish failed"),
                    }
                }
                Err(BusError::Lagged(n)) => warn!(missed = n, "jetstream outbound: lagged"),
                Err(BusError::Closed) => {
                    info!("jetstream outbound: local bus closed");
                    return;
                }
                Err(e) => {
                    error!(error = %e, "jetstream outbound: unexpected bus error");
                    return;
                }
            }
        }
    }
}

async fn run_outbound(
    client: Arc<async_nats::Client>,
    mut subscriber: Subscriber,
    host_tag: String,
    subject: String,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                debug!("nats outbound: shutdown");
                return;
            }
            res = subscriber.recv() => match res {
                Ok(event) => {
                    if !is_local_originated(&event, &host_tag) {
                        // Came from another host (we received it inbound).
                        // Not ours to republish.
                        continue;
                    }
                    let bytes = match serde_json::to_vec(&event) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "nats outbound: serialize failed");
                            continue;
                        }
                    };
                    if let Err(e) = client.publish(subject.clone(), bytes.into()).await {
                        warn!(error = %e, "nats outbound: publish failed");
                    }
                }
                Err(BusError::Lagged(n)) => warn!(missed = n, "nats outbound: lagged"),
                Err(BusError::Closed) => {
                    info!("nats outbound: local bus closed");
                    return;
                }
                Err(e) => {
                    error!(error = %e, "nats outbound: unexpected bus error");
                    return;
                }
            }
        }
    }
}

fn decode_event(bytes: &[u8]) -> Result<Event, NatsError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Decode one inbound NATS payload and, unless it is our own echo, republish it
/// onto the local bus — counting it as a *federated ingress* so the otherwise
/// invisible cross-host event flow is observable on `/metrics`. Shared by the
/// core and JetStream inbound loops (previously duplicated inline). Decode
/// failures are logged and dropped; the JetStream caller still acks afterward.
///
/// The federated count is the trust-boundary signal: every event it counts is
/// one that entered the local correlator→responder path from another host (see
/// F-2026-111 — inbound federated events currently drive local response with no
/// per-event attestation). Surfacing the volume is the prerequisite for any
/// later policy on it; this function changes no behavior, it only observes.
fn republish_inbound(
    payload: &[u8],
    local_host_tag: &str,
    publisher: &Publisher,
    federated_inbound: Option<&AtomicU64>,
) {
    match decode_event(payload) {
        Ok(mut event) => {
            if event.host_tag == local_host_tag {
                debug!(id = %event.id, "nats inbound: dropping self-echo");
                return;
            }
            if let Some(c) = federated_inbound {
                c.fetch_add(1, Ordering::Relaxed);
            }
            // Local-only provenance taint: this event came from another host, so
            // mark it federated before it enters the local bus. The correlator
            // propagates this onto derived findings and the responder applies the
            // federation trust-boundary policy (F-2026-111). `federated` is
            // `#[serde(skip)]`, so a peer can't preset it — it's stamped here.
            event.federated = true;
            publisher.publish_lossy(event);
        }
        Err(e) => warn!(error = %e, len = payload.len(), "nats inbound: decode failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;

    fn synth_event(host: &str) -> Event {
        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1,
            SeverityId::Informational,
            host,
            "nats.test",
            0,
        )
        .with_message("synthetic")
    }

    #[test]
    fn subject_layout_matches_documented_form() {
        assert_eq!(
            outbound_subject("selfdef.events", "h-1"),
            "selfdef.events.h-1"
        );
        assert_eq!(inbound_subject("selfdef.events"), "selfdef.events.>");
    }

    #[test]
    fn subject_sanitizes_dangerous_chars() {
        // Spaces, dots, and NATS wildcards in a host_tag would break
        // the subject grammar; the helper normalizes them to dashes.
        let s = outbound_subject("p", "weird.host *name>");
        assert!(!s.contains(' '));
        assert!(!s.contains('*'));
        assert!(!s.contains('>'));
        // Exactly one '.' separator between prefix and tag.
        assert_eq!(s.matches('.').count(), 1);
    }

    #[test]
    fn local_origination_check_matches_host_tag() {
        let local = "this-host";
        let ours = synth_event(local);
        let theirs = synth_event("other-host");
        assert!(is_local_originated(&ours, local));
        assert!(!is_local_originated(&theirs, local));
    }

    #[test]
    fn decode_round_trips_through_json() {
        let ev = synth_event("h");
        let bytes = serde_json::to_vec(&ev).unwrap();
        let back = decode_event(&bytes).unwrap();
        assert_eq!(back.id, ev.id);
        assert_eq!(back.host_tag, "h");
    }

    #[test]
    fn durable_consumer_name_concats_prefix_and_host() {
        assert_eq!(
            durable_consumer_name("selfdef-bridge", "host-01"),
            "selfdef-bridge-host-01"
        );
    }

    #[test]
    fn durable_consumer_name_sanitizes_disallowed_chars() {
        // JetStream durable names only allow alphanumeric, `-`, `_`.
        // Dots, spaces, and the NATS wildcards are scrubbed to `-`.
        let n = durable_consumer_name("p", "a.b c*d>e/f");
        assert!(!n.contains('.'));
        assert!(!n.contains(' '));
        assert!(!n.contains('*'));
        assert!(!n.contains('>'));
        assert!(!n.contains('/'));
        assert!(n.starts_with("p-"));
    }

    #[test]
    fn republish_inbound_counts_and_publishes_a_federated_event() {
        // A remote-host event is republished onto the local bus AND counted as
        // a federated ingress (the observability signal for F-2026-111).
        let bus = selfdef_bus::Bus::new(8);
        let sub = bus.subscribe();
        let publisher = bus.publisher();
        let counter = AtomicU64::new(0);
        let bytes = serde_json::to_vec(&synth_event("other-host")).unwrap();

        republish_inbound(&bytes, "this-host", &publisher, Some(&counter));

        assert_eq!(counter.load(Ordering::Relaxed), 1, "federated event must be counted");
        // The event reached the local bus.
        let mut sub = sub;
        let got = sub
            .try_recv()
            .expect("bus recv ok")
            .expect("federated event must be republished locally");
        assert_eq!(got.host_tag, "other-host");
        assert!(
            got.federated,
            "an inbound event from another host must be tainted federated-origin"
        );
    }

    #[test]
    fn republish_inbound_drops_self_echo_without_counting() {
        // Our own event bouncing back must be dropped and NOT counted as
        // federated ingress (it never left the local trust boundary).
        let bus = selfdef_bus::Bus::new(8);
        let sub = bus.subscribe();
        let publisher = bus.publisher();
        let counter = AtomicU64::new(0);
        let bytes = serde_json::to_vec(&synth_event("this-host")).unwrap();

        republish_inbound(&bytes, "this-host", &publisher, Some(&counter));

        assert_eq!(counter.load(Ordering::Relaxed), 0, "self-echo must not count as federated");
        let mut sub = sub;
        assert!(matches!(sub.try_recv(), Ok(None)), "self-echo must not be republished");
    }

    #[test]
    fn republish_inbound_drops_undecodable_payload() {
        // A garbage payload is logged + dropped: no publish, no count, no panic.
        let bus = selfdef_bus::Bus::new(8);
        let sub = bus.subscribe();
        let publisher = bus.publisher();
        let counter = AtomicU64::new(0);

        republish_inbound(b"not json", "this-host", &publisher, Some(&counter));

        assert_eq!(counter.load(Ordering::Relaxed), 0);
        let mut sub = sub;
        assert!(matches!(sub.try_recv(), Ok(None)));
    }

    #[test]
    fn jetstream_defaults_are_conservative() {
        let js = JetStreamConfig::default();
        assert!(!js.enabled);
        assert_eq!(js.stream_name, "selfdef-events");
        assert_eq!(js.durable_consumer_prefix, "selfdef-bridge");
        assert_eq!(js.max_age_secs, 7 * 24 * 3600);
        assert_eq!(js.max_bytes, -1);
        assert_eq!(js.max_msgs, -1);
    }
}
