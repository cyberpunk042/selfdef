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
//! subscriber reads from. NATS is glue between daemons. JetStream
//! durability, replay, and topology are out of scope for this
//! milestone — pure NATS Core publish/subscribe is enough to land
//! multi-host correlation.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::sync::Arc;

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
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            subject_prefix: "selfdef.events".into(),
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

/// Run the NATS bridge until `shutdown` is cancelled. The bridge
/// spawns two child tasks (outbound publisher, inbound subscriber)
/// and joins them on shutdown.
pub async fn run_bridge(
    cfg: NatsConfig,
    host_tag: String,
    publisher: Publisher,
    subscriber: Subscriber,
    shutdown: CancellationToken,
) -> Result<(), NatsError> {
    let client = async_nats::connect(&cfg.url).await?;
    info!(url = %cfg.url, prefix = %cfg.subject_prefix, "nats: connected");

    let out_subject = outbound_subject(&cfg.subject_prefix, &host_tag);
    let in_subject = inbound_subject(&cfg.subject_prefix);

    let mut inbound_sub = client.subscribe(in_subject.clone()).await?;
    info!(subject = %in_subject, "nats: subscribed");

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
                        match decode_event(&msg.payload) {
                            Ok(event) => {
                                if event.host_tag == host_tag {
                                    debug!(id = %event.id, "nats inbound: dropping self-echo");
                                    continue;
                                }
                                publisher.publish_lossy(event);
                            }
                            Err(e) => warn!(error = %e, len = msg.payload.len(), "nats inbound: decode failed"),
                        }
                    }
                }
            }
        })
    };

    // Wait for shutdown, then await both tasks.
    shutdown.cancelled().await;
    let _ = out_task.await;
    let _ = in_task.await;
    info!("nats bridge stopped");
    Ok(())
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
}
