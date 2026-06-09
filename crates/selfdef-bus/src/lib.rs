//! Event bus carrying [`selfdef_core::Event`] between collectors and consumers.
//!
//! M3 ships a single in-proc backend backed by [`tokio::sync::broadcast`]:
//! all subscribers see every event. Lagged subscribers receive
//! [`BusError::Lagged`] and must resubscribe (or accept the gap).
//!
//! A NATS JetStream backend arrives in a later milestone, behind the same
//! [`Bus`]/[`Publisher`]/[`Subscriber`] interface.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use selfdef_core::Event;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::warn;

#[derive(Debug, Error)]
pub enum BusError {
    #[error("no active subscribers; event dropped")]
    NoSubscribers,
    #[error("subscriber lagged behind by {0} events; some events were missed")]
    Lagged(u64),
    #[error("bus is closed")]
    Closed,
}

/// The event bus. Construct once per daemon; clone [`Publisher`] freely.
#[derive(Debug)]
pub struct Bus {
    sender: broadcast::Sender<Event>,
}

impl Bus {
    /// Construct a new bus with the given per-subscriber backlog capacity.
    /// When a subscriber is slower than this, it lags and receives a
    /// [`BusError::Lagged`] on its next `recv`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Get a [`Publisher`] handle. Cheap to clone.
    #[must_use]
    pub fn publisher(&self) -> Publisher {
        Publisher {
            tx: self.sender.clone(),
        }
    }

    /// Subscribe. Returns a [`Subscriber`] that yields events from this
    /// point forward — events emitted before subscribing are not delivered.
    #[must_use]
    pub fn subscribe(&self) -> Subscriber {
        Subscriber {
            rx: self.sender.subscribe(),
        }
    }

    /// Number of currently-active subscribers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

// ---------------------------------------------------------------- Publisher

/// Producer side of the bus.
#[derive(Debug, Clone)]
pub struct Publisher {
    tx: broadcast::Sender<Event>,
}

impl Publisher {
    /// Publish an event. Returns the number of subscribers it was queued to,
    /// or [`BusError::NoSubscribers`] if nobody is listening.
    pub fn publish(&self, event: Event) -> Result<usize, BusError> {
        self.tx.send(event).map_err(|_| BusError::NoSubscribers)
    }

    /// Publish, downgrading "no subscribers" to a warn log. Use this from
    /// collectors that should keep running regardless.
    pub fn publish_lossy(&self, event: Event) {
        if let Err(e) = self.publish(event) {
            warn!(error = %e, "publish failed");
        }
    }
}

// ---------------------------------------------------------------- Subscriber

/// Consumer side of the bus.
#[derive(Debug)]
pub struct Subscriber {
    rx: broadcast::Receiver<Event>,
}

impl Subscriber {
    /// Receive the next event.
    pub async fn recv(&mut self) -> Result<Event, BusError> {
        match self.rx.recv().await {
            Ok(e) => Ok(e),
            Err(broadcast::error::RecvError::Lagged(n)) => Err(BusError::Lagged(n)),
            Err(broadcast::error::RecvError::Closed) => Err(BusError::Closed),
        }
    }

    /// Non-blocking receive: return the next already-buffered event without
    /// waiting. `Ok(None)` means nothing is buffered right now (the ring is
    /// empty); `Err(Closed)` means every [`Publisher`] *and* the owning [`Bus`]
    /// have been dropped; `Err(Lagged)` reports skipped events.
    ///
    /// This exists so a consumer can drain its backlog on shutdown. The [`Bus`]
    /// keeps its own sender alive, so a consumer can't wait for `Closed` to know
    /// "no more events" — it must pull what's buffered without blocking.
    pub fn try_recv(&mut self) -> Result<Option<Event>, BusError> {
        match self.rx.try_recv() {
            Ok(e) => Ok(Some(e)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Lagged(n)) => Err(BusError::Lagged(n)),
            Err(broadcast::error::TryRecvError::Closed) => Err(BusError::Closed),
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;

    fn make_event(seq: u64) -> Event {
        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1,
            SeverityId::Informational,
            "test-host",
            "test",
            seq,
        )
    }

    #[tokio::test]
    async fn publish_then_subscribe_misses_old_events() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        // publish before anyone subscribes — should fail
        assert!(matches!(
            pub_.publish(make_event(1)).unwrap_err(),
            BusError::NoSubscribers
        ));

        let _sub = bus.subscribe();
        // now there's a subscriber, publish succeeds
        assert_eq!(pub_.publish(make_event(2)).unwrap(), 1);
    }

    #[tokio::test]
    async fn one_publisher_many_subscribers() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut s1 = bus.subscribe();
        let mut s2 = bus.subscribe();

        pub_.publish(make_event(1)).unwrap();
        pub_.publish(make_event(2)).unwrap();

        let e1 = s1.recv().await.unwrap();
        let e2 = s1.recv().await.unwrap();
        let f1 = s2.recv().await.unwrap();
        let f2 = s2.recv().await.unwrap();

        assert_eq!(e1.metadata.sequence, 1);
        assert_eq!(e2.metadata.sequence, 2);
        assert_eq!(f1.metadata.sequence, 1);
        assert_eq!(f2.metadata.sequence, 2);
    }

    #[tokio::test]
    async fn try_recv_drains_buffer_then_reports_empty() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();
        pub_.publish(make_event(1)).unwrap();
        pub_.publish(make_event(2)).unwrap();
        // Drains the two buffered events without blocking, then Empty.
        assert_eq!(sub.try_recv().unwrap().unwrap().metadata.sequence, 1);
        assert_eq!(sub.try_recv().unwrap().unwrap().metadata.sequence, 2);
        assert!(sub.try_recv().unwrap().is_none(), "ring now empty");
        // Even with the Bus alive (it holds a sender), Empty — not Closed —
        // is what a drained-but-open ring reports.
        assert!(matches!(sub.try_recv(), Ok(None)));
    }

    #[tokio::test]
    async fn slow_subscriber_gets_lagged_error() {
        let bus = Bus::new(2);
        let pub_ = bus.publisher();
        let mut slow = bus.subscribe();

        for i in 0..10 {
            // Some sends after capacity will internally drop oldest; the
            // slow subscriber will then surface Lagged on next recv.
            let _ = pub_.publish(make_event(i));
        }

        let err = slow.recv().await;
        assert!(matches!(err, Err(BusError::Lagged(_))));
    }
}
