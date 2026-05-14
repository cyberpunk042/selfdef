//! Shared state passed into every handler.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use selfdef_bus::{Bus, Publisher};
use selfdef_correlator::Correlator;
use selfdef_responder::Responder;
use selfdef_store::SqliteStore;

use crate::TokenFingerprint;
use crate::metrics::Metrics;

/// Handles the API needs from the daemon. Control-plane handles are
/// optional so tests (and the read-only-only deployment) can construct
/// state without them; control endpoints return 503 when missing.
#[derive(Clone, Default)]
pub struct ControlHandles {
    pub correlator: Option<Arc<Correlator>>,
    pub responder: Option<Arc<Responder>>,
    pub publisher: Option<Publisher>,
}

/// SDD-007 D-2: shared per-token counter map. Each entry tracks the
/// number of live `/events/stream` subscribers attributable to that
/// token's SHA-256 fingerprint. `std::sync::Mutex` (not the tokio
/// version) lets the RAII `SubscriberGuard::Drop` decrement
/// synchronously without an async context. The lock is held only for
/// the HashMap insert/remove + one atomic load — microseconds per
/// connect/disconnect.
pub(crate) type PerTokenCounters = Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<SqliteStore>,
    pub bus: Arc<Bus>,
    pub host_tag: String,
    pub schema_version: u32,
    pub crate_version: &'static str,
    pub started_at: Instant,
    pub control: ControlHandles,
    /// Process-wide Prometheus counters. Constructed empty by
    /// [`Self::new`]; the daemon populates it via
    /// [`crate::run_metrics_ingest`].
    pub metrics: Arc<Metrics>,
    /// F-2027-061: live count of `/events/stream` subscribers
    /// across **all** tokens. Capped at
    /// [`crate::handlers::MAX_SSE_SUBSCRIBERS`] (default 64) as a
    /// process-wide backstop. Shared across clones so every handler
    /// call hits the same counter.
    pub sse_subscribers: Arc<AtomicUsize>,
    /// SDD-007 D-2 / F-2028-037: per-token live count of
    /// `/events/stream` subscribers, keyed by SHA-256 fingerprint.
    /// Each entry is capped at
    /// [`crate::handlers::MAX_SSE_SUBSCRIBERS_PER_TOKEN`] (default 8).
    /// Entries are removed by `SubscriberGuard::Drop` when the count
    /// hits zero so a rotating operator doesn't leak HashMap entries.
    pub(crate) sse_subscribers_per_token: PerTokenCounters,
}

impl ApiState {
    #[must_use]
    pub fn new(store: Arc<SqliteStore>, bus: Arc<Bus>, host_tag: String) -> Self {
        let metrics = Arc::new(Metrics::new(host_tag.clone()));
        Self {
            store,
            bus,
            host_tag,
            schema_version: selfdef_core::SCHEMA_VERSION,
            crate_version: env!("CARGO_PKG_VERSION"),
            started_at: Instant::now(),
            control: ControlHandles::default(),
            metrics,
            sse_subscribers: Arc::new(AtomicUsize::new(0)),
            sse_subscribers_per_token: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Override the metrics handle (used when the daemon wants the
    /// ingest task and the API to share one Arc).
    #[must_use]
    pub fn with_metrics(mut self, m: Arc<Metrics>) -> Self {
        self.metrics = m;
        self
    }

    /// Builder-style: attach the correlator handle for `/rules/reload`.
    #[must_use]
    pub fn with_correlator(mut self, c: Arc<Correlator>) -> Self {
        self.control.correlator = Some(c);
        self
    }

    /// Builder-style: attach the responder handle for `/panic` and
    /// `/actions/{name}/run`.
    #[must_use]
    pub fn with_responder(mut self, r: Arc<Responder>) -> Self {
        self.control.responder = Some(r);
        self
    }

    /// Builder-style: attach a publisher so control endpoints can emit
    /// audit events onto the bus.
    #[must_use]
    pub fn with_publisher(mut self, p: Publisher) -> Self {
        self.control.publisher = Some(p);
        self
    }

    /// **Test-only**: snapshot of the per-token subscriber-counter
    /// HashMap keys. Used by SDD-007's leak-check test to assert
    /// the map empties when the last subscriber under a fingerprint
    /// drops.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn sse_subscribers_per_token_keys(&self) -> Vec<crate::TokenFingerprint> {
        let map = self
            .sse_subscribers_per_token
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        map.keys().copied().collect()
    }
}
