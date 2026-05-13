//! Shared state passed into every handler.

use std::sync::Arc;
use std::time::Instant;

use selfdef_bus::{Bus, Publisher};
use selfdef_correlator::Correlator;
use selfdef_responder::Responder;
use selfdef_store::SqliteStore;

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
}
