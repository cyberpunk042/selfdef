//! Shared state passed into every handler.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use selfdef_bus::{Bus, Publisher};
use selfdef_correlator::Correlator;
use selfdef_notifier_engine::EscalationEngine;
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
    /// Entries are removed by `SubscriberGuard::Drop` when the count
    /// hits zero so a rotating operator doesn't leak HashMap entries.
    pub(crate) sse_subscribers_per_token: PerTokenCounters,
    /// SDD-007 D-4 / F-2028-037: operator-tunable caps. `None`
    /// falls back to the compiled-in defaults
    /// ([`crate::handlers::MAX_SSE_SUBSCRIBERS`] = 64 global and
    /// [`crate::handlers::MAX_SSE_SUBSCRIBERS_PER_TOKEN`] = 8 per
    /// token). Use [`Self::with_sse_caps`] to override at startup
    /// from the daemon config.
    pub(crate) sse_caps: SseCaps,
    /// SDD-008 D-4 HTTP ack: handle to the escalation engine for
    /// `GET /notify/ack/:token`. `None` when the operator hasn't
    /// configured `[notifier].escalations_path` (legacy chain path);
    /// the route returns 503 in that case. Wired in by the daemon
    /// at startup when the engine path is active.
    pub(crate) escalation_engine: Option<Arc<EscalationEngine>>,
    /// Grant-governance: how `POST /v1/grants/issue` treats a new grant
    /// whose scope overlaps an existing *active* grant. Defaults to
    /// [`GrantsOverlapPolicy::Off`] (no check — historical behavior);
    /// the daemon raises it from `[grants].overlap_policy`. Kept as an
    /// api-local enum so this crate doesn't depend on `selfdef-config`.
    pub(crate) grants_overlap_policy: GrantsOverlapPolicy,
}

/// Grant overlap-governance policy (api-local mirror of the config enum).
/// The daemon maps `selfdef_config::GrantsOverlapPolicy` onto this at
/// startup so the handler layer carries no config dependency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GrantsOverlapPolicy {
    /// No overlap check — issuance proceeds unconditionally.
    #[default]
    Off,
    /// Issue, but log a warning when the new grant overlaps an active one.
    Warn,
    /// Refuse (HTTP 409) a new grant that overlaps an existing active grant.
    Refuse,
}

/// SDD-007 D-4: operator-tunable SSE cap overrides. The daemon
/// reads `[api].max_sse_subscribers` and
/// `[api].max_sse_subscribers_per_token` from the config and
/// populates these via [`ApiState::with_sse_caps`]. `None` (and
/// `Some(0)`, which we treat as "operator left it commented") use
/// the compiled-in defaults.
#[derive(Clone, Copy, Default, Debug)]
pub struct SseCaps {
    pub global: Option<usize>,
    pub per_token: Option<usize>,
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
            sse_caps: SseCaps::default(),
            escalation_engine: None,
            grants_overlap_policy: GrantsOverlapPolicy::Off,
        }
    }

    /// Builder-style: set the grant overlap-governance policy. The daemon
    /// calls this from `[grants].overlap_policy`. Default is
    /// [`GrantsOverlapPolicy::Off`] (no check).
    #[must_use]
    pub fn with_grants_overlap_policy(mut self, policy: GrantsOverlapPolicy) -> Self {
        self.grants_overlap_policy = policy;
        self
    }

    /// Accessor for the grant overlap-governance policy (handlers + tests).
    pub(crate) fn grants_overlap_policy(&self) -> GrantsOverlapPolicy {
        self.grants_overlap_policy
    }

    /// SDD-008 D-4: install the escalation engine handle so the
    /// `/notify/ack/:token` route can record acks. Daemon calls this
    /// from `build_notifier_path` when `[notifier].escalations_path`
    /// is set. Routes return 503 if this is `None`.
    #[must_use]
    pub fn with_escalation_engine(mut self, engine: Arc<EscalationEngine>) -> Self {
        self.escalation_engine = Some(engine);
        self
    }

    /// Engine accessor for handlers + tests.
    pub(crate) fn escalation_engine(&self) -> Option<Arc<EscalationEngine>> {
        self.escalation_engine.clone()
    }

    /// SDD-007 D-4: install operator-tuned SSE caps. Either field
    /// may be `None`/`Some(0)` to fall back to the compiled-in
    /// default for that knob.
    #[must_use]
    pub fn with_sse_caps(mut self, caps: SseCaps) -> Self {
        self.sse_caps = caps;
        self
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
