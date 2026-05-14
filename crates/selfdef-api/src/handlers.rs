//! HTTP request handlers.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::state::ApiState;

const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 1_000;

/// F-2027-061: global cap on concurrent `/events/stream`
/// subscribers. Each subscription holds a tokio task plus a
/// 64-slot mpsc buffer; the cap bounds the worst-case memory +
/// task footprint an authenticated TCP client can pin.
pub(crate) const MAX_SSE_SUBSCRIBERS: usize = 64;

/// F-2027-062: deadline on every SSE forwarder `tx.send().await`.
/// A reader that opens the stream and stops draining its buffer
/// would otherwise block the writer task indefinitely (the 64-slot
/// mpsc fills, then `send()` parks). On timeout the writer drops
/// the client (which also drops the `SubscriberGuard`).
const SSE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
pub(crate) struct PageQuery {
    #[serde(default)]
    pub n: Option<u32>,
}

impl PageQuery {
    fn limit(&self) -> u32 {
        self.n.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct StatusBody {
    pub host_tag: String,
    pub schema_version: u32,
    pub crate_version: &'static str,
    pub event_count: u64,
    pub uptime_secs: u64,
}

pub(crate) async fn status(State(s): State<ApiState>) -> Result<Json<StatusBody>, ApiError> {
    let event_count = s.store.count().await.unwrap_or(0);
    Ok(Json(StatusBody {
        host_tag: s.host_tag.clone(),
        schema_version: s.schema_version,
        crate_version: s.crate_version,
        event_count,
        uptime_secs: s.started_at.elapsed().as_secs(),
    }))
}

pub(crate) async fn events(
    State(s): State<ApiState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<selfdef_core::Event>>, ApiError> {
    let evts = s.store.recent(q.limit()).await.map_err(ApiError::store)?;
    Ok(Json(evts))
}

pub(crate) async fn findings(
    State(s): State<ApiState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<selfdef_core::Event>>, ApiError> {
    let evts = s
        .store
        .recent_findings(q.limit())
        .await
        .map_err(ApiError::store)?;
    Ok(Json(evts))
}

/// SSE live tail. Subscribes to the bus and forwards every event as a
/// JSON-serialized SSE data frame. The forwarding task exits when the
/// client disconnects (the mpsc tx fails to send).
/// Prometheus exposition endpoint. Renders the daemon's counters in
/// `text/plain; version=0.0.4` so any vanilla Prometheus scrape can
/// ingest them. The store size is read live (one SQL `COUNT` query)
/// so the `selfdef_store_events` gauge tracks the hot store
/// without mirroring its writes in an atomic.
pub(crate) async fn metrics(State(s): State<ApiState>) -> Response {
    let store_count = s.store.count().await.unwrap_or(0);
    let body = s.metrics.render(store_count);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// RAII handle that increments the per-state SSE subscriber
/// counter on acquire and decrements it on drop. Acquire returns
/// `None` if the counter has already reached the cap, in which
/// case the handler responds with 503 (no task is spawned).
struct SubscriberGuard {
    counter: Arc<AtomicUsize>,
}

impl SubscriberGuard {
    fn try_acquire(counter: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= cap {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Self {
                        counter: Arc::clone(counter),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) async fn events_stream(
    State(s): State<ApiState>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, ApiError> {
    // F-2027-061: refuse the connection if the per-process cap is
    // already saturated. The guard moves into the spawned task so
    // the count drops back when the writer exits (client closed,
    // bus closed, send timeout, etc.).
    let Some(guard) = SubscriberGuard::try_acquire(&s.sse_subscribers, MAX_SSE_SUBSCRIBERS) else {
        return Err(ApiError::with_status(
            StatusCode::SERVICE_UNAVAILABLE,
            "sse subscriber cap reached",
        ));
    };

    let mut sub = s.bus.subscribe();
    // 64 is enough headroom for typical bursts; over-eager rules can lag
    // the broadcast and we surface that as a `:lagged` SSE comment line.
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(64);

    tokio::spawn(async move {
        // Hold the cap-guard for the lifetime of the writer task.
        // F-2027-061: when the task exits the counter decrements.
        let _guard = guard;
        // F-2027-029: emit an explicit `event: shutdown` frame
        // when the writer task exits cleanly (bus closed = daemon
        // shutdown). The reader (`selfdefctl events follow`) uses
        // this to distinguish "stream ended because the daemon is
        // going away" from "TCP got chopped mid-stream" — the
        // former is a clean exit (code 0), the latter looks like
        // a crash.
        //
        // The frame is best-effort: if the client already
        // disconnected we silently return (same pattern as the
        // happy-path send error handling).
        let send_shutdown = |tx: &tokio::sync::mpsc::Sender<SseEvent>, reason: &str| {
            let frame = SseEvent::default().event("shutdown").data(reason);
            // Use try_send so we don't await an already-closed channel.
            let _ = tx.try_send(frame);
        };

        // F-2027-062: wrap every send in a deadline. A slow or
        // stuck client lets the 64-slot mpsc fill, after which
        // `tx.send().await` would park forever; the timeout
        // forces the writer to drop the client and return so
        // the subscriber-counter slot is freed.
        let send_with_timeout = |tx: &tokio::sync::mpsc::Sender<SseEvent>, frame: SseEvent| {
            let tx = tx.clone();
            async move {
                match tokio::time::timeout(SSE_SEND_TIMEOUT, tx.send(frame)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err("disconnected"),
                    Err(_) => Err("slow-client timeout"),
                }
            }
        };

        loop {
            match sub.recv().await {
                Ok(event) => match serde_json::to_string(&event) {
                    Ok(json) => {
                        let frame = SseEvent::default().data(json);
                        if let Err(reason) = send_with_timeout(&tx, frame).await {
                            debug!(reason, "sse: stopping forwarder");
                            return;
                        }
                    }
                    Err(e) => warn!(error = %e, "sse: failed to serialize event"),
                },
                Err(selfdef_bus::BusError::Lagged(n)) => {
                    let frame = SseEvent::default()
                        .event("lagged")
                        .data(format!("missed {n} events"));
                    if let Err(reason) = send_with_timeout(&tx, frame).await {
                        debug!(reason, "sse: stopping forwarder mid-lag");
                        return;
                    }
                }
                Err(selfdef_bus::BusError::Closed) => {
                    debug!("sse: bus closed");
                    send_shutdown(&tx, "bus closed");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "sse: bus error");
                    send_shutdown(&tx, "bus error");
                    return;
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx).map(Ok);
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}

// -------------------------------------------------- error type

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn with_status(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }

    /// F-2027-063: store errors used to flatten verbatim into
    /// the JSON 500 body. Any future store-error message that
    /// names an internal path (e.g.
    /// `sqlite: open /var/lib/selfdef/state.sqlite: permission denied`)
    /// would leak that path to the (authenticated) caller. We
    /// now log the detail server-side at WARN and ship a generic
    /// `"store unavailable"` to the client. The status code
    /// (500) tells the caller the API is the wrong place to
    /// debug — the operator gets the real message in the
    /// daemon's logs.
    pub(crate) fn store(e: impl std::fmt::Display) -> Self {
        warn!(error = %e, "api: store error");
        Self::with_status(StatusCode::INTERNAL_SERVER_ERROR, "store unavailable")
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        // Only log 5xx — 4xx are routine and would otherwise spam.
        if self.status.is_server_error() {
            warn!(error = %self.message, status = %self.status, "api error");
        }
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}
