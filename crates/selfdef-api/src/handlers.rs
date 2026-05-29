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

use crate::TokenFingerprint;
use crate::state::ApiState;

const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 1_000;

/// F-2027-061: global cap on concurrent `/events/stream`
/// subscribers. Each subscription holds a tokio task plus a
/// 64-slot mpsc buffer; the cap bounds the worst-case memory +
/// task footprint an authenticated TCP client can pin.
pub(crate) const MAX_SSE_SUBSCRIBERS: usize = 64;

/// SDD-007 / F-2028-037: per-token cap on concurrent
/// `/events/stream` subscribers. One bearer-holder (or an
/// attacker who exfiltrated a token) used to be able to
/// saturate the global cap from a single process, denying
/// service to every other authenticated client. The per-token
/// cap bounds each token's slice. 8 is well below the global
/// cap so multiple tokens can coexist; raise via the
/// `[api].max_sse_subscribers_per_token` config knob if the
/// deployment legitimately needs more.
pub(crate) const MAX_SSE_SUBSCRIBERS_PER_TOKEN: usize = 8;

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
    let mut body = s.metrics.render(store_count);
    // Four-watchdog set gauges (MS046/MS047/MS044/MS048). Filesystem
    // reads at scrape time — degrades gracefully (zero counts / -1
    // chain-events) when watchdog ring buffers / audit logs missing.
    body.push_str(&crate::watchdog_metrics::render());
    // MS022 SSE subscriber quota gauges. Reads sse_subscribers +
    // sse_subscribers_per_token off ApiState; the per-token map is
    // sampled under-lock then formatted lock-free. Exposes the
    // operator-controlled caps + the live saturation ratio.
    body.push_str(&crate::sse_quota_metrics::render(&s));
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

/// SDD-008 D-4 HTTP ack: `GET /notify/ack/:token`.
///
/// Looks up `token` in the escalation engine, marks the matching
/// row as acked (one-shot; idempotent — a second click is a no-op
/// with the same 200 OK as the first). Returns:
///
/// - **200 OK** with a small plain-text page when the ack succeeded
///   or the token was already acked (we can't tell them apart from
///   the operator's perspective — both mean "selfdef knows you've
///   seen this").
/// - **404 Not Found** when the token is unknown (typo, or the row
///   was `selfdefctl notify forget`ten before the operator clicked).
/// - **503 Service Unavailable** when the daemon is on the legacy
///   chain path (`[notifier].escalations_path` unset → no engine
///   handle → no ack to record).
///
/// Authentication: this endpoint is reachable to anyone with the
/// token. That's by design — the token IS the auth. Tokens are
/// UUIDv7 (122 bits of entropy after the timestamp prefix); they
/// ride out-of-band over the channels (ntfy, email, …) which are
/// operator-trusted paths. An attacker with the token has the
/// same authority as the operator who saw the notification.
pub(crate) async fn notify_ack(
    State(s): State<ApiState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    let Some(engine) = s.escalation_engine() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "escalation engine not configured (set [notifier].escalations_path)\n",
        )
            .into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match engine.record_ack_by_token(&token, now).await {
        Ok(Some((event_id, title))) => {
            debug!(%event_id, title = %title, "notify_ack: row acked via HTTP");
            let body = format!(
                "Acknowledged.\n\nEvent: {event_id}\nTitle:  {title}\nAt:     unix={now}\n",
            );
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                body,
            )
                .into_response()
        }
        Ok(None) => {
            // Either unknown token, OR known-but-already-acked, OR
            // known-but-closed. The engine's record_ack_by_token
            // can't distinguish "already acked" from "unknown" in
            // its current shape (both return Ok(None)). We render
            // a 404 for any of these — the operator sees the
            // ambiguity and can run `selfdefctl notify list` to
            // disambiguate. A future revision could surface the
            // "already acked" case as 200; for v1 we err on the
            // side of clarity.
            debug!(token, "notify_ack: token not found or already resolved");
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "Token not found (unknown, already acked, or forgotten)\n",
            )
                .into_response()
        }
        Err(e) => {
            warn!(token, error = %e, "notify_ack: engine error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "engine error\n",
            )
                .into_response()
        }
    }
}

/// RAII handle that increments the per-process and per-token SSE
/// subscriber counters on acquire and decrements both on drop.
/// SDD-007 D-2: when the per-token counter hits zero on drop, the
/// `HashMap` entry is removed so a rotating operator doesn't leak
/// entries. Anonymous requests (no fingerprint — only happens via
/// the UNIX-socket `with_full_capability` path, where bearer-auth
/// isn't applied) skip the per-token cap and only count against
/// the global cap.
struct SubscriberGuard {
    global: Arc<AtomicUsize>,
    per_token: Option<(crate::state::PerTokenCounters, TokenFingerprint)>,
}

enum AcquireError {
    GlobalCap,
    PerTokenCap,
}

impl SubscriberGuard {
    fn try_acquire(
        state: &ApiState,
        fingerprint: Option<TokenFingerprint>,
    ) -> Result<Self, AcquireError> {
        // SDD-007 D-4: caps may be operator-overridden via
        // `[api].max_sse_subscribers{,_per_token}`. `None`/`0`
        // falls back to the compiled-in defaults.
        let cap_global = match state.sse_caps.global {
            Some(n) if n > 0 => n,
            _ => MAX_SSE_SUBSCRIBERS,
        };
        let cap_per_token = match state.sse_caps.per_token {
            Some(n) if n > 0 => n,
            _ => MAX_SSE_SUBSCRIBERS_PER_TOKEN,
        };
        // Try the per-token cap first so we surface the more-specific
        // "per-token sse cap reached" reason when a single token is
        // the cause. SDD-007 D-6.
        let per_token = if let Some(fp) = fingerprint {
            let mut map = state
                .sse_subscribers_per_token
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let entry = map.entry(fp).or_insert_with(|| AtomicUsize::new(0));
            // The entry's atomic is owned by the map; we look at it
            // under the lock to avoid the lock-free CAS pattern
            // racing against entry removal in Drop.
            let current = entry.load(Ordering::Acquire);
            if current >= cap_per_token {
                return Err(AcquireError::PerTokenCap);
            }
            entry.fetch_add(1, Ordering::AcqRel);
            Some((Arc::clone(&state.sse_subscribers_per_token), fp))
        } else {
            None
        };

        // Global cap: CAS-loop on the process-wide counter.
        let counter = &state.sse_subscribers;
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= cap_global {
                // Undo the per-token increment so the next request
                // under the same token still gets its full slice.
                if let Some((map, fp)) = &per_token {
                    let m = map.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = m.get(fp) {
                        c.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                return Err(AcquireError::GlobalCap);
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        global: Arc::clone(counter),
                        per_token,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        // Decrement the global counter first; it's a pure atomic and
        // can't fail. F-2028-012: assert under test that the counter
        // never goes negative — a future logic bug (double-drop,
        // acquire without holding the guard) would surface as a
        // panic in debug builds instead of silent corruption.
        let prev_global = self.global.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            prev_global > 0,
            "global SubscriberGuard counter underflow (prev = 0)",
        );
        // Decrement the per-token counter and prune the map entry if
        // this was the last subscriber under that fingerprint. The
        // prune keeps the HashMap bounded across token rotations.
        if let Some((map, fp)) = self.per_token.take() {
            let mut m = map.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = m.get(&fp) {
                let prev = c.fetch_sub(1, Ordering::AcqRel);
                debug_assert!(
                    prev > 0,
                    "per-token SubscriberGuard counter underflow for fp={fp:?}",
                );
                if prev == 1 {
                    m.remove(&fp);
                }
            } else {
                debug_assert!(false, "per-token entry missing on guard drop for fp={fp:?}",);
            }
        }
    }
}

pub(crate) async fn events_stream(
    State(s): State<ApiState>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, ApiError> {
    // SDD-007 D-1: bearer-auth threads the SHA-256 fingerprint of
    // the presented token into request extensions. Anonymous
    // callers (UNIX-socket `with_full_capability`) won't have one
    // and bypass the per-token cap — they're operator-controlled.
    let fingerprint = request.extensions().get::<TokenFingerprint>().copied();

    // F-2027-061 + SDD-007 D-2: refuse with a typed reason if
    // either the per-token or process-wide cap is saturated.
    let guard = match SubscriberGuard::try_acquire(&s, fingerprint) {
        Ok(g) => g,
        Err(AcquireError::PerTokenCap) => {
            return Err(ApiError::with_status(
                StatusCode::SERVICE_UNAVAILABLE,
                "per-token sse cap reached",
            ));
        }
        Err(AcquireError::GlobalCap) => {
            return Err(ApiError::with_status(
                StatusCode::SERVICE_UNAVAILABLE,
                "sse subscriber cap reached",
            ));
        }
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
                    // F-2028-013: name the deadline so an operator reading
                    // the daemon log line doesn't have to grep the source
                    // to learn what the timeout was. The literal must
                    // stay in sync with SSE_SEND_TIMEOUT above; the const
                    // is documented inline next to this string.
                    Err(_) => Err("slow-client timeout (30s)"),
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
