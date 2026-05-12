//! HTTP request handlers.

use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::state::ApiState;

const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 1_000;

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
pub(crate) async fn events_stream(
    State(s): State<ApiState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let mut sub = s.bus.subscribe();
    // 64 is enough headroom for typical bursts; over-eager rules can lag
    // the broadcast and we surface that as a `:lagged` SSE comment line.
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(64);

    tokio::spawn(async move {
        loop {
            match sub.recv().await {
                Ok(event) => match serde_json::to_string(&event) {
                    Ok(json) => {
                        let frame = SseEvent::default().data(json);
                        if tx.send(frame).await.is_err() {
                            debug!("sse client disconnected; stopping forwarder");
                            return;
                        }
                    }
                    Err(e) => warn!(error = %e, "sse: failed to serialize event"),
                },
                Err(selfdef_bus::BusError::Lagged(n)) => {
                    let frame = SseEvent::default()
                        .event("lagged")
                        .data(format!("missed {n} events"));
                    if tx.send(frame).await.is_err() {
                        return;
                    }
                }
                Err(selfdef_bus::BusError::Closed) => {
                    debug!("sse: bus closed");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "sse: bus error");
                    return;
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx).map(Ok);
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
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

    pub(crate) fn store(e: impl std::fmt::Display) -> Self {
        Self::with_status(StatusCode::INTERNAL_SERVER_ERROR, format!("store: {e}"))
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
