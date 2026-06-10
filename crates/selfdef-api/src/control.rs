//! Control-plane handlers — the "write side" of the API.
//!
//! These verbs do things rather than just report state: reload rules,
//! engage panic mode, fire a single named action against an event. Each
//! one publishes an audit-trail [`selfdef_core::Event`] onto the bus
//! (source = `"selfdef.api"`, class = `INCIDENT_FINDING`,
//! severity = `Informational`) so the operator can grep the store and
//! see who poked the daemon and when.
//!
//! ## Auth boundary
//!
//! Control verbs require the **Full** capability and reject Read-only
//! callers with `403 Forbidden` — enforced by the `RequireControl`
//! extractor, which every mutating handler in this module takes as its
//! first argument (`rules_reload`, `panic_fire`, `actions_run`). The
//! capability is assigned per transport / per token:
//!
//! - UNIX socket transport: granted `Capability::Full` unconditionally
//!   (`with_capability` in the transport layer) — trusted by filesystem
//!   permissions. Anyone who can write to the socket already has the
//!   equivalent of `sudo systemctl reload selfdefd` via the unit file's
//!   `ExecReload`, so a `/rules/reload` doesn't widen the attack surface.
//! - TCP transport: the bearer token in `[api].token_file` decides the
//!   grant — the `control` token earns `Capability::Full`; the `read`
//!   token earns `Capability::Read`, which is accepted on read/GET verbs
//!   but returns `403` on every control verb above. Operators who expose
//!   the API publicly should still put a reverse proxy in front with TLS
//!   + audit logging.
//!
//! Read-only handlers (e.g. `actions_list`) omit the extractor by design.

use axum::Json;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::handlers::ApiError;
use crate::state::ApiState;
use crate::transport::Capability;

/// Extractor for the `Full` capability. Use it as the first argument
/// of any handler that should reject Read-only callers.
///
/// Returns `403 Forbidden` (not `401`) when the request is authenticated
/// but the presented credentials don't carry the Full grant — the
/// caller has identity, just not authority.
pub(crate) struct RequireControl;

// axum-core 0.4 uses `#[async_trait]` for FromRequestParts; matching
// the attribute keeps the trait impl's lifetimes consistent with the
// declaration. async-trait is already a workspace dep via tower.
#[async_trait::async_trait]
impl<S> FromRequestParts<S> for RequireControl
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<Capability>().copied() {
            Some(Capability::Full) => Ok(Self),
            Some(Capability::Read) => Err(ApiError::with_status(
                StatusCode::FORBIDDEN,
                "control verb requires the control token",
            )),
            None => Err(ApiError::with_status(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            )),
        }
    }
}

// -------------------- audit helper

fn emit_audit(state: &ApiState, action: &str, status: &str, details: serde_json::Value) {
    let Some(pub_) = state.control.publisher.as_ref() else {
        return;
    };
    let event = selfdef_core::Event::new(
        selfdef_core::category::ClassUid::INCIDENT_FINDING,
        1,
        selfdef_core::severity::SeverityId::Informational,
        &state.host_tag,
        "selfdef.api",
        0,
    )
    .with_message(format!("api.control {action}: {status}"))
    .with_raw(serde_json::json!({
        "action": action,
        "status": status,
        "details": details,
    }));
    pub_.publish_lossy(event);
}

// -------------------- POST /rules/reload

#[derive(Debug, Serialize)]
pub(crate) struct RulesReloadResponse {
    pub rules_loaded: usize,
}

pub(crate) async fn rules_reload(
    _cap: RequireControl,
    State(s): State<ApiState>,
) -> Result<Json<RulesReloadResponse>, ApiError> {
    let Some(corr) = s.control.correlator.clone() else {
        return Err(ApiError::unavailable("correlator handle not configured"));
    };
    match corr.load_rules() {
        Ok(n) => {
            info!(rules = n, "api: /rules/reload OK");
            emit_audit(
                &s,
                "rules_reload",
                "ok",
                serde_json::json!({"rules_loaded": n}),
            );
            Ok(Json(RulesReloadResponse { rules_loaded: n }))
        }
        Err(e) => {
            warn!(error = %e, "api: /rules/reload failed");
            emit_audit(
                &s,
                "rules_reload",
                "error",
                serde_json::json!({"error": e.to_string()}),
            );
            Err(ApiError::internal(format!("rule reload failed: {e}")))
        }
    }
}

// -------------------- POST /panic

#[derive(Debug, Deserialize)]
pub(crate) struct PanicRequest {
    /// Must match the daemon's host_tag. Prevents accidental fire from
    /// a hostile or misconfigured client (the same safety belt
    /// `selfdefctl panic --confirm <host>` enforces).
    pub confirm: String,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PanicResponse {
    pub dispatched: bool,
    pub host_tag: String,
}

pub(crate) async fn panic_fire(
    _cap: RequireControl,
    State(s): State<ApiState>,
    Json(req): Json<PanicRequest>,
) -> Result<Json<PanicResponse>, ApiError> {
    if req.confirm != s.host_tag {
        emit_audit(
            &s,
            "panic",
            "rejected",
            serde_json::json!({"reason": "confirm hostname mismatch"}),
        );
        return Err(ApiError::bad_request(format!(
            "confirm '{}' does not match host '{}'",
            req.confirm, s.host_tag
        )));
    }
    let Some(resp) = s.control.responder.clone() else {
        return Err(ApiError::unavailable("responder handle not configured"));
    };

    let msg = req
        .message
        .unwrap_or_else(|| "PANIC: manual lockdown via API".into());
    let event = selfdef_core::Event::new(
        selfdef_core::category::ClassUid::DETECTION_FINDING,
        1,
        selfdef_core::severity::SeverityId::Critical,
        &s.host_tag,
        "selfdef.panic",
        0,
    )
    .with_message(&msg);

    resp.fire(&event).await;
    info!("api: /panic dispatched");
    emit_audit(
        &s,
        "panic",
        "dispatched",
        serde_json::json!({"message": msg}),
    );

    Ok(Json(PanicResponse {
        dispatched: true,
        host_tag: s.host_tag.clone(),
    }))
}

// -------------------- POST /actions/{name}/run

#[derive(Debug, Deserialize)]
pub(crate) struct ActionRunRequest {
    /// Either a freshly-supplied event JSON, or a reference to one
    /// already in the hot store. Exactly one must be set.
    #[serde(default)]
    pub event: Option<selfdef_core::Event>,
    #[serde(default)]
    pub event_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActionRunResponse {
    pub action: String,
    pub status: String,
    pub notes: String,
}

pub(crate) async fn actions_run(
    _cap: RequireControl,
    State(s): State<ApiState>,
    Path(name): Path<String>,
    Json(req): Json<ActionRunRequest>,
) -> Result<Json<ActionRunResponse>, ApiError> {
    let Some(resp) = s.control.responder.clone() else {
        return Err(ApiError::unavailable("responder handle not configured"));
    };

    let event = match (req.event, req.event_id) {
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "specify exactly one of `event` or `event_id`",
            ));
        }
        (None, None) => {
            return Err(ApiError::bad_request(
                "missing `event` or `event_id` in request body",
            ));
        }
        (Some(e), None) => e,
        (None, Some(id)) => {
            let uuid = uuid::Uuid::parse_str(&id)
                .map_err(|_| ApiError::bad_request(format!("invalid event_id: {id}")))?;
            s.store
                .get(uuid)
                .await
                .map_err(|e| ApiError::internal(format!("store: {e}")))?
                .ok_or_else(|| ApiError::not_found(format!("no event with id {id}")))?
        }
    };

    let outcome = resp.dispatch_single(&name, &event).await;
    match outcome {
        None => {
            emit_audit(
                &s,
                "actions.run",
                "unknown_action",
                serde_json::json!({"action": name}),
            );
            Err(ApiError::not_found(format!("unknown action: {name}")))
        }
        Some(Err(e)) => {
            emit_audit(
                &s,
                "actions.run",
                "error",
                serde_json::json!({"action": name, "error": e.to_string()}),
            );
            Err(ApiError::internal(format!("action failed: {e}")))
        }
        Some(Ok(o)) => {
            let status = match o.status {
                selfdef_responder::actions::Status::Success => "success",
                selfdef_responder::actions::Status::DryRun => "dry_run",
                selfdef_responder::actions::Status::Skipped => "skipped",
            };
            emit_audit(
                &s,
                "actions.run",
                status,
                serde_json::json!({"action": name, "notes": o.notes}),
            );
            Ok(Json(ActionRunResponse {
                action: name,
                status: status.into(),
                notes: o.notes,
            }))
        }
    }
}

// -------------------- GET /actions  (discovery)

#[derive(Debug, Serialize)]
pub(crate) struct ActionsListResponse {
    pub actions: Vec<&'static str>,
}

pub(crate) async fn actions_list(
    State(s): State<ApiState>,
) -> Result<Json<ActionsListResponse>, ApiError> {
    let actions = s
        .control
        .responder
        .as_ref()
        .map(|r| r.action_names())
        .unwrap_or_default();
    Ok(Json(ActionsListResponse { actions }))
}

// -------------------- error helpers (extend ApiError)

impl ApiError {
    pub(crate) fn internal(msg: impl Into<String>) -> Self {
        Self::with_status(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
    pub(crate) fn bad_request(msg: impl Into<String>) -> Self {
        Self::with_status(StatusCode::BAD_REQUEST, msg)
    }
    pub(crate) fn not_found(msg: impl Into<String>) -> Self {
        Self::with_status(StatusCode::NOT_FOUND, msg)
    }
    pub(crate) fn unavailable(msg: impl Into<String>) -> Self {
        Self::with_status(StatusCode::SERVICE_UNAVAILABLE, msg)
    }
}
