//! M12 integration test: exercise the API router via
//! `tower::ServiceExt::oneshot`, so we cover routing, JSON serialization,
//! and the bearer-token middleware without spinning up a real socket.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use selfdef_api::{ApiState, router, with_full_capability};
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tower::ServiceExt;

/// Tests construct the router and then wrap it the same way the
/// UNIX-socket transport does — every test request is treated as
/// Full-capability. Per-token-gating tests below assemble their own
/// router with a custom layer instead.
fn app(state: ApiState) -> axum::Router {
    with_full_capability(router(state))
}

async fn build_state() -> (ApiState, Arc<Bus>, Arc<SqliteStore>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    // Seed the store with one normal event and one Critical finding so
    // both /events and /findings have content to return.
    let evt = selfdef_core::Event::new(
        ClassUid::PROCESS_ACTIVITY,
        1,
        SeverityId::Informational,
        "test-host",
        "m12.test",
        0,
    )
    .with_message("exec /bin/ls");
    store.insert(&evt).await.unwrap();

    let finding = selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        "test-host",
        "m12.test",
        1,
    )
    .with_message("synthetic finding for m12 test");
    store.insert(&finding).await.unwrap();

    let bus = Arc::new(Bus::new(16));
    let state = ApiState::new(Arc::clone(&store), Arc::clone(&bus), "test-host".into());
    // Leak the tempdir so the SQLite file outlives the test scope.
    std::mem::forget(dir);
    (state, bus, store)
}

#[tokio::test]
async fn status_returns_host_and_counters() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/status")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["host_tag"], "test-host");
    assert_eq!(v["event_count"], 2);
    assert!(v["schema_version"].is_number());
    assert!(v["crate_version"].is_string());
}

#[tokio::test]
async fn findings_returns_only_findings_category() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/findings?n=10")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("array");
    // Only the Critical finding should be returned, not the
    // Informational PROCESS_ACTIVITY event.
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["severity_id"], 5);
}

#[tokio::test]
async fn events_paginates_with_n_query_param() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events?n=1")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn events_returns_default_page_size_when_n_missing() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/does-not-exist")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// ---------------- control plane

fn make_critical_finding() -> selfdef_core::Event {
    selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        "test-host",
        "m13.control.test",
        0,
    )
    .with_message("synthetic critical for control test")
}

fn dummy_action_set() -> Vec<std::sync::Arc<dyn selfdef_responder::actions::Action>> {
    use selfdef_responder::actions::{
        ForensicsBundleAction, KillPidAction, NotifyAction, SnapshotProcAction,
    };

    #[derive(Default)]
    struct NullNotifier;
    #[async_trait::async_trait]
    impl selfdef_notifier::Notifier for NullNotifier {
        async fn notify(
            &self,
            _event: &selfdef_core::Event,
        ) -> Result<(), selfdef_notifier::NotifierError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "null"
        }
    }
    let notifier: std::sync::Arc<dyn selfdef_notifier::Notifier> =
        std::sync::Arc::new(NullNotifier);
    let tmp = std::env::temp_dir().join("selfdef-api-test-snapshots");
    let forensics = std::env::temp_dir().join("selfdef-api-test-forensics");
    vec![
        std::sync::Arc::new(NotifyAction::new(notifier)),
        std::sync::Arc::new(KillPidAction::new()),
        std::sync::Arc::new(SnapshotProcAction::new(tmp)),
        std::sync::Arc::new(ForensicsBundleAction::new(forensics)),
    ]
}

async fn state_with_control(dry_run: bool) -> ApiState {
    let (state, bus, _store) = build_state().await;
    let responder = std::sync::Arc::new(selfdef_responder::Responder::new(
        dummy_action_set(),
        vec![
            "notify".into(),
            "kill_pid".into(),
            "snapshot_proc".into(),
            "forensics_bundle".into(),
        ],
        dry_run,
    ));
    state
        .with_responder(responder)
        .with_publisher(bus.publisher())
}

#[tokio::test]
async fn actions_list_returns_registered_action_names() {
    let state = state_with_control(true).await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/actions")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 16).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let actions = v["actions"].as_array().unwrap();
    let names: Vec<&str> = actions.iter().map(|x| x.as_str().unwrap()).collect();
    assert!(names.contains(&"notify"));
    assert!(names.contains(&"forensics_bundle"));
}

#[tokio::test]
async fn rules_reload_returns_503_when_correlator_not_wired() {
    // build_state() returns an ApiState without a correlator handle.
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/rules/reload")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn panic_rejects_hostname_mismatch() {
    let state = state_with_control(true).await;
    let app = app(state);
    let body = serde_json::json!({"confirm": "wrong-host"}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/panic")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(res.into_body(), 1 << 16).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = v["error"].as_str().unwrap();
    assert!(msg.contains("test-host"));
}

#[tokio::test]
async fn panic_dispatches_when_hostname_matches() {
    let state = state_with_control(true).await;
    let app = app(state);
    let body = serde_json::json!({"confirm": "test-host"}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/panic")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 16).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["dispatched"], true);
    assert_eq!(v["host_tag"], "test-host");
}

#[tokio::test]
async fn actions_run_dry_run_returns_outcome() {
    let state = state_with_control(true).await;
    let app = app(state);
    let event = make_critical_finding();
    let body = serde_json::json!({"event": serde_json::to_value(&event).unwrap()}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/actions/notify/run")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 16).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["action"], "notify");
    assert_eq!(v["status"], "dry_run");
}

#[tokio::test]
async fn actions_run_unknown_action_returns_404() {
    let state = state_with_control(true).await;
    let app = app(state);
    let event = make_critical_finding();
    let body = serde_json::json!({"event": serde_json::to_value(&event).unwrap()}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/actions/no-such-action/run")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn actions_run_requires_event_or_event_id() {
    let state = state_with_control(true).await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/actions/notify/run")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ---------------- read plane (continued)

#[tokio::test]
async fn body_round_trips_as_real_event_envelopes() {
    // Catch regressions where /events returns something that doesn't
    // deserialize as selfdef_core::Event (e.g. if we ever switched to a
    // slimmed projection).
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events?n=10")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let events: Vec<selfdef_core::Event> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|e| e.severity_id == SeverityId::Critical));
    // CORS layer should be permissive on the response, but we don't bind
    // that contract in tests — the middleware is unit-tested by axum.
    let _ = header::CONTENT_TYPE;
}

// ---------------- per-token capability gating

use selfdef_api::{Capability, with_capability};

/// Build a router that simulates the TCP transport with only the
/// read-only token presented: every request gets stamped with
/// `Capability::Read` before hitting the handlers.
async fn read_only_app() -> axum::Router {
    let state = state_with_control(true).await;
    with_capability(router(state), Capability::Read)
}

#[tokio::test]
async fn read_endpoints_allow_read_capability() {
    let app = read_only_app().await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("/status")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn actions_list_allows_read_capability() {
    // GET /actions is discovery — useful from a read-only dashboard,
    // so it intentionally accepts the read token.
    let app = read_only_app().await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("/actions")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn rules_reload_rejects_read_capability_with_403() {
    let app = read_only_app().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/rules/reload")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn panic_rejects_read_capability_with_403() {
    let app = read_only_app().await;
    let body = serde_json::json!({"confirm": "test-host"}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/panic")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn actions_run_rejects_read_capability_with_403() {
    let app = read_only_app().await;
    let event = make_critical_finding();
    let body = serde_json::json!({"event": serde_json::to_value(&event).unwrap()}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/actions/notify/run")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn control_endpoint_rejects_anonymous_with_401() {
    // No capability layer at all — simulates a request that bypassed
    // the auth middleware (shouldn't happen with the live transport,
    // but the extractor still handles the case).
    let state = state_with_control(true).await;
    let app = router(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/rules/reload")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// --------------------------------------------------------------- /metrics
//
// Prometheus exposition coverage: that the endpoint responds, carries
// the right Content-Type, reflects counter ingest from the bus, and
// reports a live store size.

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_exposition() {
    let (state, _bus, _store) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ct.starts_with("text/plain"),
        "expected Prometheus content-type, got: {ct}",
    );
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    for line in [
        "# TYPE selfdef_build_info gauge",
        "# TYPE selfdef_uptime_seconds counter",
        "# TYPE selfdef_store_events gauge",
        "# TYPE selfdef_events_total counter",
        "# TYPE selfdef_findings_total counter",
    ] {
        assert!(body.contains(line), "missing `{line}`:\n{body}");
    }
    // build_state seeded 2 events in the store.
    assert!(
        body.contains("selfdef_store_events 2"),
        "expected store gauge = 2:\n{body}",
    );
}

#[tokio::test]
async fn metrics_reflect_ingest_counters_via_record_event() {
    // Directly drive the ingest path that the daemon's task uses, then
    // scrape and assert the counters show up. Avoids racing on a
    // background subscriber.
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    let (state, _bus, _store) = build_state().await;

    let m = state.metrics.clone();
    for _ in 0..3 {
        m.record_event(&selfdef_core::Event::new(
            ClassUid::SSH_ACTIVITY,
            1,
            SeverityId::Informational,
            "test-host",
            "ingest.test",
            0,
        ));
    }
    m.record_event(&selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::High,
        "test-host",
        "ingest.test",
        0,
    ));

    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("selfdef_events_total 4"),
        "expected events_total = 4:\n{body}",
    );
    assert!(
        body.contains(&format!(
            "selfdef_events_by_class_total{{class_uid=\"{}\"}} 3",
            ClassUid::SSH_ACTIVITY.0,
        )),
        "expected SSH class counter = 3:\n{body}",
    );
    assert!(
        body.contains("selfdef_findings_total 1"),
        "expected findings_total = 1:\n{body}",
    );
    assert!(
        body.contains(&format!(
            "selfdef_findings_by_severity_total{{severity_id=\"{}\"}} 1",
            SeverityId::High as u32,
        )),
        "expected high-severity finding counter:\n{body}",
    );
}

#[tokio::test]
async fn metrics_ingest_task_subscribes_to_bus() {
    // End-to-end: spawn the real ingest task, publish an event, and
    // assert the counter is incremented within a short timeout.
    use selfdef_bus::Publisher;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    use tokio_util::sync::CancellationToken;

    let (state, bus, _store) = build_state().await;
    let metrics = state.metrics.clone();
    let shutdown = CancellationToken::new();
    let task_metrics = metrics.clone();
    let task_bus = bus.clone();
    let task_sd = shutdown.clone();
    let task = tokio::spawn(async move {
        selfdef_api::run_metrics_ingest(task_metrics, task_bus, task_sd).await;
    });

    // Wait for the ingest task to call bus.subscribe() before we
    // publish — otherwise on a current_thread runtime the publish
    // would race ahead of the subscriber and the event would be lost.
    for _ in 0..100 {
        tokio::task::yield_now().await;
        if bus.receiver_count() > 0 {
            break;
        }
    }
    assert!(
        bus.receiver_count() > 0,
        "ingest task did not subscribe within 100 yields",
    );

    // Publish a finding.
    let pub_: Publisher = bus.publisher();
    let evt = selfdef_core::Event::new(
        ClassUid::DETECTION_FINDING,
        1,
        SeverityId::Critical,
        "test-host",
        "ingest.test",
        0,
    );
    pub_.publish_lossy(evt);

    // Poll until the counter shows up (or time out).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let rendered = metrics.render(0);
        if rendered.contains("selfdef_findings_total 1") {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("metrics ingest did not record event in 2s:\n{rendered}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
}
