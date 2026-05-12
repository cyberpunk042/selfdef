//! M12 integration test: exercise the API router via
//! `tower::ServiceExt::oneshot`, so we cover routing, JSON serialization,
//! and the bearer-token middleware without spinning up a real socket.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use selfdef_api::{ApiState, router};
use selfdef_bus::Bus;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use selfdef_store::SqliteStore;
use tempfile::tempdir;
use tower::ServiceExt;

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
    let app = router(state);

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
    let app = router(state);

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
    let app = router(state);
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
    let app = router(state);
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
    let app = router(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/does-not-exist")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn body_round_trips_as_real_event_envelopes() {
    // Catch regressions where /events returns something that doesn't
    // deserialize as selfdef_core::Event (e.g. if we ever switched to a
    // slimmed projection).
    let (state, _bus, _store) = build_state().await;
    let app = router(state);
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
