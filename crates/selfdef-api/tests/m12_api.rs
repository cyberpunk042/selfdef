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

async fn build_state() -> (ApiState, Arc<Bus>, Arc<SqliteStore>, tempfile::TempDir) {
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
    // F-2027-055: previously this leaked `dir` via `std::mem::forget` to
    // keep the sqlite file alive for the test's lifetime. The handle now
    // returns alongside so the caller holds it on the stack; the dir is
    // cleaned up cleanly on test exit. The SqliteStore's open handle
    // survives the file being unlink'd (Linux inode semantics) — but we
    // don't *need* to rely on that since the caller keeps the TempDir
    // until they're done with the store.
    (state, bus, store, dir)
}

#[tokio::test]
async fn status_returns_host_and_counters() {
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    // F-2027-054: use per-test tempdirs instead of the
    // host-global `temp_dir().join("selfdef-api-test-*")`. The
    // pre-fix code shared those two paths across every test in
    // the suite — parallel runs would step on each other's
    // snapshot / forensics outputs. `tempfile::tempdir()` gives
    // each test its own scratch path; the leak (via
    // `std::mem::forget` below) deliberately keeps the dirs
    // alive for the lifetime of the test process so a control
    // verb that writes to them can still find the path.
    let snap_dir = tempfile::tempdir().expect("snap tmp");
    let forensics_dir = tempfile::tempdir().expect("forensics tmp");
    let snap_path = snap_dir.path().to_path_buf();
    let forensics_path = forensics_dir.path().to_path_buf();
    std::mem::forget(snap_dir);
    std::mem::forget(forensics_dir);
    vec![
        std::sync::Arc::new(NotifyAction::new(notifier)),
        std::sync::Arc::new(KillPidAction::new()),
        std::sync::Arc::new(SnapshotProcAction::new(snap_path)),
        std::sync::Arc::new(ForensicsBundleAction::new(forensics_path)),
    ]
}

async fn state_with_control(dry_run: bool) -> ApiState {
    let (state, bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    let (state, _bus, _store, _dir) = build_state().await;
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
    // F-2026-061: assert the exact Prometheus content-type, not a
    // permissive `starts_with`. Prometheus's exposition format spec
    // pins the version pragma; allowing any `text/plain; ...` would
    // let a bug shipping `text/plain; charset=ascii` (no version)
    // pass silently.
    assert_eq!(
        ct, "text/plain; version=0.0.4; charset=utf-8",
        "expected exact Prometheus content-type, got: {ct}",
    );
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    // Each TYPE line must be present and unique. Substring-only
    // checks let a duplicate metric definition through; counting
    // per name catches it.
    for type_line in [
        "# TYPE selfdef_build_info gauge",
        "# TYPE selfdef_uptime_seconds counter",
        "# TYPE selfdef_store_events gauge",
        "# TYPE selfdef_events_total counter",
        "# TYPE selfdef_findings_total counter",
    ] {
        let n = body.matches(type_line).count();
        assert_eq!(
            n, 1,
            "expected exactly one `{type_line}` line, found {n}:\n{body}"
        );
    }
    // build_state seeded 2 events in the store.
    assert!(
        body.contains("selfdef_store_events 2"),
        "expected store gauge = 2:\n{body}",
    );
    // Spot-check a sample-line shape: every non-comment, non-empty
    // line either starts with a valid metric name + label set + value,
    // or is a blank line. A line that looks like a `#` comment but
    // doesn't follow `# (HELP|TYPE) <name>` would be a bug.
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            assert!(
                rest.starts_with("HELP ") || rest.starts_with("TYPE "),
                "comment line not in HELP/TYPE form: {line}",
            );
            continue;
        }
        // Sample line: <name>[{labels}] <value>. We require at
        // least one whitespace separating the name+labels from
        // the value.
        assert!(
            trimmed.contains(' '),
            "metric line missing value separator: {line}",
        );
    }
}

#[tokio::test]
async fn metrics_reflect_ingest_counters_via_record_event() {
    // Directly drive the ingest path that the daemon's task uses, then
    // scrape and assert the counters show up. Avoids racing on a
    // background subscriber.
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    let (state, _bus, _store, _dir) = build_state().await;

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

    // F-2027-056: parse the exposition body via the P-2 parser
    // (SDD-005) instead of substring-matching the raw bytes.
    // The parser enforces every Prometheus invariant the
    // hand-rolled `body.contains(...)` checks would miss: unique
    // `(name, labels)` pairs, well-formed sample lines, valid
    // label-string escaping.
    let exp = prom::parse(&body).expect("metrics body must parse cleanly");
    let ssh_class = format!("{}", ClassUid::SSH_ACTIVITY.0);
    let high_sev = format!("{}", SeverityId::High as u32);
    assert_eq!(
        exp.find("selfdef_events_total", &[])
            .map(|s| s.value.as_str()),
        Some("4"),
        "events_total = 4 expected; got:\n{body}",
    );
    assert_eq!(
        exp.find(
            "selfdef_events_by_class_total",
            &[("class_uid", ssh_class.as_str())],
        )
        .map(|s| s.value.as_str()),
        Some("3"),
        "SSH class counter = 3 expected; got:\n{body}",
    );
    assert_eq!(
        exp.find("selfdef_findings_total", &[])
            .map(|s| s.value.as_str()),
        Some("1"),
        "findings_total = 1 expected; got:\n{body}",
    );
    assert_eq!(
        exp.find(
            "selfdef_findings_by_severity_total",
            &[("severity_id", high_sev.as_str())],
        )
        .map(|s| s.value.as_str()),
        Some("1"),
        "high-severity finding counter expected; got:\n{body}",
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

    let (state, bus, _store, _dir) = build_state().await;
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

// ---------------- SDD-005 D-2b / Test-2 : Prometheus exposition parser
//
// The pre-SDD-005 `/metrics` tests substring-matched on the body, which
// let format violations slip (duplicate metric definitions, malformed
// sample lines, label-order regressions). This block adds a small
// format-strict parser + reuses it across the existing tests so future
// metric additions can't degrade the exposition.

/// F-2027-030: end-to-end test that real bus overflow surfaces
/// as an SSE `event: lagged` frame on the wire. The hand-crafted
/// lagged-event corpus in `cli_events_follow.rs` covers the
/// reader side; this test covers the writer side under a real
/// `BusError::Lagged(_)`.
#[tokio::test]
async fn events_stream_emits_lagged_frame_on_real_bus_overflow() {
    // Tiny bus so we can force overflow with a handful of
    // publishes. Bus capacity is per-subscriber lag buffer; a
    // subscriber that doesn't poll fast enough sees Lagged once
    // capacity is exceeded.
    let bus = Arc::new(Bus::new(2));
    let dir = tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("state.sqlite")).unwrap());
    let state = ApiState::new(Arc::clone(&store), Arc::clone(&bus), "test-host".into());
    // F-2027-055: keep `dir` on the test's stack frame instead of
    // leaking it. The sqlite store's open file descriptor survives
    // the eventual unlink (Linux inode semantics), but holding the
    // TempDir until the test returns means we don't have to rely
    // on that — and the dir gets cleaned cleanly on test exit.
    let _dir_holder = dir;
    let app = app(state);

    // Connect to /events/stream. The handler subscribes to the
    // bus before returning the response; we hold off polling the
    // body while we overflow the bus.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    use selfdef_bus::Publisher;
    let pub_: Publisher = bus.publisher();
    // Publish well above the 2-slot capacity. The subscriber
    // task (inside events_stream) reads them into its mpsc
    // channel, but if it can't keep up, the bus emits Lagged.
    // To force lag deterministically: we yield without polling
    // the response body, then publish many events.
    for i in 0..100 {
        let evt = selfdef_core::Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1,
            SeverityId::Informational,
            "test-host",
            "lag.test",
            0,
        )
        .with_message(format!("lag-burst-{i}"));
        pub_.publish_lossy(evt);
    }

    // Poll the body until we see an `event: lagged` frame
    // (or time out). The body is a streaming SSE response;
    // we accumulate bytes until we see the marker.
    let body = resp.into_body();
    let mut body_stream = body.into_data_stream();
    let mut buf = Vec::<u8>::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_lagged = false;
    use futures::StreamExt as _;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(500), body_stream.next()).await
        {
            Ok(Some(Ok(chunk))) => {
                buf.extend_from_slice(&chunk);
                if buf
                    .windows(b"event: lagged".len())
                    .any(|w| w == b"event: lagged")
                {
                    saw_lagged = true;
                    break;
                }
            }
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(
        saw_lagged,
        "expected `event: lagged` frame after bus overflow; body so far:\n{}",
        String::from_utf8_lossy(&buf),
    );
}

mod prom {
    //! Minimal Prometheus exposition parser for SDD-005 D-2b. Not a
    //! general parser — only handles what we emit (counters and gauges
    //! with `{key="value",...}` labels and a numeric value). Refuses
    //! quoted-newlines and escapes the only escape sequence we use
    //! (`\\`-`\\"` for `"` in label values).
    use std::collections::BTreeMap;

    /// One sample line: `<name>{<labels>}? <value>`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Sample {
        pub(crate) name: String,
        pub(crate) labels: BTreeMap<String, String>,
        /// Stored as the raw `<value>` token so the test asserts on the
        /// exposition's emitted string, not a parsed-then-formatted
        /// `f64` round-trip.
        pub(crate) value: String,
    }

    impl Sample {
        pub(crate) fn key(&self) -> (String, BTreeMap<String, String>) {
            (self.name.clone(), self.labels.clone())
        }
    }

    /// Parsed exposition body. Carries every sample line and every
    /// HELP/TYPE comment by metric name, with the lookup convenience
    /// methods the tests need.
    #[derive(Debug, Default)]
    pub(crate) struct Exposition {
        pub(crate) samples: Vec<Sample>,
        pub(crate) types: BTreeMap<String, String>,
        pub(crate) helps: BTreeMap<String, String>,
    }

    impl Exposition {
        pub(crate) fn find(&self, name: &str, labels: &[(&str, &str)]) -> Option<&Sample> {
            let want: BTreeMap<String, String> = labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            self.samples
                .iter()
                .find(|s| s.name == name && s.labels == want)
        }

        pub(crate) fn value(&self, name: &str, labels: &[(&str, &str)]) -> Option<&str> {
            self.find(name, labels).map(|s| s.value.as_str())
        }
    }

    pub(crate) fn parse(body: &str) -> Result<Exposition, String> {
        let mut out = Exposition::default();
        for (lineno, raw_line) in body.lines().enumerate() {
            let line = raw_line.trim_end();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some(rem) = rest.strip_prefix("HELP ") {
                    let mut it = rem.splitn(2, ' ');
                    let name = it.next().unwrap_or_default().to_string();
                    let help = it.next().unwrap_or_default().to_string();
                    out.helps.insert(name, help);
                } else if let Some(rem) = rest.strip_prefix("TYPE ") {
                    let mut it = rem.splitn(2, ' ');
                    let name = it.next().unwrap_or_default().to_string();
                    let typ = it.next().unwrap_or_default().to_string();
                    out.types.insert(name, typ);
                } else {
                    return Err(format!(
                        "line {}: malformed comment (not HELP/TYPE): {raw_line}",
                        lineno + 1,
                    ));
                }
                continue;
            }
            if line.starts_with('#') {
                return Err(format!(
                    "line {}: comments must use `# ` prefix: {raw_line}",
                    lineno + 1,
                ));
            }
            let sample = parse_sample_line(line)
                .ok_or_else(|| format!("line {}: malformed sample: {raw_line}", lineno + 1))?;
            out.samples.push(sample);
        }
        // Prometheus invariant: each (name, labels) pair appears at
        // most once in a scrape.
        let mut seen: BTreeMap<(String, BTreeMap<String, String>), usize> = BTreeMap::new();
        for s in &out.samples {
            *seen.entry(s.key()).or_insert(0) += 1;
        }
        for ((name, labels), n) in &seen {
            if *n > 1 {
                return Err(format!(
                    "duplicate sample: {name}{labels:?} appears {n} times — Prometheus invariant violated",
                ));
            }
        }
        Ok(out)
    }

    fn parse_sample_line(line: &str) -> Option<Sample> {
        let line = line.trim();
        let (name, rest) = split_name(line)?;
        let (labels, rest) = if let Some(stripped) = rest.strip_prefix('{') {
            let close = find_unescaped_close(stripped)?;
            let labels = parse_labels(&stripped[..close])?;
            (labels, stripped[close + 1..].trim_start())
        } else {
            (BTreeMap::new(), rest.trim_start())
        };
        let value = rest.split_whitespace().next()?.to_string();
        Some(Sample {
            name: name.to_string(),
            labels,
            value,
        })
    }

    fn split_name(line: &str) -> Option<(&str, &str)> {
        let mut end = 0;
        for (i, c) in line.char_indices() {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
                end = i + c.len_utf8();
            } else {
                break;
            }
        }
        if end == 0 {
            return None;
        }
        Some((&line[..end], &line[end..]))
    }

    fn find_unescaped_close(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        let mut i = 0;
        let mut in_string = false;
        let mut escape = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = !in_string;
            } else if b == b'}' && !in_string {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn parse_labels(s: &str) -> Option<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        let mut rest = s.trim();
        while !rest.is_empty() {
            let eq = rest.find('=')?;
            let key = rest[..eq].trim().to_string();
            let after = rest[eq + 1..].trim_start();
            let after = after.strip_prefix('"')?;
            let mut end = 0;
            let bytes = after.as_bytes();
            let mut escape = false;
            while end < bytes.len() {
                if escape {
                    escape = false;
                } else if bytes[end] == b'\\' {
                    escape = true;
                } else if bytes[end] == b'"' {
                    break;
                }
                end += 1;
            }
            if end >= bytes.len() {
                return None;
            }
            let raw = &after[..end];
            // We only ever emit `\\` and `\"`; decode them.
            let mut value = String::new();
            let mut chars = raw.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(next) = chars.next() {
                        value.push(next);
                    }
                } else {
                    value.push(c);
                }
            }
            out.insert(key, value);
            rest = after[end + 1..].trim_start();
            if let Some(r) = rest.strip_prefix(',') {
                rest = r.trim_start();
            }
        }
        Some(out)
    }

    #[cfg(test)]
    mod self_tests {
        use super::*;

        #[test]
        fn parses_counter_with_labels() {
            let body = "# HELP foo bar\n# TYPE foo counter\nfoo{a=\"1\",b=\"2\"} 7\n";
            let e = parse(body).unwrap();
            assert_eq!(e.types.get("foo").map(|s| s.as_str()), Some("counter"));
            assert_eq!(e.value("foo", &[("a", "1"), ("b", "2")]), Some("7"));
        }

        #[test]
        fn rejects_duplicate_sample() {
            let body = "x 1\nx 2\n";
            let err = parse(body).unwrap_err();
            assert!(err.contains("duplicate sample"), "got: {err}");
        }

        #[test]
        fn rejects_unknown_comment() {
            let body = "# COMMENT what\nx 1\n";
            assert!(parse(body).is_err());
        }
    }
}

#[tokio::test]
async fn metrics_exposition_passes_format_strict_parse() {
    // SDD-005 D-2b: the same /metrics test as above, but
    // parsing the body format-strictly rather than substring
    // matching. Catches duplicate (name, labels) keys, malformed
    // sample lines, and orphan HELP/TYPE comments — none of which
    // the pre-SDD-005 substring matcher would have caught.
    let (state, _bus, _store, _dir) = build_state().await;
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
    let parsed = prom::parse(&body).unwrap_or_else(|e| panic!("parse failed: {e}\nbody:\n{body}"));

    // Required metrics are typed and emit a sample with the
    // expected value.
    for required in [
        "selfdef_build_info",
        "selfdef_uptime_seconds",
        "selfdef_store_events",
        "selfdef_events_total",
        "selfdef_findings_total",
    ] {
        assert!(
            parsed.types.contains_key(required),
            "missing TYPE for {required}; types: {:?}",
            parsed.types,
        );
    }
    // build_state seeded 2 events in the store.
    assert_eq!(
        parsed.value("selfdef_store_events", &[]),
        Some("2"),
        "store gauge mismatch; samples: {:?}",
        parsed.samples,
    );
}

#[tokio::test]
async fn metrics_allows_read_capability() {
    // SDD-005 D-2b / closes F-2026-032: pre-SDD-005, the
    // capability-gating tests covered /status and /actions but
    // not /metrics. A dashboard scraping with the read-only
    // token expects /metrics to be reachable; this asserts it.
    let app = read_only_app().await;
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
        .unwrap_or_default();
    assert_eq!(ct, "text/plain; version=0.0.4; charset=utf-8");
}
