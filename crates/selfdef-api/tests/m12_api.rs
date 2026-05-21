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

/// F-2027-061: once `MAX_SSE_SUBSCRIBERS` connections are live,
/// the next `/events/stream` request must be rejected with 503
/// rather than spawning a fresh subscriber + tokio task. Dropping
/// a held response frees the slot once the writer next tries to
/// forward a bus event (the writer parks in `sub.recv().await`
/// otherwise, which is exactly the slow-reader case F-2027-062
/// guards against with a send timeout).
#[tokio::test]
async fn events_stream_rejects_over_cap_with_503() {
    use selfdef_api::MAX_SSE_SUBSCRIBERS;
    use selfdef_bus::Publisher;

    let (state, bus, _store, _dir) = build_state().await;
    let app = app(state);

    // Open the cap-worth of streams; each Response carries the
    // streaming body whose Drop frees the writer task — keep them
    // all alive for the duration of the test.
    let mut held = Vec::with_capacity(MAX_SSE_SUBSCRIBERS);
    for i in 0..MAX_SSE_SUBSCRIBERS {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/events/stream")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "subscriber {i} should connect under cap",
        );
        held.push(resp);
    }

    // The (cap+1)th request must be refused.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Drop one held response. The writer task is parked in
    // `sub.recv().await`; publish one bus event so the writer
    // wakes, tries to forward, the dropped channel fails the
    // send, and the task exits — freeing the slot.
    held.pop();
    let pub_: Publisher = bus.publisher();
    let evt = selfdef_core::Event::new(
        ClassUid::PROCESS_ACTIVITY,
        1,
        SeverityId::Informational,
        "test-host",
        "cap.test",
        0,
    )
    .with_message("wake-dropped-writer");
    pub_.publish_lossy(evt);

    // Yield + small sleep so the writer tasks run their send +
    // Drop chains.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "freed slot should accept new subscriber",
    );
}

// ---------------------------------------------------------------
// SDD-007 / F-2028-037: per-token SSE subscriber quota tests.
//
// The five test cases mirror the SDD-007 D-5 test matrix:
//
//   D-5.1 — per-token cap reached
//   D-5.2 — per-token cap is per-token (token B unaffected by A)
//   D-5.3 — global cap still applies (multiple tokens, none over per-token cap)
//   D-5.4 — rotation frees slots eventually (covered by drop-frees test below)
//   D-5.5 — per-token counter drops to zero (HashMap entry pruned)
//
// All tests use `with_full_capability_for_fingerprint` to skip
// real bearer-auth while threading a specific TokenFingerprint
// into request extensions — exactly the post-bearer-auth state.
// ---------------------------------------------------------------

fn app_for_token(state: ApiState, fp: selfdef_api::TokenFingerprint) -> axum::Router {
    selfdef_api::with_full_capability_for_fingerprint(selfdef_api::router(state), fp)
}

/// F-2029-003: `Some(0)` on the cap fields means "operator left
/// it explicitly at zero in the config TOML, which is the same as
/// not setting it at all → use the compiled-in default". A future
/// refactor that drops the `n > 0` guard inside `try_acquire` and
/// starts treating `Some(0)` literally would silently saturate the
/// caps at the very first request. This test pins the contract.
#[tokio::test]
async fn events_stream_zero_caps_fall_back_to_defaults() {
    use selfdef_api::{SseCaps, TokenFingerprint};

    let (state, _bus, _store, _dir) = build_state().await;
    let state = state.with_sse_caps(SseCaps {
        global: Some(0),
        per_token: Some(0),
    });
    let fp = TokenFingerprint::of("alice-zero-cap");
    let app = app_for_token(state, fp);

    // Both caps set to Some(0) → fall back to default (64 global,
    // 8 per-token). The first request must succeed; if try_acquire
    // started honouring `Some(0)` literally, this would 503.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Some(0) must fall back to defaults, not saturate immediately",
    );
}

/// SDD-007 D-4 follow-up: operator-tuned `[api].max_sse_subscribers_per_token`
/// overrides the compiled-in default. Setting the cap to 2 means the
/// 3rd connection with the same fingerprint gets 503 regardless of
/// what the default is.
#[tokio::test]
async fn events_stream_per_token_cap_honours_operator_override() {
    use selfdef_api::{SseCaps, TokenFingerprint};

    let (state, _bus, _store, _dir) = build_state().await;
    let state = state.with_sse_caps(SseCaps {
        global: None,
        per_token: Some(2),
    });
    let fp = TokenFingerprint::of("alice-low-cap");
    let app = app_for_token(state, fp);

    let req1 = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let r1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let r2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(r2.status(), StatusCode::OK);

    // Override is 2; the 3rd request must be refused even though
    // the compiled-in default would have allowed it.
    let req3 = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let r3 = app.oneshot(req3).await.unwrap();
    assert_eq!(r3.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(r3.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "per-token sse cap reached");
}

/// SDD-007 D-4 follow-up: operator-tuned `[api].max_sse_subscribers`
/// overrides the global default. Setting to 1 saturates immediately.
#[tokio::test]
async fn events_stream_global_cap_honours_operator_override() {
    use selfdef_api::SseCaps;

    let (state, _bus, _store, _dir) = build_state().await;
    let state = state.with_sse_caps(SseCaps {
        global: Some(1),
        per_token: None,
    });
    // `app(state)` uses with_full_capability which doesn't thread a
    // fingerprint, so the per-token path is skipped — only the
    // global cap applies. Override of 1 → 2nd request is refused.
    let app = app(state);

    let req1 = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let r1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let r2 = app.oneshot(req2).await.unwrap();
    assert_eq!(r2.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(r2.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "sse subscriber cap reached");
}

/// D-5.1: opening `MAX_SSE_SUBSCRIBERS_PER_TOKEN` connections with
/// the same fingerprint succeeds; the (cap+1)th gets 503 with the
/// per-token typed reason (distinguishable from the global 503).
#[tokio::test]
async fn events_stream_per_token_cap_reached() {
    use selfdef_api::{MAX_SSE_SUBSCRIBERS_PER_TOKEN, TokenFingerprint};

    let (state, _bus, _store, _dir) = build_state().await;
    let fp = TokenFingerprint::of("alice-token");
    let app = app_for_token(state, fp);

    let mut held = Vec::with_capacity(MAX_SSE_SUBSCRIBERS_PER_TOKEN);
    for i in 0..MAX_SSE_SUBSCRIBERS_PER_TOKEN {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/events/stream")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "subscriber {i} under per-token cap"
        );
        held.push(resp);
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["error"], "per-token sse cap reached",
        "expected per-token typed reason; got: {body:?}",
    );
}

/// D-5.2: per-token caps are per-fingerprint. A second token gets
/// its own slice even when the first is fully saturated.
#[tokio::test]
async fn events_stream_per_token_cap_does_not_affect_other_tokens() {
    use selfdef_api::{MAX_SSE_SUBSCRIBERS_PER_TOKEN, TokenFingerprint};

    let (state, _bus, _store, _dir) = build_state().await;
    let fp_a = TokenFingerprint::of("alice");
    let fp_b = TokenFingerprint::of("bob");

    // Saturate token A's slice. Need to use the same router for
    // all of A's calls so the in-memory state is shared.
    let app_a = app_for_token(state.clone(), fp_a);
    let mut held_a = Vec::with_capacity(MAX_SSE_SUBSCRIBERS_PER_TOKEN);
    for i in 0..MAX_SSE_SUBSCRIBERS_PER_TOKEN {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/events/stream")
            .body(Body::empty())
            .unwrap();
        let resp = app_a.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "A's subscriber {i}");
        held_a.push(resp);
    }

    // Token B should still succeed — its slice is empty.
    let app_b = app_for_token(state.clone(), fp_b);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app_b.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token B should bypass token A's saturated slice",
    );
}

/// D-5.5: when a per-token subscriber drops, the HashMap entry is
/// pruned (no leak across many short-lived sessions). The state's
/// `sse_subscribers_per_token` map drops back to empty.
#[tokio::test]
async fn events_stream_per_token_counter_drops_to_zero_on_disconnect() {
    use selfdef_api::TokenFingerprint;
    use selfdef_bus::Publisher;

    let (state, bus, _store, _dir) = build_state().await;
    let fp = TokenFingerprint::of("alice-leak-check");
    let app = app_for_token(state.clone(), fp);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/events/stream")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Drop the response → ReceiverStream closes → writer task's
    // next tx.send fails → guard drops. The drop chain is async,
    // so we publish a bus event to wake the writer + give the
    // runtime a tick.
    drop(resp);
    let pub_: Publisher = bus.publisher();
    let evt = selfdef_core::Event::new(
        ClassUid::PROCESS_ACTIVITY,
        1,
        SeverityId::Informational,
        "test-host",
        "leak.test",
        0,
    )
    .with_message("wake-writer");
    pub_.publish_lossy(evt);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Map should now have no entry for the fingerprint (pruned by
    // the guard's Drop).
    let keys = state.sse_subscribers_per_token_keys();
    assert!(
        !keys.contains(&fp),
        "per-token entry must be pruned after last subscriber drops; keys: {keys:?}",
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

// ---------------- SDD-008 D-4 HTTP ack tests

#[tokio::test]
async fn notify_ack_returns_503_when_engine_not_wired() {
    // Default ApiState has no escalation engine — the route is
    // present (operators can flip the knob on without a route-
    // table change) but returns 503.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/notify/ack/any-token")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

async fn build_state_with_engine() -> (
    ApiState,
    std::sync::Arc<selfdef_notifier_engine::EscalationEngine>,
    tempfile::TempDir,
) {
    use std::sync::Arc;
    let (state, _bus, _store, dir) = build_state().await;
    // Open the engine inside the same tempdir so it's cleaned up.
    let engine_path = dir.path().join("escalations.sqlite");
    let engine = Arc::new(selfdef_notifier_engine::EscalationEngine::open(&engine_path).unwrap());
    let state = state.with_escalation_engine(Arc::clone(&engine));
    (state, engine, dir)
}

async fn enqueue_for_token(
    engine: &selfdef_notifier_engine::EscalationEngine,
    token: &str,
    title: &str,
) -> selfdef_notifier_orchestrator::EventId {
    use selfdef_notifier_orchestrator::{EventId, Payload, PayloadId};
    let event_id = EventId(uuid::Uuid::now_v7());
    let payload = Payload {
        id: PayloadId::new(),
        event_id: Some(event_id),
        title: title.into(),
        body: format!("body for {title}"),
        severity: SeverityId::High,
        ack_link: None,
        event_kind: None,
        ack_token: Some(token.to_string()),
    };
    engine.enqueue(&payload, 100, 0).await.unwrap();
    event_id
}

#[tokio::test]
async fn notify_ack_unknown_token_returns_404() {
    let (state, _engine, _dir) = build_state_with_engine().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/notify/ack/this-token-was-never-enqueued")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn notify_ack_known_token_returns_200_and_acks() {
    let (state, engine, _dir) = build_state_with_engine().await;
    let _eid = enqueue_for_token(&engine, "happy-path-token", "ssh brute").await;

    let app = app(state.clone());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/notify/ack/happy-path-token")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = to_bytes(res.into_body(), 1_024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();
    assert!(body.contains("Acknowledged"), "body: {body}");
    assert!(body.contains("ssh brute"), "title in body: {body}");

    // Verify the row IS acked in the engine.
    let due = engine.take_due(1_000, 10).await.unwrap();
    assert_eq!(due.len(), 0, "acked rows must not be take_due-able");
}

#[tokio::test]
async fn notify_ack_idempotent_second_click_returns_404() {
    // First click acks; second click can't distinguish "unknown"
    // from "already acked" so it 404s. The handler doc-comment
    // notes this is intentional for v1; a future revision could
    // surface "already acked" as 200.
    let (state, engine, _dir) = build_state_with_engine().await;
    let _eid = enqueue_for_token(&engine, "double-click", "alert").await;

    let app1 = app(state.clone());
    let req1 = Request::builder()
        .method(Method::GET)
        .uri("/notify/ack/double-click")
        .body(Body::empty())
        .unwrap();
    let res1 = app1.oneshot(req1).await.unwrap();
    assert_eq!(res1.status(), StatusCode::OK);

    let app2 = app(state);
    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/notify/ack/double-click")
        .body(Body::empty())
        .unwrap();
    let res2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(res2.status(), StatusCode::NOT_FOUND);
}

// =========================================================================
// Four-watchdog HTTP routes (MS046 + MS047 + MS044 + MS048)
//
// End-to-end integration tests via tower::ServiceExt::oneshot. The
// runtime ring buffers + audit logs are not present on the test runner;
// these tests verify the routes are wired + return well-formed JSON +
// degrade gracefully when no watchdog state exists (the expected
// fresh-host behavior).
// =========================================================================

#[tokio::test]
async fn watchdog_friction_audit_route_returns_200_with_aggregate() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/friction-audit")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Aggregate is one of the documented states; on a fresh host with
    // no ring buffer, it's "unknown".
    let agg = v["aggregate"].as_str().unwrap();
    assert!(
        ["ok", "fail", "override", "unknown"].contains(&agg),
        "aggregate {agg:?} not in documented vocab"
    );
    assert!(v["verdicts"].is_array());
    assert!(v["overrides"].is_array());
}

#[tokio::test]
async fn watchdog_perimeter_route_returns_200_with_default_allowlist() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/perimeter")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Default allowlist must include sain-01 §6 verbatim 4 entries.
    let allow = v["default_allowlist"].as_array().unwrap();
    let allow_str: Vec<&str> = allow.iter().filter_map(|x| x.as_str()).collect();
    assert!(allow_str.contains(&"/usr/bin/python3"));
    assert!(allow_str.contains(&"/usr/bin/nvidia-smi"));
    assert!(allow_str.contains(&"/usr/local/bin/vllm"));
    assert!(allow_str.contains(&"/usr/bin/podman"));
}

#[tokio::test]
async fn watchdog_guardian_route_returns_200_with_socket_state() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/guardian")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["tetragon_socket_present"].is_boolean());
    assert!(v["verdicts"].is_array());
    let agg = v["aggregate"].as_str().unwrap();
    assert!(
        ["ok", "alert", "degraded", "unknown"].contains(&agg),
        "guardian aggregate {agg:?} not in documented vocab"
    );
}

#[tokio::test]
async fn watchdog_scheduler_route_returns_200_with_decisions_array() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/scheduler")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["decisions"].is_array());
    let agg = v["aggregate"].as_str().unwrap();
    assert!(
        ["ok", "backpressure", "unknown"].contains(&agg),
        "scheduler aggregate {agg:?} not in documented vocab"
    );
}

#[tokio::test]
async fn watchdog_scheduler_weights_route_returns_six_profile_matrix() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    // No ?profile filter → all six profiles returned.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/scheduler/weights")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = v.as_array().expect("weights endpoint returns an array");
    assert_eq!(arr.len(), 6, "expected 6 profile rows, got {}", arr.len());

    // Check the careful profile's risk weight is 1.0 per MS048 R11299.
    let careful = arr
        .iter()
        .find(|e| e["profile"].as_str() == Some("careful"))
        .expect("careful profile missing");
    let risk = careful["weights"]["risk"].as_f64().expect("risk weight is number");
    assert!((risk - 1.0).abs() < 0.001, "careful.risk should be 1.0, got {risk}");
}

#[tokio::test]
async fn watchdog_scheduler_weights_unknown_profile_returns_400() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/scheduler/weights?profile=bogus")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn watchdog_scheduler_explain_unknown_id_returns_404() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/scheduler/explain/req-does-not-exist")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modules_show_unknown_returns_404() {
    // /v1/modules/:name with a name that isn't shipped on the test
    // runner's modules dir returns 404 (not 500).
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules/does-not-exist")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modules_show_rejects_directory_traversal() {
    // Path-traversal attempts return 404 with the validation-failure
    // message, not 500. Defense in depth — selfdef-api should NEVER
    // attempt to read paths the operator didn't sanction.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    // Use a name with disallowed chars (uppercase + slash).
    // axum's path-param decoding rejects bare '..' early, so we use
    // an uppercase character that still reaches our handler.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules/INVALID")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modules_check_route_returns_404_for_unknown_module() {
    // MS006/MS016..MS031 per-module check surface. Unknown module
    // slug → 404 (same shape as show()).
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules/no-such-module/check")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modules_check_route_rejects_invalid_slug() {
    // Same kebab-case validation as show() — directory traversal
    // attempts (`../etc`) MUST be rejected without filesystem access.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules/foo..bar/check")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modules_diff_route_returns_200_with_three_buckets() {
    // MS011 Z-13 / SD-R83: /v1/modules/diff partitions catalog vs
    // host config into installed / available / orphaned. On the CI
    // runner the default modules dir doesn't exist + no modules.toml,
    // so we expect empty buckets but a well-formed envelope.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules/diff")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["installed"].is_array(), "installed must be array");
    assert!(v["available"].is_array(), "available must be array");
    assert!(v["orphaned"].is_array(), "orphaned must be array");
    assert!(v["counts"]["installed"].is_number());
    assert!(v["counts"]["available"].is_number());
    assert!(v["counts"]["orphaned"].is_number());
    assert!(v["modules_dir"].is_string());
    assert!(v["modules_toml"].is_string());
}

#[tokio::test]
async fn modules_route_returns_200_with_list() {
    // Verifies GET /v1/modules returns a well-formed JSON body.
    // On the test runner, DEFAULT_MODULES_DIR (/usr/share/selfdef/modules)
    // doesn't exist — handler should gracefully return an empty list.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/modules")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["modules"].is_array(), "modules field must be array");
    assert!(v["modules_dir"].is_string(), "modules_dir field must be string");
}

#[tokio::test]
async fn module_metrics_emitted_through_metrics_endpoint() {
    // MS006: selfdef_modules_{shipped,active}_total gauges flow through
    // the /metrics handler so Grafana/Prometheus can chart operator
    // module activation state.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();
    for series in ["selfdef_modules_shipped_total", "selfdef_modules_active_total"] {
        assert!(
            body.contains(&format!("# HELP {series}")),
            "missing HELP comment for {series}"
        );
        assert!(
            body.contains(&format!("# TYPE {series} gauge")),
            "missing TYPE comment for {series}"
        );
    }
}

#[tokio::test]
async fn watchdog_metrics_values_are_valid_prometheus_numbers() {
    // Every watchdog gauge must emit a numeric value (i64 or f64) per
    // Prometheus exposition format spec. Catches a regression where a
    // series accidentally emits 'NaN' or non-numeric junk that would
    // silently break Prometheus ingest.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();

    let mut checked = 0usize;
    for line in body.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Only check the four-watchdog series — other series like
        // selfdef_events_total carry labels that complicate parsing.
        if !line.contains("selfdef_friction_audit_")
            && !line.contains("selfdef_perimeter_")
            && !line.contains("selfdef_guardian_")
            && !line.contains("selfdef_scheduler_")
        {
            continue;
        }
        // No-labels watchdog gauges: "name value". Split on first ' '.
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        assert_eq!(parts.len(), 2, "malformed watchdog metric line: {line:?}");
        let value = parts[1];
        // Must parse as i64 OR finite f64. Reject NaN/Inf/non-numeric.
        let parsed = value.parse::<i64>().is_ok()
            || value
                .parse::<f64>()
                .map(|f| f.is_finite())
                .unwrap_or(false);
        assert!(
            parsed,
            "watchdog metric line has non-numeric/non-finite value: {line:?}",
        );
        checked += 1;
    }
    // Sanity check that we actually parsed the 15 watchdog gauges.
    assert!(
        checked >= 15,
        "expected at least 15 watchdog gauge lines, got {checked}"
    );
}

#[tokio::test]
async fn watchdog_metrics_emitted_through_metrics_endpoint() {
    // Verifies the watchdog_metrics::render() output appended in
    // handlers::metrics actually flows through the axum handler. Catches
    // a regression where someone removes the watchdog_metrics push but
    // leaves the unit tests passing.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();
    // Pre-existing selfdef-bus metrics must still be present.
    assert!(
        body.contains("selfdef_uptime_seconds"),
        "selfdef-bus metrics missing from /metrics body"
    );
    // Every four-watchdog series must be present per
    // selfdef-api/src/watchdog_metrics.rs.
    for series in [
        "selfdef_friction_audit_verdicts_total",
        "selfdef_friction_audit_failing_total",
        "selfdef_friction_audit_overrides_total",
        "selfdef_perimeter_verdicts_total",
        "selfdef_perimeter_sigkills_total",
        "selfdef_perimeter_extensions_total",
        "selfdef_perimeter_policy_present",
        "selfdef_perimeter_audit_chain_events",
        "selfdef_guardian_verdicts_total",
        "selfdef_guardian_failed_responses_total",
        "selfdef_guardian_tetragon_socket_present",
        "selfdef_guardian_audit_chain_events",
        "selfdef_scheduler_decisions_total",
        "selfdef_scheduler_backpressured_decisions_total",
        "selfdef_scheduler_audit_chain_events",
    ] {
        assert!(
            body.contains(&format!("# HELP {series}")),
            "missing HELP comment for {series} in /metrics body"
        );
        assert!(
            body.contains(&format!("# TYPE {series} gauge")),
            "missing TYPE comment for {series} in /metrics body"
        );
    }
}

#[tokio::test]
async fn watchdog_history_routes_honor_limit_query() {
    let (state, _bus, _store, _dir) = build_state().await;
    let app_a = app(state.clone());
    let app_b = app(state.clone());

    for uri in [
        "/v1/friction-audit/history?limit=5",
        "/v1/perimeter/history?limit=5",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        // Each oneshot consumes the router; use clones.
        let app = if uri.contains("friction") {
            app_a.clone()
        } else {
            app_b.clone()
        };
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "uri {uri} expected 200");
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["verdicts"].is_array(), "uri {uri} verdicts not array");
    }
}

#[tokio::test]
async fn audit_chains_route_returns_200_with_three_chains() {
    // MS009: /v1/audit-chains runs the 3 watchdog audit-chain checks.
    // On a CI runner the OCSF files don't exist so every chain will
    // return ok=false (with an error string). We assert shape + that
    // exactly 3 chains appear in canonical order.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/audit-chains")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let worst = v["worst"].as_str().expect("worst must be string");
    assert!(
        ["ok", "critical"].contains(&worst),
        "worst must be ok/critical; got {worst}"
    );
    let chains = v["chains"].as_array().expect("chains must be array");
    assert_eq!(chains.len(), 3);
    let names: Vec<&str> = chains.iter().map(|c| c["watchdog"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["perimeter", "guardian", "scheduler"]);
    for (i, c) in chains.iter().enumerate() {
        assert!(c["path"].is_string(), "row {i} path must be string");
        assert!(
            c["events_verified"].is_number(),
            "row {i} events_verified must be number"
        );
        assert!(c["ok"].is_boolean(), "row {i} ok must be bool");
        // error is null when ok=true, string when ok=false
        let ok = c["ok"].as_bool().unwrap();
        if ok {
            assert!(c["error"].is_null(), "row {i} error must be null when ok=true");
        } else {
            assert!(
                c["error"].is_string(),
                "row {i} error must be string when ok=false"
            );
        }
    }
}

#[tokio::test]
async fn health_route_returns_200_with_composite_body() {
    // MS011 Z-6: /v1/health aggregates alerts/network/storage/raid/
    // gpu/cpu into a composite worst-state + per-component rows.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["ok", "warn", "critical", "unknown"].contains(&worst),
        "worst must be normalized to ok/warn/critical/unknown; got {worst}"
    );

    let comps = v["components"].as_array().expect("components must be array");
    let expected_names = ["alerts", "network", "storage", "raid", "gpu", "cpu"];
    assert_eq!(
        comps.len(),
        expected_names.len(),
        "expected exactly {} components",
        expected_names.len()
    );
    for (i, exp) in expected_names.iter().enumerate() {
        let c = &comps[i];
        assert_eq!(
            c["name"].as_str().unwrap(),
            *exp,
            "row {i} name mismatch"
        );
        let s = c["state"].as_str().unwrap();
        assert!(
            ["ok", "warn", "critical", "unknown"].contains(&s),
            "row {i} state must be ok/warn/critical/unknown; got {s}"
        );
        assert!(c["detail"].is_string(), "row {i} detail must be string");
    }
    // cpu component never degrades (always reports ok per the
    // documented contract — operator choice is not health).
    let cpu_state = comps[5]["state"].as_str().unwrap();
    assert_eq!(
        cpu_state, "ok",
        "cpu row must always be ok (mode is operator choice, not health)"
    );
}

#[tokio::test]
async fn cpu_route_returns_200_with_well_formed_body() {
    // MS011 Z-4: /v1/cpu reads /sys/devices/system/cpu/*/cpufreq/
    // scaling_governor + SMT state, classifies into a named mode.
    // On a host without cpufreq (container?), governors is empty +
    // cpufreq_present is false + mode is "custom".
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/cpu")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let mode = v["mode"].as_str().expect("mode must be a string");
    assert!(
        [
            "ultra-low-power",
            "balanced",
            "sustained-burst",
            "peak-inference",
            "custom",
        ]
        .contains(&mode),
        "mode must be one of the 5 named values; got {mode}"
    );
    assert!(v["governors"].is_array(), "governors must be array");
    assert!(v["smt_enabled"].is_boolean(), "smt_enabled must be bool");
    assert!(
        v["cpufreq_present"].is_boolean(),
        "cpufreq_present must be bool"
    );
    assert!(v["smt_present"].is_boolean(), "smt_present must be bool");
}

#[tokio::test]
async fn gpu_route_returns_200_with_well_formed_body() {
    // MS011 Z-5: /v1/gpu probes nvidia-smi + reads operator policy.
    // On a host without nvidia-smi installed, gpus list is empty
    // (parse_nvidia_smi_power_csv returns empty for empty body).
    // We verify response shape + the policy-path field.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/gpu")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["green", "yellow", "red", "unknown"].contains(&worst),
        "worst must be green/yellow/red/unknown; got {worst}"
    );
    assert!(v["policy_path"].is_string(), "policy_path must be string");
    assert!(
        v["policy_present"].is_boolean(),
        "policy_present must be bool"
    );
    let gpus = v["gpus"].as_array().expect("gpus must be array");
    for (i, g) in gpus.iter().enumerate() {
        assert!(g["index"].is_number(), "row {i} index must be number");
        assert!(
            g["tolerance_watts"].is_number(),
            "row {i} tolerance_watts must be number"
        );
        let s = g["state"].as_str().unwrap();
        assert!(
            ["green", "yellow", "red", "unknown"].contains(&s),
            "row {i} state must be green/yellow/red/unknown; got {s}"
        );
        assert!(g["detail"].is_string(), "row {i} detail must be string");
    }
}

#[tokio::test]
async fn raid_route_returns_200_with_well_formed_body() {
    // MS011 Z-9: /v1/raid reads /proc/mdstat (best-effort). On a
    // host without MD support `arrays` is empty + mdstat_present is
    // false; on a host with arrays we just assert response shape.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/raid")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["green", "yellow", "red"].contains(&worst),
        "worst must be green/yellow/red; got {worst}"
    );
    assert!(
        v["mdstat_present"].is_boolean(),
        "mdstat_present must be bool"
    );
    let arrays = v["arrays"].as_array().expect("arrays must be array");
    for (i, a) in arrays.iter().enumerate() {
        assert!(a["name"].is_string(), "row {i} name must be string");
        assert!(a["level"].is_string(), "row {i} level must be string");
        assert!(a["health"].is_string(), "row {i} health must be string");
        assert!(a["members"].is_array(), "row {i} members must be array");
        let s = a["state"].as_str().unwrap();
        assert!(
            ["green", "yellow", "red"].contains(&s),
            "row {i} state must be green/yellow/red; got {s}"
        );
    }
}

#[tokio::test]
async fn storage_route_returns_200_with_well_formed_body() {
    // MS011 Z-10: /v1/storage returns per-mount usage + per-log-dir
    // byte/file counts. Mount count depends on the runner; we assert
    // shape + worst-state enum value rather than counts.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/storage")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 256 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["green", "yellow", "red"].contains(&worst),
        "worst must be green/yellow/red; got {worst}"
    );

    let mounts = v["mounts"].as_array().expect("mounts must be array");
    // Every mount row must have the documented shape.
    for (i, m) in mounts.iter().enumerate() {
        assert!(m["source"].is_string(), "row {i} source must be string");
        assert!(m["fstype"].is_string(), "row {i} fstype must be string");
        assert!(m["mountpoint"].is_string(), "row {i} mountpoint must be string");
        assert!(m["used_pct"].is_number(), "row {i} used_pct must be number");
        let s = m["state"].as_str().unwrap();
        assert!(
            ["green", "yellow", "red"].contains(&s),
            "row {i} state must be green/yellow/red; got {s}"
        );
    }

    let log_dirs = v["log_dirs"].as_array().expect("log_dirs must be array");
    assert_eq!(log_dirs.len(), 3, "expected 3 selfdef-managed log dirs");
    let expected_paths = ["/var/log/selfdef", "/var/cache/selfdef", "/var/lib/selfdef"];
    for (i, exp) in expected_paths.iter().enumerate() {
        let d = &log_dirs[i];
        assert_eq!(d["path"].as_str().unwrap(), *exp);
        assert!(d["bytes"].is_number());
        assert!(d["files"].is_number());
        assert!(d["exists"].is_boolean());
    }
}

#[tokio::test]
async fn network_route_returns_200_with_five_components() {
    // MS011 Z-7: /v1/network returns the 5 operator-relevant network
    // components in canonical order. State values depend on the
    // runner (most CI hosts don't have cloudflared/tailscale/traefik
    // running — those will report `unknown`), so we assert shape +
    // order + that each row has a state in the allowed enum.
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/network")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["green", "yellow", "red", "unknown"].contains(&worst),
        "worst must be green/yellow/red/unknown; got {worst}"
    );

    let comps = v["components"]
        .as_array()
        .expect("components must be array");
    assert_eq!(comps.len(), 5, "expected exactly 5 components");
    let expected = ["internet", "dns", "cloudflared", "tailscale", "traefik"];
    for (i, exp) in expected.iter().enumerate() {
        let c = &comps[i];
        assert_eq!(c["name"].as_str().unwrap(), *exp, "row {i} name mismatch");
        let s = c["state"].as_str().unwrap();
        assert!(
            ["green", "yellow", "red", "unknown"].contains(&s),
            "row {i} state must be green/yellow/red/unknown; got {s}"
        );
        assert!(c["detail"].is_string(), "row {i} detail must be string");
    }
}

#[tokio::test]
async fn hardware_routes_return_200_with_well_formed_bodies() {
    // MS010 + SDD-018: the three /v1/hardware* routes must serve
    // JSON. The actual values depend on the host (CI runner may
    // have AVX-512 or not, GPUs or not, etc.), so we assert shape
    // and presence-of-required-keys, not values.
    let (state, _bus, _store, _dir) = build_state().await;
    let app_a = app(state.clone());
    let app_b = app(state.clone());
    let app_c = app(state);

    // /v1/hardware — full snapshot.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/hardware")
        .body(Body::empty())
        .unwrap();
    let res = app_a.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "/v1/hardware expected 200");
    let bytes = to_bytes(res.into_body(), 256 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["cpu"].is_object(), "snapshot must have cpu object");
    assert!(v["memory"].is_object(), "snapshot must have memory object");
    assert!(v["gpus"].is_array(), "snapshot must have gpus array");
    assert!(v["pcie"].is_object(), "snapshot must have pcie object");
    assert!(
        v["probed_at"].is_string(),
        "snapshot must have probed_at timestamp"
    );

    // /v1/hardware/capabilities — derived flags.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/hardware/capabilities")
        .body(Body::empty())
        .unwrap();
    let res = app_b.oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "/v1/hardware/capabilities expected 200"
    );
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        v.is_object(),
        "capabilities response must be a JSON object; got {v}"
    );

    // /v1/hardware/sain01 — match verdict envelope.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/hardware/sain01")
        .body(Body::empty())
        .unwrap();
    let res = app_c.oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "/v1/hardware/sain01 expected 200"
    );
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        v["sain01"].is_object(),
        "sain01 envelope must wrap sain01 object"
    );
    // The Sain01Match has an `overall` field (Sain01Verdict enum:
    // Match/NearMatch/NoMatch) serialized by serde — at minimum it's
    // a string or has a recognizable enum tag. We just assert presence
    // + a few of the boolean indicator fields here; the selfdef-
    // hardware crate has its own unit tests for the verdict semantics.
    assert!(
        v["sain01"]["overall"].is_string() || v["sain01"]["overall"].is_object(),
        "sain01 envelope must include an overall verdict; got {}",
        v["sain01"]
    );
    assert!(
        v["sain01"]["cpu_avx512_vnni"].is_boolean(),
        "sain01 envelope must include cpu_avx512_vnni bool"
    );
    assert!(
        v["sain01"]["pcie_dual_x8_present"].is_boolean(),
        "sain01 envelope must include pcie_dual_x8_present bool"
    );
}

#[tokio::test]
async fn alerts_route_returns_200_with_nine_classified_rows() {
    // MS027 + /v1/alerts: server-side classification of the 9 four-
    // watchdog alert series. Both the PWA dashboard and the
    // selfdefctl alerts CLI consume this; we verify the shape +
    // canonical ordering (so client code can index by position).
    let (state, _bus, _store, _dir) = build_state().await;
    let app = app(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/alerts")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let worst = v["worst"].as_str().expect("worst must be a string");
    assert!(
        ["ok", "warn", "critical", "unknown"].contains(&worst),
        "worst must be one of ok/warn/critical/unknown; got {worst}"
    );

    let alerts = v["alerts"].as_array().expect("alerts must be array");
    assert_eq!(alerts.len(), 9, "expected exactly 9 alert rows");

    let expected_names = [
        "FrictionAuditFailing",
        "PerimeterSigkill",
        "PerimeterPolicyMissing",
        "PerimeterChainBroken",
        "GuardianFailedResponse",
        "GuardianTetragonSocketMissing",
        "GuardianChainBroken",
        "SchedulerSustainedBackpressure",
        "SchedulerChainBroken",
    ];
    for (i, expected) in expected_names.iter().enumerate() {
        let row = &alerts[i];
        assert_eq!(
            row["name"].as_str().unwrap(),
            *expected,
            "row {i} name mismatch"
        );
        let state = row["state"].as_str().unwrap();
        assert!(
            ["ok", "warn", "critical", "unknown"].contains(&state),
            "row {i} state must be one of ok/warn/critical/unknown; got {state}"
        );
        assert!(row["ms"].is_string(), "row {i} ms must be string");
        assert!(row["series"].is_string(), "row {i} series must be string");
        assert!(
            row["threshold"].is_string(),
            "row {i} threshold must be string"
        );
        // value is either f64 or null (when series isn't exported)
        assert!(
            row["value"].is_number() || row["value"].is_null(),
            "row {i} value must be number or null"
        );
    }
}
