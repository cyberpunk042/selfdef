//! Prometheus metrics for the selfdef daemon.
//!
//! Surface: [`Metrics`] carries the atomic counters; [`render`] turns
//! them into a single Prometheus exposition-format string. The
//! daemon spawns one [`run_ingest`] task that subscribes to the bus
//! and bumps counters per event, so the handler stays a cheap dump.
//!
//! Counters intentionally use small label sets (class_uid as a number,
//! severity_id as a number) — high-cardinality labels (host_tag,
//! source string) would blow up Prometheus's TSDB on a busy host.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use selfdef_bus::{Bus, BusError};
use selfdef_core::Event;
use selfdef_core::category::CategoryUid;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Process-wide metrics for the daemon. Cloning is cheap (Arc'd).
pub struct Metrics {
    started_at: Instant,
    host_tag: String,
    crate_version: &'static str,
    schema_version: u32,

    /// Total events seen on the bus, by class_uid.
    events_by_class: Mutex<HashMap<u32, u64>>,
    /// Total findings (category 2 events), by severity_id.
    findings_by_severity: Mutex<HashMap<u32, u64>>,
    /// Total findings (category 2 events), by the title of the rule that
    /// produced them (carried in `raw.rule_title` by the correlator). Lets
    /// the dashboard break the finding stream down per rule — e.g. the
    /// `selfdef_watchdog_alert` rule (SDD-062) that routes the
    /// detection-watchdog alert tier.
    findings_by_rule: Mutex<HashMap<String, u64>>,
    /// Sum of all event counters — cheaper to read than locking the map.
    events_total: AtomicU64,
    findings_total: AtomicU64,
    /// Number of times the bus reported the ingest subscriber lagged
    /// behind the broadcast. Non-zero means metrics are
    /// under-counting and the operator should resize the bus.
    ingest_lag_events: AtomicU64,

    /// SDD-081 retention sweeps run + cumulative events pruned.
    /// `selfdef_store_events` shows the live hot-store size; these show
    /// the retention enforcement actually WORKING (sweeps executed +
    /// events deleted past the horizon), so an operator can chart that
    /// `hot_retention_days` is bounding the store rather than just trust
    /// the log line.
    retention_sweeps_total: AtomicU64,
    retention_pruned_total: AtomicU64,
    /// 1 when retention is enabled (`hot_retention_days > 0`), 0 when the
    /// operator opted out. Lets a consumer alert distinguish "retention
    /// disabled" (enabled=0 → sweeps stay 0 by design) from "retention
    /// stalled" (enabled=1 but sweeps not advancing). Set once at startup.
    retention_enabled: AtomicU64,

    /// M060 mirror-export per-artifact publish counters. Keys are the
    /// canonical artifact filename (e.g. `"grants.json"`); values are
    /// (ok_count, failed_count). Set + bumped by the daemon's
    /// `mirror_export_loop` on every tick — exposed at `/metrics` so
    /// Prometheus can scrape directly from selfdefd without needing the
    /// sovereign-os textfile-collector path.
    m060_publish_counts: Mutex<HashMap<String, (u64, u64)>>,
    /// M060 mirror-export per-artifact last-publish unix timestamp (in
    /// seconds since epoch). Set on every successful publish; consumers
    /// derive `age = time() - this` to detect stalled publishers.
    m060_last_publish_unix: Mutex<HashMap<String, u64>>,
}

impl Metrics {
    /// Construct a fresh metrics block with no events recorded.
    #[must_use]
    pub fn new(host_tag: impl Into<String>) -> Self {
        Self {
            started_at: Instant::now(),
            host_tag: host_tag.into(),
            crate_version: env!("CARGO_PKG_VERSION"),
            schema_version: selfdef_core::SCHEMA_VERSION,
            events_by_class: Mutex::new(HashMap::new()),
            findings_by_severity: Mutex::new(HashMap::new()),
            findings_by_rule: Mutex::new(HashMap::new()),
            events_total: AtomicU64::new(0),
            findings_total: AtomicU64::new(0),
            ingest_lag_events: AtomicU64::new(0),
            retention_sweeps_total: AtomicU64::new(0),
            retention_pruned_total: AtomicU64::new(0),
            retention_enabled: AtomicU64::new(0),
            m060_publish_counts: Mutex::new(HashMap::new()),
            m060_last_publish_unix: Mutex::new(HashMap::new()),
        }
    }

    /// Record one M060 mirror-publish attempt. `artifact` is the
    /// canonical filename (e.g. `"grants.json"`). On success, increments
    /// the ok counter + stamps the last-publish gauge to now. On failure,
    /// increments only the failed counter.
    pub fn record_m060_publish(&self, artifact: &str, ok: bool) {
        let mut counts = self
            .m060_publish_counts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = counts.entry(artifact.to_string()).or_insert((0, 0));
        if ok {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        drop(counts);
        if ok {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut ts = self
                .m060_last_publish_unix
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            ts.insert(artifact.to_string(), now);
        }
    }

    /// Record one event observation. Called from the ingest task per
    /// bus message. O(1) under brief mutex contention.
    pub fn record_event(&self, event: &Event) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        {
            let mut m = self
                .events_by_class
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *m.entry(event.class_uid.0).or_insert(0) += 1;
        }
        if event.category_uid == CategoryUid::Findings {
            self.findings_total.fetch_add(1, Ordering::Relaxed);
            let mut m = self
                .findings_by_severity
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *m.entry(event.severity_id as u32).or_insert(0) += 1;

            if let Some(rule) = event
                .raw
                .as_ref()
                .and_then(|r| r.get("rule_title"))
                .and_then(serde_json::Value::as_str)
            {
                let mut by_rule = self
                    .findings_by_rule
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *by_rule.entry(rule.to_string()).or_insert(0) += 1;
            }
        }
    }

    /// Count one missed-event lag from the bus broadcast subscriber.
    pub fn record_ingest_lag(&self, n: u64) {
        self.ingest_lag_events.fetch_add(n, Ordering::Relaxed);
    }

    /// Record one SDD-081 retention sweep: bump the sweep counter and add
    /// `pruned` to the cumulative pruned-events counter. `pruned` may be 0
    /// (a sweep that found nothing past the horizon still counts).
    pub fn record_retention_sweep(&self, pruned: u64) {
        self.retention_sweeps_total.fetch_add(1, Ordering::Relaxed);
        self.retention_pruned_total
            .fetch_add(pruned, Ordering::Relaxed);
    }

    /// Set whether retention is enabled (`hot_retention_days > 0`). Called
    /// once at daemon startup; lets consumers tell "disabled" from "stalled".
    pub fn set_retention_enabled(&self, enabled: bool) {
        self.retention_enabled
            .store(u64::from(enabled), Ordering::Relaxed);
    }

    /// Render the current counters as a Prometheus exposition-format
    /// document. `store_count` is sampled at render time so the
    /// gauge reflects the live store size — we don't try to mirror it
    /// in an atomic.
    #[must_use]
    pub fn render(&self, store_count: u64) -> String {
        let mut out = String::with_capacity(1024);

        // build_info: a gauge of 1 with labels carrying version metadata.
        // Prometheus-idiomatic way to expose static build info without
        // creating an actual numeric "version" series.
        out.push_str("# HELP selfdef_build_info Build metadata (always 1).\n");
        out.push_str("# TYPE selfdef_build_info gauge\n");
        writeln!(
            out,
            "selfdef_build_info{{version=\"{}\",schema=\"{}\",host_tag=\"{}\"}} 1",
            escape(self.crate_version),
            self.schema_version,
            escape(&self.host_tag),
        )
        .unwrap();

        out.push_str("# HELP selfdef_uptime_seconds Daemon uptime in seconds.\n");
        out.push_str("# TYPE selfdef_uptime_seconds counter\n");
        writeln!(
            out,
            "selfdef_uptime_seconds {}",
            self.started_at.elapsed().as_secs()
        )
        .unwrap();

        out.push_str("# HELP selfdef_store_events Current event count in the hot store.\n");
        out.push_str("# TYPE selfdef_store_events gauge\n");
        writeln!(out, "selfdef_store_events {store_count}").unwrap();

        out.push_str("# HELP selfdef_events_total Events published to the bus.\n");
        out.push_str("# TYPE selfdef_events_total counter\n");
        writeln!(
            out,
            "selfdef_events_total {}",
            self.events_total.load(Ordering::Relaxed),
        )
        .unwrap();

        out.push_str(
            "# HELP selfdef_events_by_class_total Events published to the bus, by class_uid.\n",
        );
        out.push_str("# TYPE selfdef_events_by_class_total counter\n");
        // Snapshot the map under the lock, then drop the lock before
        // writing — keeps the lock window short even on the small
        // chance that a metrics scrape coincides with a burst of
        // bus traffic.
        let class_snapshot: Vec<(u32, u64)> = {
            let m = self
                .events_by_class
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut v: Vec<_> = m.iter().map(|(k, v)| (*k, *v)).collect();
            v.sort_unstable_by_key(|(k, _)| *k);
            v
        };
        for (class, count) in class_snapshot {
            writeln!(
                out,
                "selfdef_events_by_class_total{{class_uid=\"{class}\"}} {count}",
            )
            .unwrap();
        }

        out.push_str("# HELP selfdef_findings_total Findings (category 2 events).\n");
        out.push_str("# TYPE selfdef_findings_total counter\n");
        writeln!(
            out,
            "selfdef_findings_total {}",
            self.findings_total.load(Ordering::Relaxed),
        )
        .unwrap();

        out.push_str("# HELP selfdef_findings_by_severity_total Findings, by severity_id.\n");
        out.push_str("# TYPE selfdef_findings_by_severity_total counter\n");
        let sev_snapshot: Vec<(u32, u64)> = {
            let m = self
                .findings_by_severity
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut v: Vec<_> = m.iter().map(|(k, v)| (*k, *v)).collect();
            v.sort_unstable_by_key(|(k, _)| *k);
            v
        };
        for (sev, count) in sev_snapshot {
            writeln!(
                out,
                "selfdef_findings_by_severity_total{{severity_id=\"{sev}\"}} {count}",
            )
            .unwrap();
        }

        out.push_str("# HELP selfdef_findings_by_rule_total Findings, by the title of the rule that produced them.\n");
        out.push_str("# TYPE selfdef_findings_by_rule_total counter\n");
        let rule_snapshot: Vec<(String, u64)> = {
            let m = self
                .findings_by_rule
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut v: Vec<_> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
            v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            v
        };
        for (rule, count) in rule_snapshot {
            writeln!(
                out,
                "selfdef_findings_by_rule_total{{rule=\"{}\"}} {count}",
                escape(&rule),
            )
            .unwrap();
        }

        out.push_str("# HELP selfdef_ingest_lag_events_total Events missed by the metrics ingest subscriber (bus over-subscribed).\n");
        out.push_str("# TYPE selfdef_ingest_lag_events_total counter\n");
        writeln!(
            out,
            "selfdef_ingest_lag_events_total {}",
            self.ingest_lag_events.load(Ordering::Relaxed),
        )
        .unwrap();

        out.push_str(
            "# HELP selfdef_store_retention_sweeps_total Retention sweeps run (SDD-081).\n",
        );
        out.push_str("# TYPE selfdef_store_retention_sweeps_total counter\n");
        writeln!(
            out,
            "selfdef_store_retention_sweeps_total {}",
            self.retention_sweeps_total.load(Ordering::Relaxed),
        )
        .unwrap();
        out.push_str(
            "# HELP selfdef_store_retention_pruned_total Events deleted by retention past the hot_retention_days horizon (cumulative, SDD-081).\n",
        );
        out.push_str("# TYPE selfdef_store_retention_pruned_total counter\n");
        writeln!(
            out,
            "selfdef_store_retention_pruned_total {}",
            self.retention_pruned_total.load(Ordering::Relaxed),
        )
        .unwrap();
        out.push_str(
            "# HELP selfdef_store_retention_enabled 1 when hot_retention_days>0 (retention on), else 0 (SDD-081).\n",
        );
        out.push_str("# TYPE selfdef_store_retention_enabled gauge\n");
        writeln!(
            out,
            "selfdef_store_retention_enabled {}",
            self.retention_enabled.load(Ordering::Relaxed),
        )
        .unwrap();

        // M060 mirror-export per-artifact publish counters. Two series
        // sharing the `artifact` label: ok + failed. Operators alert on
        // any failed > 0 OR on stale last-publish (now - ts > threshold).
        out.push_str(
            "# HELP selfdef_m060_mirror_publish_total M060 mirror-export attempts, by artifact + result.\n",
        );
        out.push_str("# TYPE selfdef_m060_mirror_publish_total counter\n");
        let publish_snapshot: Vec<(String, (u64, u64))> = {
            let m = self
                .m060_publish_counts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut v: Vec<_> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
            v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            v
        };
        for (artifact, (ok, failed)) in &publish_snapshot {
            writeln!(
                out,
                "selfdef_m060_mirror_publish_total{{artifact=\"{}\",result=\"ok\"}} {ok}",
                escape(artifact),
            )
            .unwrap();
            writeln!(
                out,
                "selfdef_m060_mirror_publish_total{{artifact=\"{}\",result=\"failed\"}} {failed}",
                escape(artifact),
            )
            .unwrap();
        }

        // M060 last-publish unix timestamp per artifact. Prometheus
        // pattern: `time() - selfdef_m060_mirror_last_publish_unix > 300`
        // catches the "stale" failure mode (>5 min since last successful
        // publish). Per-artifact granularity so the operator sees which
        // publisher specifically is stuck.
        out.push_str("# HELP selfdef_m060_mirror_last_publish_unix Unix timestamp of last successful M060 mirror publish, per artifact.\n");
        out.push_str("# TYPE selfdef_m060_mirror_last_publish_unix gauge\n");
        let ts_snapshot: Vec<(String, u64)> = {
            let m = self
                .m060_last_publish_unix
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut v: Vec<_> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
            v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            v
        };
        for (artifact, ts) in &ts_snapshot {
            writeln!(
                out,
                "selfdef_m060_mirror_last_publish_unix{{artifact=\"{}\"}} {ts}",
                escape(artifact),
            )
            .unwrap();
        }

        out
    }
}

/// Escape a label-value string for Prometheus exposition format.
///
/// Reference: <https://prometheus.io/docs/instrumenting/exposition_formats/>
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Subscribe to the bus and bump counters until shutdown. The daemon
/// spawns one of these next to the correlator / responder tasks.
///
/// **Gating contract** (F-2027-015): only spawn this task when the API
/// is enabled — without an HTTP scrape surface the counters are dead
/// weight. The daemon enforces this at
/// `crates/selfdef-daemon/src/main.rs::main` (the metrics ingest task
/// is built inside the `if cfg.api.enabled` branch).
///
/// **Lag semantics**: when the broadcast bus reports the subscriber
/// fell behind (`BusError::Lagged(n)`), the lag is accounted on
/// `selfdef_ingest_lag_events_total` so operators can see the
/// undercount and resize the bus. Other bus errors log and continue;
/// only `BusError::Closed` exits.
pub async fn run_ingest(
    metrics: std::sync::Arc<Metrics>,
    bus: std::sync::Arc<Bus>,
    shutdown: CancellationToken,
) {
    let mut sub = bus.subscribe();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                debug!("metrics ingest shutting down");
                return;
            }
            res = sub.recv() => match res {
                Ok(event) => metrics.record_event(&event),
                Err(BusError::Lagged(n)) => {
                    metrics.record_ingest_lag(n);
                    warn!(missed = n, "metrics ingest lagged");
                }
                Err(BusError::Closed) => {
                    debug!("metrics ingest: bus closed");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "metrics ingest bus error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::severity::SeverityId;

    fn ev(class: ClassUid, sev: SeverityId) -> Event {
        Event::new(class, 1, sev, "test-host", "test.source", 0)
    }

    #[test]
    fn record_event_increments_total_and_per_class() {
        let m = Metrics::new("test-host");
        m.record_event(&ev(ClassUid::SSH_ACTIVITY, SeverityId::Informational));
        m.record_event(&ev(ClassUid::SSH_ACTIVITY, SeverityId::Informational));
        m.record_event(&ev(ClassUid::PROCESS_ACTIVITY, SeverityId::Informational));
        assert_eq!(m.events_total.load(Ordering::Relaxed), 3);
        let by_class = m.events_by_class.lock().unwrap();
        assert_eq!(by_class.get(&ClassUid::SSH_ACTIVITY.0).copied(), Some(2));
        assert_eq!(
            by_class.get(&ClassUid::PROCESS_ACTIVITY.0).copied(),
            Some(1)
        );
    }

    #[test]
    fn record_event_findings_bucket_only_for_category_2() {
        let m = Metrics::new("test-host");
        m.record_event(&ev(ClassUid::SSH_ACTIVITY, SeverityId::Informational)); // category 4
        m.record_event(&ev(ClassUid::DETECTION_FINDING, SeverityId::High)); // category 2
        m.record_event(&ev(ClassUid::DETECTION_FINDING, SeverityId::High));
        m.record_event(&ev(ClassUid::DETECTION_FINDING, SeverityId::Critical));
        assert_eq!(m.findings_total.load(Ordering::Relaxed), 3);
        let by_sev = m.findings_by_severity.lock().unwrap();
        assert_eq!(by_sev.get(&(SeverityId::High as u32)).copied(), Some(2));
        assert_eq!(by_sev.get(&(SeverityId::Critical as u32)).copied(), Some(1));
        assert_eq!(by_sev.get(&(SeverityId::Informational as u32)), None);
    }

    #[test]
    fn findings_bucket_by_rule_title_from_raw() {
        let m = Metrics::new("test-host");
        let finding = |title: &str| {
            ev(ClassUid::DETECTION_FINDING, SeverityId::High)
                .with_raw(serde_json::json!({ "rule_title": title }))
        };
        m.record_event(&finding("selfdef watchdog alert-tier finding"));
        m.record_event(&finding("selfdef watchdog alert-tier finding"));
        m.record_event(&finding("sudoers tamper"));
        // A finding with no rule_title is counted in totals but not bucketed.
        m.record_event(&ev(ClassUid::DETECTION_FINDING, SeverityId::High));
        // A non-finding event never touches the by-rule bucket.
        m.record_event(&ev(ClassUid::SSH_ACTIVITY, SeverityId::Informational));

        let by_rule = m.findings_by_rule.lock().unwrap();
        assert_eq!(
            by_rule.get("selfdef watchdog alert-tier finding").copied(),
            Some(2)
        );
        assert_eq!(by_rule.get("sudoers tamper").copied(), Some(1));
        assert_eq!(by_rule.len(), 2);
        drop(by_rule);

        let body = m.render(0);
        assert!(body.contains("# TYPE selfdef_findings_by_rule_total counter"));
        assert!(
            body.contains(
                "selfdef_findings_by_rule_total{rule=\"selfdef watchdog alert-tier finding\"} 2"
            ),
            "{body}"
        );
    }

    #[test]
    fn render_produces_valid_prometheus_exposition() {
        let m = Metrics::new("my-host");
        m.record_event(&ev(ClassUid::SSH_ACTIVITY, SeverityId::Informational));
        m.record_event(&ev(ClassUid::DETECTION_FINDING, SeverityId::Critical));
        let body = m.render(42);

        // Header presence and TYPE/HELP shape.
        for required in [
            "# TYPE selfdef_build_info gauge",
            "# TYPE selfdef_uptime_seconds counter",
            "# TYPE selfdef_store_events gauge",
            "# TYPE selfdef_events_total counter",
            "# TYPE selfdef_events_by_class_total counter",
            "# TYPE selfdef_findings_total counter",
            "# TYPE selfdef_findings_by_severity_total counter",
            "# TYPE selfdef_ingest_lag_events_total counter",
        ] {
            assert!(
                body.contains(required),
                "missing line `{required}`:\n{body}",
            );
        }

        // Body values.
        assert!(body.contains("selfdef_store_events 42"), "{body}");
        assert!(body.contains("selfdef_events_total 2"), "{body}");
        assert!(body.contains("selfdef_findings_total 1"), "{body}");
        assert!(
            body.contains(&format!(
                "selfdef_events_by_class_total{{class_uid=\"{}\"}} 1",
                ClassUid::SSH_ACTIVITY.0,
            )),
            "{body}",
        );
        assert!(
            body.contains(&format!(
                "selfdef_findings_by_severity_total{{severity_id=\"{}\"}} 1",
                SeverityId::Critical as u32,
            )),
            "{body}",
        );
        // build_info gauge with the host_tag we passed.
        assert!(body.contains("host_tag=\"my-host\""), "{body}");
        assert!(body.contains(" 1\n"), "build_info gauge value:\n{body}");
    }

    #[test]
    fn label_values_are_escaped() {
        // Labels that contain `"` or `\` need to round-trip through
        // the Prometheus parser unambiguously. host_tag is the only
        // operator-controlled label value we render.
        let m = Metrics::new(r#"weird "host\name"#);
        let body = m.render(0);
        // Input has one `"` and one `\` — each gets one backslash
        // prefix in the exposition format. The result is wrapped in
        // a pair of un-escaped `"` from the printf template itself.
        assert!(
            body.contains(r#"host_tag="weird \"host\\name""#),
            "escape failed:\n{body}",
        );
    }

    #[test]
    fn ingest_lag_counter_accumulates() {
        let m = Metrics::new("h");
        m.record_ingest_lag(5);
        m.record_ingest_lag(3);
        let body = m.render(0);
        assert!(body.contains("selfdef_ingest_lag_events_total 8"), "{body}",);
    }

    #[test]
    fn m060_publish_ok_increments_counter_and_stamps_timestamp() {
        let m = Metrics::new("h");
        m.record_m060_publish("grants.json", true);
        m.record_m060_publish("grants.json", true);
        let body = m.render(0);
        assert!(
            body.contains(
                "selfdef_m060_mirror_publish_total{artifact=\"grants.json\",result=\"ok\"} 2"
            ),
            "{body}"
        );
        // A successful publish must stamp the last-publish gauge.
        assert!(
            body.contains("selfdef_m060_mirror_last_publish_unix{artifact=\"grants.json\"}"),
            "{body}"
        );
    }

    #[test]
    fn m060_publish_failed_increments_counter_but_does_not_stamp_timestamp() {
        let m = Metrics::new("h");
        m.record_m060_publish("audit.json", false);
        m.record_m060_publish("audit.json", false);
        m.record_m060_publish("audit.json", false);
        let body = m.render(0);
        assert!(
            body.contains(
                "selfdef_m060_mirror_publish_total{artifact=\"audit.json\",result=\"failed\"} 3"
            ),
            "{body}"
        );
        // No successful publishes → last-publish gauge for this artifact
        // MUST NOT appear (we don't fabricate a 0 — operators want to
        // know honestly that the publisher has never succeeded).
        assert!(
            !body.contains("selfdef_m060_mirror_last_publish_unix{artifact=\"audit.json\"}"),
            "last-publish gauge must NOT be present when no ok publishes: {body}"
        );
    }

    #[test]
    fn m060_publish_metrics_track_both_ok_and_failed_independently() {
        let m = Metrics::new("h");
        m.record_m060_publish("rules.json", true);
        m.record_m060_publish("rules.json", false);
        m.record_m060_publish("rules.json", true);
        m.record_m060_publish("rules.json", false);
        m.record_m060_publish("rules.json", true);
        let body = m.render(0);
        assert!(
            body.contains(
                "selfdef_m060_mirror_publish_total{artifact=\"rules.json\",result=\"ok\"} 3"
            ),
            "{body}"
        );
        assert!(
            body.contains(
                "selfdef_m060_mirror_publish_total{artifact=\"rules.json\",result=\"failed\"} 2"
            ),
            "{body}"
        );
    }

    #[test]
    fn m060_publish_metrics_label_distinct_artifacts_separately() {
        let m = Metrics::new("h");
        m.record_m060_publish("grants.json", true);
        m.record_m060_publish("audit.json", true);
        m.record_m060_publish("cli.json", true);
        m.record_m060_publish("tui.json", true);
        let body = m.render(0);
        for artifact in ["grants.json", "audit.json", "cli.json", "tui.json"] {
            let line = format!(
                "selfdef_m060_mirror_publish_total{{artifact=\"{artifact}\",result=\"ok\"}} 1"
            );
            assert!(body.contains(&line), "missing {line} in {body}");
        }
    }

    #[test]
    fn m060_publish_metrics_render_with_help_and_type_lines() {
        let m = Metrics::new("h");
        m.record_m060_publish("grants.json", true);
        let body = m.render(0);
        // Prometheus-required HELP + TYPE lines must precede the series.
        assert!(body.contains("# HELP selfdef_m060_mirror_publish_total"));
        assert!(body.contains("# TYPE selfdef_m060_mirror_publish_total counter"));
        assert!(body.contains("# HELP selfdef_m060_mirror_last_publish_unix"));
        assert!(body.contains("# TYPE selfdef_m060_mirror_last_publish_unix gauge"));
    }

    #[test]
    fn m060_publish_metrics_absent_when_nothing_recorded() {
        let m = Metrics::new("h");
        let body = m.render(0);
        // HELP/TYPE lines may appear but no concrete series.
        assert!(
            !body.contains("selfdef_m060_mirror_publish_total{"),
            "should not emit any artifact-labeled series until recorded: {body}"
        );
        assert!(
            !body.contains("selfdef_m060_mirror_last_publish_unix{"),
            "should not emit any last-publish gauge until ok recorded: {body}"
        );
    }
}
