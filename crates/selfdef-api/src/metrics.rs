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
    /// Sum of all event counters — cheaper to read than locking the map.
    events_total: AtomicU64,
    findings_total: AtomicU64,
    /// Number of times the bus reported the ingest subscriber lagged
    /// behind the broadcast. Non-zero means metrics are
    /// under-counting and the operator should resize the bus.
    ingest_lag_events: AtomicU64,
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
            events_total: AtomicU64::new(0),
            findings_total: AtomicU64::new(0),
            ingest_lag_events: AtomicU64::new(0),
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
        }
    }

    /// Count one missed-event lag from the bus broadcast subscriber.
    pub fn record_ingest_lag(&self, n: u64) {
        self.ingest_lag_events.fetch_add(n, Ordering::Relaxed);
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

        out.push_str("# HELP selfdef_ingest_lag_events_total Events missed by the metrics ingest subscriber (bus over-subscribed).\n");
        out.push_str("# TYPE selfdef_ingest_lag_events_total counter\n");
        writeln!(
            out,
            "selfdef_ingest_lag_events_total {}",
            self.ingest_lag_events.load(Ordering::Relaxed),
        )
        .unwrap();

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
}
