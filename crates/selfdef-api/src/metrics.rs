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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
    /// Configured responder autonomous-response severity floor as its OCSF
    /// `severity_id` repr (F-2026-092): 0 = no floor (every finding processed),
    /// else the minimum grade a finding must reach to be auto-dispatched on the
    /// bus path. Set once at startup. Combined with
    /// `selfdef_findings_by_severity_total`, an operator can chart exactly how
    /// many findings the floor is suppressing — a too-high floor silently
    /// swallowing real detections becomes visible rather than invisible.
    responder_min_severity_floor: AtomicU64,
    /// Live cumulative bus-lag counters for the two consequential consumers,
    /// shared (`Arc`) with the consumers themselves so the gauge reads their
    /// real count with no copy. The broadcast bus gives each subscriber its own
    /// ring buffer, so the responder and correlator lag independently of the
    /// metrics ingest task (`ingest_lag_events`). A lagging *responder* dropped
    /// findings before any action fired; a lagging *correlator* dropped raw
    /// events before any rule saw them — both far more consequential than the
    /// metrics task under-counting. Unset until the daemon wires them.
    responder_lag: OnceLock<Arc<AtomicU64>>,
    correlator_lag: OnceLock<Arc<AtomicU64>>,
    /// Cumulative destructive actions suppressed by the responder's dedup /
    /// rate-cap circuit-breakers. Shares the responder's `Arc<AtomicU64>`; unset
    /// (no series emitted) until the daemon wires it.
    responder_suppressed: OnceLock<Arc<AtomicU64>>,
    /// Rate-cap circuit-breaker trips ONLY (not routine dedup). Shares the
    /// responder's `Arc<AtomicU64>`; unset until the daemon wires it. This is
    /// the series the circuit-breaker alert keys on, so a benign duplicate
    /// suppression doesn't raise it.
    responder_ratecap_tripped: OnceLock<Arc<AtomicU64>>,

    /// Destructive actions refused because their finding was federated-origin and
    /// `[responder].act_on_federated` is off (F-2026-111 fail-closed). Shares the
    /// responder's `Arc<AtomicU64>`; unset until wired. Distinct from the
    /// circuit-breaker counters — a trust-boundary refusal, not a flood.
    responder_federated_refused: OnceLock<Arc<AtomicU64>>,

    /// Cumulative inbound federated events (from OTHER hosts via the NATS
    /// bridge) republished onto the local bus — i.e. events that entered the
    /// local correlator→responder path from across the trust boundary. Shares
    /// the bridge's `Arc<AtomicU64>`; unset until the daemon wires it. Surfaces
    /// the otherwise-invisible cross-host ingress (see F-2026-111).
    nats_federated_inbound: OnceLock<Arc<AtomicU64>>,

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
            responder_min_severity_floor: AtomicU64::new(0),
            responder_lag: OnceLock::new(),
            correlator_lag: OnceLock::new(),
            responder_suppressed: OnceLock::new(),
            responder_ratecap_tripped: OnceLock::new(),
            responder_federated_refused: OnceLock::new(),
            nats_federated_inbound: OnceLock::new(),
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

    /// Set the configured responder autonomous-response severity floor as its
    /// OCSF `severity_id` repr (F-2026-092). `0` means no floor. Called once at
    /// daemon startup after the floor is parsed from `responder.min_severity`.
    pub fn set_responder_min_severity_floor(&self, floor_repr: u32) {
        self.responder_min_severity_floor
            .store(u64::from(floor_repr), Ordering::Relaxed);
    }

    /// Wire the live bus-lag counters shared with the responder and correlator.
    /// Take an `Arc<AtomicU64>` each; the same `Arc` is handed to
    /// `Responder::with_lag_counter` / `Correlator::with_lag_counter` so the
    /// rendered counters read the consumers' real lag with no copy. Call once at
    /// daemon startup. When unset, the two `*_lag_events_total` series are not
    /// emitted (so a deployment without the wiring shows no misleading zeros).
    /// Idempotent: only the first call per source takes effect (`OnceLock`).
    pub fn set_lag_sources(&self, responder: Arc<AtomicU64>, correlator: Arc<AtomicU64>) {
        let _ = self.responder_lag.set(responder);
        let _ = self.correlator_lag.set(correlator);
    }

    /// Wire the destructive-action suppression counter shared with the responder
    /// (the same `Arc` handed to `Responder::with_suppressed_counter`). Call once
    /// at daemon startup; when unset the `*_suppressed_destructive_total` series
    /// is not emitted. Idempotent (`OnceLock`).
    pub fn set_responder_suppressed_source(&self, suppressed: Arc<AtomicU64>) {
        let _ = self.responder_suppressed.set(suppressed);
    }

    /// Wire the rate-cap circuit-breaker trip counter shared with the responder
    /// (the same `Arc` handed to `Responder::with_ratecap_counter`). Distinct
    /// from `set_responder_suppressed_source`: this series counts ONLY genuine
    /// rate-cap trips, so the circuit-breaker alert doesn't fire on routine
    /// dedup. Call once at startup; idempotent (`OnceLock`).
    pub fn set_responder_ratecap_tripped_source(&self, tripped: Arc<AtomicU64>) {
        let _ = self.responder_ratecap_tripped.set(tripped);
    }

    /// Wire the inbound-federated-event counter shared with the NATS bridge (the
    /// same `Arc` handed to `run_bridge`). Exposes `selfdef_nats_inbound_federated_events_total`
    /// — the cross-host ingress volume into the local response path. Call once at
    /// startup; when unset the series is not emitted. Idempotent (`OnceLock`).
    pub fn set_nats_federated_inbound_source(&self, federated: Arc<AtomicU64>) {
        let _ = self.nats_federated_inbound.set(federated);
    }

    /// Wire the federation-refusal counter shared with the responder (the same
    /// `Arc` handed to `Responder::with_federated_refused_counter`). Exposes
    /// `selfdef_responder_federated_refused_total` — destructive actions refused
    /// by the fail-closed federation trust boundary. Call once at startup;
    /// idempotent (`OnceLock`).
    pub fn set_responder_federated_refused_source(&self, refused: Arc<AtomicU64>) {
        let _ = self.responder_federated_refused.set(refused);
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

        out.push_str(
            "# HELP selfdef_responder_min_severity_floor Responder autonomous-response severity floor as OCSF severity_id (0 = no floor); findings below it are not auto-dispatched (F-2026-092).\n",
        );
        out.push_str("# TYPE selfdef_responder_min_severity_floor gauge\n");
        writeln!(
            out,
            "selfdef_responder_min_severity_floor {}",
            self.responder_min_severity_floor.load(Ordering::Relaxed),
        )
        .unwrap();

        // Consequential-consumer bus lag. Emitted only when the daemon wired the
        // shared counters; each reads the consumer's live count. A non-zero
        // responder series means findings were dropped before any action fired;
        // a non-zero correlator series means raw events were dropped before any
        // rule saw them. Distinct from `selfdef_ingest_lag_events_total` (the
        // metrics task), which only under-counts stats.
        if let Some(c) = self.responder_lag.get() {
            out.push_str(
                "# HELP selfdef_responder_lag_events_total Findings dropped because the responder lagged the bus (no action fired).\n",
            );
            out.push_str("# TYPE selfdef_responder_lag_events_total counter\n");
            writeln!(
                out,
                "selfdef_responder_lag_events_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(c) = self.responder_suppressed.get() {
            out.push_str(
                "# HELP selfdef_responder_suppressed_destructive_total Destructive actions suppressed by the responder dedup / rate-cap circuit-breakers.\n",
            );
            out.push_str("# TYPE selfdef_responder_suppressed_destructive_total counter\n");
            writeln!(
                out,
                "selfdef_responder_suppressed_destructive_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(c) = self.responder_ratecap_tripped.get() {
            out.push_str(
                "# HELP selfdef_responder_ratecap_tripped_total Times the responder's destructive-action rate-cap circuit-breaker tripped (global flood breaker; excludes routine per-target dedup).\n",
            );
            out.push_str("# TYPE selfdef_responder_ratecap_tripped_total counter\n");
            writeln!(
                out,
                "selfdef_responder_ratecap_tripped_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(c) = self.responder_federated_refused.get() {
            out.push_str(
                "# HELP selfdef_responder_federated_refused_total Destructive actions refused because the finding was federated-origin and [responder].act_on_federated is off (fail-closed trust boundary).\n",
            );
            out.push_str("# TYPE selfdef_responder_federated_refused_total counter\n");
            writeln!(
                out,
                "selfdef_responder_federated_refused_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(c) = self.nats_federated_inbound.get() {
            out.push_str(
                "# HELP selfdef_nats_inbound_federated_events_total Inbound events from other hosts (via the NATS bridge) republished onto the local bus — cross-host ingress into the correlator/responder path.\n",
            );
            out.push_str("# TYPE selfdef_nats_inbound_federated_events_total counter\n");
            writeln!(
                out,
                "selfdef_nats_inbound_federated_events_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(c) = self.correlator_lag.get() {
            out.push_str(
                "# HELP selfdef_correlator_lag_events_total Raw events dropped because the correlator lagged the bus (missed detections).\n",
            );
            out.push_str("# TYPE selfdef_correlator_lag_events_total counter\n");
            writeln!(
                out,
                "selfdef_correlator_lag_events_total {}",
                c.load(Ordering::Relaxed)
            )
            .unwrap();
        }

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
    fn retention_metrics_render_sweeps_pruned_and_enabled() {
        // SDD-081 retention metrics back the cockpit + selfdef-local
        // "retention liveness" panels; a render regression that dropped any
        // of the three would silently flat-line those panels. Lock all
        // three TYPE lines + their values here so the exposition can't drift.
        let m = Metrics::new("h");
        m.set_retention_enabled(true);
        m.record_retention_sweep(3); // sweep #1 pruned 3
        m.record_retention_sweep(0); // sweep #2 pruned 0 (nothing aged out)
        let body = m.render(0);
        for required in [
            "# TYPE selfdef_store_retention_sweeps_total counter",
            "# TYPE selfdef_store_retention_pruned_total counter",
            "# TYPE selfdef_store_retention_enabled gauge",
        ] {
            assert!(body.contains(required), "missing `{required}`:\n{body}");
        }
        // Two sweeps ran; cumulative pruned is 3; retention is enabled.
        assert!(
            body.contains("selfdef_store_retention_sweeps_total 2"),
            "{body}"
        );
        assert!(
            body.contains("selfdef_store_retention_pruned_total 3"),
            "{body}"
        );
        assert!(body.contains("selfdef_store_retention_enabled 1"), "{body}");
    }

    #[test]
    fn responder_min_severity_floor_renders_default_zero_and_set_value() {
        // F-2026-092: the floor gauge defaults to 0 (no floor) and reflects the
        // configured grade once set. Locks the TYPE line + both values so the
        // suppression-observability series can't silently drop.
        let m = Metrics::new("h");
        let default_body = m.render(0);
        assert!(
            default_body.contains("# TYPE selfdef_responder_min_severity_floor gauge"),
            "{default_body}"
        );
        assert!(
            default_body.contains("selfdef_responder_min_severity_floor 0"),
            "default floor is 0 (none):\n{default_body}"
        );
        // SeverityId::High has OCSF severity_id repr 4.
        m.set_responder_min_severity_floor(4);
        let set_body = m.render(0);
        assert!(
            set_body.contains("selfdef_responder_min_severity_floor 4"),
            "floor set to High(4):\n{set_body}"
        );
    }

    #[test]
    fn consumer_lag_series_appear_only_when_wired_and_read_live() {
        // F-2026-094: the responder/correlator lag counters are NOT emitted
        // until the daemon wires the shared Arcs (so an un-wired deployment
        // shows no misleading zeros), and once wired they read the Arc live.
        let m = Metrics::new("h");
        let unwired = m.render(0);
        assert!(
            !unwired.contains("selfdef_responder_lag_events_total"),
            "lag series must be absent until wired:\n{unwired}"
        );
        assert!(
            !unwired.contains("selfdef_correlator_lag_events_total"),
            "{unwired}"
        );

        let responder_lag = Arc::new(AtomicU64::new(0));
        let correlator_lag = Arc::new(AtomicU64::new(0));
        m.set_lag_sources(Arc::clone(&responder_lag), Arc::clone(&correlator_lag));

        // Live: bumping the shared Arc is reflected in the next render.
        responder_lag.fetch_add(7, Ordering::Relaxed);
        correlator_lag.fetch_add(2, Ordering::Relaxed);
        let wired = m.render(0);
        assert!(
            wired.contains("# TYPE selfdef_responder_lag_events_total counter"),
            "{wired}"
        );
        assert!(
            wired.contains("selfdef_responder_lag_events_total 7"),
            "{wired}"
        );
        assert!(
            wired.contains("selfdef_correlator_lag_events_total 2"),
            "{wired}"
        );
    }

    #[test]
    fn ratecap_tripped_series_is_distinct_from_the_aggregate_suppressed_total() {
        // F-2026-114: the circuit-breaker alert keys on the rate-cap-trip series,
        // which must be a SEPARATE counter from the aggregate suppressed total
        // (the latter also counts routine dedup). Both are absent until wired and
        // read their shared Arc live.
        let m = Metrics::new("h");
        let unwired = m.render(0);
        assert!(
            !unwired.contains("selfdef_responder_ratecap_tripped_total"),
            "rate-cap series must be absent until wired:\n{unwired}"
        );

        let suppressed = Arc::new(AtomicU64::new(0));
        let ratecap = Arc::new(AtomicU64::new(0));
        m.set_responder_suppressed_source(Arc::clone(&suppressed));
        m.set_responder_ratecap_tripped_source(Arc::clone(&ratecap));

        // Model a run with 3 dedup suppressions + 1 rate-cap trip: the aggregate
        // counts all 4; the rate-cap series counts only the genuine breaker trip.
        suppressed.fetch_add(4, Ordering::Relaxed);
        ratecap.fetch_add(1, Ordering::Relaxed);
        let wired = m.render(0);
        assert!(
            wired.contains("# TYPE selfdef_responder_ratecap_tripped_total counter"),
            "{wired}"
        );
        assert!(
            wired.contains("selfdef_responder_ratecap_tripped_total 1"),
            "rate-cap series must read its Arc live:\n{wired}"
        );
        assert!(
            wired.contains("selfdef_responder_suppressed_destructive_total 4"),
            "aggregate total stays separate (includes dedup):\n{wired}"
        );
    }

    #[test]
    fn federated_refused_series_appears_only_when_wired_and_reads_live() {
        // F-2026-111 fail-closed observability: refusals of federated-origin
        // destructive actions are absent until wired, then read the Arc live.
        let m = Metrics::new("h");
        assert!(
            !m.render(0).contains("selfdef_responder_federated_refused_total"),
            "refusal series must be absent until wired"
        );
        let refused = Arc::new(AtomicU64::new(0));
        m.set_responder_federated_refused_source(Arc::clone(&refused));
        refused.fetch_add(3, Ordering::Relaxed);
        let wired = m.render(0);
        assert!(
            wired.contains("# TYPE selfdef_responder_federated_refused_total counter"),
            "{wired}"
        );
        assert!(
            wired.contains("selfdef_responder_federated_refused_total 3"),
            "{wired}"
        );
    }

    #[test]
    fn nats_federated_inbound_series_appears_only_when_wired_and_reads_live() {
        // Cross-host ingress (F-2026-111 observability) is absent until the
        // daemon wires the NATS bridge counter, then reads the shared Arc live.
        let m = Metrics::new("h");
        assert!(
            !m.render(0).contains("selfdef_nats_inbound_federated_events_total"),
            "federated-ingress series must be absent until wired"
        );

        let federated = Arc::new(AtomicU64::new(0));
        m.set_nats_federated_inbound_source(Arc::clone(&federated));
        federated.fetch_add(5, Ordering::Relaxed);
        let wired = m.render(0);
        assert!(
            wired.contains("# TYPE selfdef_nats_inbound_federated_events_total counter"),
            "{wired}"
        );
        assert!(
            wired.contains("selfdef_nats_inbound_federated_events_total 5"),
            "{wired}"
        );
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
