//! `selfdef-scheduler::ocsf_emitter` — M01169: OCSF JSONL emission for
//! `BackpressureDriver` output (SIEM / security-event consumer pipeline).
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module `M01169 selfdef-scheduler-ocsf-emitter`
//! per `~/selfdef/backlog/milestones/MS048-goldilocks-scheduler-hardware-
//! aware-resource-routing.md`. Pairs with M01168 (Prometheus exporter):
//! both consume `DriverReading`; M01168 emits gauges to node_exporter
//! textfile collector for Grafana; M01169 emits OCSF events to a JSONL
//! log for the SIEM consumer pipeline.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — peace-machine clause
//! "disciplined enough to explain itself" + Core Law clause
//! "ZFS remembers" (every scheduler observation is durable + auditable
//! in an OCSF stream that lands on the tank/vault/context ZFS dataset).
//!
//! ## What this module provides
//!
//! 1. `render_ocsf_event(&DriverReading) -> String` — produces ONE
//!    OCSF-aligned JSON object per `DriverReading`, terminated with
//!    `\n` so concatenation forms a JSONL stream. Class:
//!    `Detection Finding` (class_uid 2004 in OCSF 1.1).
//!    Severity scales with degraded-substrate count and active
//!    backpressure surfaces.
//! 2. `append_ocsf_jsonl(path, event)` — atomic append using
//!    `OpenOptions::append(true)` + a single `write_all` call (POSIX-
//!    atomic for writes ≤ PIPE_BUF on regular files; the JSON objects
//!    are well under that bound).
//! 3. `OcsfSeverityId` enum — typed wrapper around the OCSF
//!    severity integer enum (Informational/Low/Medium/High).
//!    Determined by `derive_severity_id()` from a `DriverReading`.
//! 4. `DEFAULT_OCSF_PATH` — re-exports the `crate::DEFAULT_OCSF_PATH`
//!    convention used elsewhere in selfdef-scheduler
//!    (`/var/log/selfdef/scheduler.ocsf.jsonl`).
//!
//! ## OCSF event shape (one per poll)
//!
//! ```json
//! {
//!   "time": 1700000000000,
//!   "category_uid": 2,
//!   "class_uid": 2004,
//!   "type_uid": 200401,
//!   "activity_id": 1,
//!   "severity_id": 1,
//!   "metadata": {
//!     "version": "1.1.0",
//!     "product": {"name": "selfdef-scheduler"}
//!   },
//!   "observables": [
//!     {"name": "cpu_psi", "type": "Fraction", "value": 0.2},
//!     {"name": "blackwell_vram_util", "type": "Fraction", "value": 0.85},
//!     {"name": "human_gate_queue_depth", "type": "Counter", "value": 3},
//!     {"name": "substrate_degraded_count", "type": "Counter", "value": 0}
//!   ],
//!   "status_id": 1,
//!   "raw_data": "{...full DriverReading JSON...}"
//! }
//! ```
//!
//! ## Severity derivation
//!
//! - Informational (1) — all substrates healthy, no backpressure
//!   surface firing.
//! - Low (2) — one substrate degraded OR one backpressure surface
//!   firing.
//! - Medium (3) — multiple substrates degraded OR multiple
//!   backpressure surfaces firing.
//! - High (4) — all substrates degraded (scheduler is operating
//!   blind) OR critical backpressure (Blackwell VRAM high + cpu/ram
//!   simultaneously).
//!
//! ## Non-goals
//!
//! - Not a Prometheus exporter (separate M01168, already shipped).
//! - Not a per-event signer. MS003-multisig signing of audit
//!   records lives in M01172 — separate slot.
//! - Not a multi-class emitter. One class per poll keeps the SIEM
//!   ingestion shape stable.
//!
//! Standing rule: We do not minimize anything.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::backpressure_driver::{DriverReading, SourceStatus};
use crate::{Decision, Route};

/// Re-export the crate-level OCSF JSONL log path constant.
pub const DEFAULT_OCSF_PATH: &str = crate::DEFAULT_OCSF_PATH;

/// OCSF Detection Finding class UID per OCSF 1.1 schema.
pub const OCSF_CLASS_DETECTION_FINDING: u32 = 2004;

/// OCSF Findings category UID per OCSF 1.1 schema.
pub const OCSF_CATEGORY_FINDINGS: u32 = 2;

/// OCSF activity_id for Create.
pub const OCSF_ACTIVITY_CREATE: u32 = 1;

/// OCSF status_id for Success (the emit succeeded; the event content
/// may still describe degraded substrate).
pub const OCSF_STATUS_SUCCESS: u32 = 1;

/// Typed OCSF severity enum. Matches OCSF 1.1 severity_id values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OcsfSeverityId {
    /// 1 — Informational.
    Informational,
    /// 2 — Low.
    Low,
    /// 3 — Medium.
    Medium,
    /// 4 — High.
    High,
}

impl OcsfSeverityId {
    /// Numeric OCSF severity_id wire value.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        match self {
            Self::Informational => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
        }
    }
}

/// Derive an OCSF severity_id from a `DriverReading` per the policy
/// documented in the module header.
#[must_use]
pub fn derive_severity_id(reading: &DriverReading) -> OcsfSeverityId {
    let degraded = reading.substrate_health.degraded_count();
    let surfaces = active_backpressure_surfaces(reading);

    // High: all substrates degraded (scheduler blind) OR Blackwell
    // VRAM high in combination with CPU or RAM pressure (critical
    // resource-exhaustion pattern from dump 18193 backpressure table).
    if degraded == 3
        || (reading.state.blackwell_vram_high
            && (reading.state.cpu_pressure || reading.state.ram_pressure))
    {
        return OcsfSeverityId::High;
    }
    // Medium: multiple substrates degraded OR multiple backpressure
    // surfaces firing.
    if degraded >= 2 || surfaces >= 2 {
        return OcsfSeverityId::Medium;
    }
    // Low: any one substrate degraded OR any one backpressure surface
    // firing.
    if degraded == 1 || surfaces == 1 {
        return OcsfSeverityId::Low;
    }
    OcsfSeverityId::Informational
}

fn active_backpressure_surfaces(reading: &DriverReading) -> u32 {
    let s = &reading.state;
    (s.cpu_pressure as u32)
        + (s.ram_pressure as u32)
        + (s.io_pressure as u32)
        + (s.blackwell_vram_high as u32)
        + (s.gpu3090_busy as u32)
        + (s.human_gate_queue_high as u32)
}

/// Render one `DriverReading` into one OCSF-aligned JSON line
/// (terminated by `\n`). Caller appends to the JSONL log.
#[must_use]
pub fn render_ocsf_event(reading: &DriverReading) -> String {
    let now_unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let severity = derive_severity_id(reading);

    // Observables array: every continuous + discrete signal.
    let m = &reading.measurements;
    let s = &reading.state;
    let h = &reading.substrate_health;
    let observables = json!([
        observable("cpu_psi", "Fraction", json!(m.cpu_psi as f64)),
        observable("mem_psi", "Fraction", json!(m.mem_psi as f64)),
        observable("io_psi", "Fraction", json!(m.io_psi as f64)),
        observable(
            "blackwell_vram_util",
            "Fraction",
            json!(m.blackwell_vram_util as f64)
        ),
        observable("gpu3090_util", "Fraction", json!(m.gpu3090_util as f64)),
        observable(
            "human_gate_queue_depth",
            "Counter",
            json!(m.human_gate_queue_depth)
        ),
        observable("cpu_pressure", "Boolean", json!(s.cpu_pressure)),
        observable("ram_pressure", "Boolean", json!(s.ram_pressure)),
        observable("io_pressure", "Boolean", json!(s.io_pressure)),
        observable(
            "blackwell_vram_high",
            "Boolean",
            json!(s.blackwell_vram_high)
        ),
        observable("gpu3090_busy", "Boolean", json!(s.gpu3090_busy)),
        observable(
            "human_gate_queue_high",
            "Boolean",
            json!(s.human_gate_queue_high)
        ),
        observable("psi_healthy", "Boolean", json!(h.psi_status.is_healthy())),
        observable("dcgm_healthy", "Boolean", json!(h.dcgm_status.is_healthy())),
        observable(
            "human_gate_healthy",
            "Boolean",
            json!(h.human_gate_status.is_healthy())
        ),
        observable(
            "substrate_degraded_count",
            "Counter",
            json!(h.degraded_count())
        ),
    ]);

    // Enrichments: per-source status reason text (only emitted when
    // not healthy). Lets the SIEM correlate substrate-degraded events
    // with their reason without re-scraping logs.
    let mut enrichments: Vec<Value> = Vec::new();
    push_status_enrichment(&mut enrichments, "psi", &h.psi_status);
    push_status_enrichment(&mut enrichments, "dcgm", &h.dcgm_status);
    push_status_enrichment(&mut enrichments, "human_gate", &h.human_gate_status);

    let mut event = json!({
        "time": now_unix_millis,
        "category_uid": OCSF_CATEGORY_FINDINGS,
        "class_uid": OCSF_CLASS_DETECTION_FINDING,
        "type_uid": OCSF_CLASS_DETECTION_FINDING * 100 + OCSF_ACTIVITY_CREATE,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "severity_id": severity.as_u32(),
        "status_id": OCSF_STATUS_SUCCESS,
        "metadata": {
            "version": crate::OCSF_SCHEMA_VERSION,
            "product": {
                "name": "selfdef-scheduler",
                "vendor_name": "selfdef",
            }
        },
        "observables": observables,
        "raw_data": serde_json::to_string(reading).unwrap_or_else(|_| "{}".into()),
    });
    if !enrichments.is_empty() {
        event["enrichments"] = json!(enrichments);
    }

    let mut out = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    out.push('\n');
    out
}

fn observable(name: &str, ty: &str, value: Value) -> Value {
    json!({"name": name, "type": ty, "value": value})
}

fn push_status_enrichment(out: &mut Vec<Value>, source: &str, status: &SourceStatus) {
    let (kind, reason) = match status {
        SourceStatus::Healthy => return,
        SourceStatus::Unavailable(r) => ("unavailable", r.as_str()),
        SourceStatus::Errored(r) => ("errored", r.as_str()),
    };
    out.push(json!({
        "name": format!("{source}_status"),
        "data": {"kind": kind, "reason": reason}
    }));
}

/// Append `event_line` (which must already end in `\n`) to the JSONL
/// log at `path`. Creates parent directories + file if absent.
///
/// # Errors
///
/// Returns `std::io::Error` on open / write failure.
pub fn append_ocsf_jsonl(path: &Path, event_line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(event_line.as_bytes())?;
    // Durability, not just a userspace flush: `File::flush` is a no-op (a File
    // has no userspace buffer), so the previous `flush()` left this stream
    // crash-non-durable despite the module's "ZFS remembers / durable +
    // auditable" contract. fdatasync the appended bytes so a Detection-Finding
    // emitted just before a crash survives for the SIEM, matching the
    // append-log durability the sibling sinks use (history-sink,
    // shared-audit-summary) and the chained audit emitter (emit_audit_entry).
    file.sync_data()?;
    Ok(())
}

// ============================================================================
// Decision OCSF emission (parallels render_ocsf_event for routing decisions)
// ============================================================================

/// Derive an OCSF severity_id for a scheduling [`Decision`].
///
/// Mirrors [`derive_severity_id`]'s surface-count scaling, keyed on the
/// routing outcome:
/// - **High** — route is [`Route::Hibernate`]: the scheduler deferred /
///   refused to route, either the Key Scheduling Law's clause-2 safety stop
///   ("never let cheap speculation commit without expensive verification when
///   risk demands it") or every compute tier under backpressure. The most
///   operationally-significant outcome.
/// - **Medium** — two or more backpressure surfaces firing, OR route fell
///   back to [`Route::Cpu`] (deterministic cortex) from a GPU tier.
/// - **Low** — exactly one backpressure surface firing.
/// - **Informational** — routed to a compute tier with no backpressure.
#[must_use]
pub fn derive_decision_severity_id(decision: &Decision) -> OcsfSeverityId {
    let surfaces = u32::from(decision.backpressure.pressure_count());
    if matches!(decision.route, Route::Hibernate) {
        return OcsfSeverityId::High;
    }
    if surfaces >= 2 || matches!(decision.route, Route::Cpu) {
        return OcsfSeverityId::Medium;
    }
    if surfaces == 1 {
        return OcsfSeverityId::Low;
    }
    OcsfSeverityId::Informational
}

/// Render one scheduling [`Decision`] into one OCSF Detection Finding JSON
/// line (terminated by `\n`).
///
/// Parallel to [`render_ocsf_event`] (which covers substrate polls); this
/// covers routing decisions so the SIEM sees BOTH what the scheduler observed
/// AND what it decided. `metadata.event_kind = "scheduler_decision"`
/// distinguishes these from the `"scheduler_observation"` poll events at
/// ingestion. The decision rationale (route + Law clause) rides in `message`;
/// `finding_info.uid` is the `request_id` so a decision finding correlates
/// with its `/v1/scheduler/explain/:request-id` detail.
#[must_use]
pub fn render_decision_ocsf(decision: &Decision) -> String {
    let now_unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let severity = derive_decision_severity_id(decision);
    let a = decision.axis_scores;
    let b = decision.backpressure;
    let observables = json!([
        observable(
            "profile",
            "String",
            json!(format!("{:?}", decision.profile))
        ),
        observable("route", "String", json!(format!("{:?}", decision.route))),
        observable("compound", "Fraction", json!(a.compound as f64)),
        observable("latency", "Fraction", json!(a.latency as f64)),
        observable("cost", "Fraction", json!(a.cost as f64)),
        observable("risk", "Fraction", json!(a.risk as f64)),
        observable("energy", "Fraction", json!(a.energy as f64)),
        observable(
            "human_attention",
            "Fraction",
            json!(a.human_attention as f64)
        ),
        observable(
            "hardware_pressure",
            "Fraction",
            json!(a.hardware_pressure as f64)
        ),
        observable("backpressure_count", "Counter", json!(b.pressure_count())),
    ]);

    let event = json!({
        "time": now_unix_millis,
        "category_uid": OCSF_CATEGORY_FINDINGS,
        "class_uid": OCSF_CLASS_DETECTION_FINDING,
        "type_uid": OCSF_CLASS_DETECTION_FINDING * 100 + OCSF_ACTIVITY_CREATE,
        "activity_id": OCSF_ACTIVITY_CREATE,
        "severity_id": severity.as_u32(),
        "status_id": OCSF_STATUS_SUCCESS,
        "message": decision.rationale,
        "metadata": {
            "version": crate::OCSF_SCHEMA_VERSION,
            "product": {
                "name": "selfdef-scheduler",
                "vendor_name": "selfdef",
            },
            "event_kind": "scheduler_decision",
        },
        "finding_info": {
            "uid": decision.request_id,
            "title": format!(
                "scheduler routed {:?} under {:?}",
                decision.route, decision.profile
            ),
        },
        "observables": observables,
        "raw_data": serde_json::to_string(decision).unwrap_or_else(|_| "{}".into()),
    });

    let mut out = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    out.push('\n');
    out
}

/// Convenience: render a [`Decision`] OCSF finding and append it to the
/// JSONL log at `path` in one call (composes [`render_decision_ocsf`] +
/// [`append_ocsf_jsonl`]).
///
/// # Errors
/// Returns `std::io::Error` on open / write failure.
pub fn emit_decision_ocsf(path: &Path, decision: &Decision) -> std::io::Result<()> {
    append_ocsf_jsonl(path, &render_decision_ocsf(decision))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backpressure_driver::SubstrateHealth;
    use crate::{BackpressureState, ResourceMeasurements};
    use tempfile::tempdir;

    fn baseline_reading() -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 1_700_000_000_000_000,
            measurements: ResourceMeasurements {
                blackwell_vram_util: 0.30,
                gpu3090_util: 0.20,
                cpu_psi: 0.10,
                mem_psi: 0.05,
                io_psi: 0.02,
                human_gate_queue_depth: 1,
            },
            state: BackpressureState {
                blackwell_vram_high: false,
                gpu3090_busy: false,
                cpu_pressure: false,
                ram_pressure: false,
                io_pressure: false,
                human_gate_queue_high: false,
            },
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    fn parse_event_line(line: &str) -> Value {
        let trimmed = line.trim_end_matches('\n');
        serde_json::from_str(trimmed).expect("event line must be valid JSON")
    }

    // ---------------- OcsfSeverityId ----------------------------------

    #[test]
    fn severity_wire_values_match_ocsf_spec() {
        assert_eq!(OcsfSeverityId::Informational.as_u32(), 1);
        assert_eq!(OcsfSeverityId::Low.as_u32(), 2);
        assert_eq!(OcsfSeverityId::Medium.as_u32(), 3);
        assert_eq!(OcsfSeverityId::High.as_u32(), 4);
    }

    // ---------------- derive_severity_id --------------------------------

    #[test]
    fn baseline_clean_is_informational() {
        assert_eq!(
            derive_severity_id(&baseline_reading()),
            OcsfSeverityId::Informational
        );
    }

    #[test]
    fn one_degraded_substrate_is_low() {
        let mut r = baseline_reading();
        r.substrate_health.psi_status = SourceStatus::Unavailable("x".into());
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::Low);
    }

    #[test]
    fn one_backpressure_surface_firing_is_low() {
        let mut r = baseline_reading();
        r.state.cpu_pressure = true;
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::Low);
    }

    #[test]
    fn two_degraded_substrates_is_medium() {
        let mut r = baseline_reading();
        r.substrate_health.psi_status = SourceStatus::Unavailable("a".into());
        r.substrate_health.dcgm_status = SourceStatus::Errored("b".into());
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::Medium);
    }

    #[test]
    fn two_backpressure_surfaces_firing_is_medium() {
        let mut r = baseline_reading();
        r.state.cpu_pressure = true;
        r.state.io_pressure = true;
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::Medium);
    }

    #[test]
    fn all_three_substrates_degraded_is_high() {
        let mut r = baseline_reading();
        r.substrate_health.psi_status = SourceStatus::Unavailable("a".into());
        r.substrate_health.dcgm_status = SourceStatus::Errored("b".into());
        r.substrate_health.human_gate_status = SourceStatus::Unavailable("c".into());
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::High);
    }

    #[test]
    fn blackwell_vram_plus_cpu_pressure_is_high() {
        let mut r = baseline_reading();
        r.state.blackwell_vram_high = true;
        r.state.cpu_pressure = true;
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::High);
    }

    #[test]
    fn blackwell_vram_plus_ram_pressure_is_high() {
        let mut r = baseline_reading();
        r.state.blackwell_vram_high = true;
        r.state.ram_pressure = true;
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::High);
    }

    #[test]
    fn blackwell_vram_alone_is_low() {
        let mut r = baseline_reading();
        r.state.blackwell_vram_high = true;
        assert_eq!(derive_severity_id(&r), OcsfSeverityId::Low);
    }

    // ---------------- render_ocsf_event content ------------------------

    #[test]
    fn renders_single_line_terminated_by_newline() {
        let line = render_ocsf_event(&baseline_reading());
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
    }

    #[test]
    fn renders_ocsf_class_and_category_uids() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        assert_eq!(v["class_uid"], 2004);
        assert_eq!(v["category_uid"], 2);
        assert_eq!(v["activity_id"], 1);
        assert_eq!(v["type_uid"], 200401);
    }

    #[test]
    fn renders_metadata_product() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        assert_eq!(v["metadata"]["product"]["name"], "selfdef-scheduler");
        assert_eq!(v["metadata"]["version"], crate::OCSF_SCHEMA_VERSION);
    }

    #[test]
    fn renders_all_observables_with_types() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        let obs = v["observables"].as_array().unwrap();
        // 6 measurements + 6 backpressure-state booleans + 3 source-
        // healthy booleans + 1 degraded-count = 16 observables.
        assert_eq!(obs.len(), 16);
        let names: Vec<&str> = obs.iter().map(|o| o["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"cpu_psi"));
        assert!(names.contains(&"blackwell_vram_util"));
        assert!(names.contains(&"human_gate_queue_depth"));
        assert!(names.contains(&"cpu_pressure"));
        assert!(names.contains(&"psi_healthy"));
        assert!(names.contains(&"substrate_degraded_count"));
    }

    #[test]
    fn renders_observable_values_match_input() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        let obs = v["observables"].as_array().unwrap();
        let cpu = obs.iter().find(|o| o["name"] == "cpu_psi").unwrap();
        // f32 → f64 widening introduces sub-ε artifacts; tolerate them.
        assert!((cpu["value"].as_f64().unwrap() - 0.10).abs() < 1e-6);
        let queue = obs
            .iter()
            .find(|o| o["name"] == "human_gate_queue_depth")
            .unwrap();
        assert_eq!(queue["value"].as_u64().unwrap(), 1);
    }

    #[test]
    fn healthy_substrates_yield_no_enrichments() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        // When all healthy, the enrichments key is absent.
        assert!(v.get("enrichments").is_none());
    }

    #[test]
    fn degraded_substrate_appears_in_enrichments_with_reason() {
        let mut r = baseline_reading();
        r.substrate_health.psi_status = SourceStatus::Unavailable("kernel < 4.20".to_string());
        r.substrate_health.dcgm_status = SourceStatus::Errored("driver crash".to_string());
        let v = parse_event_line(&render_ocsf_event(&r));
        let enr = v["enrichments"].as_array().unwrap();
        assert_eq!(enr.len(), 2);
        let psi = enr.iter().find(|e| e["name"] == "psi_status").unwrap();
        assert_eq!(psi["data"]["kind"], "unavailable");
        assert_eq!(psi["data"]["reason"], "kernel < 4.20");
        let dcgm = enr.iter().find(|e| e["name"] == "dcgm_status").unwrap();
        assert_eq!(dcgm["data"]["kind"], "errored");
        assert_eq!(dcgm["data"]["reason"], "driver crash");
    }

    #[test]
    fn raw_data_contains_serialized_reading() {
        let v = parse_event_line(&render_ocsf_event(&baseline_reading()));
        let raw = v["raw_data"].as_str().unwrap();
        // raw_data is a JSON string containing the DriverReading
        // (serialized once, then embedded as a string so SIEM tooling
        // can re-parse on demand without polluting the top-level shape).
        let inner: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(inner["measurements"]["cpu_psi"].as_f64().unwrap(), 0.10);
    }

    #[test]
    fn severity_high_when_blackwell_plus_cpu() {
        let mut r = baseline_reading();
        r.state.blackwell_vram_high = true;
        r.state.cpu_pressure = true;
        let v = parse_event_line(&render_ocsf_event(&r));
        assert_eq!(v["severity_id"], 4);
    }

    // ---------------- append_ocsf_jsonl --------------------------------

    #[test]
    fn append_creates_file_with_single_line() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("scheduler.ocsf.jsonl");
        let line = render_ocsf_event(&baseline_reading());
        append_ocsf_jsonl(&path, &line).unwrap();
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read_back, line);
    }

    #[test]
    fn append_concatenates_multiple_events() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("scheduler.ocsf.jsonl");
        let l1 = render_ocsf_event(&baseline_reading());
        let mut r2 = baseline_reading();
        r2.state.cpu_pressure = true;
        let l2 = render_ocsf_event(&r2);
        append_ocsf_jsonl(&path, &l1).unwrap();
        append_ocsf_jsonl(&path, &l2).unwrap();
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert!(read_back.starts_with(&l1));
        assert!(read_back.ends_with(&l2));
        assert_eq!(read_back.matches('\n').count(), 2);
    }

    #[test]
    fn append_creates_parent_dir() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nested/dir/scheduler.ocsf.jsonl");
        append_ocsf_jsonl(&path, "{}\n").unwrap();
        assert!(path.exists());
    }

    // ---------------- Constants ----------------------------------------

    #[test]
    fn ocsf_constants_match_spec() {
        assert_eq!(OCSF_CLASS_DETECTION_FINDING, 2004);
        assert_eq!(OCSF_CATEGORY_FINDINGS, 2);
        assert_eq!(OCSF_ACTIVITY_CREATE, 1);
        assert_eq!(OCSF_STATUS_SUCCESS, 1);
    }

    // ---------------- Decision OCSF emission ---------------------------

    fn decision_with(route: Route, backpressure: BackpressureState) -> Decision {
        use crate::{AxisSignals, Profile, evaluate_objective};
        let scores = evaluate_objective(
            AxisSignals {
                latency: 0.9,
                cost: 0.8,
                risk: 0.7,
                energy: 0.6,
                human_attention: 0.5,
                hardware_pressure: 0.4,
            },
            Profile::Production,
        );
        Decision::new(
            "req-0190abcd-7e11-7000-8000-deadbeef0001",
            Profile::Production,
            route,
            scores,
            backpressure,
            1_700_000_000_000,
            "sain-01",
            "policy-kid-1",
            "route=Hibernate [SpeculationRequiresVerification]: risk demands verification",
        )
    }

    #[test]
    fn decision_severity_hibernate_is_high() {
        let d = decision_with(Route::Hibernate, BackpressureState::clean());
        assert_eq!(derive_decision_severity_id(&d), OcsfSeverityId::High);
    }

    #[test]
    fn decision_severity_cpu_fallback_is_medium() {
        let d = decision_with(Route::Cpu, BackpressureState::clean());
        assert_eq!(derive_decision_severity_id(&d), OcsfSeverityId::Medium);
    }

    #[test]
    fn decision_severity_two_surfaces_is_medium() {
        let bp = BackpressureState {
            blackwell_vram_high: true,
            gpu3090_busy: true,
            ..BackpressureState::clean()
        };
        let d = decision_with(Route::Rtx3090, bp);
        assert_eq!(derive_decision_severity_id(&d), OcsfSeverityId::Medium);
    }

    #[test]
    fn decision_severity_one_surface_is_low() {
        let bp = BackpressureState {
            io_pressure: true,
            ..BackpressureState::clean()
        };
        let d = decision_with(Route::Blackwell, bp);
        assert_eq!(derive_decision_severity_id(&d), OcsfSeverityId::Low);
    }

    #[test]
    fn decision_severity_clean_blackwell_is_informational() {
        let d = decision_with(Route::Blackwell, BackpressureState::clean());
        assert_eq!(
            derive_decision_severity_id(&d),
            OcsfSeverityId::Informational
        );
    }

    #[test]
    fn render_decision_ocsf_is_valid_jsonl_with_event_kind() {
        let d = decision_with(Route::Hibernate, BackpressureState::clean());
        let line = render_decision_ocsf(&d);
        assert!(line.ends_with('\n'));
        let v: Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        assert_eq!(v["class_uid"], 2004);
        assert_eq!(v["severity_id"], 4); // Hibernate => High
        assert_eq!(v["metadata"]["event_kind"], "scheduler_decision");
        assert_eq!(
            v["finding_info"]["uid"],
            "req-0190abcd-7e11-7000-8000-deadbeef0001"
        );
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("risk demands verification")
        );
        // route + profile surfaced as observables
        let obs = v["observables"].as_array().unwrap();
        assert!(obs.iter().any(|o| o["name"] == "route"));
        assert!(obs.iter().any(|o| o["name"] == "compound"));
    }
}
