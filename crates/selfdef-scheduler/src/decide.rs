//! `decide` — the top-level scheduling orchestrator (MS048 SDD-031 D2
//! "Decision emitter").
//!
//! The crate doc promised a `Scheduler` orchestrator that "ingests request
//! signals, evaluates objective under active profile + backpressure, emits a
//! [`Decision`], appends to audit chain". Every constituent now exists:
//!
//! - [`crate::backpressure_driver::BackpressureDriver::poll`] → [`DriverReading`]
//! - [`crate::objective_signals::score_current_substrate`] → [`crate::AxisScores`]
//! - [`crate::scheduling_law::recommend_route`] → route + Law clause + rationale
//! - [`Decision::new`] + [`Decision::validate`] → the persisted verdict
//! - [`crate::emit_audit_entry`] → SHA-256-chained append
//!
//! This module composes them into the single entry point the runtime calls
//! per request. [`decide`] is pure (takes a pre-polled [`DriverReading`], no
//! I/O) so it is unit-testable with the Mock substrate trio;
//! [`decide_and_audit`] adds the audit-append side effect.
//!
//! Standing rule: We do not minimize anything.

use std::path::Path;

use crate::backpressure_driver::DriverReading;
use crate::objective_signals::score_current_substrate;
use crate::scheduling_law::recommend_route;
use crate::{
    AxisSignals, Decision, MirrorError, Profile, SchedulerError, emit_audit_entry,
    write_ring_buffer,
};

/// Max rationale length the [`Decision::validate`] invariant allows
/// (R-row bound). The orchestrator truncates the composed rationale at a
/// char boundary so a long composite explanation can never fail validation.
pub const RATIONALE_MAX: usize = 512;

/// All the per-request inputs the orchestrator needs that are NOT derivable
/// from the substrate poll.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Unique request id (UUIDv7 — minted by the caller, sortable by time).
    pub request_id: String,
    /// Active profile in effect for this request.
    pub profile: Profile,
    /// The four model/router-proposed axes (latency/cost/risk/energy); the
    /// two substrate axes are overwritten from the live reading.
    pub model_signals: AxisSignals,
    /// Human-attention queue cap for the human-attention axis ramp.
    pub max_queue: u32,
    /// Decision timestamp (ms since epoch — caller supplies the clock).
    pub ts_ms: u64,
    /// Host the scheduler ran on.
    pub hostname: String,
    /// Policy signer kid (MS003 — which key the daemon's policy signature
    /// uses; verify-only doctrine, the daemon never holds the private key).
    pub signer_kid_policy: String,
}

/// Truncate a rationale to [`RATIONALE_MAX`] on a UTF-8 char boundary.
#[must_use]
fn clamp_rationale(s: String) -> String {
    if s.len() <= RATIONALE_MAX {
        return s;
    }
    let mut end = RATIONALE_MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Compose a validated [`Decision`] from a live [`DriverReading`] and the
/// per-request [`RequestContext`]. Pure — no I/O.
///
/// Pipeline: score the substrate under the profile → recommend a route under
/// the Key Scheduling Law → build the `Decision` (backpressure taken
/// verbatim from the reading's state) → validate.
///
/// # Errors
/// Returns the first [`Decision::validate`] invariant violation (e.g. empty
/// request id / hostname / signer, zero timestamp, out-of-range axis score).
pub fn decide(reading: &DriverReading, ctx: &RequestContext) -> Result<Decision, MirrorError> {
    let scores = score_current_substrate(reading, ctx.model_signals, ctx.profile, ctx.max_queue);
    let rec = recommend_route(reading, ctx.profile, &scores);
    let rationale = clamp_rationale(format!("route={:?} [{:?}]: {}", rec.route, rec.law_clause, rec.rationale));
    let decision = Decision::new(
        ctx.request_id.clone(),
        ctx.profile,
        rec.route,
        scores,
        reading.state,
        ctx.ts_ms,
        ctx.hostname.clone(),
        ctx.signer_kid_policy.clone(),
        rationale,
    );
    decision.validate()?;
    Ok(decision)
}

/// [`decide`] then append the resulting [`Decision`] to the SHA-256-chained
/// audit log at `audit_log`.
///
/// # Errors
/// Returns [`SchedulerError::InvalidDecision`] when the composed decision
/// fails validation, or [`SchedulerError::Io`] / [`SchedulerError::Serde`]
/// when the audit append fails.
pub fn decide_and_audit(
    reading: &DriverReading,
    ctx: &RequestContext,
    audit_log: &Path,
) -> Result<Decision, SchedulerError> {
    let decision =
        decide(reading, ctx).map_err(|e| SchedulerError::InvalidDecision(e.to_string()))?;
    emit_audit_entry(audit_log, &decision)?;
    Ok(decision)
}

/// [`decide`] then persist the [`Decision`] to BOTH the SHA-256-chained
/// audit log (`audit_log`) AND the decision ring buffer (`ring_dir`,
/// bounded to `max_entries`).
///
/// This is the full production persistence path. The audit log is the
/// tamper-evident chain (integrity); the ring buffer is what the operator's
/// `GET /v1/scheduler` / `/history` / `/explain` HTTP surface reads
/// (observability). Without the ring write, the orchestrator's decisions are
/// in the audit chain but invisible to the live HTTP surface — this closes
/// that gap.
///
/// Audit append happens first (the integrity record is authoritative); the
/// ring write follows (observability is best-effort relative to integrity).
///
/// # Errors
/// Returns [`SchedulerError::InvalidDecision`] on validation failure, or
/// [`SchedulerError::Io`] / [`SchedulerError::Serde`] when either persistence
/// step fails.
pub fn decide_and_persist(
    reading: &DriverReading,
    ctx: &RequestContext,
    audit_log: &Path,
    ring_dir: &Path,
    max_entries: usize,
) -> Result<Decision, SchedulerError> {
    let decision =
        decide(reading, ctx).map_err(|e| SchedulerError::InvalidDecision(e.to_string()))?;
    emit_audit_entry(audit_log, &decision)?;
    write_ring_buffer(ring_dir, &decision, max_entries)?;
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Route;
    use crate::ResourceMeasurements;
    use crate::backpressure_driver::SubstrateHealth;
    use crate::objective_signals::DEFAULT_HUMAN_ATTENTION_QUEUE_CAP;
    use selfdef_scheduler_mirror::BackpressureState;

    fn reading(measurements: ResourceMeasurements, state: BackpressureState) -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 0,
            measurements,
            state,
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    fn ctx(profile: Profile) -> RequestContext {
        RequestContext {
            request_id: "req-0190abcd-7e11-7000-8000-000000000001".to_string(),
            profile,
            model_signals: AxisSignals {
                latency: 0.7,
                cost: 0.7,
                risk: 0.7,
                energy: 0.7,
                human_attention: 0.0, // overwritten
                hardware_pressure: 0.0, // overwritten
            },
            max_queue: DEFAULT_HUMAN_ATTENTION_QUEUE_CAP,
            ts_ms: 1_700_000_000_000,
            hostname: "sain-01".to_string(),
            signer_kid_policy: "policy-kid-1".to_string(),
        }
    }

    #[test]
    fn decide_produces_valid_decision_on_calm_production() {
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());
        let d = decide(&r, &ctx(Profile::Production)).expect("valid decision");
        assert_eq!(d.route, Route::Blackwell);
        assert_eq!(d.profile, Profile::Production);
        assert_eq!(d.backpressure, BackpressureState::clean());
        // substrate axes overwrote the 0.0 placeholders
        assert_eq!(d.axis_scores.hardware_pressure, 1.0);
        assert_eq!(d.axis_scores.human_attention, 1.0);
        d.validate().expect("re-validate");
    }

    #[test]
    fn decide_carries_backpressure_state_into_decision() {
        let state = BackpressureState {
            blackwell_vram_high: true,
            ..BackpressureState::clean()
        };
        let r = reading(
            ResourceMeasurements {
                blackwell_vram_util: 0.95,
                ..ResourceMeasurements::clean()
            },
            state,
        );
        let d = decide(&r, &ctx(Profile::Production)).expect("valid");
        assert_eq!(d.backpressure, state);
        // oracle pressured ⇒ falls to scout
        assert_eq!(d.route, Route::Rtx3090);
    }

    #[test]
    fn decide_rejects_empty_request_id() {
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());
        let mut c = ctx(Profile::Fast);
        c.request_id = String::new();
        assert!(decide(&r, &c).is_err());
    }

    #[test]
    fn decide_rejects_zero_timestamp() {
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());
        let mut c = ctx(Profile::Fast);
        c.ts_ms = 0;
        assert!(decide(&r, &c).is_err());
    }

    #[test]
    fn rationale_is_within_bound() {
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());
        let d = decide(&r, &ctx(Profile::Careful)).expect("valid");
        assert!(d.rationale.len() <= RATIONALE_MAX);
        assert!(!d.rationale.is_empty());
    }

    #[test]
    fn clamp_rationale_respects_char_boundary() {
        let long = "é".repeat(400); // 800 bytes, 400 chars
        let clamped = clamp_rationale(long);
        assert!(clamped.len() <= RATIONALE_MAX);
        // did not split a multibyte char (round-trips as valid UTF-8)
        assert!(clamped.chars().all(|c| c == 'é'));
    }

    #[test]
    fn decide_and_audit_appends_a_chained_entry() {
        let dir = std::env::temp_dir().join(format!(
            "selfdef-decide-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("scheduler_audit.log");
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());

        let d1 = decide_and_audit(&r, &ctx(Profile::Production), &log).expect("emit 1");
        let mut c2 = ctx(Profile::Fast);
        c2.request_id = "req-0190abcd-7e11-7000-8000-000000000002".to_string();
        let d2 = decide_and_audit(&r, &c2, &log).expect("emit 2");

        assert_eq!(d1.route, Route::Blackwell);
        assert_eq!(d2.route, Route::Rtx3090);
        // both decisions were appended as separate JSONL lines, each
        // carrying the SHA-256 chain field
        let body = std::fs::read_to_string(&log).expect("read audit log");
        let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);
        for l in &lines {
            assert!(l.contains("prev_event_sha256"), "line missing chain field: {l}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn decide_and_persist_reaches_both_audit_and_ring() {
        use crate::read_ring_buffer;
        let dir = std::env::temp_dir().join(format!(
            "selfdef-persist-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("scheduler_audit.log");
        let ring = dir.join("ring");
        let r = reading(ResourceMeasurements::clean(), BackpressureState::clean());

        let d = decide_and_persist(&r, &ctx(Profile::Production), &log, &ring, 256)
            .expect("persist");
        assert_eq!(d.route, Route::Blackwell);

        // audit log got the chained entry
        let body = std::fs::read_to_string(&log).expect("read audit");
        assert!(body.contains("prev_event_sha256"));

        // ring buffer now surfaces the decision (what the HTTP /v1/scheduler reads)
        let ring_decisions = read_ring_buffer(&ring).expect("read ring");
        assert_eq!(ring_decisions.len(), 1);
        assert_eq!(ring_decisions[0].request_id, d.request_id);
        assert_eq!(ring_decisions[0].route, Route::Blackwell);

        std::fs::remove_dir_all(&dir).ok();
    }
}
