//! `selfdef-scheduler-mirror` — MS007 typed-mirror crate exposing the
//! selfdef Goldilocks Scheduler (avx-plus-plus dump tail lines
//! 18000-18250) Decision state READ-ONLY for:
//!   - sovereign-os cockpit `sovereign-cockpit-scheduler-panel`
//!   - selfdef MS043 R10180 TUI authority-panel row
//!   - selfdef MS027 observability stream (read-only consumer)
//!
//! Implements MS048 catalog rows R11462-R11465 (typed mirror discipline).
//!
//! Per MS007 cross-repo binding doctrine, mirrors expose state read-only;
//! mutations proxy via MS003-signed operator request only.
//!
//! Cross-references:
//! - SDD-031 goldilocks-scheduler specification
//! - MS048 milestone catalog (backlog/milestones/MS048-*.md)
//! - Sister mirrors (three-watchdog trio): selfdef-friction-audit-mirror,
//!   selfdef-perimeter-mirror, selfdef-guardian-mirror — same pattern
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse to
/// deserialize Decisions whose `schema_version` does not match what
/// they were built against.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// The six profiles per MS040 + dump lines 18004-18040.
/// The scheduler honors profile-specific rule sets when deciding routing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// favor latency / scout-first / shallow verification (dump 18011-18014)
    Fast,
    /// favor correctness / oracle verification / tests required (dump 18016-18019)
    Careful,
    /// local-only / cloud routes disabled / strict memory exposure (dump 18021-18024)
    Private,
    /// preserve continuity / batch approvals / sandbox-first / checkpoint often (dump 18026-18030)
    Autonomous,
    /// wide branch search / sandbox only / no host commit (dump 18032-18035)
    Experimental,
    /// strict commit gates / low variance / strong observability (dump 18037-18040)
    Production,
}

impl Profile {
    /// Iterate all profiles in dump-listed order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Fast,
            Self::Careful,
            Self::Private,
            Self::Autonomous,
            Self::Experimental,
            Self::Production,
        ]
    }

    /// Stable display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Careful => "careful",
            Self::Private => "private",
            Self::Autonomous => "autonomous",
            Self::Experimental => "experimental",
            Self::Production => "production",
        }
    }
}

/// Where the scheduler routed the request.
///
/// Maps to the hardware tier table in dump 18260-18272:
/// - `Blackwell` = RTX PRO 6000 Blackwell (oracle, large resident models)
/// - `Rtx3090` = RTX 3090 (scout, SLMs, drafts, embeddings)
/// - `Cpu` = Ryzen 9900X AVX-512 (deterministic cortex; policy/routing/masks)
/// - `Hybrid` = work split across two or more tiers
/// - `Hibernate` = branch suspended (e.g. waiting on test result; dump 18244-18247)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    /// Routed to RTX PRO 6000 Blackwell (oracle tier).
    Blackwell,
    /// Routed to RTX 3090 (scout tier).
    Rtx3090,
    /// Routed to Ryzen 9900X AVX-512 (deterministic cortex).
    Cpu,
    /// Hybrid — work split across multiple tiers.
    Hybrid,
    /// Branch hibernated — deferred pending another resource.
    Hibernate,
}

/// 7-axis objective breakdown per dump lines 18204-18211.
///
/// Each axis is a normalized score in [0.0, 1.0] where 1.0 = ideal
/// (low latency / low cost / low risk / etc — i.e. higher score is
/// better along each axis). The `compound` field is the per-profile
/// weighted sum (computed by the runtime crate per MS048 R11330).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct AxisScores {
    /// Latency axis score (1.0 = fast; dump 18206)
    pub latency: f32,
    /// Cost axis score (1.0 = cheap; dump 18207)
    pub cost: f32,
    /// Risk axis score (1.0 = low risk; dump 18208)
    pub risk: f32,
    /// Energy axis score (1.0 = low energy; dump 18209)
    pub energy: f32,
    /// Human attention axis score (1.0 = low operator burden; dump 18210)
    pub human_attention: f32,
    /// Hardware pressure axis score (1.0 = low pressure; dump 18211)
    pub hardware_pressure: f32,
    /// Compound 7th axis — per-profile weighted sum of the other 6
    /// (the actual objective value the scheduler is maximizing).
    pub compound: f32,
}

/// Backpressure state across the five surfaces (dump lines 18175-18197).
///
/// Each field is `true` when the surface's threshold has been breached
/// and the scheduler is applying the corresponding response policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackpressureState {
    /// Blackwell VRAM utilization ≥ 90% (R11333)
    pub blackwell_vram_high: bool,
    /// RTX 3090 GPU busy ≥ 80% sustained 5s (R11337)
    pub gpu3090_busy: bool,
    /// CPU PSI some/avg10 > 50% (R11340)
    pub cpu_pressure: bool,
    /// Memory PSI some/avg10 > 30% (R11343)
    pub ram_pressure: bool,
    /// IO PSI some/avg10 > 40% (R11346)
    pub io_pressure: bool,
    /// Human gate queue > 5 pending approvals (R11349)
    pub human_gate_queue_high: bool,
}

impl BackpressureState {
    /// Construct a clean state (no surfaces under pressure).
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            blackwell_vram_high: false,
            gpu3090_busy: false,
            cpu_pressure: false,
            ram_pressure: false,
            io_pressure: false,
            human_gate_queue_high: false,
        }
    }

    /// How many surfaces are currently under pressure.
    #[must_use]
    pub const fn pressure_count(&self) -> u8 {
        (self.blackwell_vram_high as u8)
            + (self.gpu3090_busy as u8)
            + (self.cpu_pressure as u8)
            + (self.ram_pressure as u8)
            + (self.io_pressure as u8)
            + (self.human_gate_queue_high as u8)
    }

    /// Whether ANY surface is currently under pressure.
    #[must_use]
    pub const fn any_pressure(&self) -> bool {
        self.pressure_count() > 0
    }
}

/// A single scheduling decision (read-only verdict).
///
/// Per MS048 R11463: emitted by the scheduler runtime, consumed by the
/// CLI / HTTP API / cockpit panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    /// Schema version (MUST equal `SCHEMA_VERSION`).
    pub schema_version: String,
    /// Unique request id (UUIDv7 — sortable by time).
    pub request_id: String,
    /// Profile in effect when the decision was made.
    pub profile: Profile,
    /// Where the scheduler routed the request.
    pub route: Route,
    /// 7-axis objective breakdown for this decision.
    pub axis_scores: AxisScores,
    /// Backpressure state at decision time.
    pub backpressure: BackpressureState,
    /// Decision timestamp (ms since epoch).
    pub ts_ms: u64,
    /// Host where the scheduler ran.
    pub hostname: String,
    /// MS003 signing key id for the active scheduler policy.
    pub signer_kid_policy: String,
    /// MS003 signing key id of an active operator force-override, if any.
    pub override_signer_kid: Option<String>,
    /// Free-form decision rationale (≤ 512 chars; R11384).
    pub rationale: String,
}

/// Errors produced by the mirror surface.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// Schema-version drift.
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// Empty signer kid.
    #[error("signer_kid_policy is empty (MS003 binding required)")]
    EmptyPolicySigner,
    /// Empty hostname.
    #[error("hostname is empty (MS026 OCSF binding requires device.hostname)")]
    EmptyHostname,
    /// Bad timestamp.
    #[error("ts_ms must be >= 1 (got 0)")]
    BadTimestamp,
    /// Empty request id.
    #[error("request_id is empty (UUIDv7 required for replay invariant)")]
    EmptyRequestId,
    /// Rationale too long.
    #[error("rationale exceeds 512 chars (got {0})")]
    RationaleTooLong(usize),
    /// Axis score out of bounds.
    #[error("axis score out of [0.0, 1.0]: {axis}={value}")]
    AxisScoreOutOfBounds {
        /// Which axis violated bounds.
        axis: &'static str,
        /// The out-of-bounds value.
        value: f32,
    },
    /// JSON deserialization error.
    #[error("serde_json: {0}")]
    Serde(String),
}

impl Decision {
    /// Construct a new Decision at compile-time-checked schema version.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        profile: Profile,
        route: Route,
        axis_scores: AxisScores,
        backpressure: BackpressureState,
        ts_ms: u64,
        hostname: impl Into<String>,
        signer_kid_policy: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            request_id: request_id.into(),
            profile,
            route,
            axis_scores,
            backpressure,
            ts_ms,
            hostname: hostname.into(),
            signer_kid_policy: signer_kid_policy.into(),
            override_signer_kid: None,
            rationale: rationale.into(),
        }
    }

    /// Attach an operator-force-override signer kid (R11401).
    #[must_use]
    pub fn with_override_signer(mut self, kid: impl Into<String>) -> Self {
        self.override_signer_kid = Some(kid.into());
        self
    }

    /// Validate per MS048 R11463-R11465.
    ///
    /// # Errors
    /// Returns the first invariant violation found.
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SchedulerError::SchemaMismatch(self.schema_version.clone()));
        }
        if self.request_id.is_empty() {
            return Err(SchedulerError::EmptyRequestId);
        }
        if self.signer_kid_policy.is_empty() {
            return Err(SchedulerError::EmptyPolicySigner);
        }
        if self.hostname.is_empty() {
            return Err(SchedulerError::EmptyHostname);
        }
        if self.ts_ms == 0 {
            return Err(SchedulerError::BadTimestamp);
        }
        if self.rationale.len() > 512 {
            return Err(SchedulerError::RationaleTooLong(self.rationale.len()));
        }
        let a = self.axis_scores;
        for (axis, value) in [
            ("latency", a.latency),
            ("cost", a.cost),
            ("risk", a.risk),
            ("energy", a.energy),
            ("human_attention", a.human_attention),
            ("hardware_pressure", a.hardware_pressure),
            ("compound", a.compound),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(SchedulerError::AxisScoreOutOfBounds { axis, value });
            }
        }
        Ok(())
    }

    /// Convenience: did this decision route to the oracle tier (Blackwell)?
    #[must_use]
    pub fn is_oracle(&self) -> bool {
        matches!(self.route, Route::Blackwell)
    }

    /// Convenience: did this decision hibernate the branch (backpressure response)?
    #[must_use]
    pub fn is_hibernated(&self) -> bool {
        matches!(self.route, Route::Hibernate)
    }

    /// Convenience: was this decision made under operator-force-override?
    #[must_use]
    pub fn is_overridden(&self) -> bool {
        self.override_signer_kid.is_some()
    }

    /// Deserialize + validate in one call.
    ///
    /// # Errors
    /// Returns `SchedulerError::Serde` on parse failure or any validate() violation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SchedulerError> {
        let d: Self = serde_json::from_slice(bytes)
            .map_err(|e| SchedulerError::Serde(e.to_string()))?;
        d.validate()?;
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_scores() -> AxisScores {
        AxisScores {
            latency: 0.9,
            cost: 0.8,
            risk: 0.7,
            energy: 0.6,
            human_attention: 0.5,
            hardware_pressure: 0.8,
            compound: 0.75,
        }
    }

    fn sample() -> Decision {
        Decision::new(
            "req-abc-123",
            Profile::Careful,
            Route::Blackwell,
            clean_scores(),
            BackpressureState::clean(),
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
            "code-bug verify step (top 2 candidates)",
        )
    }

    #[test]
    fn valid_decision_passes_validation() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = sample();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), SchedulerError::SchemaMismatch(_)));
    }

    #[test]
    fn empty_request_id_rejected() {
        let mut d = sample();
        d.request_id.clear();
        assert!(matches!(d.validate().unwrap_err(), SchedulerError::EmptyRequestId));
    }

    #[test]
    fn empty_signer_rejected() {
        let mut d = sample();
        d.signer_kid_policy.clear();
        assert!(matches!(d.validate().unwrap_err(), SchedulerError::EmptyPolicySigner));
    }

    #[test]
    fn empty_hostname_rejected() {
        let mut d = sample();
        d.hostname.clear();
        assert!(matches!(d.validate().unwrap_err(), SchedulerError::EmptyHostname));
    }

    #[test]
    fn zero_timestamp_rejected() {
        let mut d = sample();
        d.ts_ms = 0;
        assert!(matches!(d.validate().unwrap_err(), SchedulerError::BadTimestamp));
    }

    #[test]
    fn rationale_over_512_rejected() {
        let mut d = sample();
        d.rationale = "x".repeat(513);
        assert!(matches!(
            d.validate().unwrap_err(),
            SchedulerError::RationaleTooLong(513)
        ));
    }

    #[test]
    fn axis_score_negative_rejected() {
        let mut d = sample();
        d.axis_scores.latency = -0.1;
        assert!(matches!(
            d.validate().unwrap_err(),
            SchedulerError::AxisScoreOutOfBounds { axis: "latency", .. }
        ));
    }

    #[test]
    fn axis_score_over_one_rejected() {
        let mut d = sample();
        d.axis_scores.cost = 1.01;
        assert!(matches!(
            d.validate().unwrap_err(),
            SchedulerError::AxisScoreOutOfBounds { axis: "cost", .. }
        ));
    }

    #[test]
    fn axis_score_compound_validated() {
        let mut d = sample();
        d.axis_scores.compound = 2.0;
        assert!(matches!(
            d.validate().unwrap_err(),
            SchedulerError::AxisScoreOutOfBounds { axis: "compound", .. }
        ));
    }

    #[test]
    fn convenience_predicates() {
        let s = sample();
        assert!(s.is_oracle());
        assert!(!s.is_hibernated());
        assert!(!s.is_overridden());
        let with_ov = sample().with_override_signer("kid-op-7");
        assert!(with_ov.is_overridden());
    }

    #[test]
    fn backpressure_clean_no_pressure() {
        let b = BackpressureState::clean();
        assert_eq!(b.pressure_count(), 0);
        assert!(!b.any_pressure());
    }

    #[test]
    fn backpressure_counts_correctly() {
        let b = BackpressureState {
            blackwell_vram_high: true,
            gpu3090_busy: false,
            cpu_pressure: true,
            ram_pressure: false,
            io_pressure: false,
            human_gate_queue_high: true,
        };
        assert_eq!(b.pressure_count(), 3);
        assert!(b.any_pressure());
    }

    #[test]
    fn profile_all_six_present() {
        assert_eq!(Profile::all().len(), 6);
    }

    #[test]
    fn profile_labels_match_dump_verbatim() {
        for (p, want) in [
            (Profile::Fast, "fast"),
            (Profile::Careful, "careful"),
            (Profile::Private, "private"),
            (Profile::Autonomous, "autonomous"),
            (Profile::Experimental, "experimental"),
            (Profile::Production, "production"),
        ] {
            assert_eq!(p.label(), want);
        }
    }

    #[test]
    fn profile_kebab_case_serializes() {
        for (p, want) in [
            (Profile::Fast, "\"fast\""),
            (Profile::Autonomous, "\"autonomous\""),
            (Profile::Experimental, "\"experimental\""),
        ] {
            let j = serde_json::to_string(&p).unwrap();
            assert_eq!(j, want);
        }
    }

    #[test]
    fn route_kebab_case_serializes() {
        for (r, want) in [
            (Route::Blackwell, "\"blackwell\""),
            (Route::Rtx3090, "\"rtx3090\""),
            (Route::Cpu, "\"cpu\""),
            (Route::Hybrid, "\"hybrid\""),
            (Route::Hibernate, "\"hibernate\""),
        ] {
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(j, want);
        }
    }

    #[test]
    fn serde_roundtrip() {
        let d = sample();
        let j = serde_json::to_string(&d).expect("serialize");
        let back: Decision = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(d, back);
    }

    #[test]
    fn from_json_validates_in_one_call() {
        let d = sample();
        let bytes = serde_json::to_vec(&d).unwrap();
        let parsed = Decision::from_json(&bytes).expect("parse + validate");
        assert_eq!(parsed, d);
    }

    #[test]
    fn from_json_rejects_schema_drift() {
        let bad = r#"{"schema_version":"9.9.9","request_id":"r","profile":"fast","route":"blackwell","axis_scores":{"latency":0.9,"cost":0.8,"risk":0.7,"energy":0.6,"human_attention":0.5,"hardware_pressure":0.8,"compound":0.75},"backpressure":{"blackwell_vram_high":false,"gpu3090_busy":false,"cpu_pressure":false,"ram_pressure":false,"io_pressure":false,"human_gate_queue_high":false},"ts_ms":1,"hostname":"h","signer_kid_policy":"k","override_signer_kid":null,"rationale":"r"}"#;
        assert!(matches!(
            Decision::from_json(bad.as_bytes()).unwrap_err(),
            SchedulerError::SchemaMismatch(_)
        ));
    }
}
