//! `scheduling_law` — route recommendation under the Key Scheduling Law
//! (MS048 SDD-031, dump tail 18000-18250).
//!
//! [`crate::replay`] notes that "Full route inference lands in a later
//! round" and keeps the original route; nothing in the crate yet *picks* a
//! [`Route`] from the live substrate + profile. This module supplies that
//! missing middle of the scheduling loop:
//!
//! ```text
//!   poll() -> DriverReading
//!     -> score_current_substrate(...) -> AxisScores
//!       -> recommend_route(&reading, profile, &scores) -> RouteRecommendation
//! ```
//!
//! **Every branch composes only already-verbatim-encoded source** — no new
//! routing rule is invented here (operator standing rule: "you cannot invent
//! crap, its my projects"). The primitives composed are:
//!
//! - **Key Scheduling Law** (SDD-031 §, verbatim from the dump tail):
//!   *"Never let expensive cognition wait on cheap preparation. Never let
//!   cheap speculation commit without expensive verification when risk
//!   demands it."* — the two clauses become [`LawClause::ExpensiveCognitionNotDeferred`]
//!   and [`LawClause::SpeculationRequiresVerification`].
//! - **`Route` tier semantics** (verbatim doc on the mirror enum): Blackwell
//!   = oracle tier, Rtx3090 = scout tier, Cpu = deterministic cortex,
//!   Hibernate = "branch hibernated — deferred pending another resource".
//! - **`ProfileRules`** (already verbatim-encoded from dump 18011-18040):
//!   `scout_first` (R11248 Fast), `oracle_verification_required`,
//!   `tests_required`, `strict_commit_gates`.
//! - **`BackpressureState`** surfaces (verbatim per R11333-R11349):
//!   `blackwell_vram_high`, `gpu3090_busy`, `cpu_pressure`, `ram_pressure`,
//!   `io_pressure`.
//!
//! Stage-1 framing matches the rest of the crate: arbitration uses one
//! operator-tunable risk threshold (the same MS003-tunable-threshold pattern
//! as [`crate::BackpressureThresholds`]); deeper hybrid-split inference lands
//! in a later round.
//!
//! Standing rule: We do not minimize anything.

use crate::backpressure_driver::DriverReading;
use crate::{AxisScores, Profile, ProfileRules, Route};

/// Risk-score floor below which the Key Scheduling Law's second clause
/// engages ("when risk demands it"). [`AxisScores::risk`] is `1.0` for low
/// risk and `0.0` for high risk, so a score *below* this floor means risk is
/// high enough to demand expensive verification before any committing route.
///
/// Stage-1 default; operator-tunable under the same MS003-multisig threshold
/// discipline as [`crate::BackpressureThresholds`] (a future `scheduler.toml`
/// `[law]` section). Not a new rule — it parameterizes the verbatim
/// "when risk demands it" clause.
pub const RISK_DEMANDS_VERIFICATION_FLOOR: f32 = 0.5;

/// Which clause of the Key Scheduling Law (if any) governed a
/// recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LawClause {
    /// Neither clause forced the choice — the route is the first admissible
    /// tier in the profile's preference order.
    None,
    /// Clause 1: *"Never let expensive cognition wait on cheap
    /// preparation."* The oracle tier (Blackwell) was admissible and was
    /// chosen rather than deferring it.
    ExpensiveCognitionNotDeferred,
    /// Clause 2: *"Never let cheap speculation commit without expensive
    /// verification when risk demands it."* Risk was high and the profile
    /// demands verification, so the recommendation was escalated to the
    /// oracle tier (or hibernated when the oracle is unavailable) rather
    /// than committing on a scout/cortex speculation.
    SpeculationRequiresVerification,
}

/// A route recommendation with the rationale + which Law clause governed it.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteRecommendation {
    /// The recommended route.
    pub route: Route,
    /// Which Key Scheduling Law clause governed the choice.
    pub law_clause: LawClause,
    /// Human-readable rationale citing the verbatim primitive(s) applied.
    pub rationale: String,
}

/// Whether the oracle tier (Blackwell) is admissible — i.e. its VRAM is not
/// flagged high (verbatim `BackpressureState::blackwell_vram_high`).
#[must_use]
fn blackwell_admissible(reading: &DriverReading) -> bool {
    !reading.state.blackwell_vram_high
}

/// Whether the scout tier (Rtx3090) is admissible — i.e. it is not flagged
/// busy (verbatim `BackpressureState::gpu3090_busy`).
#[must_use]
fn rtx3090_admissible(reading: &DriverReading) -> bool {
    !reading.state.gpu3090_busy
}

/// Whether the deterministic-cortex tier (Cpu) is admissible — i.e. none of
/// the three PSI surfaces (cpu / ram / io) are flagged under pressure
/// (verbatim `BackpressureState` surfaces).
#[must_use]
fn cpu_admissible(reading: &DriverReading) -> bool {
    !(reading.state.cpu_pressure || reading.state.ram_pressure || reading.state.io_pressure)
}

/// Whether a given route is admissible under current backpressure.
/// Hybrid is admissible iff at least one compute tier is; Hibernate is
/// always admissible (it is the deferral fallback).
#[must_use]
fn route_admissible(route: Route, reading: &DriverReading) -> bool {
    match route {
        Route::Blackwell => blackwell_admissible(reading),
        Route::Rtx3090 => rtx3090_admissible(reading),
        Route::Cpu => cpu_admissible(reading),
        Route::Hybrid => {
            blackwell_admissible(reading) || rtx3090_admissible(reading) || cpu_admissible(reading)
        }
        Route::Hibernate => true,
    }
}

/// The profile's compute-tier preference order, composing verbatim
/// `ProfileRules` with the verbatim `Route` tier semantics.
///
/// - `scout_first` (R11248, Fast profile) ⇒ scout tier (Rtx3090) leads,
///   oracle (Blackwell) second, cortex (Cpu) last.
/// - otherwise ⇒ oracle (Blackwell) leads — the default per the Key
///   Scheduling Law's first clause (don't make expensive cognition wait).
#[must_use]
fn preference_order(rules: ProfileRules) -> [Route; 3] {
    if rules.scout_first {
        [Route::Rtx3090, Route::Blackwell, Route::Cpu]
    } else {
        [Route::Blackwell, Route::Rtx3090, Route::Cpu]
    }
}

/// Whether the active profile demands expensive verification before a
/// committing route — verbatim `ProfileRules` flags
/// `oracle_verification_required` (Careful) ∨ `tests_required` ∨
/// `strict_commit_gates` (Production).
#[must_use]
fn profile_demands_verification(rules: ProfileRules) -> bool {
    rules.oracle_verification_required || rules.tests_required || rules.strict_commit_gates
}

/// Recommend a [`Route`] from a live [`DriverReading`], the active
/// [`Profile`], and the [`AxisScores`] produced by
/// [`crate::objective_signals::score_current_substrate`].
///
/// Application order (each step cites the verbatim primitive it composes):
///
/// 1. **Law clause 2** — if risk demands verification
///    (`scores.risk < RISK_DEMANDS_VERIFICATION_FLOOR`) and the profile
///    demands verification, the committing route MUST be the oracle tier
///    (Blackwell). If Blackwell is admissible → Blackwell; else → Hibernate
///    (defer rather than let cheap speculation commit).
/// 2. **Preference order** — otherwise pick the first admissible tier in the
///    profile's preference order. When that tier is the oracle (Blackwell),
///    **Law clause 1** is recorded: expensive cognition was not deferred.
/// 3. **Fallback** — if no compute tier is admissible, Hibernate (verbatim
///    "deferred pending another resource").
#[must_use]
pub fn recommend_route(
    reading: &DriverReading,
    profile: Profile,
    scores: &AxisScores,
) -> RouteRecommendation {
    let rules = ProfileRules::for_profile(profile);

    // --- Law clause 2: cheap speculation must not commit when risk demands
    //     verification (SDD-031 verbatim) ---
    if scores.risk < RISK_DEMANDS_VERIFICATION_FLOOR && profile_demands_verification(rules) {
        if blackwell_admissible(reading) {
            return RouteRecommendation {
                route: Route::Blackwell,
                law_clause: LawClause::SpeculationRequiresVerification,
                rationale: format!(
                    "risk score {:.2} < floor {RISK_DEMANDS_VERIFICATION_FLOOR:.2} and profile \
                     {profile:?} demands verification (oracle_verification_required/\
                     tests_required/strict_commit_gates); escalated to oracle tier (Blackwell)",
                    scores.risk
                ),
            };
        }
        return RouteRecommendation {
            route: Route::Hibernate,
            law_clause: LawClause::SpeculationRequiresVerification,
            rationale: format!(
                "risk score {:.2} < floor {RISK_DEMANDS_VERIFICATION_FLOOR:.2} and profile \
                 {profile:?} demands verification, but oracle tier (Blackwell) VRAM is under \
                 pressure; hibernating rather than letting cheap speculation commit",
                scores.risk
            ),
        };
    }

    // --- Preference order over admissible tiers ---
    for route in preference_order(rules) {
        if route_admissible(route, reading) {
            let law_clause = if route == Route::Blackwell {
                LawClause::ExpensiveCognitionNotDeferred
            } else {
                LawClause::None
            };
            return RouteRecommendation {
                route,
                law_clause,
                rationale: format!(
                    "profile {profile:?} preference order selected first admissible tier {route:?}"
                ),
            };
        }
    }

    // --- Fallback: every compute tier under pressure ---
    RouteRecommendation {
        route: Route::Hibernate,
        law_clause: LawClause::None,
        rationale: "all compute tiers (Blackwell/Rtx3090/Cpu) under backpressure; hibernating \
             pending another resource"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceMeasurements;
    use crate::backpressure_driver::SubstrateHealth;
    use selfdef_scheduler_mirror::BackpressureState;

    fn reading_with_state(state: BackpressureState) -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 0,
            measurements: ResourceMeasurements::clean(),
            state,
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    fn scores_with_risk(risk: f32) -> AxisScores {
        AxisScores {
            latency: 0.8,
            cost: 0.8,
            risk,
            energy: 0.8,
            human_attention: 0.8,
            hardware_pressure: 0.8,
            compound: 0.8,
        }
    }

    #[test]
    fn calm_production_low_risk_picks_oracle() {
        // Production is not scout_first ⇒ oracle leads; clean substrate ⇒
        // Blackwell admissible; low risk (high score) ⇒ clause 2 inactive.
        let r = reading_with_state(BackpressureState::clean());
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        assert_eq!(rec.route, Route::Blackwell);
        assert_eq!(rec.law_clause, LawClause::ExpensiveCognitionNotDeferred);
    }

    #[test]
    fn fast_profile_is_scout_first() {
        // Fast is scout_first ⇒ scout tier (Rtx3090) leads even on clean
        // substrate. Fast does not demand verification, so clause 2 inactive.
        let r = reading_with_state(BackpressureState::clean());
        let rec = recommend_route(&r, Profile::Fast, &scores_with_risk(0.9));
        assert_eq!(rec.route, Route::Rtx3090);
        assert_eq!(rec.law_clause, LawClause::None);
    }

    #[test]
    fn high_risk_verifying_profile_escalates_to_oracle() {
        // Careful demands oracle_verification_required; high risk
        // (risk score 0.2 < floor 0.5) ⇒ clause 2 escalates to Blackwell.
        let r = reading_with_state(BackpressureState::clean());
        let rec = recommend_route(&r, Profile::Careful, &scores_with_risk(0.2));
        assert_eq!(rec.route, Route::Blackwell);
        assert_eq!(rec.law_clause, LawClause::SpeculationRequiresVerification);
    }

    #[test]
    fn high_risk_verifying_profile_hibernates_when_oracle_pressured() {
        // Same as above but Blackwell VRAM high ⇒ cannot commit on
        // speculation; hibernate rather than route to scout/cortex.
        let state = BackpressureState {
            blackwell_vram_high: true,
            ..BackpressureState::clean()
        };
        let r = reading_with_state(state);
        let rec = recommend_route(&r, Profile::Careful, &scores_with_risk(0.2));
        assert_eq!(rec.route, Route::Hibernate);
        assert_eq!(rec.law_clause, LawClause::SpeculationRequiresVerification);
    }

    #[test]
    fn high_risk_nonverifying_profile_does_not_force_oracle() {
        // Fast does NOT demand verification, so even high risk leaves clause
        // 2 inactive: scout-first preference holds.
        let r = reading_with_state(BackpressureState::clean());
        let rec = recommend_route(&r, Profile::Fast, &scores_with_risk(0.1));
        assert_eq!(rec.route, Route::Rtx3090);
        assert_eq!(rec.law_clause, LawClause::None);
    }

    #[test]
    fn oracle_pressure_falls_to_scout() {
        // Production oracle-first, but Blackwell VRAM high ⇒ next admissible
        // is Rtx3090. Low risk so clause 2 inactive.
        let state = BackpressureState {
            blackwell_vram_high: true,
            ..BackpressureState::clean()
        };
        let r = reading_with_state(state);
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        assert_eq!(rec.route, Route::Rtx3090);
        assert_eq!(rec.law_clause, LawClause::None);
    }

    #[test]
    fn all_tiers_pressured_hibernates() {
        let state = BackpressureState {
            blackwell_vram_high: true,
            gpu3090_busy: true,
            cpu_pressure: true,
            ram_pressure: true,
            io_pressure: true,
            human_gate_queue_high: false,
        };
        let r = reading_with_state(state);
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        assert_eq!(rec.route, Route::Hibernate);
        assert_eq!(rec.law_clause, LawClause::None);
    }

    #[test]
    fn cpu_admissible_only_when_no_psi_surface_fires() {
        let state = BackpressureState {
            blackwell_vram_high: true,
            gpu3090_busy: true,
            io_pressure: true, // one PSI surface ⇒ cpu inadmissible
            ..BackpressureState::clean()
        };
        let r = reading_with_state(state);
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        // Blackwell + Rtx3090 + Cpu all inadmissible ⇒ hibernate.
        assert_eq!(rec.route, Route::Hibernate);
    }

    #[test]
    fn cpu_chosen_when_gpus_pressured_but_psi_clear() {
        let state = BackpressureState {
            blackwell_vram_high: true,
            gpu3090_busy: true,
            ..BackpressureState::clean()
        };
        let r = reading_with_state(state);
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        assert_eq!(rec.route, Route::Cpu);
        assert_eq!(rec.law_clause, LawClause::None);
    }

    #[test]
    fn risk_floor_is_half() {
        assert_eq!(RISK_DEMANDS_VERIFICATION_FLOOR, 0.5);
    }

    #[test]
    fn rationale_is_populated() {
        let r = reading_with_state(BackpressureState::clean());
        let rec = recommend_route(&r, Profile::Production, &scores_with_risk(0.9));
        assert!(!rec.rationale.is_empty());
    }
}
