//! `scenarios` — M01167: canonical scheduler decision fixtures.
//!
//! Encodes the avx-plus-plus dump's worked scheduling examples (the
//! "Concrete Scheduler Decision Example" + per-profile rules, dump tail lines
//! ~18211-18262) as canned `(DriverReading, RequestContext)` fixtures that
//! drive the full [`crate::decide::decide`] path. CI + the cockpit
//! integration check run these to verify the scheduler routes the dump's own
//! examples the way the dump describes — no invented scenarios, every fixture
//! traces to a dump passage (operator rule: "you cannot invent crap").
//!
//! The dump's canonical example (verbatim shape, line ~18213):
//!
//! ```text
//! Task: code bug.
//!   Map:    CPU + tools inspect repo
//!   Draft:  3090 produces 4 patch candidates       (scout tier)
//!   Filter: AVX checks touched paths, risk, dup edits
//!   Verify: Blackwell reviews top 2                 (oracle tier)
//!   Test:   sandbox runs targeted tests
//!   Commit: if pass, ZFS snapshot + apply
//! If Blackwell is busy: 3090 diagnostics / CPU static checks / memory recall
//! If tests are slow:    branch hibernates; other work proceeds
//! ```
//!
//! Tier roles (verbatim, dump line ~18289): Blackwell = oracle (verification /
//! final reasoning), RTX 3090 = scout (drafts / SLMs / exploration), Ryzen
//! AVX-512 = deterministic cortex.
//!
//! Standing rule: We do not minimize anything.

use crate::backpressure_driver::{DriverReading, SubstrateHealth};
use crate::decide::RequestContext;
use crate::{AxisSignals, Profile, ResourceMeasurements};
use selfdef_scheduler_mirror::BackpressureState;

/// A named, dump-grounded decision scenario: the live substrate snapshot plus
/// the per-request context, ready to feed [`crate::decide::decide`].
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Short scenario id (stable; used as the CI fixture name).
    pub name: &'static str,
    /// One-line description with the dump passage it encodes.
    pub description: &'static str,
    /// The substrate snapshot.
    pub reading: DriverReading,
    /// The per-request context.
    pub ctx: RequestContext,
}

fn reading(measurements: ResourceMeasurements, state: BackpressureState) -> DriverReading {
    DriverReading {
        captured_at_unix_micros: 1_700_000_000_000_000,
        measurements,
        state,
        substrate_health: SubstrateHealth::all_healthy(),
    }
}

fn ctx(request_id: &str, profile: Profile, risk: f32) -> RequestContext {
    RequestContext {
        request_id: request_id.to_string(),
        profile,
        // latency/cost/energy are mid; `risk` is the axis the scenarios vary
        // (1.0 = low risk, 0.0 = high risk — see AxisScores doc).
        model_signals: AxisSignals {
            latency: 0.7,
            cost: 0.7,
            risk,
            energy: 0.7,
            human_attention: 0.0,   // overwritten from substrate
            hardware_pressure: 0.0, // overwritten from substrate
        },
        max_queue: crate::objective_signals::DEFAULT_HUMAN_ATTENTION_QUEUE_CAP,
        ts_ms: 1_700_000_000_000,
        hostname: "sain-01".to_string(),
        signer_kid_policy: "policy-kid-1".to_string(),
    }
}

/// **Code-bug Verify phase, clean substrate.** Dump: "Verify: Blackwell
/// reviews top 2". High-risk change under a verifying profile (`Careful` —
/// `oracle_verification_required`); the oracle tier is free, so the scheduler
/// routes verification to Blackwell.
#[must_use]
pub fn code_bug_verify_clean() -> Scenario {
    Scenario {
        name: "code_bug_verify_clean",
        description: "dump ~18213 code-bug Verify phase; oracle free → Blackwell (oracle verification)",
        reading: reading(ResourceMeasurements::clean(), BackpressureState::clean()),
        // high risk (a code change to commit) ⇒ low risk score
        ctx: ctx("req-codebug-verify-clean", Profile::Careful, 0.2),
    }
}

/// **Code-bug Verify phase, Blackwell busy.** Dump: "If Blackwell is busy:
/// ... branch hibernates; other work proceeds." The verify decision cannot
/// commit a high-risk change without oracle verification and the oracle is
/// VRAM-pressured, so this *verify* decision defers (Hibernate) — the rest of
/// the task (diagnostics on 3090/CPU) proceeds under its own, lower-risk
/// decisions.
#[must_use]
pub fn code_bug_verify_oracle_pressured() -> Scenario {
    let state = BackpressureState {
        blackwell_vram_high: true,
        ..BackpressureState::clean()
    };
    Scenario {
        name: "code_bug_verify_oracle_pressured",
        description: "dump ~18244 'If Blackwell is busy' — high-risk verify defers (Hibernate) when oracle VRAM high",
        reading: reading(
            ResourceMeasurements {
                blackwell_vram_util: 0.95,
                ..ResourceMeasurements::clean()
            },
            state,
        ),
        ctx: ctx("req-codebug-verify-busy", Profile::Careful, 0.2),
    }
}

/// **Code-bug Draft phase, Fast profile.** Dump: "Draft: 3090 produces 4
/// patch candidates" — the scout tier drafts. `Fast` is `scout_first`, the
/// draft is low-risk exploration, so the scheduler routes to RTX 3090.
#[must_use]
pub fn code_bug_draft_scout() -> Scenario {
    Scenario {
        name: "code_bug_draft_scout",
        description: "dump ~18216 code-bug Draft phase; Fast scout_first → Rtx3090 (scout drafts)",
        reading: reading(ResourceMeasurements::clean(), BackpressureState::clean()),
        // low risk (drafting candidates, not committing) ⇒ high risk score
        ctx: ctx("req-codebug-draft", Profile::Fast, 0.85),
    }
}

/// **All compute tiers pressured.** Dump backpressure table (~18181): every
/// surface firing; no tier admissible ⇒ the branch hibernates pending another
/// resource.
#[must_use]
pub fn all_tiers_pressured() -> Scenario {
    let state = BackpressureState {
        blackwell_vram_high: true,
        gpu3090_busy: true,
        cpu_pressure: true,
        ram_pressure: true,
        io_pressure: true,
        human_gate_queue_high: false,
    };
    Scenario {
        name: "all_tiers_pressured",
        description: "dump ~18181 backpressure table; every compute tier pressured → Hibernate",
        reading: reading(
            ResourceMeasurements {
                blackwell_vram_util: 0.95,
                gpu3090_util: 0.95,
                cpu_psi: 0.8,
                mem_psi: 0.8,
                io_psi: 0.8,
                human_gate_queue_depth: 0,
            },
            state,
        ),
        ctx: ctx("req-all-pressured", Profile::Production, 0.9),
    }
}

/// All canonical scenarios (the CI fixture set).
#[must_use]
pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        code_bug_verify_clean(),
        code_bug_verify_oracle_pressured(),
        code_bug_draft_scout(),
        all_tiers_pressured(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Route;
    use crate::decide::decide;

    #[test]
    fn code_bug_verify_clean_routes_oracle() {
        let s = code_bug_verify_clean();
        let d = decide(&s.reading, &s.ctx).expect("valid");
        // dump: "Verify: Blackwell reviews top 2"
        assert_eq!(d.route, Route::Blackwell, "{}", s.description);
    }

    #[test]
    fn code_bug_verify_oracle_pressured_defers() {
        let s = code_bug_verify_oracle_pressured();
        let d = decide(&s.reading, &s.ctx).expect("valid");
        // dump: high-risk verify cannot commit without the oracle ⇒ defer
        assert_eq!(d.route, Route::Hibernate, "{}", s.description);
    }

    #[test]
    fn code_bug_draft_routes_scout() {
        let s = code_bug_draft_scout();
        let d = decide(&s.reading, &s.ctx).expect("valid");
        // dump: "Draft: 3090 produces 4 patch candidates"
        assert_eq!(d.route, Route::Rtx3090, "{}", s.description);
    }

    #[test]
    fn all_tiers_pressured_hibernates() {
        let s = all_tiers_pressured();
        let d = decide(&s.reading, &s.ctx).expect("valid");
        assert_eq!(d.route, Route::Hibernate, "{}", s.description);
    }

    #[test]
    fn every_scenario_produces_a_valid_decision() {
        for s in all_scenarios() {
            let d = decide(&s.reading, &s.ctx)
                .unwrap_or_else(|e| panic!("{} failed to decide: {e}", s.name));
            d.validate()
                .unwrap_or_else(|e| panic!("{} produced invalid decision: {e}", s.name));
        }
    }

    #[test]
    fn scenario_set_is_the_expected_four() {
        let names: Vec<&str> = all_scenarios().iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "code_bug_verify_clean",
                "code_bug_verify_oracle_pressured",
                "code_bug_draft_scout",
                "all_tiers_pressured",
            ]
        );
    }
}
