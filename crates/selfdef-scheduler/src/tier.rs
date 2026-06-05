//! `tier` — M01149 core: canonical conversions across the tier enums.
//!
//! The scheduler's modules each name the three compute tiers with their own
//! enum, because each models a different facet:
//!
//! | enum | facet | Blackwell | RTX 3090 | Ryzen AVX |
//! |---|---|---|---|---|
//! | [`crate::Route`] | routing outcome | `Blackwell` | `Rtx3090` | `Cpu` |
//! | [`crate::tier_work_policy::HardwareTier`] | work-class policy | `Blackwell` | `Rtx3090` | `Cpu` |
//! | [`crate::request_lifecycle::Plane`] | lifecycle step owner | `Oracle` | `Scout` | `Cpu` |
//! | [`crate::speculative_parallelism::SpeculationRole`] | speculation role | `Verify` | `Predict` | `Prune` |
//!
//! The dump uses the tiers consistently across every section (Blackwell =
//! oracle = verifier; 3090 = scout = predictor; Ryzen AVX = cortex = pruner —
//! e.g. dump 18278-18289 architecture summary + 4830-4832 speculation +
//! 18289 tier roles). This module is the single canonical mapping so a
//! consumer can move between facets without re-deriving the correspondence.
//!
//! [`Route::Hybrid`] (multi-tier) and [`Route::Hibernate`] (no tier) have no
//! single compute tier, so the `from_route` conversions return [`None`] for
//! them — honest, not invented.
//!
//! Standing rule: We do not minimize anything.

use crate::Route;
use crate::request_lifecycle::Plane;
use crate::speculative_parallelism::SpeculationRole;
use crate::tier_work_policy::HardwareTier;

/// Map a [`HardwareTier`] to its routing [`Route`].
#[must_use]
pub const fn tier_to_route(tier: HardwareTier) -> Route {
    match tier {
        HardwareTier::Blackwell => Route::Blackwell,
        HardwareTier::Rtx3090 => Route::Rtx3090,
        HardwareTier::Cpu => Route::Cpu,
    }
}

/// Map a single-tier [`Route`] to its [`HardwareTier`]. `Hybrid` / `Hibernate`
/// have no single tier → [`None`].
#[must_use]
pub const fn route_to_tier(route: Route) -> Option<HardwareTier> {
    match route {
        Route::Blackwell => Some(HardwareTier::Blackwell),
        Route::Rtx3090 => Some(HardwareTier::Rtx3090),
        Route::Cpu => Some(HardwareTier::Cpu),
        Route::Hybrid | Route::Hibernate => None,
    }
}

/// Map a [`HardwareTier`] to its lifecycle [`Plane`].
#[must_use]
pub const fn tier_to_plane(tier: HardwareTier) -> Plane {
    match tier {
        HardwareTier::Blackwell => Plane::Oracle,
        HardwareTier::Rtx3090 => Plane::Scout,
        HardwareTier::Cpu => Plane::Cpu,
    }
}

/// Map a [`HardwareTier`] to its [`SpeculationRole`] (Blackwell verifies, 3090
/// predicts, CPU prunes — dump 4830-4832).
#[must_use]
pub const fn tier_to_speculation_role(tier: HardwareTier) -> SpeculationRole {
    match tier {
        HardwareTier::Blackwell => SpeculationRole::Verify,
        HardwareTier::Rtx3090 => SpeculationRole::Predict,
        HardwareTier::Cpu => SpeculationRole::Prune,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIERS: [HardwareTier; 3] = [
        HardwareTier::Blackwell,
        HardwareTier::Rtx3090,
        HardwareTier::Cpu,
    ];

    #[test]
    fn route_tier_roundtrips_for_single_tiers() {
        for t in TIERS {
            assert_eq!(route_to_tier(tier_to_route(t)), Some(t));
        }
    }

    #[test]
    fn hybrid_and_hibernate_have_no_tier() {
        assert_eq!(route_to_tier(Route::Hybrid), None);
        assert_eq!(route_to_tier(Route::Hibernate), None);
    }

    #[test]
    fn blackwell_is_oracle_and_verifier() {
        assert_eq!(tier_to_route(HardwareTier::Blackwell), Route::Blackwell);
        assert_eq!(tier_to_plane(HardwareTier::Blackwell), Plane::Oracle);
        assert_eq!(
            tier_to_speculation_role(HardwareTier::Blackwell),
            SpeculationRole::Verify
        );
    }

    #[test]
    fn scout_3090_is_predictor() {
        assert_eq!(tier_to_plane(HardwareTier::Rtx3090), Plane::Scout);
        assert_eq!(
            tier_to_speculation_role(HardwareTier::Rtx3090),
            SpeculationRole::Predict
        );
    }

    #[test]
    fn cpu_is_cortex_and_pruner() {
        assert_eq!(tier_to_plane(HardwareTier::Cpu), Plane::Cpu);
        assert_eq!(
            tier_to_speculation_role(HardwareTier::Cpu),
            SpeculationRole::Prune
        );
    }

    #[test]
    fn every_tier_maps_to_all_four_facets_distinctly() {
        // The three tiers map to three distinct routes, planes, and roles.
        let routes: Vec<Route> = TIERS.iter().map(|t| tier_to_route(*t)).collect();
        let planes: Vec<Plane> = TIERS.iter().map(|t| tier_to_plane(*t)).collect();
        let roles: Vec<SpeculationRole> =
            TIERS.iter().map(|t| tier_to_speculation_role(*t)).collect();
        // distinct within each facet
        for i in 0..3 {
            for j in (i + 1)..3 {
                assert_ne!(routes[i], routes[j]);
                assert_ne!(planes[i], planes[j]);
                assert_ne!(roles[i], roles[j]);
            }
        }
    }
}
