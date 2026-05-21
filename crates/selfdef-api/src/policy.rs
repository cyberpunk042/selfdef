//! `GET /v1/policy` — MS033 / SDD-051 D-2 policy-cluster schema
//! discovery.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct PolicySchema {
    pub clusters: &'static [ClusterDescriptor],
    pub total_crates: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterDescriptor {
    pub name: &'static str,
    pub crates: &'static [&'static str],
}

const CLUSTERS: &[ClusterDescriptor] = &[
    ClusterDescriptor {
        name: "conflict + decision",
        crates: &[
            "selfdef-policy-decision",
            "selfdef-policy-conflict-detector",
            "selfdef-policy-conflict-resolver",
        ],
    },
    ClusterDescriptor {
        name: "bundle + signing",
        crates: &[
            "selfdef-policy-bundle-signature",
            "selfdef-policy-bundle-pack",
            "selfdef-policy-bundle-staging",
        ],
    },
    ClusterDescriptor {
        name: "mutation discipline",
        crates: &[
            "selfdef-policy-mutation-record",
            "selfdef-policy-revert-window",
            "selfdef-policy-grace-period",
        ],
    },
    ClusterDescriptor {
        name: "dry-run + staging",
        crates: &[
            "selfdef-policy-dry-run",
            "selfdef-policy-shadow-mode",
            "selfdef-policy-rollout-stage",
            "selfdef-policy-traffic-ramp",
        ],
    },
    ClusterDescriptor {
        name: "spec validation",
        crates: &[
            "selfdef-policy-spec-validator",
            "selfdef-policy-shape-checker",
        ],
    },
    ClusterDescriptor {
        name: "lifecycle / time-window",
        crates: &[
            "selfdef-policy-cooldown-window",
            "selfdef-policy-change-window",
            "selfdef-policy-sunset-policy",
        ],
    },
    ClusterDescriptor {
        name: "storage + distribution",
        crates: &[
            "selfdef-policy-cas-store",
            "selfdef-policy-cache-key",
            "selfdef-policy-bus",
            "selfdef-policy-delta-feed",
            "selfdef-policy-decision-batcher",
        ],
    },
    ClusterDescriptor {
        name: "cross-cutting controls",
        crates: &[
            "selfdef-policy-budget-ledger",
            "selfdef-policy-blast-radius-cap",
            "selfdef-policy-namespace-policy",
            "selfdef-policy-version-pin",
            "selfdef-policy-feature-flag",
            "selfdef-policy-diff-classifier",
            "selfdef-policy-test-harness",
        ],
    },
];

pub(crate) async fn show() -> Json<PolicySchema> {
    let total: usize = CLUSTERS.iter().map(|c| c.crates.len()).sum();
    Json(PolicySchema {
        clusters: CLUSTERS,
        total_crates: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_counts_match_sdd_051() {
        assert_eq!(CLUSTERS.len(), 8); // 8 functional clusters per SDD-051
        let total: usize = CLUSTERS.iter().map(|c| c.crates.len()).sum();
        // 3+3+3+4+2+3+5+7 = 30 crates organized into clusters as of
        // 2026-05-21. (Total `selfdef-policy-*` crate count in workspace
        // is 36; the remaining 6 are not yet cluster-organized and will
        // be added as classification settles.)
        assert_eq!(total, 30, "cluster total expected 30 (3+3+3+4+2+3+5+7)");
    }
}
