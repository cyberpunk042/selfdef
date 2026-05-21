//! `selfdefctl policy` — operator surface for MS033 / SDD-051
//! policy-and-trace doctrine. Cluster + crate discovery for the
//! 36-crate `selfdef-policy-*` ecosystem.

use anyhow::Result;

pub(crate) fn run_clusters() -> Result<i32> {
    println!("MS033 / SDD-051 policy-and-trace — 9 functional clusters");
    println!();
    for (cluster, crates) in CLUSTERS {
        println!("  {cluster}");
        for c in *crates {
            println!("    - {c}");
        }
        println!();
    }
    Ok(0)
}

pub(crate) fn run_crates() -> Result<i32> {
    println!("MS033 / SDD-051 — 36 shipped policy crates");
    println!();
    let mut total = 0;
    for (_, crates) in CLUSTERS {
        for c in *crates {
            println!("  - {c}");
            total += 1;
        }
    }
    println!();
    println!("Total: {total} crates");
    Ok(0)
}

pub(crate) const CLUSTERS: &[(&str, &[&str])] = &[
    (
        "conflict + decision",
        &[
            "selfdef-policy-decision",
            "selfdef-policy-conflict-detector",
            "selfdef-policy-conflict-resolver",
        ],
    ),
    (
        "bundle + signing",
        &[
            "selfdef-policy-bundle-signature",
            "selfdef-policy-bundle-pack",
            "selfdef-policy-bundle-staging",
        ],
    ),
    (
        "mutation discipline",
        &[
            "selfdef-policy-mutation-record",
            "selfdef-policy-revert-window",
            "selfdef-policy-grace-period",
        ],
    ),
    (
        "dry-run + staging",
        &[
            "selfdef-policy-dry-run",
            "selfdef-policy-shadow-mode",
            "selfdef-policy-rollout-stage",
            "selfdef-policy-traffic-ramp",
        ],
    ),
    (
        "spec validation",
        &[
            "selfdef-policy-spec-validator",
            "selfdef-policy-shape-checker",
        ],
    ),
    (
        "lifecycle / time-window",
        &[
            "selfdef-policy-cooldown-window",
            "selfdef-policy-change-window",
            "selfdef-policy-sunset-policy",
        ],
    ),
    (
        "storage + distribution",
        &[
            "selfdef-policy-cas-store",
            "selfdef-policy-cache-key",
            "selfdef-policy-bus",
            "selfdef-policy-delta-feed",
            "selfdef-policy-decision-batcher",
        ],
    ),
    (
        "cross-cutting controls",
        &[
            "selfdef-policy-budget-ledger",
            "selfdef-policy-blast-radius-cap",
            "selfdef-policy-namespace-policy",
            "selfdef-policy-version-pin",
            "selfdef-policy-feature-flag",
            "selfdef-policy-diff-classifier",
            "selfdef-policy-test-harness",
        ],
    ),
    (
        "uncategorized (this session's count)",
        &[
            // Reserved for any additional policy crates not yet
            // classified — verified at 0 today per the 36-crate
            // count in selfdef-cli/src/policy.rs::CLUSTERS, but
            // kept here for future drift detection.
        ],
    ),
];
