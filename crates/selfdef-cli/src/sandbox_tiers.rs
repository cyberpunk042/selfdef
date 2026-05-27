//! `selfdefctl sandbox-tiers` — operator surface for MS032 / SDD-047
//! 5-tier capability ladder + promotion-gate enforcement.
//!
//! Discovery-only — tier transitions are operator-driven through the
//! signed-config flow per SDD-047 caller contract (not CLI-invocable).

use anyhow::Result;

pub(crate) fn run_tiers() -> Result<i32> {
    println!("MS032 / SDD-047 5-tier sandbox capability ladder");
    println!();
    println!(
        "Tier   scope                                                  subproc  net  persist  hostfs"
    );
    println!(
        "------------------------------------------------------------------------------------------"
    );
    for (tier, scope, sub, net, pers, fs) in &[
        (
            "Tier0",
            "pure read-only observe; no side effects",
            false,
            false,
            false,
            false,
        ),
        (
            "Tier1",
            "minimal — limited capabilities",
            false,
            false,
            false,
            false,
        ),
        (
            "Tier2",
            "chroot + read-only host FS mount; no network",
            true,
            false,
            false,
            true,
        ),
        (
            "Tier3",
            "controlled network egress (per SDD-046 NetworkProfile)",
            true,
            true,
            false,
            true,
        ),
        (
            "Tier4",
            "full sandbox with persistent state",
            true,
            true,
            true,
            true,
        ),
    ] {
        println!("{tier:<6} {scope:<55} {sub:<8} {net:<4} {pers:<8} {fs:<6}");
    }
    println!();
    println!("4 PromotionGate variants:");
    for (g, desc) in &[
        ("Routine", "no extra check (typically demotion)"),
        ("SingleOperator", "single MS003-signed approval"),
        (
            "DoubleOperator",
            "two distinct MS003 signatures (high-tier)",
        ),
        ("Forbidden", "transition refused unconditionally"),
    ] {
        println!("  - {g:<16} {desc}");
    }
    println!();
    println!("Companion crates:");
    for (c, role) in &[
        (
            "selfdef-sandbox-tier-policy",
            "272 LOC, 15 tests — enum + capability tuples + gates",
        ),
        (
            "selfdef-sandbox-dispatcher",
            "269 LOC, 14 tests — route-by-tier semantics",
        ),
        (
            "selfdef-sandbox-fs-isolation",
            "227 LOC — per-tier filesystem mount strategy",
        ),
        (
            "selfdef-sandbox-network-isolation",
            "188 LOC — per-tier network namespace strategy",
        ),
        (
            "selfdef-sandbox-mirror",
            "441 LOC — cross-repo state projection (MS007)",
        ),
    ] {
        println!("  - {c:<35} {role}");
    }
    Ok(0)
}
