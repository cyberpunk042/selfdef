//! `selfdefctl authority` — operator surface for MS039 + MS040 +
//! SDD-049 authority tiers + trust rings + 6-profile matrix.
//!
//! Single subverb (the matrix is small enough to print in one screen).

use anyhow::Result;

pub(crate) fn run_matrix() -> Result<i32> {
    println!("MS039 + MS040 / SDD-049 authority matrix");
    println!();
    println!("7 authority levels (per dump 17215-17532):");
    for (lvl, scope) in &[
        ("L0", "observe-only (no side effects)"),
        (
            "L1",
            "local in-process state (no FS / network / subprocess)",
        ),
        ("L2", "local FS reads, NO writes (R09202)"),
        ("L3", "local FS writes within workspace (per SDD-045)"),
        ("L4", "external network egress (per SDD-046)"),
        ("L5", "external state mutation (cloud APIs, write-acked)"),
        (
            "L6",
            "persistent durable changes (every commit through SDD-043)",
        ),
    ] {
        println!("  {} — {}", lvl, scope);
    }
    println!();
    println!("5 trust rings (per dump 17215-17532):");
    println!("  Ring   scope                                   L-cap");
    println!("  ----------------------------------------------------");
    for (r, scope, cap) in &[
        ("Ring0", "operator-direct (cockpit + console)", "L6"),
        ("Ring1", "daemon-internal", "L5"),
        ("Ring2", "operator-sandboxed agent", "L4"),
        ("Ring3", "third-party tool plugin", "L3"),
        ("Ring4", "external untrusted code", "L1"),
    ] {
        println!("  {:<6} {:<38} {}", r, scope, cap);
    }
    println!();
    println!("6 profile envelopes (per dump 17468-17500):");
    println!("  Profile        max L  ring-cap  sandbox req      gate");
    println!("  ----------------------------------------------------------------");
    for (p, l, ring, sb, gate) in &[
        ("private", "L1", "Ring 2", "Tier A", "operator approval"),
        ("fast", "L4", "Ring 2", "Tier A", "TTL ≤ 60s default"),
        (
            "careful",
            "L5",
            "Ring 2",
            "Tier A or B",
            "oracle + tests + sim",
        ),
        ("paranoid", "L4", "Ring 1", "Tier A", "double-operator"),
        (
            "production",
            "L6",
            "Ring 0",
            "Tier B",
            "full commit-authority",
        ),
        (
            "experimental",
            "L5",
            "Ring 3",
            "Tier C",
            "high cycle budget",
        ),
    ] {
        println!("  {:<14} {:<6} {:<9} {:<16} {}", p, l, ring, sb, gate);
    }
    println!();
    println!("4 TransitionGate variants (per selfdef-mode-transition-authority):");
    for (g, desc) in &[
        ("Routine", "no extra gate"),
        ("DirectShift", "explicit operator acknowledgement"),
        ("SnapshotRequired", "ZFS snapshot evidence required"),
        ("Forbidden", "refused unconditionally"),
    ] {
        println!("  - {:<18} {}", g, desc);
    }
    println!();
    println!("5 authority crates shipped (per SDD-049):");
    for (c, role) in &[
        (
            "selfdef-mode-transition-authority",
            "227 LOC — 4-gate matrix",
        ),
        ("selfdef-toggle-audit-authority", "270 LOC — toggle policy"),
        (
            "selfdef-config-mutation-authority",
            "225 LOC — config gating",
        ),
        (
            "selfdef-recovery-snapshot-authority",
            "257 LOC — snapshot gate",
        ),
        (
            "selfdef-profile-authority-gate",
            "660 LOC — 6-profile matrix",
        ),
    ] {
        println!("  - {:<35} {}", c, role);
    }
    Ok(0)
}
