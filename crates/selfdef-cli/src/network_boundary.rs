//! `selfdefctl network-boundary` — operator surface for MS038 /
//! SDD-046 5-profile egress enforcement.
//!
//! Two subverbs:
//!   - `profiles` — print the 5 NetworkProfile variants with their
//!     bit values + scope table + cross-cycle bindings to MS032 +
//!     MS039
//!   - `classify <bits>` — parse a u8 + report which NetworkProfile
//!     it encodes (or None)
//!
//! Source: SDD-046 § Open questions D-1.

use anyhow::{Result, anyhow};
use selfdef_network_boundary::NetworkProfile;

fn print_profiles() {
    println!("MS038 / SDD-046 network-boundary 5-profile ladder");
    println!();
    println!("Profile             bits      scope");
    println!("--------------------------------------------------------");
    for (profile, scope) in &[
        (NetworkProfile::Offline, "no egress"),
        (
            NetworkProfile::PackageRegistries,
            "npm / PyPI / crates.io / …",
        ),
        (NetworkProfile::DocsOnly, "+ read-only documentation hosts"),
        (NetworkProfile::ArbitraryWeb, "+ general egress"),
        (
            NetworkProfile::AuthenticatedBrowser,
            "+ logged-in session websites",
        ),
    ] {
        println!(
            "{:<20}{:08b}  {}",
            format!("{profile:?}"),
            profile.policy_bits(),
            scope
        );
    }
    println!();
    println!("Cross-cycle bindings:");
    println!(
        "  - F04527 — Tier A=offline / Tier B=package-registries / Tier C=docs+arbitrary / Tier D=authenticated-browser"
    );
    println!("  - F04526 — capability_word bits 16..23 encode the 5 profile values");
    println!("  - F04528 — composes with MS039 authority-graded egress (Ring 0-4)");
}

pub(crate) fn run_profiles() -> Result<i32> {
    print_profiles();
    Ok(0)
}

pub(crate) fn run_classify(bits_arg: &str) -> Result<i32> {
    let bits: u8 = bits_arg
        .strip_prefix("0b")
        .map(|s| u8::from_str_radix(s, 2))
        .unwrap_or_else(|| bits_arg.parse())
        .map_err(|e| anyhow!("could not parse {bits_arg:?} as u8 (decimal or 0bXXXX): {e}"))?;
    match NetworkProfile::from_policy_bits(bits) {
        Some(p) => {
            println!("policy_bits=0b{bits:08b} ({bits}) → NetworkProfile::{p:?}");
            Ok(0)
        }
        None => {
            println!("policy_bits=0b{bits:08b} ({bits}) → not a canonical NetworkProfile");
            Ok(1)
        }
    }
}
