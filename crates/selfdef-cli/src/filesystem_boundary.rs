//! `selfdefctl filesystem-boundary` — operator surface for MS037 /
//! SDD-045 explicit-exchange directory discipline.
//!
//! Three subverbs (discovery + drift detection):
//!   - `doctrine` — print the 3-dir layout + 6-step import pipeline,
//!     5-field patch schema, 6 application predicates, 2 verbatim
//!     doctrinal phrases
//!   - `schema` — print the full SDD-045 contract
//!
//! Source: SDD-045 § Open questions D-1.

use anyhow::Result;

fn print_doctrine() {
    println!("MS037 / SDD-045 filesystem-boundary doctrine");
    println!();
    println!("3 exchange directories (per E0372 dump 3556-3558):");
    println!("  - /ai-exchange/inbox     host → VM input drop (M00942)");
    println!("  - /ai-exchange/outbox    VM → host output drop (M00943)");
    println!("  - /ai-exchange/artifacts binary outputs (M00944)");
    println!();
    println!("6-step import pipeline (per E0374 dump 3566-3572):");
    for (i, step) in [
        "Parse",
        "Scan",
        "Diff",
        "PolicyCheck",
        "OracleReview  (conditional on risk_flags)",
        "Commit",
    ]
    .iter()
    .enumerate()
    {
        println!("  {}. {step}", i + 1);
    }
    println!();
    println!("5-field patch schema (per E0375 dump 3578-3584):");
    for f in &[
        "unified_diff",
        "metadata",
        "declared_files_touched",
        "test_notes",
        "risk_flags",
    ] {
        println!("  - {f}");
    }
    println!();
    println!("6 application predicates (per E0376 dump 3588-3594):");
    for p in &[
        "paths_inside_workspace",
        "no_forbidden_files",
        "diff_parses",
        "policy_allows_writes",
        "branch_budget_permits",
        "user_approval_required + user_approval_granted",
    ] {
        println!("  - {p}");
    }
    println!();
    println!("Doctrines preserved verbatim (per E0371 + E0373):");
    println!("  \"Use explicit exchange directories\"");
    println!("  \"VM writes proposals, not final state\"");
}

fn print_schema() {
    print_doctrine();
    println!();
    println!("Caller contract (per SDD-045 § Recommended design):");
    for (i, step) in [
        "Read patch from outbox/ as PatchEnvelope",
        "Validate via validate_patch()",
        "Advance ImportStep: Parse → Scan → Diff → PolicyCheck",
        "Advance OracleReview (conditional on risk_flags)",
        "Construct PredicateChecks with the 6 booleans",
        "assert_application_ready() — refuse on Err",
        "Construct SDD-043 CommitEnvelope (commit_type=FileWrite)",
        "selfdef_commit_authority::validate() — refuse on Err",
        "Persist commit to audit chain (SDD-007)",
    ]
    .iter()
    .enumerate()
    {
        println!("  {}. {step}", i + 1);
    }
}

pub(crate) fn run_doctrine() -> Result<i32> {
    print_doctrine();
    Ok(0)
}

pub(crate) fn run_schema() -> Result<i32> {
    print_schema();
    Ok(0)
}
