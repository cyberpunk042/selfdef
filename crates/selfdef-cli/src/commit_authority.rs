//! `selfdefctl commit-authority` — operator surface for MS041 / SDD-043
//! durable-change discipline.
//!
//! Three subverbs:
//!   - `types` — print the 8 commit types + 5 mandatory fields +
//!     3 high-risk gates + classifier rules
//!   - `validate <file>` — read a JSON CommitEnvelope from disk and
//!     run `selfdef_commit_authority::validate`; surface every error
//!     with the exact F-finding / R-row reference
//!   - `classify <file>` — read a JSON CommitEnvelope and report
//!     whether it's classified high-risk per F04871..F04875
//!
//! Reads happen against `selfdef_commit_authority` directly — no
//! daemon round-trip required. Operators can validate envelope
//! drafts offline before they're presented to a durable-change call
//! site.
//!
//! Source: SDD-043 § Open questions D-1 + the
//! `selfdef-commit-authority` crate's public surface.

use std::path::Path;

use anyhow::{Context, Result};
use selfdef_commit_authority::{CommitEnvelope, is_high_risk, validate};

fn print_types() {
    println!("MS041 / SDD-043 commit-authority schema");
    println!();
    println!("8 commit types (per R09611..R09648):");
    for t in &[
        "FileWrite",
        "MemoryWrite",
        "PolicyUpdate",
        "ProfileUpdate",
        "AdapterPromotion",
        "CloudExposureLog",
        "ToolSideEffect",
        "WorkflowCompletion",
    ] {
        println!("  - {t}");
    }
    println!();
    println!("5 mandatory fields (per R09602..R09606):");
    println!("  - actor          (MS003 fingerprint of the committing party)");
    println!("  - reason         (human-readable; non-empty per R09657)");
    println!("  - policy_decision (Allowed | AllowedWithCaveats | Denied)");
    println!("  - rollback_status (Reversible | Reversed | Unavailable)");
    println!("  - trace_ref      (MS049 cross-cutting trace reference)");
    println!();
    println!("3 high-risk additional gates (per R09607..R09609 + E0420):");
    println!("  - snapshot_id        (pre-commit state snapshot)");
    println!("  - test_eval_id       (test/eval pass evidence)");
    println!("  - oracle_or_human    (oracle approval OR human gate)");
    println!();
    println!("High-risk classifier (per F04871..F04875):");
    println!("  - AdapterPromotion       → ALWAYS high-risk");
    println!("  - L6 Persist authority   → ALWAYS high-risk");
    println!("  - CloudExposureLog       → ALWAYS high-risk");
    println!("  - production L5 commits  → ALWAYS high-risk");
    println!("  - autonomous L5 outside predeclared gate → ALWAYS high-risk");
    println!();
    println!("Refusal rules (per F04852 + F04855):");
    println!("  - rollback_status=Unavailable + is_high_risk=true → REJECT");
    println!("  - signature empty                                  → REJECT");
    println!("  - any mandatory field empty                        → REJECT");
    println!("  - high_risk_gate missing/incomplete on high-risk   → REJECT");
}

fn load_envelope(path: &Path) -> Result<CommitEnvelope> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading commit envelope from {}", path.display()))?;
    let env: CommitEnvelope = serde_json::from_str(&body)
        .with_context(|| format!("parsing commit envelope JSON from {}", path.display()))?;
    Ok(env)
}

fn print_classify(env: &CommitEnvelope) {
    let high_risk = is_high_risk(env);
    println!(
        "classification: {}",
        if high_risk { "HIGH-RISK" } else { "low-risk" }
    );
    println!("  commit_type:       {:?}", env.commit_type);
    println!("  profile:           {:?}", env.profile);
    println!("  authority_level:   {:?}", env.authority_level);
    println!("  within autonomous gate: {}", env.within_autonomous_gate);
    if high_risk {
        println!();
        println!("Reasons (per F04871..F04875 classifier):");
        if matches!(
            env.commit_type,
            selfdef_commit_authority::CommitType::AdapterPromotion
        ) {
            println!("  - commit_type=AdapterPromotion (F04871)");
        }
        if matches!(
            env.commit_type,
            selfdef_commit_authority::CommitType::CloudExposureLog
        ) {
            println!("  - commit_type=CloudExposureLog (F04873)");
        }
        // The remaining classifier triggers depend on AuthorityLevel /
        // Profile enums shipped in selfdef-policy-decision; their
        // string repr is the operator's primary read.
    }
}

pub(crate) fn run_types() -> Result<i32> {
    print_types();
    Ok(0)
}

pub(crate) fn run_validate(path: &Path) -> Result<i32> {
    let env = load_envelope(path)?;
    match validate(&env) {
        Ok(()) => {
            println!(
                "VALID — {} commit envelope passes all mandatory + high-risk gates",
                if is_high_risk(&env) {
                    "HIGH-RISK"
                } else {
                    "low-risk"
                }
            );
            Ok(0)
        }
        Err(e) => {
            println!("INVALID — {e}");
            Ok(1)
        }
    }
}

pub(crate) fn run_classify(path: &Path) -> Result<i32> {
    let env = load_envelope(path)?;
    print_classify(&env);
    Ok(if is_high_risk(&env) { 1 } else { 0 })
}
