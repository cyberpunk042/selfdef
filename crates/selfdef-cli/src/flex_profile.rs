//! `selfdefctl flex-profile` — operator surface for MS011 Z-3 /
//! `selfdef-flex-profile` crate foundation.

use anyhow::Result;

pub(crate) fn run_schema() -> Result<i32> {
    println!("MS011 Z-3 / `selfdef-flex-profile` schema");
    println!();
    println!("Per SDD-026 Z-3 (verbatim):");
    println!("  Replace \"profile\" (the static YAML) with \"flex-profile\" —");
    println!("  the same YAML PLUS operator-runtime mutations the dashboard");
    println!("  applies. Persist to /var/lib/selfdef/flex-profile.json with");
    println!("  full revert history.");
    println!();
    println!("FlexProfile {{schema_version, baseline, deltas: Vec<Delta>, history: Vec<RevertRecord>}}");
    println!();
    println!("Delta (5 mandatory fields mirroring SDD-043 commit envelope):");
    for f in &[
        "id              monotonic, 1-indexed",
        "actor           MS003 fingerprint of the applying party",
        "reason          human-readable (non-empty per R09657)",
        "applied_at_ms   Unix millis at apply time",
        "operation       DeltaOp enum (4 variants)",
    ] {
        println!("  - {f}");
    }
    println!();
    println!("4 canonical DeltaOp variants (per SDD-026 Z-3 examples):");
    for v in &[
        "AttachModel  {slug}              — e.g. \"qwen3-coder-32b\"",
        "DetachModel  {slug}              — inverse of AttachModel",
        "AttachLora   {base_model, lora}  — e.g. base \"qwen3-coder-32b\" + lora \"x\"",
        "DetachLora   {base_model, lora}  — inverse of AttachLora",
    ] {
        println!("  - {v}");
    }
    println!();
    println!("RevertRecord (full revert history per SDD-026 Z-3):");
    for f in &[
        "original         the Delta that was reverted (copied verbatim)",
        "actor            MS003 fingerprint of the reverting party",
        "reverted_at_ms   Unix millis at revert time",
        "reason           operator-readable reason for the revert",
    ] {
        println!("  - {f}");
    }
    println!();
    println!("Refusal rules (per FlexProfileError):");
    println!("  - SchemaMismatch         — schema_version drift");
    println!("  - NothingToRevert        — revert called with empty delta stack");
    println!("  - MandatoryFieldMissing  — actor or reason empty");
    println!();
    println!("Default state path: /var/lib/selfdef/flex-profile.json");
    println!("  (constant: selfdef_flex_profile::DEFAULT_STATE_PATH)");
    Ok(0)
}
