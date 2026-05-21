//! `selfdefctl capability-tokens` — operator surface for MS035 /
//! SDD-044 typed authority handles.
//!
//! Two subverbs (discovery-only; the daemon's in-memory token store
//! per SDD-044 D-3 isn't currently exposed for mutation via CLI):
//!   - `verdicts` — print the 5 CheckVerdict variants + their
//!     semantics
//!   - `schema` — print the full SDD-044 schema (Token shape + Verdict
//!     ladder + scope vocabulary + companion crates)
//!
//! Source: SDD-044 § Open questions D-1 + the
//! `selfdef-capability-token-store` crate's public surface.

use anyhow::Result;

fn print_verdicts() {
    println!("MS035 / SDD-044 CheckVerdict ladder");
    println!();
    println!("5 verdicts returned by `CapabilityTokenStore::check(id, scope, now_ms)`:");
    for (verdict, desc) in &[
        ("Ok",            "token present + active + not revoked + carries the requested scope"),
        ("Expired",       "token present but `now_ms > expires_at_ms`"),
        ("Revoked",       "token present but `revoked == true`"),
        ("Unknown",       "no token registered under this id"),
        ("MissingScope",  "token Ok-otherwise but does not carry the requested scope"),
    ] {
        println!("  - {:<13} {}", verdict, desc);
    }
}

fn print_schema() {
    println!("MS035 / SDD-044 capability-tokens schema");
    println!();
    println!("Token shape (per `selfdef-capability-token-store::Token`):");
    println!("  - id              (operator-chosen identifier)");
    println!("  - holder          (MS003 fingerprint of holder actor)");
    println!("  - scopes          (BTreeSet<String>; canonical names from selfdef-capability-word)");
    println!("  - expires_at_ms   (mandatory; bounded TTL per SDD-044 goal 3)");
    println!("  - revoked         (bool; surgical revocation per SDD-044 goal 4)");
    println!();
    println!("Companion crates (per SDD-044 § Recommended design):");
    for (crate_name, role) in &[
        ("selfdef-capability-token-store",   "215 LOC, 9 tests — issue + revoke + check primitives"),
        ("selfdef-capability-word",          "496 LOC — canonical scope vocabulary (drift-prevention)"),
        ("selfdef-capability-mirror",        "416 LOC — cross-repo state projection (MS007 typed-mirror)"),
        ("selfdef-tool-capability-policy",   "12 tests — per-tool scope requirements (consumes scopes)"),
        ("selfdef-profile-authority-gate",   "660 LOC — gates profile transitions on holder scopes"),
    ] {
        println!("  - {:<35} {}", crate_name, role);
    }
    println!();
    println!("Caller contract (per SDD-044):");
    println!("  1. Determine required scope from selfdef-capability-word");
    println!("  2. Read token id from operator-presented header / config");
    println!("  3. Call store.check(id, scope, now_ms)");
    println!("  4. Branch on CheckVerdict:");
    println!("     Ok           → proceed; SDD-043 commit envelope");
    println!("     Expired/Revoked/Unknown/MissingScope → refuse + audit");
    println!();
    println!("Refusal rules:");
    println!("  - Non-Ok CheckVerdict → REFUSE (operator-readable error citing verdict)");
    println!("  - Issue without scope present in selfdef-capability-word → REJECT (drift defense)");
}

pub(crate) fn run_verdicts() -> Result<i32> {
    print_verdicts();
    Ok(0)
}

pub(crate) fn run_schema() -> Result<i32> {
    print_schema();
    Ok(0)
}
