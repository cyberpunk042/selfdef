//! `selfdefctl flex-profile` — operator surface for MS011 Z-3 /
//! `selfdef-flex-profile` crate foundation.
//!
//! 2 subverbs:
//!   - `schema`  — static doctrine + Delta + DeltaOp + RevertRecord
//!     + refusal rules (offline; no daemon needed)
//!   - `show`    — live state read via GET /v1/flex-profile (calls
//!     the daemon; prints baseline + delta count +
//!     revert count + latest delta)

use std::process::Command;

use anyhow::{Context, Result, anyhow};

pub(crate) fn run_schema() -> Result<i32> {
    println!("MS011 Z-3 / `selfdef-flex-profile` schema");
    println!();
    println!("Per SDD-026 Z-3 (verbatim):");
    println!("  Replace \"profile\" (the static YAML) with \"flex-profile\" —");
    println!("  the same YAML PLUS operator-runtime mutations the dashboard");
    println!("  applies. Persist to /var/lib/selfdef/flex-profile.json with");
    println!("  full revert history.");
    println!();
    println!(
        "FlexProfile {{schema_version, baseline, deltas: Vec<Delta>, history: Vec<RevertRecord>}}"
    );
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

/// `selfdefctl flex-profile show` — fetch live state via
/// GET /v1/flex-profile.
fn fetch_endpoint() -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                "http://localhost/v1/flex-profile",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/flex-profile")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "-H",
                &format!("Authorization: Bearer {token}"),
                &format!("{url}/v1/flex-profile"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/flex-profile")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/flex-profile — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = fetch_endpoint()?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/flex-profile"))?;
    let state_present = parsed
        .get("state_present")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let state_path = parsed
        .get("state_path")
        .and_then(|v| v.as_str())
        .unwrap_or("(no path)");
    if !state_present {
        println!("flex-profile: EMPTY");
        println!("  state path: {state_path}");
        println!("  (no flex-profile persisted yet — operator hasn't applied any deltas)");
        return Ok(0);
    }
    let state = parsed.get("state").and_then(|v| v.as_object());
    let baseline = state
        .and_then(|s| s.get("baseline"))
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let deltas = state
        .and_then(|s| s.get("deltas"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let history = state
        .and_then(|s| s.get("history"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let schema_version = state
        .and_then(|s| s.get("schema_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    println!("flex-profile state");
    println!("  baseline:        {baseline}");
    println!("  schema_version:  {schema_version}");
    println!("  state path:      {state_path}");
    println!("  active deltas:   {}", deltas.len());
    println!("  revert history:  {}", history.len());
    if let Some(latest) = deltas.last() {
        let id = latest.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let actor = latest.get("actor").and_then(|v| v.as_str()).unwrap_or("?");
        let reason = latest.get("reason").and_then(|v| v.as_str()).unwrap_or("?");
        println!("  latest delta:    id={id} actor={actor} reason={reason:?}");
    }
    if let Some(latest) = history.last() {
        let id = latest
            .get("original")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let actor = latest.get("actor").and_then(|v| v.as_str()).unwrap_or("?");
        let reason = latest.get("reason").and_then(|v| v.as_str()).unwrap_or("?");
        println!("  latest revert:   id={id} actor={actor} reason={reason:?}");
    }
    Ok(0)
}
