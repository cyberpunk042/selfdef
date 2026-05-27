//! `selfdefctl tool-authority` — operator surface for MS042 / SDD-050
//! 11-crate tool-policy pipeline.
//!
//! Two subverbs:
//!   - `tools` — print the 8 canonical ToolId variants + the 9-gate
//!     composition pipeline + per-gate decision vocabulary
//!   - `permits <tool> <mode> <profile>` — call
//!     `selfdef_tool_capability_policy::is_authorized` against the
//!     supplied triple; print Allow / NotAuthorized
//!
//! Discovery-only — no daemon round-trip required. Operators + agents
//! can learn the tool-authority contract offline.
//!
//! Source: SDD-050 § Open questions D-1 + the
//! `selfdef-tool-capability-policy` crate's public surface.

use anyhow::{Context, Result, anyhow};

fn print_tools() {
    println!("MS042 / SDD-050 tool-authority schema");
    println!();
    println!("8 canonical tool ids (per dump 17422-17445):");
    for t in &[
        "Shell           — arbitrary shell command",
        "FsRead          — filesystem read",
        "FsWrite         — filesystem write",
        "WebFetch        — HTTP GET / POST (gated by SDD-046 NetworkProfile)",
        "ModelInference  — LLM call",
        "McpBridge       — MCP tool dispatch",
        "ReplayControl   — replay / counterfactual",
        "CliBridge       — selfdefctl bridge call",
    ] {
        println!("  - {t}");
    }
    println!();
    println!("9-gate composition pipeline (per SDD-050 § Recommended design):");
    for (i, gate) in [
        "admit             (selfdef-tool-invocation-rate-limit)  — Allow / Denied",
        "permits           (selfdef-tool-capability-policy)      — Allow / NotAuthorized",
        "version-pin       (selfdef-tool-version-pinning)        — Allow / VersionMismatch",
        "redact-args       (selfdef-tool-arg-redaction-policy)   — exact / suffix / prefix / wildcard",
        "audit             (SDD-043 ToolSideEffect commit)       — emit envelope",
        "invoke            (caller-owned)                        — execute the tool",
        "watchdog          (selfdef-tool-stream-watchdog)        — Ok / Silence / TotalElapsed",
        "admit_chunk       (selfdef-tool-output-byte-quota)      — Accept / Truncate / Refuse",
        "truncate          (selfdef-tool-output-truncation-policy) — HeadOnly / HeadTail / MiddleEllipsis",
    ]
    .iter()
    .enumerate()
    {
        println!("  {}. {gate}", i + 1);
    }
    println!();
    println!("Post-pipeline:");
    println!("  - shape-check     (selfdef-tool-output-language-policy) — Pass / ShapeMismatch");
    println!(
        "  - veil-wrap       (selfdef-tool-output-trust-veil)      — Veil<Tier>; consumers unveil_with_tier(expected)"
    );
    println!();
    println!("Refusal rules:");
    println!("  - Any non-Allow gate verdict → REFUSE (operator-readable error citing gate)");
    println!(
        "  - VeilTierMismatch on unveil → REFUSE (typed cross-tier promotion blocked per SDD-050 D-4)"
    );
}

/// Parse + run the `permits <tool> <mode> <profile>` subverb.
pub(crate) fn run_permits(tool_arg: &str, mode_arg: &str, profile_arg: &str) -> Result<i32> {
    use selfdef_tool_capability_policy as policy;
    let tool = parse_tool(tool_arg)?;
    let mode = parse_mode(mode_arg)?;
    let profile = parse_profile(profile_arg)?;
    let allowed = policy::is_authorized(tool, mode, profile);
    println!(
        "permits({tool_arg}, {mode_arg}, {profile_arg}) = {}",
        if allowed { "ALLOW" } else { "NOT_AUTHORIZED" }
    );
    Ok(if allowed { 0 } else { 1 })
}

fn parse_tool(s: &str) -> Result<selfdef_tool_capability_policy::ToolId> {
    use selfdef_tool_capability_policy::ToolId;
    match s.to_ascii_lowercase().replace('-', "").as_str() {
        "shell" => Ok(ToolId::Shell),
        "fsread" => Ok(ToolId::FsRead),
        "fswrite" => Ok(ToolId::FsWrite),
        "webfetch" => Ok(ToolId::WebFetch),
        "modelinference" => Ok(ToolId::ModelInference),
        "mcpbridge" => Ok(ToolId::McpBridge),
        "replaycontrol" => Ok(ToolId::ReplayControl),
        "clibridge" => Ok(ToolId::CliBridge),
        _ => Err(anyhow!(
            "unknown tool {s:?} (expected: shell | fs-read | fs-write | web-fetch | model-inference | mcp-bridge | replay-control | cli-bridge)"
        )),
    }
}

fn parse_mode(s: &str) -> Result<selfdef_execution_mode_policy::ExecutionMode> {
    use selfdef_execution_mode_policy::ExecutionMode;
    match s.to_ascii_lowercase().replace('-', "").as_str() {
        "plan" => Ok(ExecutionMode::Plan),
        "dryrun" => Ok(ExecutionMode::DryRun),
        "shadow" => Ok(ExecutionMode::Shadow),
        "sandbox" => Ok(ExecutionMode::Sandbox),
        "execute" => Ok(ExecutionMode::Execute),
        "replay" => Ok(ExecutionMode::Replay),
        "debug" => Ok(ExecutionMode::Debug),
        _ => Err(anyhow!(
            "unknown mode {s:?} (expected: plan | dry-run | shadow | sandbox | execute | replay | debug)"
        )),
    }
}

fn parse_profile(s: &str) -> Result<selfdef_profile_authority_gate::Profile> {
    use selfdef_profile_authority_gate::Profile;
    match s.to_ascii_lowercase().as_str() {
        "private" => Ok(Profile::Private),
        "fast" => Ok(Profile::Fast),
        "careful" => Ok(Profile::Careful),
        "autonomous" => Ok(Profile::Autonomous),
        "experimental" => Ok(Profile::Experimental),
        "production" => Ok(Profile::Production),
        _ => Err(anyhow!(
            "unknown profile {s:?} (expected: private | fast | careful | autonomous | experimental | production)"
        )),
    }
}

pub(crate) fn run_tools() -> Result<i32> {
    print_tools();
    Ok(0)
}

pub(crate) fn run_permits_cli(tool: &str, mode: &str, profile: &str) -> Result<i32> {
    run_permits(tool, mode, profile).context("permits check")
}
