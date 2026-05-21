//! `GET /v1/tool-authority` — MS042 / SDD-050 D-2 schema discovery
//! surface.
//!
//! Returns the static tool-policy doctrine as JSON so agents (MCP /
//! dashboard / external tooling) can learn the 11-crate tool-policy
//! pipeline contract without reading the Rust source.
//!
//! Static-only — the doctrine doesn't change at runtime.
//!
//! Source: SDD-050 § Open questions D-2 + `selfdefctl tool-authority
//! tools` (the CLI variant shipped at commit 1e28fe4).

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct ToolAuthoritySchema {
    pub tool_ids: &'static [ToolDescriptor],
    pub execution_modes: &'static [&'static str],
    pub profiles: &'static [&'static str],
    pub gate_pipeline: &'static [GateDescriptor],
    pub post_pipeline: &'static [&'static str],
    pub refusal_rules: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolDescriptor {
    pub id: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct GateDescriptor {
    pub order: u8,
    pub name: &'static str,
    pub crate_name: &'static str,
    pub vocabulary: &'static str,
}

const TOOL_IDS: &[ToolDescriptor] = &[
    ToolDescriptor { id: "Shell", description: "arbitrary shell command" },
    ToolDescriptor { id: "FsRead", description: "filesystem read" },
    ToolDescriptor { id: "FsWrite", description: "filesystem write" },
    ToolDescriptor { id: "WebFetch", description: "HTTP GET / POST (gated by SDD-046 NetworkProfile)" },
    ToolDescriptor { id: "ModelInference", description: "LLM call" },
    ToolDescriptor { id: "McpBridge", description: "MCP tool dispatch" },
    ToolDescriptor { id: "ReplayControl", description: "replay / counterfactual" },
    ToolDescriptor { id: "CliBridge", description: "selfdefctl bridge call" },
];

const EXECUTION_MODES: &[&str] = &[
    "Plan", "DryRun", "Shadow", "Sandbox", "Execute", "Replay", "Debug",
];

const PROFILES: &[&str] = &[
    "Private", "Fast", "Careful", "Autonomous", "Experimental", "Production",
];

const GATE_PIPELINE: &[GateDescriptor] = &[
    GateDescriptor { order: 1, name: "admit", crate_name: "selfdef-tool-invocation-rate-limit", vocabulary: "Allow / Denied" },
    GateDescriptor { order: 2, name: "permits", crate_name: "selfdef-tool-capability-policy", vocabulary: "Allow / NotAuthorized" },
    GateDescriptor { order: 3, name: "version-pin", crate_name: "selfdef-tool-version-pinning", vocabulary: "Allow / VersionMismatch" },
    GateDescriptor { order: 4, name: "redact-args", crate_name: "selfdef-tool-arg-redaction-policy", vocabulary: "exact / suffix / prefix / wildcard" },
    GateDescriptor { order: 5, name: "audit", crate_name: "selfdef-commit-authority", vocabulary: "SDD-043 ToolSideEffect commit envelope" },
    GateDescriptor { order: 6, name: "invoke", crate_name: "(caller-owned)", vocabulary: "execute the tool" },
    GateDescriptor { order: 7, name: "watchdog", crate_name: "selfdef-tool-stream-watchdog", vocabulary: "Ok / Silence / TotalElapsed" },
    GateDescriptor { order: 8, name: "admit_chunk", crate_name: "selfdef-tool-output-byte-quota", vocabulary: "Accept / Truncate / Refuse" },
    GateDescriptor { order: 9, name: "truncate", crate_name: "selfdef-tool-output-truncation-policy", vocabulary: "HeadOnly / HeadTail / MiddleEllipsis" },
];

const POST_PIPELINE: &[&str] = &[
    "shape-check (selfdef-tool-output-language-policy) — Pass / ShapeMismatch",
    "veil-wrap (selfdef-tool-output-trust-veil) — Veil<Tier>; consumers unveil_with_tier(expected)",
];

const REFUSAL_RULES: &[&str] = &[
    "Any non-Allow gate verdict → REFUSE (operator-readable error citing gate)",
    "VeilTierMismatch on unveil → REFUSE (typed cross-tier promotion blocked per SDD-050 D-4)",
];

/// `GET /v1/tool-authority` handler.
pub(crate) async fn show() -> Json<ToolAuthoritySchema> {
    Json(ToolAuthoritySchema {
        tool_ids: TOOL_IDS,
        execution_modes: EXECUTION_MODES,
        profiles: PROFILES,
        gate_pipeline: GATE_PIPELINE,
        post_pipeline: POST_PIPELINE,
        refusal_rules: REFUSAL_RULES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_match_sdd_050() {
        assert_eq!(TOOL_IDS.len(), 8);
        assert_eq!(TOOL_IDS[0].id, "Shell");
        assert_eq!(TOOL_IDS[7].id, "CliBridge");
        assert_eq!(EXECUTION_MODES.len(), 7);
        assert_eq!(PROFILES.len(), 6);
        assert_eq!(GATE_PIPELINE.len(), 9);
        assert_eq!(GATE_PIPELINE[0].name, "admit");
        assert_eq!(GATE_PIPELINE[8].name, "truncate");
    }

    #[test]
    fn gate_pipeline_orders_monotonic() {
        let mut last = 0u8;
        for g in GATE_PIPELINE {
            assert!(
                g.order > last,
                "gate pipeline must be monotonic: gate {} at order {} after order {}",
                g.name,
                g.order,
                last
            );
            last = g.order;
        }
    }
}
