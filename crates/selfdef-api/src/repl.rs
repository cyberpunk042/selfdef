//! `GET /v1/repl` — MS011 Z-12 / SDD-026 multi-tier REPL discovery.
//!
//! Mirrors the CLI's `selfdefctl repl tiers --json` output but
//! served over HTTP so the dashboard's planned REPL tab + external
//! MCP clients can discover the Tier 1 callable surface.
//!
//! The CLI ships the Python bootstrap that operators pipe into
//! `python3 -i`; this HTTP route is the discovery surface, not the
//! interpreter.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct ReplSchema {
    pub tiers: &'static [TierDescriptor],
    pub bootstrap_command: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct TierDescriptor {
    pub id: u8,
    pub name: &'static str,
    pub language: &'static str,
    pub status: &'static str,
    pub description: &'static str,
    pub example_callables: &'static [&'static str],
}

const TIERS: &[TierDescriptor] = &[
    TierDescriptor {
        id: 0,
        name: "Programming",
        language: "Rust",
        status: "shipped",
        description: "Rust crates linked against selfdef-core directly. Highest performance + full type-safety. The path the shipping CLI binary already takes.",
        example_callables: &[
            "selfdef_hardware::probe",
            "selfdef_hardware::derive_capabilities",
            "selfdef_signing::Verifier::load",
        ],
    },
    TierDescriptor {
        id: 1,
        name: "Proto-Programming",
        language: "Python",
        status: "shipped",
        description: "Python REPL with subprocess wrappers around selfdefctl verbs. Operator pastes `python3 -i -c \"$(selfdefctl repl bootstrap)\"` for a session with hardware() / posture() / modules() / models() / mcp_tools() / lora_*() callables that shell out + parse the JSON. SD-R85 seed.",
        example_callables: &[
            "hardware()",
            "posture()",
            "modules(category=None, phase=None)",
            "models()",
            "mcp_tools()",
            "modules_diff(host_config=None, dir=None)",
            "modules_install_options(host_config=None, dir=None, category=None, only_ready=False)",
            "modules_install_plan(host_config=None, dir=None, category=None)",
            "lora_list / lora_attach / lora_detach / lora_set_status",
            "SD-R97 aliases: h() p() m() mi(slug) md() mio() mip() lo() la() ld() ls() mt() mtt() rh(N)",
            "SD-R97 @track(name) — wasted-path tracker for Tier 2 macros",
        ],
    },
    TierDescriptor {
        id: 2,
        name: "Proto-Proto-Programming",
        language: "Python (operator-defined)",
        status: "operator-pull",
        description: "Operator-owned layer on TOP of Tier 1. Custom CoT loops + DSL macros + token-saving aliases that wrap Tier 1 calls into operator-meaningful idioms. We ship Tier 1 + the manifest; operator owns Tier 2.",
        example_callables: &["(operator-supplied macros — register with @selfdef_macro)"],
    },
];

const BOOTSTRAP_COMMAND: &str =
    "python3 -i -c \"$(selfdefctl repl bootstrap)\"";

pub(crate) async fn show() -> Json<ReplSchema> {
    Json(ReplSchema {
        tiers: TIERS,
        bootstrap_command: BOOTSTRAP_COMMAND,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_canonical_order() {
        assert_eq!(TIERS.len(), 3);
        assert_eq!(TIERS[0].id, 0);
        assert_eq!(TIERS[0].name, "Programming");
        assert_eq!(TIERS[1].id, 1);
        assert_eq!(TIERS[1].name, "Proto-Programming");
        assert_eq!(TIERS[2].id, 2);
        assert_eq!(TIERS[2].name, "Proto-Proto-Programming");
    }

    #[test]
    fn bootstrap_command_matches_cli() {
        assert!(BOOTSTRAP_COMMAND.contains("selfdefctl repl bootstrap"));
    }
}
