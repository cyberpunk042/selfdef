//! SD-R84 (SDD-026 Z-11 foundation) — MCP tool manifest surface.
//!
//! The future `selfdef-mcp-server` (stdio + TCP transports) exposes
//! a curated subset of `selfdefctl` verbs as MCP tool calls. THIS
//! module is the FOUNDATION brick: it pins the operator-facing
//! manifest format + content (which verbs are exposable + their
//! input/output schemas) so the operator's `claude-code` (or any
//! other MCP client) can READ the same manifest the server will
//! later serve.
//!
//! `selfdefctl mcp tools` renders the manifest; default is JSON for
//! programmatic consumers, `--human` for terminal-readable form.
//!
//! Operator workflow (verbatim from the SDD-026 directive):
//!   "Allow to interoperate with an MCP via tools calls and/or MCP.
//!    (e.g. I might install node, claude and whatever deps and use
//!    it on it.)"
//!
//! Curated subset (cycle-8 opening): read-only verbs only. Write
//! verbs (apply / set-mode / fetch) land in subsequent rounds with
//! explicit opt-in per-tool gates.

use serde::Serialize;

/// One MCP tool entry — JSON-Schema-shaped input + output + the
/// underlying selfdefctl invocation the future server runs.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct McpTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
    /// Operator-readable mapping from MCP tool to the CLI command
    /// the server will exec internally. Surfaces in --human output.
    pub backing_cli: &'static str,
    /// "read-only" / "write" — operator filters which class lands.
    pub category: &'static str,
}

/// SD-R84: the curated cycle-8 tool set.
pub(crate) fn tools() -> Vec<McpTool> {
    vec![
        McpTool {
            name: "selfdef.hardware.posture",
            description: "Render the SAIN-01 hardware-exploit posture summary \
                 (CPU + AVX-512 + ternary AOT capability + ZMM lane \
                  width + recommended Wasm-AOT command). Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "json": {
                        "type": "boolean",
                        "default": false,
                        "description": "machine-readable JSON instead of banner"
                    }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl hardware posture [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.hardware.export",
            description: "Emit the HardwareCapabilities JSON document operators \
                 consume cross-repo (sovereign-os reads this to mirror \
                 the selfdef view of the host). Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "output": {
                        "type": "string",
                        "description": "optional destination path; default stdout"
                    }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl hardware export [--output PATH]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.list",
            description: "List every module manifest in the catalog with optional \
                 --category / --phase filters and --json output. Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "json": { "type": "boolean", "default": false },
                    "category": { "type": "string" },
                    "phase": { "type": "string", "enum": ["pre", "main", "post"] }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules list [--json] [--category C] [--phase P]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.diff",
            description: "Partition catalog × host-config into installed / available \
                 / orphaned buckets. Operator discovers what's installable \
                 and what's stale. Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host_config": { "type": "string" },
                    "dir": { "type": "string" },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules diff [--host-config P] [--dir D] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.install_options",
            description: "SD-R86 (SDD-026 Z-13): surface uninstalled-but-available \
                 catalog modules with operator-actionable recommendations \
                 (ready / blocked-by-hardware / blocked-by-missing-deps / \
                 needs-review). Drives the dashboard's 'Install options' tab. \
                 Operator-named 'modules options-to-install'. Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host_config": { "type": "string" },
                    "dir": { "type": "string" },
                    "category": { "type": "string" },
                    "only_ready": { "type": "boolean", "default": false },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules install-options [--host-config P] [--dir D] [--category C] [--only-ready] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.info",
            description: "Print full module manifest. With --resolved, evaluate \
                 the gate against this host and surface which any_of OR-\
                 branch matched (SD-R80). Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["slug"],
                "properties": {
                    "slug": { "type": "string" },
                    "dir": { "type": "string" },
                    "with_host_status": { "type": "boolean", "default": false },
                    "resolved": { "type": "boolean", "default": false },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules info <slug> [--dir D] [--with-host-status] [--resolved] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.models.lora.list",
            description: "List LoRA adapters tracked in the operator's state file \
                 (SD-R81). Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "state": { "type": "string" },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl models lora list [--state P] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.models.list",
            description: "List registered models in the catalog with R71 taxonomy \
                 columns (class / quant / size / vram / context). Read-only.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "dir": { "type": "string" }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl models list [--dir D]",
            category: "read-only",
        },
    ]
}

pub(crate) fn render_tools_json() -> String {
    let doc = serde_json::json!({
        "schema_version": "1.0.0",
        "round": "SD-R84",
        "sdd_vector": "SDD-026 Z-11 foundation",
        "doctrine": "read-only verbs only in cycle 8; write verbs require \
                     explicit opt-in per-tool gates in future rounds",
        "tools": tools(),
    });
    serde_json::to_string_pretty(&doc).expect("serializes")
}

pub(crate) fn render_tools_human() -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(
        &mut buf,
        "── SD-R84 selfdef MCP tool manifest (SDD-026 Z-11 foundation) ──"
    )
    .unwrap();
    writeln!(&mut buf, "  doctrine: read-only verbs only in cycle 8").unwrap();
    let tools = tools();
    writeln!(&mut buf, "  tools: {}", tools.len()).unwrap();
    writeln!(&mut buf).unwrap();
    for t in &tools {
        writeln!(&mut buf, "  • {}", t.name).unwrap();
        writeln!(&mut buf, "      category: {}", t.category).unwrap();
        writeln!(&mut buf, "      backing_cli: {}", t.backing_cli).unwrap();
        // Wrap the description at ~70 cols for terminal readability.
        let mut col = 0usize;
        write!(&mut buf, "      description: ").unwrap();
        for word in t.description.split_whitespace() {
            if col + word.len() + 1 > 70 {
                write!(&mut buf, "\n                   ").unwrap();
                col = 0;
            }
            if col > 0 {
                write!(&mut buf, " ").unwrap();
                col += 1;
            }
            write!(&mut buf, "{word}").unwrap();
            col += word.len();
        }
        writeln!(&mut buf).unwrap();
        writeln!(&mut buf).unwrap();
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdr84_json_manifest_round_trips() {
        let s = render_tools_json();
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
        assert_eq!(v["schema_version"], "1.0.0");
        assert_eq!(v["round"], "SD-R84");
        let arr = v["tools"].as_array().expect("tools array");
        assert!(arr.len() >= 6);
        for t in arr {
            // Every entry must have the three load-bearing keys.
            assert!(t["name"].is_string());
            assert!(t["description"].is_string());
            assert!(t["backing_cli"].is_string());
            assert!(t["category"].is_string());
            assert!(t["input_schema"].is_object());
        }
    }

    #[test]
    fn sdr84_cycle_8_doctrine_read_only_only() {
        // Every tool MUST be category=read-only in cycle 8.
        for t in tools() {
            assert_eq!(
                t.category, "read-only",
                "tool {} must be read-only in cycle 8",
                t.name
            );
        }
    }

    #[test]
    fn sdr84_human_output_carries_tool_names_and_descriptions() {
        let out = render_tools_human();
        assert!(out.contains("SD-R84 selfdef MCP tool manifest"));
        for t in tools() {
            assert!(out.contains(t.name), "{} missing in human output", t.name);
            assert!(
                out.contains(t.backing_cli),
                "{} backing_cli missing",
                t.name
            );
        }
    }

    #[test]
    fn sdr84_input_schemas_are_well_formed_json_schemas() {
        // Every tool's input_schema must declare type=object +
        // additionalProperties=false (sane defaults for MCP tools).
        for t in tools() {
            assert_eq!(
                t.input_schema["type"], "object",
                "{} input_schema must declare type=object",
                t.name
            );
            assert_eq!(
                t.input_schema["additionalProperties"], false,
                "{} input_schema should set additionalProperties=false",
                t.name
            );
        }
    }
}
