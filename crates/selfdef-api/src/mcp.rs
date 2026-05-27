//! `GET /v1/mcp` — MS011 Z-11 / SDD-026 + SD-R84 MCP-interop
//! foundation discovery surface.
//!
//! Documents the MCP-server tool-manifest contract that
//! `selfdef-mcp-server` (planned) will serve to operator's
//! `claude-code` (or any MCP client). The CLI's
//! `selfdefctl mcp tools` already prints the full catalog;
//! this HTTP endpoint provides the meta-shape (transports,
//! framings, schemas, curation policy) without duplicating the
//! per-tool definitions.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct McpSchema {
    pub transports: &'static [&'static str],
    pub framings: &'static [&'static str],
    pub curation_policy: &'static [&'static str],
    pub catalog_source: &'static str,
    pub schema_format: &'static str,
}

const TRANSPORTS: &[&str] = &[
    "stdio — line-delimited JSON (default)",
    "stdio — LSP framing (Content-Length headers)",
    "tcp   — line-delimited JSON over TCP socket",
];

const FRAMINGS: &[&str] = &[
    "lines — newline-delimited JSON-RPC 2.0",
    "lsp   — Content-Length-framed JSON-RPC 2.0",
];

const CURATION_POLICY: &[&str] = &[
    "cycle-8 opening: read-only verbs only (status / events / findings / health / alerts / trio / modules / ...)",
    "write verbs (apply / set-mode / fetch) deferred to subsequent rounds with operator-tier gates",
    "every tool carries name + description + input_schema + output_schema (JSON Schema strict mode)",
    "sensitive arg redaction per SDD-050 D-1 (passwords / tokens / wildcards) applied before audit",
    "every invocation routes through SDD-050 9-gate pipeline + SDD-043 ToolSideEffect commit envelope",
];

const CATALOG_SOURCE: &str = "selfdef-cli::mcp::tools() — invoke `selfdefctl mcp tools` for the JSON manifest; `--human` for terminal form";

const SCHEMA_FORMAT: &str = "JSON Schema 2020-12 strict mode";

pub(crate) async fn show() -> Json<McpSchema> {
    Json(McpSchema {
        transports: TRANSPORTS,
        framings: FRAMINGS,
        curation_policy: CURATION_POLICY,
        catalog_source: CATALOG_SOURCE,
        schema_format: SCHEMA_FORMAT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants_present() {
        assert_eq!(TRANSPORTS.len(), 3);
        assert_eq!(FRAMINGS.len(), 2);
        assert_eq!(CURATION_POLICY.len(), 5);
        assert!(CATALOG_SOURCE.contains("selfdefctl mcp tools"));
        assert!(SCHEMA_FORMAT.contains("JSON Schema"));
    }
}
