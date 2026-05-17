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
            name: "selfdef.modules.config_scaffold",
            description: "SD-R88 (SDD-026 Z-13 follow-up): emit a copy-pasteable \
                 config scaffold for one catalog module — the operator's next \
                 step AFTER SD-R87 install-plan tells them WHAT to install. \
                 Returns a ready-to-paste [modules.\"<slug>\"] block + matching \
                 [daemon.*] keys; instanced modules require the `instance` arg. \
                 Read-only (no host_config mutation).",
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["slug"],
                "properties": {
                    "slug": { "type": "string" },
                    "dir": { "type": "string" },
                    "instance": { "type": "string" },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules config-scaffold <slug> [--dir D] [--instance NAME] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.apply_plan",
            description: "SD-R93 (SDD-026 Z-13 execution): apply the SD-R87 \
                 install-plan end-to-end. Walks each step, invokes `apply \
                 --only <slug>` per step, returns per-step outcome. DRY-RUN \
                 by default (preview). Cycle-8 read-only doctrine: this MCP \
                 entry exposes ONLY the dry-run path; the `--apply` flag \
                 path is operator-CLI-only until the write-tool gate lands.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host_config": { "type": "string" },
                    "dir": { "type": "string" },
                    "category": { "type": "string" },
                    "continue_on_failure": { "type": "boolean", "default": false },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules apply-plan [--host-config P] [--dir D] [--category C] [--continue-on-failure] [--json]",
            category: "read-only",
        },
        McpTool {
            name: "selfdef.modules.install_plan",
            description: "SD-R87 (SDD-026 Z-13 closure): topologically-ordered \
                 install plan over the SD-R86 plan-ready set. Returns the \
                 numbered sequence of `selfdefctl modules apply --only <slug>` \
                 commands the operator runs. Cycles in the dep graph surface \
                 as cycle_present=true with the unresolved nodes listed; \
                 manifests must be corrected before retrying. Read-only \
                 (computes plan; does not mutate host_config).",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "host_config": { "type": "string" },
                    "dir": { "type": "string" },
                    "category": { "type": "string" },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl modules install-plan [--host-config P] [--dir D] [--category C] [--json]",
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
        // SD-R89 LoRA mutation verbs (attach / detach / set-status)
        // are deliberately NOT exposed via MCP in cycle 8 — SD-R84
        // doctrine pins MCP tools to read-only only. The CLI surface
        // covers operator-explicit LoRA writes; an MCP-write gate
        // (with SELFDEF_MCP_ALLOW_WRITES=YES) lands in a follow-up
        // round after the write-tool authorization model is signed.
        McpTool {
            name: "selfdef.repl.tier2_examples",
            description: "SD-R90 (SDD-026 Z-12 follow-up): list the operator-\
                 facing Tier 2 (Proto-Proto-Programming) example macros the \
                 CLI ships as starting-point demonstrations of the operator-\
                 extension layer. MCP-callable so an AI orchestrator can \
                 fetch the source + execute it on the operator's behalf. \
                 Returns the same {name, summary, source} rows the CLI emits.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "json": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            }),
            backing_cli: "selfdefctl repl tier2-examples [--name N] [--json]",
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

// ============================================================
// SD-R91: line-delimited JSON-RPC MCP server (stdio).
// ============================================================

/// SD-R91 (SDD-026 Z-11 closure): stdio JSON-RPC MCP server.
///
/// Wire format: line-delimited JSON-RPC 2.0. Read one request per
/// line from stdin, write one response per line to stdout. Real MCP
/// clients use Content-Length framing; a small shim can wrap this
/// for those clients, but the LINE-DELIMITED form is what we ship
/// in cycle 8 — it's testable + scriptable + composable with `jq`.
///
/// Supported methods:
///   initialize       → returns serverInfo + capabilities
///   tools/list       → returns the SD-R84 tools (only category=read-only)
///   tools/call       → dispatches to selfdefctl subprocess
///                      params: { name: "<tool>", arguments: {...} }
///   shutdown         → no-op (returns null), client should close stdin
///
/// All other methods return JSON-RPC error -32601 (Method not found).
/// Write-category tools (cycle-8 doctrine forbids these via MCP) are
/// NOT in `tools/list` output and return -32601 on `tools/call`.
///
/// exit_after: when Some(N), serve exits cleanly after handling N
/// requests (test fixture; production uses None = until stdin closes).
pub(crate) fn serve_stdio(exit_after: Option<u32>, framing: &str) -> anyhow::Result<i32> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let out = stdout.lock();
    match framing {
        "line" => serve_stdio_line(exit_after, stdin.lock(), out),
        "lsp" => serve_stdio_lsp(exit_after, stdin.lock(), out),
        other => {
            eprintln!("ERROR unknown framing {other:?} (use `line` or `lsp`)");
            Ok(2)
        }
    }
}

fn serve_stdio_line<R, W>(exit_after: Option<u32>, reader: R, mut writer: W) -> anyhow::Result<i32>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let mut handled: u32 = 0;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = handle_jsonrpc_line(trimmed);
        writeln!(writer, "{resp}")?;
        writer.flush()?;
        handled += 1;
        if let Some(n) = exit_after {
            if handled >= n {
                break;
            }
        }
    }
    Ok(0)
}

/// SD-R92 — LSP-style Content-Length framing (real MCP wire format).
///
/// Per the JSON-RPC base protocol used by LSP + MCP, each message is
/// preceded by header lines (Content-Length and optionally
/// Content-Type), a blank line, then exactly Content-Length bytes of
/// JSON payload. Responses follow the same format.
fn serve_stdio_lsp<R, W>(
    exit_after: Option<u32>,
    mut reader: R,
    mut writer: W,
) -> anyhow::Result<i32>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let mut handled: u32 = 0;
    loop {
        // Parse headers (one per line, terminated by blank line).
        let mut content_length: Option<usize> = None;
        loop {
            let mut header = String::new();
            let n = match reader.read_line(&mut header) {
                Ok(n) => n,
                Err(_) => return Ok(0),
            };
            if n == 0 {
                // EOF before any header → operator closed stdin.
                return Ok(0);
            }
            let trimmed = header.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                // Blank line: end of headers.
                break;
            }
            // Case-insensitive Content-Length: <int>
            if let Some(rest) = trimmed
                .strip_prefix("Content-Length:")
                .or_else(|| trimmed.strip_prefix("content-length:"))
            {
                if let Ok(v) = rest.trim().parse::<usize>() {
                    content_length = Some(v);
                }
            }
            // Other headers (Content-Type) are ignored — we always
            // emit application/vscode-jsonrpc; charset=utf-8.
        }
        let len = match content_length {
            Some(v) => v,
            None => {
                // Bad framing — emit a parse-error response per LSP.
                let resp = error_response(
                    serde_json::Value::Null,
                    -32700,
                    "Parse error: missing Content-Length",
                );
                write_lsp_message(&mut writer, &resp)?;
                handled += 1;
                if let Some(n) = exit_after {
                    if handled >= n {
                        break;
                    }
                }
                continue;
            }
        };
        // Read exactly `len` bytes of payload.
        let mut buf = vec![0u8; len];
        if reader.read_exact(&mut buf).is_err() {
            break;
        }
        let payload = String::from_utf8_lossy(&buf);
        let resp = handle_jsonrpc_line(payload.trim());
        write_lsp_message(&mut writer, &resp)?;
        handled += 1;
        if let Some(n) = exit_after {
            if handled >= n {
                break;
            }
        }
    }
    Ok(0)
}

/// SD-R94: TCP transport for the MCP server.
///
/// Binds `bind` (HOST:PORT), accepts connections, and dispatches each
/// using the same per-line/per-LSP-message machinery that stdio uses.
/// `exit_after` limits the total number of CONNECTIONS handled (not
/// requests) — production uses None (until killed); L3 tests pin a
/// small N for deterministic teardown.
///
/// Per-connection auth: when `token_env` is Some(VAR) and the env var
/// resolves to a non-empty value, the first line of each connection
/// MUST be `Authorization: Bearer <value>` or the connection is
/// closed without processing requests.
pub(crate) fn serve_tcp(
    bind: &str,
    framing: &str,
    token_env: Option<&str>,
    exit_after: Option<u32>,
) -> anyhow::Result<i32> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    if framing != "line" && framing != "lsp" {
        eprintln!("ERROR unknown framing {framing:?} (use `line` or `lsp`)");
        return Ok(2);
    }
    let expected_token: Option<String> = token_env
        .and_then(|v| std::env::var(v).ok())
        .filter(|s| !s.is_empty());
    if token_env.is_some() && expected_token.is_none() {
        eprintln!(
            "ERROR --token-env {:?} resolved to empty (export the env var)",
            token_env.unwrap_or("")
        );
        return Ok(2);
    }

    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR bind {bind}: {e}");
            return Ok(2);
        }
    };
    eprintln!(
        "# SD-R94 selfdef MCP TCP serving on {bind} (framing={framing}, auth={})",
        if expected_token.is_some() {
            "required"
        } else {
            "none"
        }
    );

    let mut handled: u32 = 0;
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => break,
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;

        // Per-connection auth preamble.
        if let Some(ref want) = expected_token {
            let mut header = String::new();
            if reader.read_line(&mut header).is_err() {
                handled += 1;
                if let Some(n) = exit_after {
                    if handled >= n {
                        break;
                    }
                }
                continue;
            }
            let trimmed = header.trim_end_matches(['\r', '\n']);
            let ok = trimmed
                .strip_prefix("Authorization: Bearer ")
                .or_else(|| trimmed.strip_prefix("authorization: bearer "))
                .map(|t| t == want.as_str())
                .unwrap_or(false);
            if !ok {
                let _ = writeln!(
                    writer,
                    "{}",
                    error_response(
                        serde_json::Value::Null,
                        -32001,
                        "Unauthorized: bad or missing Authorization preamble",
                    )
                );
                drop(writer);
                handled += 1;
                if let Some(n) = exit_after {
                    if handled >= n {
                        break;
                    }
                }
                continue;
            }
            eprintln!("# SD-R94 accepted {peer} (auth OK)");
        } else {
            eprintln!("# SD-R94 accepted {peer} (no auth)");
        }

        // Dispatch using the same handlers as stdio.
        let dispatch_result = match framing {
            "line" => serve_stdio_line(None, reader, writer),
            "lsp" => serve_stdio_lsp(None, reader, writer),
            _ => unreachable!(),
        };
        if let Err(e) = dispatch_result {
            eprintln!("# SD-R94 dispatch error: {e}");
        }
        handled += 1;
        if let Some(n) = exit_after {
            if handled >= n {
                break;
            }
        }
    }
    Ok(0)
}

fn write_lsp_message<W: std::io::Write>(writer: &mut W, payload: &str) -> std::io::Result<()> {
    let bytes = payload.as_bytes();
    write!(
        writer,
        "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n",
        bytes.len()
    )?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

fn handle_jsonrpc_line(line: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                serde_json::Value::Null,
                -32700,
                &format!("Parse error: {e}"),
            );
        }
    };
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = match req.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return error_response(id, -32600, "Invalid Request: missing 'method'"),
    };
    let params = req.get("params").cloned().unwrap_or(serde_json::json!({}));
    let result: Result<serde_json::Value, (i64, String)> = match method {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "selfdefctl-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": { "listChanged": false },
            },
        })),
        "tools/list" => Ok(serde_json::json!({
            "tools": tools()
                .into_iter()
                .filter(|t| t.category == "read-only")
                .map(|t| serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                }))
                .collect::<Vec<_>>(),
        })),
        "tools/call" => handle_tools_call(&params),
        "shutdown" => Ok(serde_json::Value::Null),
        _ => Err((-32601, format!("Method not found: {method}"))),
    };
    match result {
        Ok(v) => success_response(id, v),
        Err((code, msg)) => error_response(id, code, &msg),
    }
}

fn success_response(id: serde_json::Value, result: serde_json::Value) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap_or_else(|_| String::from("{}"))
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    }))
    .unwrap_or_else(|_| String::from("{}"))
}

fn handle_tools_call(params: &serde_json::Value) -> Result<serde_json::Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or((-32602, "Invalid params: missing 'name'".to_string()))?;
    let tool = tools()
        .into_iter()
        .find(|t| t.name == name && t.category == "read-only")
        .ok_or((-32601, format!("tool not exposed: {name}")))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    // Build subprocess argv from the backing_cli template + arguments.
    let argv = build_subprocess_argv(&tool, &arguments)?;
    // Spawn selfdefctl with the resolved argv.
    let exe = std::env::current_exe().map_err(|e| (-32603, format!("locating selfdefctl: {e}")))?;
    let output = std::process::Command::new(&exe)
        .arg("--config")
        .arg("/dev/null")
        .args(&argv)
        .output()
        .map_err(|e| (-32603, format!("spawn selfdefctl: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 && exit_code != 1 {
        // rc 0 + 1 are both "data emitted" cases; only ≥2 is a real
        // tool error from the MCP caller's perspective.
        return Err((
            -32000,
            format!("tool exit_code={exit_code}: {}", stderr.trim()),
        ));
    }
    Ok(serde_json::json!({
        "content": [
            { "type": "text", "text": stdout }
        ],
        "isError": exit_code != 0,
        "exit_code": exit_code,
    }))
}

fn build_subprocess_argv(
    tool: &McpTool,
    arguments: &serde_json::Value,
) -> Result<Vec<String>, (i64, String)> {
    // The backing_cli string is "selfdefctl <verb> [args]"; we want
    // just the args after "selfdefctl". Tools follow a stable pattern:
    // every tool's backing_cli starts with "selfdefctl ", and the
    // command shape mirrors the JSON schema property names: positional
    // args first, then --flag values. We re-derive argv from the
    // schema rather than parsing the backing_cli — schema is authoritative.
    let cli = tool.backing_cli;
    let cli_tail = cli.strip_prefix("selfdefctl ").unwrap_or(cli);
    // Verb words (everything before the first `[` or `<`).
    let mut verb_words: Vec<String> = Vec::new();
    for w in cli_tail.split_whitespace() {
        if w.starts_with('[') || w.starts_with('<') || w.starts_with("--") {
            break;
        }
        verb_words.push(w.to_string());
    }
    let obj = arguments
        .as_object()
        .ok_or((-32602, "arguments must be object".to_string()))?;

    // Positional args: pull each `<NAME>` from the cli template (in
    // order) and substitute from arguments by that name. Required
    // positionals are declared in `schema.required`.
    let schema = &tool.input_schema;
    let required = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Extract positional placeholder names from cli (e.g. <slug>, <adapter_id>).
    let positional_names: Vec<String> = cli_tail
        .split_whitespace()
        .filter_map(|w| {
            let w = w.trim_matches(|c| c == ',');
            if let Some(stripped) = w.strip_prefix('<') {
                stripped.strip_suffix('>').map(|s| s.replace('-', "_"))
            } else {
                None
            }
        })
        .collect();

    let mut argv = verb_words.clone();
    for pname in &positional_names {
        match obj.get(pname.as_str()) {
            Some(v) => argv.push(scalar_to_string(v)?),
            None => {
                if required.contains(pname) {
                    return Err((-32602, format!("missing required arg: {pname}")));
                }
            }
        }
    }
    // Optional named flags: every property in arguments that isn't a
    // positional becomes --kebab-case <value> (or just --kebab when
    // boolean true). Booleans-false and nulls are skipped.
    for (k, v) in obj {
        if positional_names.contains(k) {
            continue;
        }
        let flag = format!("--{}", k.replace('_', "-"));
        match v {
            serde_json::Value::Bool(true) => argv.push(flag),
            serde_json::Value::Bool(false) | serde_json::Value::Null => {}
            _ => {
                argv.push(flag);
                argv.push(scalar_to_string(v)?);
            }
        }
    }
    Ok(argv)
}

fn scalar_to_string(v: &serde_json::Value) -> Result<String, (i64, String)> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err((-32602, format!("non-scalar argument: {v}"))),
    }
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
