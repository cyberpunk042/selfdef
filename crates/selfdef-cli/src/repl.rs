//! SD-R85 (SDD-026 Z-12 foundation) — operator-facing REPL surface.
//!
//! The operator named (verbatim): "I think there is also the notion
//! of python and multiple level and something called REPL. but
//! that's just one layer, one place we can do someting with this,
//! its deeper I think, how we can go deep with the language when we
//! know what we want to do, want we want to add, to to enhence, to
//! alterate, to wrap, to save/need less tokens, save wasted paths
//! / useless tracks and stuff like all this. Programming,
//! Proto--Programing, Proto-Proto-Programming and inside REPL you
//! do you own things and you even have custom CoT or such and
//! advanced tailored features and enhencement and our own
//! integrated intelligence and etc."
//!
//! Three tiers — this round (cycle 8) seeds Tier 1; Tier 2 is the
//! operator-extension surface that wraps Tier 1 calls into custom
//! CoT loops + DSL macros + token-saving aliases.
//!
//!   Tier 0 — Programming
//!            Rust crates linked against selfdef-core directly.
//!            Highest performance + full type-safety. The path the
//!            shipping CLI binary already takes.
//!
//!   Tier 1 — Proto-Programming
//!            Python REPL with thin subprocess wrappers around
//!            selfdefctl verbs. Operator pastes
//!            `python3 -i -c "$(selfdefctl repl bootstrap)"` and
//!            gets a session with `hardware()`, `modules()`,
//!            `models()`, `mcp_tools()` Python callables that shell
//!            out + parse the JSON. Iteration cost: zero compile;
//!            usable from a Jupyter notebook in the future Z-1
//!            dashboard.
//!
//!   Tier 2 — Proto-Proto-Programming (operator-pull)
//!            The operator-owned layer on TOP of Tier 1. They write
//!            their own `def my_chat_loop(...)` wrapping Tier 1
//!            calls into custom Chain-of-Thought routines + DSL
//!            macros + token-saving aliases. We ship Tier 1 + the
//!            tier MANIFEST that names the surface; the operator
//!            owns Tier 2.
//!
//! `selfdefctl repl bootstrap` prints the Tier 1 seed script. The
//! operator pipes it into Python:
//!
//! ```text
//!   $ python3 -i -c "$(selfdefctl repl bootstrap)"
//!   selfdef REPL — Tier 1 (Proto-Programming) ready.
//!     hardware()   -> dict   (selfdefctl hardware --json)
//!     posture()    -> dict   (selfdefctl hardware posture --json)
//!     modules()    -> list   (selfdefctl modules list --json)
//!     models()     -> list   (selfdefctl models list)
//!     mcp_tools()  -> dict   (selfdefctl mcp tools)
//!   PYREPL> caps = hardware()
//!   PYREPL> caps['cpu']['ternary_aot_capable']
//!   True
//! ```
//!
//! Future round wires actual pyo3 bindings (selfdef-core →
//! native callables) for zero-subprocess Tier 1; for now subprocess
//! is good enough to seed the surface contract.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct Tier {
    pub id: u8,
    pub name: &'static str,
    pub description: &'static str,
    pub language: &'static str,
    pub status: &'static str,
    pub example_callables: Vec<&'static str>,
}

pub(crate) fn tiers() -> Vec<Tier> {
    vec![
        Tier {
            id: 0,
            name: "Programming",
            description: "Rust crates linked against selfdef-core directly. \
                 Highest performance + full type-safety. The path the \
                 shipping CLI binary already takes.",
            language: "Rust",
            status: "shipped",
            example_callables: vec![
                "selfdef_hardware::probe",
                "selfdef_hardware::derive_capabilities",
                "selfdef_signing::Verifier::load",
            ],
        },
        Tier {
            id: 1,
            name: "Proto-Programming",
            description: "Python REPL with subprocess wrappers around selfdefctl verbs. \
                 Operator pastes `python3 -i -c \"$(selfdefctl repl bootstrap)\"` \
                 and gets a session with hardware() / posture() / modules() / \
                 models() / mcp_tools() callables that shell out + parse the JSON. \
                 SD-R85 seed.",
            language: "Python",
            status: "shipped",
            example_callables: vec![
                "hardware()",
                "posture()",
                "modules(category=None, phase=None)",
                "models()",
                "mcp_tools()",
                "modules_diff(host_config=None, dir=None)",
                "modules_install_options(host_config=None, dir=None, category=None, only_ready=False)",
                "modules_install_plan(host_config=None, dir=None, category=None)",
                "modules_config_scaffold(slug, dir=None, instance=None)",
                "modules_apply_plan(host_config=None, dir=None, category=None, continue_on_failure=False)",
                "lora_list(state=None)",
                "lora_attach(adapter_id, base_model, status=None, state=None)",
                "lora_detach(adapter_id, state=None)",
                "lora_set_status(adapter_id, status, state=None)",
                "SD-R97 aliases: h() p() m() mi(slug) md() mio() mip() lo() la() ld() ls() mt() mtt() rh(N)",
                "SD-R97 @track(name) — wasted-path tracker for Tier 2 macros",
                "SD-R102 auto-load: $SELFDEF_REPL_MACROS > ~/.config/selfdef/repl-macros.py",
            ],
        },
        Tier {
            id: 2,
            name: "Proto-Proto-Programming",
            description: "Operator-owned layer on TOP of Tier 1. Custom CoT loops + DSL \
                 macros + token-saving aliases that wrap Tier 1 calls into \
                 operator-meaningful idioms. We ship Tier 1 + the manifest + \
                 the SD-R102 auto-load hook; operator owns the macros file.",
            language: "Python (operator-defined)",
            status: "operator-pull",
            example_callables: vec![
                "(operator-supplied macros — register with @selfdef_macro)",
                "SD-R102 persist: drop the file at $SELFDEF_REPL_MACROS or ~/.config/selfdef/repl-macros.py",
            ],
        },
    ]
}

pub(crate) fn render_tiers_json() -> String {
    let doc = serde_json::json!({
        "schema_version": "1.0.0",
        "round": "SD-R85",
        "sdd_vector": "SDD-026 Z-12 foundation",
        "tiers": tiers(),
    });
    serde_json::to_string_pretty(&doc).expect("serializes")
}

pub(crate) fn render_tiers_human() -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(
        &mut buf,
        "── SD-R85 selfdef REPL tier manifest (SDD-026 Z-12 foundation) ──"
    )
    .unwrap();
    for t in tiers() {
        writeln!(&mut buf).unwrap();
        writeln!(
            &mut buf,
            "Tier {} — {} ({}) [{}]",
            t.id, t.name, t.language, t.status
        )
        .unwrap();
        // Wrap description at ~70 cols.
        let mut col = 2usize;
        write!(&mut buf, "  ").unwrap();
        for word in t.description.split_whitespace() {
            if col + word.len() + 1 > 70 {
                write!(&mut buf, "\n  ").unwrap();
                col = 2;
            }
            if col > 2 {
                write!(&mut buf, " ").unwrap();
                col += 1;
            }
            write!(&mut buf, "{word}").unwrap();
            col += word.len();
        }
        writeln!(&mut buf).unwrap();
        if !t.example_callables.is_empty() {
            writeln!(&mut buf, "  callables:").unwrap();
            for c in &t.example_callables {
                writeln!(&mut buf, "    - {c}").unwrap();
            }
        }
    }
    buf
}

/// SD-R85: Python bootstrap script for Tier 1.
pub(crate) fn bootstrap_script() -> String {
    // The script intentionally uses subprocess (not pyo3 bindings) so it
    // works with any Python installed on the operator's host. Future
    // round adds the native-binding path under the same callable names.
    r#"# SD-R85 selfdef REPL bootstrap — Tier 1 (Proto-Programming).
# Pipe into Python:
#   python3 -i -c "$(selfdefctl repl bootstrap)"
import json as _json
import os   as _os
import shutil as _shutil
import subprocess as _subp
import sys as _sys

_SELFDEFCTL = _shutil.which("selfdefctl")
if _SELFDEFCTL is None:
    print(
        "ERROR selfdefctl not on PATH — Tier 1 needs the CLI installed.",
        file=_sys.stderr,
    )

# SD-R95: opt-in JSONL audit trail of every _ctl() call. Set the env
# var to a path the operator owns; the wrapper appends one line per
# invocation. Operator-pull surface: dashboards / event-timeline read
# the file alongside R246 sovereign-os events aggregator.
_HISTORY_PATH = _os.environ.get("SELFDEF_REPL_HISTORY")

def _record_history(args, rc, started_at, duration_ms):
    """Append one JSONL row to SELFDEF_REPL_HISTORY when set."""
    if not _HISTORY_PATH:
        return
    try:
        with open(_HISTORY_PATH, "a") as fh:
            fh.write(_json.dumps({
                "round": "SD-R95",
                "started_at": started_at,
                "duration_ms": duration_ms,
                "argv": list(args),
                "rc": rc,
            }) + "\n")
    except OSError:
        # Audit failure must NEVER take the operator's Tier 1 call down.
        pass

def _ctl(*args):
    """Run selfdefctl + parse JSON stdout. Returns parsed dict/list.

    SD-R95: when SELFDEF_REPL_HISTORY is set, each call is appended to
    that JSONL file with {argv, rc, started_at, duration_ms} so the
    operator gets an audit trail of every Tier 1 + Tier 2 invocation.

    SD-R101 (E8.M5): when SELFDEF_MCP_URL is set (format
    `tcp://host:port`) the call is routed through the SD-R94 MCP TCP
    transport instead of fork+exec'ing selfdefctl. The result is the
    same JSON the subprocess would have returned, but the operator's
    REPL pays a single socket roundtrip instead of a process spawn —
    closes E8.M5 (zero-subprocess Tier 1) via the MCP bridge without
    requiring pyo3 / unsafe code.

    The MCP URL can also be set on a per-call basis at the top of the
    bootstrap session — operators audit which transport was used via
    the SD-R95 history's `transport` field (added in this round).
    """
    import time as _time
    started_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    mcp_url = _os.environ.get("SELFDEF_MCP_URL", "").strip()
    if mcp_url:
        t0 = _time.time()
        try:
            result = _ctl_via_mcp(args, mcp_url)
            duration_ms = int((_time.time() - t0) * 1000)
            _record_history_v2(args, 0, started_at, duration_ms, "mcp-tcp")
            return result
        except RuntimeError:
            duration_ms = int((_time.time() - t0) * 1000)
            _record_history_v2(args, -1, started_at, duration_ms, "mcp-tcp")
            raise
    if _SELFDEFCTL is None:
        # Record the failed attempt before raising — operators auditing
        # a session see what was tried even when the CLI is missing.
        _record_history_v2(args, -1, started_at, 0, "subprocess")
        raise RuntimeError("selfdefctl missing — install the selfdef-cli crate")
    t0 = _time.time()
    r = _subp.run(
        [_SELFDEFCTL, *args],
        capture_output=True, text=True, check=False, timeout=20,
    )
    duration_ms = int((_time.time() - t0) * 1000)
    _record_history_v2(args, r.returncode, started_at, duration_ms, "subprocess")
    if r.returncode != 0:
        raise RuntimeError(
            f"selfdefctl {' '.join(args)} exited {r.returncode}: {r.stderr.strip()}"
        )
    if not r.stdout.strip():
        return None
    try:
        return _json.loads(r.stdout)
    except _json.JSONDecodeError:
        return r.stdout  # fall back to raw stdout

# SD-R101 (E8.M5): argv → MCP tool name + arguments translation.
# Each Tier 1 callable's argv shape maps to one SD-R94 MCP tool.
# Operator-readable mapping table — easy to extend as new MCP tools
# land in selfdef-cli's mcp.rs.
def _argv_to_mcp_call(args):
    """Translate (*argv) to (tool_name, arguments_dict).

    Returns None if the argv shape isn't covered by the MCP tool
    catalog (operator falls back to subprocess transparently).

    Every Tier 1 callable appends `--json`; the MCP tool schemas all
    expose a `json` boolean (default false) that we MUST set to true
    so the tool's backing CLI runs in JSON mode. The translator
    auto-injects it into the arguments dict — no caller needs to
    remember.
    """
    a = list(args)
    # Strip a trailing --json — every Tier 1 caller appends it; MCP
    # tools always return JSON when `json=true` lands in arguments.
    if a and a[-1] == "--json":
        a = a[:-1]
    if not a:
        return None

    def _with_json(tool_name, arg_dict=None):
        arg_dict = dict(arg_dict or {})
        arg_dict["json"] = True
        return tool_name, arg_dict

    # Hardware surface.
    # selfdef.hardware.export is JSON-only by design (no `json` knob in
    # its schema; adding one fails CLI argparse). Skip the auto-inject.
    if a == ["hardware"]:
        return "selfdef.hardware.export", {}
    if a == ["hardware", "posture"]:
        return _with_json("selfdef.hardware.posture")

    # Modules surface.
    if a[:2] == ["modules", "list"]:
        kw = {}
        i = 2
        while i < len(a):
            if a[i] == "--category" and i + 1 < len(a):
                kw["category"] = a[i + 1]; i += 2; continue
            if a[i] == "--phase" and i + 1 < len(a):
                kw["phase"] = a[i + 1]; i += 2; continue
            i += 1
        return _with_json("selfdef.modules.list", kw)
    if a[:2] == ["modules", "info"] and len(a) >= 3:
        kw = {"slug": a[2]}
        if "--resolved" in a:
            kw["resolved"] = True
        return _with_json("selfdef.modules.info", kw)
    if a[:2] == ["modules", "diff"]:
        return _with_json("selfdef.modules.diff", _kv_pairs(a[2:]))
    if a[:2] == ["modules", "install-options"]:
        return _with_json("selfdef.modules.install_options", _kv_pairs(a[2:]))
    if a[:2] == ["modules", "install-plan"]:
        return _with_json("selfdef.modules.install_plan", _kv_pairs(a[2:]))
    if a[:2] == ["modules", "config-scaffold"] and len(a) >= 3:
        kw = {"slug": a[2]}
        kw.update(_kv_pairs(a[3:]))
        return _with_json("selfdef.modules.config_scaffold", kw)
    if a[:2] == ["modules", "apply-plan"]:
        return _with_json("selfdef.modules.apply_plan", _kv_pairs(a[2:]))

    # LoRA surface.
    if a[:2] == ["lora", "list"]:
        return _with_json("selfdef.models.lora.list", _kv_pairs(a[2:]))
    if a[:2] == ["lora", "attach"] and len(a) >= 4:
        kw = {"adapter_id": a[2], "base_model": a[3]}
        kw.update(_kv_pairs(a[4:]))
        return _with_json("selfdef.models.lora.attach", kw)
    if a[:2] == ["lora", "detach"] and len(a) >= 3:
        kw = {"adapter_id": a[2]}
        kw.update(_kv_pairs(a[3:]))
        return _with_json("selfdef.models.lora.detach", kw)
    if a[:2] == ["lora", "set-status"] and len(a) >= 4:
        return _with_json("selfdef.models.lora.set_status", {
            "adapter_id": a[2], "status": a[3],
        })

    # REPL history.
    if a[:2] == ["repl", "history"]:
        return _with_json("selfdef.repl.history", _kv_pairs(a[2:]))

    return None

def _kv_pairs(args):
    """Walk a --k v --flag list and return a dict of {k: v} pairs,
    converting --flag (no value) to {flag: True}."""
    out = {}
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("--"):
            key = tok[2:].replace("-", "_")
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                out[key] = args[i + 1]
                i += 2
                continue
            out[key] = True
            i += 1
            continue
        i += 1
    return out

def _ctl_via_mcp(args, url):
    """SD-R101: route a Tier 1 call through SD-R94 MCP TCP."""
    if not url.startswith("tcp://"):
        raise RuntimeError(
            f"SELFDEF_MCP_URL must start with tcp:// (got {url!r})"
        )
    hostport = url[len("tcp://"):]
    if ":" not in hostport:
        raise RuntimeError(f"SELFDEF_MCP_URL malformed (need host:port): {url!r}")
    host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError as e:
        raise RuntimeError(f"SELFDEF_MCP_URL port: {e}") from e

    mapped = _argv_to_mcp_call(args)
    if mapped is None:
        # Argv not in the MCP catalog — fall back to subprocess.
        if _SELFDEFCTL is None:
            raise RuntimeError(
                f"argv {list(args)} not in MCP catalog + selfdefctl unavailable"
            )
        r = _subp.run(
            [_SELFDEFCTL, *args],
            capture_output=True, text=True, check=False, timeout=20,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"selfdefctl {' '.join(args)} exited {r.returncode}: "
                f"{r.stderr.strip()}"
            )
        if not r.stdout.strip():
            return None
        try:
            return _json.loads(r.stdout)
        except _json.JSONDecodeError:
            return r.stdout

    tool_name, arguments = mapped
    import socket as _socket
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    line = _json.dumps(req) + "\n"
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.settimeout(20)
    try:
        s.connect((host, port))
        # Optional Bearer auth — SD-R94 supports per-connection auth.
        bearer = _os.environ.get("SELFDEF_MCP_BEARER", "").strip()
        if bearer:
            s.sendall(f"Authorization: Bearer {bearer}\n".encode())
        s.sendall(line.encode())
        # Read line-delimited response.
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    try:
        resp = _json.loads(buf.decode(errors="replace"))
    except _json.JSONDecodeError as e:
        raise RuntimeError(f"MCP response not JSON: {e}; raw={buf[:200]!r}") from e
    if "error" in resp:
        err = resp["error"]
        raise RuntimeError(
            f"MCP tool {tool_name} returned error {err.get('code')}: {err.get('message')}"
        )
    result = resp.get("result", {})
    # MCP tools wrap their payload as
    # {"content":[{"type":"text","text":"<json>"}]}; unwrap when present.
    if isinstance(result, dict) and "content" in result:
        content = result.get("content")
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = content[0].get("text")
            if isinstance(text, str):
                try:
                    return _json.loads(text)
                except _json.JSONDecodeError:
                    return text
    return result

def _record_history_v2(args, rc, started_at, duration_ms, transport):
    """SD-R101: extension of SD-R95 with the `transport` field so the
    operator can tell which calls went through MCP vs subprocess."""
    if not _HISTORY_PATH:
        return
    try:
        with open(_HISTORY_PATH, "a") as fh:
            fh.write(_json.dumps({
                "round": "SD-R101",
                "started_at": started_at,
                "duration_ms": duration_ms,
                "argv": list(args),
                "rc": rc,
                "transport": transport,
            }) + "\n")
    except OSError:
        pass

def hardware():
    """selfdefctl hardware --json"""
    return _ctl("hardware", "--json")

def posture():
    """selfdefctl hardware posture --json"""
    return _ctl("hardware", "posture", "--json")

def modules(category=None, phase=None):
    """selfdefctl modules list --json [--category C] [--phase P]"""
    args = ["modules", "list", "--json"]
    if category:
        args += ["--category", category]
    if phase:
        args += ["--phase", phase]
    return _ctl(*args)

def modules_info(slug, resolved=False):
    """selfdefctl modules info <slug> [--resolved] --json"""
    args = ["modules", "info", slug, "--json"]
    if resolved:
        args.append("--resolved")
    return _ctl(*args)

def modules_diff(host_config=None, dir=None):
    """selfdefctl modules diff --json"""
    args = ["modules", "diff", "--json"]
    if host_config:
        args += ["--host-config", host_config]
    if dir:
        args += ["--dir", dir]
    return _ctl(*args)

def modules_install_options(host_config=None, dir=None, category=None, only_ready=False):
    """selfdefctl modules install-options --json [--category C] [--only-ready]

    SD-R86 (SDD-026 Z-13): surface uninstalled-but-available catalog
    modules with operator-actionable recommendations (ready /
    blocked-by-hardware / blocked-by-missing-deps / needs-review).
    """
    args = ["modules", "install-options", "--json"]
    if host_config:
        args += ["--host-config", host_config]
    if dir:
        args += ["--dir", dir]
    if category:
        args += ["--category", category]
    if only_ready:
        args.append("--only-ready")
    return _ctl(*args)

def modules_install_plan(host_config=None, dir=None, category=None):
    """selfdefctl modules install-plan --json [--category C]

    SD-R87 (SDD-026 Z-13 closure): topologically-ordered install
    sequence over the SD-R86 plan-ready set. Returns dict with
    `steps` (numbered + per-step `command`) + `skipped` rows +
    `cycle_present` flag. Dep cycles surface as cycle_present=True
    with the unresolved nodes listed; in that case the operator must
    fix the manifests before retrying.
    """
    args = ["modules", "install-plan", "--json"]
    if host_config:
        args += ["--host-config", host_config]
    if dir:
        args += ["--dir", dir]
    if category:
        args += ["--category", category]
    return _ctl(*args)

def modules_config_scaffold(slug, dir=None, instance=None):
    """selfdefctl modules config-scaffold <slug> --json [--instance NAME]

    SD-R88 (SDD-026 Z-13 follow-up): copy-pasteable config blocks for
    one module — the `[modules."<slug>"]` block for modules.toml +
    the `[daemon.*]` keys for selfdef.toml. Hardware-gate predicates
    surface as comments. Instanced modules require `instance`.
    """
    args = ["modules", "config-scaffold", slug, "--json"]
    if dir:
        args += ["--dir", dir]
    if instance:
        args += ["--instance", instance]
    return _ctl(*args)

def modules_apply_plan(host_config=None, dir=None, category=None, continue_on_failure=False):
    """selfdefctl modules apply-plan --json [--category C]

    SD-R93 (SDD-026 Z-13 execution): walk the SD-R87 install-plan +
    invoke `apply --only <slug>` per step. Tier 1 returns the DRY-RUN
    shape only — operators wanting real execution use the CLI with
    `--apply` (write-doctrine carve-out).
    """
    args = ["modules", "apply-plan", "--json"]
    if host_config:
        args += ["--host-config", host_config]
    if dir:
        args += ["--dir", dir]
    if category:
        args += ["--category", category]
    if continue_on_failure:
        args.append("--continue-on-failure")
    return _ctl(*args)

def models(dir=None):
    """selfdefctl models list (table)"""
    args = ["models", "list"]
    if dir:
        args += ["--dir", dir]
    return _ctl(*args)

def lora_list(state=None):
    """selfdefctl models lora list --json"""
    args = ["models", "lora", "list", "--json"]
    if state:
        args += ["--state", state]
    return _ctl(*args)

def lora_attach(adapter_id, base_model, status=None, state=None):
    """selfdefctl models lora attach <id> <base> [--status S] --json

    SD-R89 (SDD-025 Y-2 extension): atomic upsert of one LoRA in the
    operator state file. Re-attaching the same adapter_id replaces
    base_model + status + attached_at.
    """
    args = ["models", "lora", "attach", adapter_id, base_model, "--json"]
    if status:
        args += ["--status", status]
    if state:
        args += ["--state", state]
    return _ctl(*args)

def lora_detach(adapter_id, state=None):
    """selfdefctl models lora detach <id> --json

    SD-R89: remove one adapter by id. Raises RuntimeError when the
    adapter wasn't present (subprocess rc=1).
    """
    args = ["models", "lora", "detach", adapter_id, "--json"]
    if state:
        args += ["--state", state]
    return _ctl(*args)

def lora_set_status(adapter_id, status, state=None):
    """selfdefctl models lora set-status <id> <status> --json

    SD-R89: flip an attached LoRA's status (active / disabled /
    errored) without removing the binding.
    """
    args = ["models", "lora", "set-status", adapter_id, status, "--json"]
    if state:
        args += ["--state", state]
    return _ctl(*args)

def mcp_tools():
    """selfdefctl mcp tools (JSON manifest)"""
    return _ctl("mcp", "tools")

# ============================================================
# SD-R97 (E8.M6) — Token-saving aliases + wasted-path tracker.
#
# Operator-named (§1b verbatim): "save/need less tokens, save wasted
# paths / useless tracks and stuff like all this."
#
# Two operator-facing surfaces:
#   1. Compact aliases (h / p / m / mi / md / mio / mip / lo / la /
#      ld / ls / mt / mtt / rh) — single-character-class verbs for
#      the most-used Tier 1 callables. Cut REPL transcript length
#      by ~75% for routine probes.
#   2. wasted_path tracker: a `_track()` decorator that records when
#      the operator's Tier 2 macros return None / raise / produce
#      structurally-empty results. The wasted-path log accumulates
#      in $SELFDEF_REPL_HISTORY (when set) under outcome="wasted-path".
# ============================================================

# --- Compact aliases (alphabetical for muscle memory) ---
def h():
    """h() = hardware() — token-saving alias."""
    return hardware()

def p():
    """p() = posture() — token-saving alias."""
    return posture()

def m(c=None, ph=None):
    """m(category, phase) = modules(category, phase) — token-saving alias."""
    return modules(category=c, phase=ph)

def mi(slug, resolved=False):
    """mi(slug) = modules_info(slug) — token-saving alias."""
    return modules_info(slug, resolved=resolved)

def md():
    """md() = modules_diff() — token-saving alias."""
    return modules_diff()

def mio(only_ready=False):
    """mio() = modules_install_options() — token-saving alias."""
    return modules_install_options(only_ready=only_ready)

def mip():
    """mip() = modules_install_plan() — token-saving alias."""
    return modules_install_plan()

def lo(state=None):
    """lo() = lora_list() — token-saving alias."""
    return lora_list(state=state)

def la(adapter_id, base_model, status=None):
    """la(id, base) = lora_attach(id, base) — token-saving alias."""
    return lora_attach(adapter_id, base_model, status=status)

def ld(adapter_id):
    """ld(id) = lora_detach(id) — token-saving alias."""
    return lora_detach(adapter_id)

def ls(adapter_id, status):
    """ls(id, status) = lora_set_status(id, status) — token-saving alias."""
    return lora_set_status(adapter_id, status)

def mt():
    """mt() = mcp_tools() — token-saving alias."""
    return mcp_tools()

def mtt():
    """mtt() = repl tier2 examples inventory — token-saving alias."""
    return _ctl("repl", "tier2-examples", "--json")

def rh(limit=20):
    """rh(N) = repl history --limit N --json — token-saving alias."""
    args = ["repl", "history", "--limit", str(limit), "--json"]
    return _ctl(*args)

# --- Wasted-path tracker decorator (Tier 2 ergonomic) ---
def track(name=None):
    """SD-R97: decorator that records when wrapped Tier 2 macros
    return falsy / empty / raise. Appends to SELFDEF_REPL_HISTORY
    (when set) as outcome={ok, empty-result, raised}. Operator pulls
    `rh()` afterward to see which paths wasted tokens.

    Usage:
        @track("my_macro")
        def my_macro(x):
            return _ctl("modules", "list", "--json")

    Operator-named: "save wasted paths / useless tracks".
    """
    def _wrap(fn):
        macro_name = name or getattr(fn, "__name__", "anon")
        def _inner(*args, **kwargs):
            import time as _time
            started_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
            t0 = _time.time()
            try:
                result = fn(*args, **kwargs)
                outcome = "ok"
                if result is None:
                    outcome = "empty-result"
                elif isinstance(result, (list, dict, str)) and len(result) == 0:
                    outcome = "empty-result"
                duration_ms = int((_time.time() - t0) * 1000)
                _record_history(
                    ("tier2-macro", macro_name, *[repr(a)[:40] for a in args]),
                    {"ok": 0, "empty-result": 0, "raised": -2}[outcome],
                    started_at, duration_ms,
                )
                return result
            except Exception as e:
                duration_ms = int((_time.time() - t0) * 1000)
                _record_history(
                    ("tier2-macro", macro_name, f"raised:{type(e).__name__}"),
                    -2, started_at, duration_ms,
                )
                raise
        _inner.__name__ = macro_name
        _inner.__wrapped__ = fn
        return _inner
    return _wrap

# --- SD-R98 (E8.M4) integrated-intelligence module registry ---
# Operator-named (§1b verbatim): "Integrated-intelligence modules —
# operator-pull CoT routines registered with @selfdef_macro".
_SELFDEF_MACROS = {}

def selfdef_macro(name=None, description=None, tags=None, track_outcome=True):
    """SD-R98: register a function as an operator-pull CoT routine.

    The decorated function lands in _SELFDEF_MACROS so operators can
    list / introspect / run macros by name. When track_outcome=True
    (default) the wrapper composes with SD-R97 @track so every
    registered macro contributes to the SD-R95 audit trail.

    Usage:
        @selfdef_macro(description="health rollup",
                       tags=["health", "rollup"])
        def health_summary():
            return health_to_attention()

        list_macros()                  # discover
        macro_info("health_summary")   # introspect
        run_macro("health_summary")    # invoke by name
    """
    def _wrap(fn):
        macro_name = name or getattr(fn, "__name__", "anon")
        wrapped = track(macro_name)(fn) if track_outcome else fn
        doc = (fn.__doc__ or "").strip()
        first_line = doc.split("\n", 1)[0].strip() if doc else ""
        _SELFDEF_MACROS[macro_name] = {
            "name": macro_name,
            "description": (description or first_line or ""),
            "tags": list(tags or []),
            "track_outcome": bool(track_outcome),
            "callable": wrapped,
            "qualname": getattr(fn, "__qualname__", macro_name),
        }
        return wrapped
    return _wrap

def list_macros(tag=None):
    """SD-R98: list registered operator-pull CoT macros (optionally
    filtered by tag). Returns sorted-by-name list of dicts."""
    out = []
    for nm in sorted(_SELFDEF_MACROS.keys()):
        meta = _SELFDEF_MACROS[nm]
        if tag is not None and tag not in meta["tags"]:
            continue
        out.append({
            "name": meta["name"],
            "description": meta["description"],
            "tags": list(meta["tags"]),
            "track_outcome": meta["track_outcome"],
        })
    return out

def macro_info(name):
    """SD-R98: full metadata for a registered macro (or None)."""
    m = _SELFDEF_MACROS.get(name)
    if m is None:
        return None
    return {
        "name": m["name"],
        "description": m["description"],
        "tags": list(m["tags"]),
        "track_outcome": m["track_outcome"],
        "qualname": m["qualname"],
    }

def run_macro(name, *args, **kwargs):
    """SD-R98: invoke a registered macro by name. Raises KeyError if
    the name isn't registered — the message lists known macros so the
    operator doesn't have to grep for typos."""
    m = _SELFDEF_MACROS.get(name)
    if m is None:
        known = sorted(_SELFDEF_MACROS.keys())
        raise KeyError(f"unknown selfdef_macro {name!r}; known: {known}")
    return m["callable"](*args, **kwargs)

# ============================================================
# SD-R102 (E8.M7) — Tier 2 macro auto-load from operator-owned file.
# ------------------------------------------------------------
# Operator owns Tier 2 (per SD-R85), but Tier 2 macros are session-
# volatile by default — every fresh REPL re-imports a blank Tier 1.
# To make operator macros PERSISTENT across sessions without forcing
# them into selfdef's tree, auto-source a single operator-owned file
# at bootstrap time. Resolution order:
#   1. $SELFDEF_REPL_MACROS                      (explicit override)
#   2. $XDG_CONFIG_HOME/selfdef/repl-macros.py   (XDG-compliant)
#   3. ~/.config/selfdef/repl-macros.py          (XDG fallback)
# The file is exec()'d INTO this bootstrap's globals so @selfdef_macro
# / @track / Tier 1 callables / SD-R97 aliases are all in scope. If
# the file does not exist, the step is a no-op. If the file raises
# during exec, the error is printed but bootstrap continues — a
# broken operator-owned file MUST NOT brick the REPL.

def _autoload_user_macros():
    """SD-R102: source operator's persistent Tier 2 macros, if any."""
    candidates = []
    explicit = _os.environ.get("SELFDEF_REPL_MACROS")
    if explicit:
        candidates.append(explicit)
    else:
        xdg = _os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            candidates.append(_os.path.join(xdg, "selfdef", "repl-macros.py"))
        home = _os.environ.get("HOME")
        if home:
            candidates.append(_os.path.join(home, ".config", "selfdef", "repl-macros.py"))
    for path in candidates:
        if not _os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                src = fh.read()
            exec(compile(src, path, "exec"), globals(), globals())
            if hasattr(_sys, "ps1") or _sys.stdin.isatty():
                print(f"selfdef REPL: loaded operator macros from {path}")
        except Exception as e:
            print(f"selfdef REPL: failed to load {path}: {e!r}", file=_sys.stderr)
        return path
    return None

_USER_MACROS_PATH = _autoload_user_macros()

# Banner — only print when imported into an interactive session.
if hasattr(_sys, "ps1") or _sys.stdin.isatty():
    print("selfdef REPL — Tier 1 (Proto-Programming) ready.")
    print("  hardware()         -> dict   (selfdefctl hardware --json)")
    print("  posture()          -> dict   (selfdefctl hardware posture --json)")
    print("  modules(category=..., phase=...) -> dict")
    print("  modules_info(slug, resolved=False)")
    print("  modules_diff(host_config=..., dir=...)")
    print("  modules_install_options(host_config=..., category=..., only_ready=False)")
    print("  modules_install_plan(host_config=..., category=...)")
    print("  modules_config_scaffold(slug, dir=..., instance=...)")
    print("  modules_apply_plan(host_config=..., category=..., continue_on_failure=False)")
    print("  models()           -> str    (table)")
    print("  lora_list(state=...)")
    print("  lora_attach(adapter_id, base_model, status=..., state=...)")
    print("  lora_detach(adapter_id, state=...)")
    print("  lora_set_status(adapter_id, status, state=...)")
    print("  mcp_tools()        -> dict   (manifest)")
    print()
    print("  SD-R97 token-saving aliases:")
    print("    h()  p()  m(c,ph)  mi(slug)  md()  mio()  mip()")
    print("    lo()  la(id,m)  ld(id)  ls(id,s)  mt()  mtt()  rh(N)")
    print()
    print("  SD-R97 wasted-path tracker (Tier 2):")
    print("    @track('macro_name') def my_macro(...): ...")
    print()
    print("  SD-R98 integrated-intelligence registry (operator-pull CoT):")
    print("    @selfdef_macro(description=..., tags=[...])")
    print("    list_macros()     macro_info(name)     run_macro(name, ...)")
    print()
    print("  SD-R101 (E8.M5) zero-subprocess Tier 1 via MCP TCP bridge:")
    print("    export SELFDEF_MCP_URL=tcp://127.0.0.1:9876  # uses SD-R94")
    print("    export SELFDEF_MCP_BEARER=<token>            # optional auth")
    print("    Every _ctl(*argv) call becomes one socket roundtrip; "
          "SD-R95 history records `transport` field per call.")
    print()
    print("  Tier 2: define your own helpers atop these — the surface is yours.")
    print()
    print("  SD-R102 operator macros auto-load:")
    print("    $SELFDEF_REPL_MACROS  > $XDG_CONFIG_HOME/selfdef/repl-macros.py")
    print("                          > ~/.config/selfdef/repl-macros.py")
    if _USER_MACROS_PATH:
        print(f"    loaded: {_USER_MACROS_PATH}")
    else:
        print("    (no operator macros file found — drop one of the above to persist Tier 2)")
"#
    .to_string()
}

/// SD-R90 (SDD-026 Z-12 follow-up): ready-to-paste example Tier 2
/// macros. Operators copy them whole OR derive their own. Each
/// example is operator-readable + composes against the Tier 1
/// callable surface SD-R85 ships.
///
/// We ship these AS DEMONSTRATIONS, not as a prescriptive Tier 2 —
/// the SD-R85 manifest pins Tier 2 as operator-pull. The examples
/// just show the SHAPE of useful operator-extension macros.
pub(crate) struct Tier2Example {
    pub name: &'static str,
    pub summary: &'static str,
    pub source: &'static str,
}

pub(crate) fn tier2_examples() -> Vec<Tier2Example> {
    vec![
        Tier2Example {
            name: "hw_summary",
            summary: "1-line host summary — operator's first CoT \
                      sanity check (composes hardware() + posture()).",
            source: r#"def hw_summary():
    """SD-R90 example: 1-line host summary (Tier 2 macro)."""
    hw = hardware() or {}
    p  = posture()  or {}
    cpu = (hw.get("cpu") or {}).get("model", "?")
    cores = (hw.get("cpu") or {}).get("threads", "?")
    gpus = (hw.get("gpu") or {}).get("device_count", 0)
    mem_gib = ((hw.get("memory") or {}).get("total_bytes", 0)) // (1024**3)
    verdict = p.get("verdict") or "?"
    return f"{cpu} ({cores}T) | {gpus} GPU(s) | {mem_gib} GiB RAM | sain01={verdict}"
"#,
        },
        Tier2Example {
            name: "modules_ready_only",
            summary: "Filter install-options to only ready rows + return slugs \
                      (token-saving alias over modules_install_options()).",
            source: r#"def modules_ready_only(host_config=None, dir=None, category=None):
    """SD-R90 example: just give me the slugs I can install RIGHT NOW."""
    rep = modules_install_options(
        host_config=host_config, dir=dir,
        category=category, only_ready=True,
    ) or {}
    return [o["slug"] for o in (rep.get("options") or [])]
"#,
        },
        Tier2Example {
            name: "apply_install_plan",
            summary: "CoT loop: fetch install-plan, dry-run each step's command via _ctl. \
                      Operator-supplied confirmation gates each apply.",
            source: r#"def apply_install_plan(host_config=None, dir=None,
                       category=None, confirm=False, dry_run=True):
    """SD-R90 example: walk the SD-R87 install-plan + apply each step.

    Custom CoT: PER-STEP decide → optionally exec. dry_run=True (default)
    just prints what would happen. confirm=True bypasses the per-step
    input(). Set both to actually apply unattended (operator's choice).
    """
    plan = modules_install_plan(host_config=host_config, dir=dir,
                                category=category) or {}
    if plan.get("cycle_present"):
        return {"aborted": "dependency cycle: " + ",".join(plan.get("cycle_nodes", []))}
    out = []
    for step in plan.get("steps", []) or []:
        slug = step["slug"]
        cmd  = step["command"]
        if dry_run:
            out.append({"step": step["order"], "slug": slug, "outcome": "dry-run", "cmd": cmd})
            continue
        if not confirm:
            ans = input(f"apply {slug}? [y/N]: ").strip().lower()
            if ans != "y":
                out.append({"step": step["order"], "slug": slug, "outcome": "skipped"})
                continue
        # Real apply — split the recorded command back into args for _ctl.
        argv = cmd.split()[1:]
        try:
            res = _ctl(*argv)
            out.append({"step": step["order"], "slug": slug, "outcome": "applied", "result": res})
        except RuntimeError as e:
            out.append({"step": step["order"], "slug": slug, "outcome": "error", "error": str(e)})
    return {"plan_steps": len(plan.get("steps", [])), "results": out}
"#,
        },
        Tier2Example {
            name: "health_to_attention",
            summary: "Token-saving alias: return only the probe ids currently \
                      in attention/down severity (over hardware/posture/health).",
            source: r#"def health_to_attention():
    """SD-R90 example: just tell me what's wrong RIGHT NOW.

    Calls mcp_tools() to confirm a health-scan-equivalent tool is
    available, then drives selfdef hardware + posture + modules
    list rollup. Returns a flat list of attention items so the
    operator-side CoT doesn't have to walk nested JSON.
    """
    hw = hardware() or {}
    posture_d = posture() or {}
    attention = []
    verdict = posture_d.get("verdict")
    if verdict and verdict not in ("ok", "sain01"):
        attention.append({"area": "posture", "verdict": verdict})
    cpu = (hw.get("cpu") or {})
    if not cpu.get("avx512vnni"):
        attention.append({"area": "cpu", "missing": "avx512_vnni"})
    if (hw.get("gpu") or {}).get("device_count", 0) == 0:
        attention.append({"area": "gpu", "missing": "any-gpu"})
    return attention
"#,
        },
        Tier2Example {
            name: "registered_health_rollup",
            summary: "SD-R98 example: register a CoT routine with @selfdef_macro \
                      so operators can discover/introspect/run it by name.",
            source: r#"@selfdef_macro(description="health rollup over hardware+posture",
                tags=["health", "rollup", "sd-r98-example"])
def registered_health_rollup():
    """Operator-pull CoT: aggregate hardware + posture + attention items
    so a downstream agent can decide what to fix first."""
    hw = hardware() or {}
    p  = posture() or {}
    return {
        "verdict": p.get("verdict"),
        "cpu_model": (hw.get("cpu") or {}).get("model"),
        "gpu_count": (hw.get("gpu") or {}).get("device_count", 0),
        "attention": health_to_attention(),
    }

# Discover/introspect/run after registration:
#   list_macros()                              # → [{name, description, tags, ...}]
#   list_macros(tag="health")                  # → filtered by tag
#   macro_info("registered_health_rollup")     # → full metadata
#   run_macro("registered_health_rollup")      # → invoke by name
"#,
        },
    ]
}

pub(crate) fn cmd_tier2_examples(name: Option<&str>, json: bool) -> anyhow::Result<i32> {
    let all = tier2_examples();
    let selected: Vec<&Tier2Example> = match name {
        Some(n) => {
            let m: Vec<&Tier2Example> = all.iter().filter(|e| e.name == n).collect();
            if m.is_empty() {
                eprintln!(
                    "ERROR unknown tier2 example {n:?}; known: {:?}",
                    all.iter().map(|e| e.name).collect::<Vec<_>>()
                );
                return Ok(2);
            }
            m
        }
        None => all.iter().collect(),
    };
    if json {
        let rows: Vec<serde_json::Value> = selected
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "summary": e.summary,
                    "source": e.source,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema_version": "1.0.0",
            "round": "SD-R90",
            "sdd_vector": "SDD-026 Z-12 follow-up",
            "examples": rows,
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(0);
    }
    println!("# SD-R90 selfdef Tier 2 example macros (SDD-026 Z-12 follow-up).");
    println!("# Copy-paste into your `python3 -i -c \"$(selfdefctl repl bootstrap)\"` session.");
    println!("# These are DEMONSTRATIONS — Tier 2 is operator-pull; derive your own.");
    println!();
    for e in &selected {
        println!(
            "# ─── {} ──────────────────────────────────────────",
            e.name
        );
        println!("# {}", e.summary);
        println!();
        println!("{}", e.source);
    }
    Ok(0)
}

/// SD-R95 (SDD-026 Z-12 audit): render the JSONL history the
/// bootstrap script writes when `SELFDEF_REPL_HISTORY` is set.
///
/// Defaults: path from `SELFDEF_REPL_HISTORY` env (fallback
/// `/var/lib/selfdef/repl-history.jsonl`); limit 50 rows; tail; json
/// mode emits the full row list.
pub(crate) fn cmd_history(
    path: Option<&std::path::Path>,
    limit: usize,
    all: bool,
    json: bool,
) -> anyhow::Result<i32> {
    use std::io::BufRead;
    let resolved: std::path::PathBuf = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::var("SELFDEF_REPL_HISTORY") {
            Ok(s) if !s.is_empty() => std::path::PathBuf::from(s),
            _ => std::path::PathBuf::from("/var/lib/selfdef/repl-history.jsonl"),
        },
    };
    let mut rows: Vec<serde_json::Value> = Vec::new();
    if resolved.exists() {
        let f = std::fs::File::open(&resolved)?;
        let r = std::io::BufReader::new(f);
        for line in r.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                rows.push(v);
            }
        }
    }
    let total = rows.len();
    if !all && rows.len() > limit {
        let start = rows.len() - limit;
        rows.drain(..start);
    }
    if json {
        let doc = serde_json::json!({
            "schema_version": "1.0.0",
            "round": "SD-R95",
            "sdd_vector": "SDD-026 Z-12 audit",
            "path": resolved.display().to_string(),
            "exists": resolved.exists(),
            "total_rows": total,
            "returned_rows": rows.len(),
            "rows": rows,
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(0);
    }
    println!("── SD-R95 selfdefctl repl history (SDD-026 Z-12 audit) ──");
    println!("  path:           {}", resolved.display());
    println!("  exists:         {}", resolved.exists());
    println!("  total_rows:     {total}");
    println!("  returned_rows:  {}", rows.len());
    if rows.is_empty() {
        println!();
        println!(
            "  (no rows — set SELFDEF_REPL_HISTORY=<path> in the REPL's env, \
             then call any Tier 1 callable to populate)"
        );
        return Ok(0);
    }
    println!();
    for r in &rows {
        let ts = r["started_at"].as_str().unwrap_or("?");
        let rc = r["rc"].as_i64().unwrap_or(-1);
        let dur = r["duration_ms"].as_u64().unwrap_or(0);
        let mark = if rc == 0 { "OK  " } else { "FAIL" };
        let argv: Vec<String> = r["argv"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        println!("  [{mark}] {ts}  {dur:>5}ms  selfdefctl {}", argv.join(" "));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdr85_bootstrap_script_emits_python() {
        let s = bootstrap_script();
        assert!(s.contains("# SD-R85"));
        assert!(s.contains("import json"));
        assert!(s.contains("def hardware"));
        assert!(s.contains("def posture"));
        assert!(s.contains("def modules"));
        assert!(s.contains("def modules_diff"));
        assert!(s.contains("def modules_install_options"));
        assert!(s.contains("def modules_install_plan"));
        assert!(s.contains("def modules_config_scaffold"));
        assert!(s.contains("def modules_apply_plan"));
        assert!(s.contains("def lora_list"));
        assert!(s.contains("def lora_attach"));
        assert!(s.contains("def lora_detach"));
        assert!(s.contains("def lora_set_status"));
        assert!(s.contains("def mcp_tools"));
    }

    #[test]
    fn sdr102_bootstrap_script_includes_user_macro_autoload() {
        let s = bootstrap_script();
        assert!(s.contains("SD-R102"), "must reference SD-R102");
        assert!(
            s.contains("_autoload_user_macros"),
            "must define autoload fn"
        );
        assert!(s.contains("SELFDEF_REPL_MACROS"), "must check env var");
        assert!(s.contains("XDG_CONFIG_HOME"), "must check XDG_CONFIG_HOME");
        assert!(s.contains("repl-macros.py"), "must reference the filename");
        assert!(s.contains("_USER_MACROS_PATH"), "must store loaded path");
        assert!(
            s.contains("compile(src, path, \"exec\")"),
            "must compile-then-exec for clean tracebacks"
        );
    }

    #[test]
    fn sdr102_tier_descriptors_advertise_autoload() {
        let s = render_tiers_json();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let tiers = v["tiers"].as_array().unwrap();
        // Tier 1 advertises the auto-load env+path hints.
        let tier1_callables = tiers[1]["example_callables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(
            tier1_callables.iter().any(|s| s.contains("SD-R102")),
            "Tier 1 advertises SD-R102 auto-load: {tier1_callables:?}"
        );
        // Tier 2 advertises the persistence path.
        let tier2_callables = tiers[2]["example_callables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(
            tier2_callables.iter().any(|s| s.contains("SD-R102")),
            "Tier 2 advertises SD-R102 persistence: {tier2_callables:?}"
        );
    }

    #[test]
    fn sdr85_tiers_json_round_trips() {
        let s = render_tiers_json();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["schema_version"], "1.0.0");
        assert_eq!(v["round"], "SD-R85");
        let tiers = v["tiers"].as_array().unwrap();
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0]["id"], 0);
        assert_eq!(tiers[0]["name"], "Programming");
        assert_eq!(tiers[1]["id"], 1);
        assert_eq!(tiers[1]["name"], "Proto-Programming");
        assert_eq!(tiers[2]["id"], 2);
        assert_eq!(tiers[2]["name"], "Proto-Proto-Programming");
    }

    #[test]
    fn sdr85_tiers_human_renders_all_three() {
        let s = render_tiers_human();
        assert!(s.contains("Tier 0 — Programming"));
        assert!(s.contains("Tier 1 — Proto-Programming"));
        assert!(s.contains("Tier 2 — Proto-Proto-Programming"));
    }
}
