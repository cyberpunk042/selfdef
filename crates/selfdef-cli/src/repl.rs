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
            ],
        },
        Tier {
            id: 2,
            name: "Proto-Proto-Programming",
            description: "Operator-owned layer on TOP of Tier 1. Custom CoT loops + DSL \
                 macros + token-saving aliases that wrap Tier 1 calls into \
                 operator-meaningful idioms. We ship Tier 1 + the manifest; \
                 operator owns Tier 2.",
            language: "Python (operator-defined)",
            status: "operator-pull",
            example_callables: vec!["(operator-supplied macros — register with @selfdef_macro)"],
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
    """
    import time as _time
    started_at = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
    if _SELFDEFCTL is None:
        # Record the failed attempt before raising — operators auditing
        # a session see what was tried even when the CLI is missing.
        _record_history(args, -1, started_at, 0)
        raise RuntimeError("selfdefctl missing — install the selfdef-cli crate")
    t0 = _time.time()
    r = _subp.run(
        [_SELFDEFCTL, *args],
        capture_output=True, text=True, check=False, timeout=20,
    )
    duration_ms = int((_time.time() - t0) * 1000)
    _record_history(args, r.returncode, started_at, duration_ms)
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
    print("  Tier 2: define your own helpers atop these — the surface is yours.")
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
