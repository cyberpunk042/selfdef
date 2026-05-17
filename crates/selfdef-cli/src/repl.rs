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
                "lora_list(state=None)",
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

def _ctl(*args):
    """Run selfdefctl + parse JSON stdout. Returns parsed dict/list."""
    if _SELFDEFCTL is None:
        raise RuntimeError("selfdefctl missing — install the selfdef-cli crate")
    r = _subp.run(
        [_SELFDEFCTL, *args],
        capture_output=True, text=True, check=False, timeout=20,
    )
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

def mcp_tools():
    """selfdefctl mcp tools (JSON manifest)"""
    return _ctl("mcp", "tools")

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
    print("  models()           -> str    (table)")
    print("  lora_list(state=...)")
    print("  mcp_tools()        -> dict   (manifest)")
    print("  Tier 2: define your own helpers atop these — the surface is yours.")
"#
    .to_string()
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
        assert!(s.contains("def lora_list"));
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
