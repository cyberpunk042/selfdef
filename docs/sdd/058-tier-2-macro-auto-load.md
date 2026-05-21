# SDD-058 — Tier 2 operator-macro auto-load (SD-R102)

> Status: **implemented** — Stage-1 doctrine + Stage-2 mechanism
> ratified post-implementation. Shipped 2026-05-21 in commit f76aa8a
> alongside two new selfdef-cli unit tests covering bootstrap-script
> invariants + tier-descriptor advertising. End-to-end smoke verified
> with a real `python3 -i -c "$(selfdefctl repl bootstrap)"` session
> against three fixture files (working macros, missing file,
> SyntaxError) — all three behaviours match contract.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS011 (catalog row Z-12 SD-R102 portion).
> Builds on: SDD-026 (operator dashboard + flex-profile — Z-12
> multi-tier REPL section); SD-R85 (Tier 1 bootstrap foundation);
> SD-R98 (`@selfdef_macro` decorator registry).

## Problem

SD-R85 ships Tier 1 of the multi-tier REPL: a Python bootstrap
script the operator pastes into `python3 -i -c "$(selfdefctl repl
bootstrap)"` to expose the Tier 1 callable surface (`hardware() /
posture() / modules() / ...`). SD-R98 layered the `@selfdef_macro`
decorator + a session-local macro registry on top.

What was missing: **persistence**. Every fresh `python3 -i -c
"$(selfdefctl repl bootstrap)"` re-imports a *blank* Tier 1 surface.
Operator-authored `@selfdef_macro` Tier 2 routines are session-
volatile — type them once, lose them when the terminal closes.
Across the operator's perpetual `/goal` cycles (2h / 4h / 8h /
16h sessions, per `~/.claude/CLAUDE.md`), that's a constant
re-keying tax.

The SD-R85 manifest pins Tier 2 as **operator-pull**:

> We ship Tier 1 + the manifest; operator owns Tier 2.

So the persistence mechanism must NOT pull Tier 2 macros into the
selfdef tree — that would violate the ownership boundary. Instead,
selfdef provides a single auto-load hook; the operator owns the
file the hook reads.

## Contract

### C-1 — Resolution order

The bootstrap script's `_autoload_user_macros()` function tries
exactly three candidate paths in order, loading the first one that
exists as a regular file:

1. `$SELFDEF_REPL_MACROS` — explicit override (CI fixtures,
   per-tmux-pane macro sets, ad-hoc experimentation)
2. `$XDG_CONFIG_HOME/selfdef/repl-macros.py` — XDG-compliant
3. `~/.config/selfdef/repl-macros.py` — XDG fallback (when
   `XDG_CONFIG_HOME` is unset)

Only one file is sourced per bootstrap. Resolution order is
deterministic; the resolved path (or `None`) is stashed in module
global `_USER_MACROS_PATH` for downstream introspection.

### C-2 — Exec context

The file is `compile()`d under its real on-disk path (so Python
tracebacks point at the operator's file, not at `<string>`) then
`exec`d INTO the bootstrap's `globals()`. Consequences:

- `@selfdef_macro` / `@track` / `_ctl` / Tier 1 callables / SD-R97
  aliases / `_record_history` are all in scope. The operator's
  macros can use the full Tier 1 surface as if they were typed at
  the REPL.
- Anything the file defines becomes a global of the bootstrap
  session — accessible from the operator's interactive prompt.
- Operator-defined `@selfdef_macro` registrations land in the SD-R98
  registry, so `list_macros()` / `macro_info(name)` /
  `run_macro(name, ...)` work uniformly across in-session and
  auto-loaded macros.

### C-3 — Failure resilience

A broken operator-owned file MUST NOT brick the REPL. The auto-load
catches any `Exception` from `compile` / `exec`, prints `selfdef
REPL: failed to load <path>: <repr>` to stderr, and continues
bootstrap. The Tier 1 surface stays fully functional.

Verified by manual smoke against a syntactically-invalid fixture
(`broken_syntax = 1 +`): the SyntaxError was reported on stderr;
`hardware()` / `posture()` / decorator helpers all remained callable
in the interactive prompt.

### C-4 — Banner reporting

When the bootstrap detects an interactive session (`hasattr(sys,
"ps1") or sys.stdin.isatty()`), the banner block reports the SD-R102
state:

- If `_USER_MACROS_PATH is not None`: prints `loaded: <path>` so
  the operator sees which file was sourced.
- Otherwise: prints `(no operator macros file found — drop one of
  the above to persist Tier 2)` with the three resolution paths.

Non-interactive sessions (CI scripts, MCP transport, piped
invocations) stay silent — no banner noise.

### C-5 — Discovery surface

Both discovery surfaces advertise SD-R102:

- **HTTP**: `GET /v1/repl` — `TierDescriptor[1].example_callables`
  includes `"SD-R102 auto-load: $SELFDEF_REPL_MACROS >
  ~/.config/selfdef/repl-macros.py"`;
  `TierDescriptor[2].example_callables` includes the persistence
  guidance.
- **CLI**: `selfdefctl repl tiers --json` carries the same hints
  (mirrored in `crates/selfdef-cli/src/repl.rs`'s `tiers()` table).

This keeps the operator's external introspection paths
(dashboard / Claude MCP client / `curl --unix-socket`) aware of the
mechanism without needing to read this SDD.

## Decisions

### D-1 — Single file, not a directory tree

The auto-load reads ONE file. The operator could trivially layer
their own `import sub_macros_a; import sub_macros_b` structure into
that file, but selfdef does NOT walk a directory or glob multiple
files. Reasoning:

- Multi-file load order becomes a contract we'd have to maintain
  (alphabetical? mtime? topological dep order?).
- Python's `import` already solves modular composition — the single
  entry-point file is the natural place to express that.
- Predictability: the operator runs the bootstrap and knows exactly
  one file is sourced. Debugging is shallow.

### D-2 — `exec` INTO globals, not as a module

We do not `importlib.util.spec_from_file_location` + `exec_module`
because that would put the macros in a *separate module* whose
`@selfdef_macro` decorator references would need explicit re-import
of the bootstrap's helpers (`hardware`, `_ctl`, etc.). The whole
point of Tier 2 is "operator extends Tier 1" — `exec` into the
bootstrap's globals is the most ergonomic match.

Tradeoff: name collisions between the operator's macros and Tier 1
callables silently overwrite. That's acceptable because:

- The operator KNOWS they're writing on top of Tier 1.
- The resolution model matches how they'd write macros directly
  in the REPL session.
- `selfdef_macro` registry is keyed by name, so accidental
  collisions surface immediately when `list_macros()` is called.

### D-3 — XDG-compliant default path

`~/.config/selfdef/repl-macros.py` follows the XDG Base Directory
Specification. The `$XDG_CONFIG_HOME` interpolation is honoured for
operators who explicitly set it (typical on NixOS / declarative
setups). The explicit-override `$SELFDEF_REPL_MACROS` env var sits
above both for ad-hoc use (CI fixtures, "try macros without
clobbering my real file", per-tmux-pane sets).

### D-4 — Auto-load happens BEFORE the banner

Resolution order in the bootstrap script:

```
1. Imports + helpers + Tier 1 callables + SD-R97 aliases + SD-R98 registry
2. _autoload_user_macros()           ← runs here
3. Interactive-session banner
```

This ensures the banner can report `loaded: <path>` accurately AND
that `list_macros()` (if called from the banner) would already
include operator-defined macros. It also means a syntax error in
the operator's file surfaces BEFORE the REPL is interactively
available — better than discovering the file is broken when the
operator first calls one of their macros mid-debug session.

### D-5 — No version pinning on the operator's file

We do not require the operator's file to declare a schema version.
The Tier 1 callable surface is itself the "schema"; if a future
SD-R changes a callable's signature, the operator's macros will
break loudly at call time (TypeError) — the only viable migration
signal in a dynamic language. We accept this. The operator owns
the file; selfdef owns the callable surface.

## Test plan

Two unit tests in `crates/selfdef-cli/src/repl.rs`:

1. `sdr102_bootstrap_script_includes_user_macro_autoload` —
   asserts the emitted bootstrap script contains the SD-R102
   reference, the `_autoload_user_macros` function definition,
   `SELFDEF_REPL_MACROS` env check, `XDG_CONFIG_HOME` check,
   `repl-macros.py` filename, `_USER_MACROS_PATH` storage, and
   the `compile(src, path, "exec")` pattern for clean tracebacks.
2. `sdr102_tier_descriptors_advertise_autoload` — asserts that
   both Tier 1 + Tier 2 entries in `render_tiers_json()`'s output
   include `"SD-R102"` in their `example_callables`.

Plus the existing `sdr85_bootstrap_script_emits_python` /
`sdr85_tiers_json_round_trips` regression-guards continue to pass.

Manual smoke against a real `python3`:

| Scenario | Setup | Expected | Verified |
|---|---|---|---|
| Working fixture | `SELFDEF_REPL_MACROS=/tmp/m.py` with `@selfdef_macro def hello()` + `PROOF_OF_LOAD = 42` | both globals accessible; `_USER_MACROS_PATH` matches | ✅ |
| No file | no env vars; nonexistent `$HOME` | `_USER_MACROS_PATH is None`; banner reports the 3 resolution paths | ✅ |
| Broken file | `SELFDEF_REPL_MACROS` points at file with `broken_syntax = 1 +` | stderr message; REPL surface still callable | ✅ |

## Migration

None. SD-R102 is a pure additive surface — existing operators with
no `repl-macros.py` file see one extra line in the banner ("no
operator macros file found") and behaviour is otherwise unchanged.

## Risk + benefit

**Risk**: minimal. The auto-load is opt-in (the file must exist);
failures are caught + reported; the resolution order is documented;
the operator owns the file 100%.

**Benefit**: closes the perpetual-cycle persistence gap. Across the
operator's 2h / 4h / 8h / 16h `/goal` sessions, Tier 2 macros
authored in one session survive into the next. The auto-load also
serves as an onboarding hook: when a new operator clones selfdef on
a new machine, dropping their `repl-macros.py` into the XDG path is
the entire setup.

## Out-of-scope (future SDDs)

- **Dashboard REPL pop-out**: SDD-056 reserves an `REPL` tab; a
  WebSocket-backed in-browser REPL with the same SD-R102 auto-load
  contract is a separate Stage-3 piece. Not in SDD-058.
- **MCP-side macro registration**: SD-R94 / SD-R101 sketch a TCP
  bridge that lets Claude invoke Tier 1 callables. Whether `@selfdef
  _macro`-registered Tier 2 routines should be MCP-discoverable too
  is a future call. Not in SDD-058.
- **Macro provenance / signing**: the operator's macros file is
  trusted on-disk content. SDD-043 (commit-authority) + SDD-045
  (filesystem-boundary) would govern any future "macros must be
  signed by an authorized identity before exec" arc. Not in
  SDD-058.

## Closure

MS011 catalog row Z-12: was "discovery shipped + Tier 1 bootstrap
shipped + Tier 2 framework shipped (volatile)". With SDD-058, Z-12
now also has the **persistence** mechanism — the layer the operator
named in SDD-026 Z-12 ("DSL macros + token-saving aliases that
[…] save wasted paths") can now live across sessions without
violating the operator-pull boundary.
