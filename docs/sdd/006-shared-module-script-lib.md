# SDD-006 — Shared module-script library

> Status: implemented
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-081 (SDD-debt parent), F-2026-050
> (deferred — see "Deferred to follow-up" below),
> F-2026-051 (partial — see D-3).

## Implementation status

Shipped in the SDD-006 implementation PR. Phase A + B + C
collapsed into a single PR (per the operator's "big chunks"
steer): the shared library landed, the dispatcher exports
`SELFDEF_MODULE_LIB`, and **all eight modules** with helpers
migrated in one go (`agent-guard`, `tetragon`, `observability`,
`integrity-sentinel`, `vpn-bridge`, `bridge-l2`, `polarproxy`,
`suricata`). The migration is byte-stable: the shared helpers
match the per-module copies exactly except for the slug literal
in `log()`, which the shared lib parameterises on `${MODULE}`.

- **D-1 — Shared library**: `packaging/lib/module-lib.sh` ships
  the five helpers (`log`, `emit_status`, `die`, `run`,
  `toml_get`) plus the version pin
  (`SELFDEF_MODULE_LIB_VERSION=1`). Version-mismatch is enforced
  at source time with exit 99.
- **D-2 — Dispatcher plumbing**: `run_one` in
  `crates/selfdef-cli/src/modules.rs` exports
  `SELFDEF_MODULE_LIB` via a new `resolve_module_lib_path()` with
  the three-tier precedence (env override → workspace
  `packaging/lib/module-lib.sh` → installed
  `/usr/share/selfdef/lib/module-lib.sh`). Both branches have
  unit + integration coverage.
- **D-3 — Per-module migration**: eight `install/lib.sh` files
  now source the shared library with a `${BASH_SOURCE[0]%/*}`
  parameter-expansion fallback to the workspace path (no
  `dirname` call so the resolver works under stripped `$PATH`).
  Modules' inline-helper scripts (`bridge-l2`, `polarproxy`,
  `suricata`) gain a `lib.sh` of their own and source it from
  apply / check / uninstall. `vpn-bridge`'s and `bridge-l2`'s
  uninstall scripts override `log()` and `run()` after sourcing,
  preserving the pre-SDD-006 `[<slug>:uninstall]` log prefix
  and lenient continue-past-failure behaviour.
- **D-4 — Helpers doc**: `docs/dev/module-helpers.md` documents
  every exported helper, the caller contract, the versioning
  policy, and how to add module-specific helpers / overrides.
- **D-5 — Packaging**: `crates/selfdef-daemon/Cargo.toml`'s
  `[package.metadata.deb]` assets list installs the shared lib
  at `/usr/share/selfdef/lib/module-lib.sh` mode `0644`.
- **D-6 — Tests**:
  - Unit (`crates/selfdef-cli/src/modules.rs`):
    `resolve_module_lib_path_finds_workspace_by_default`.
    Operator-override branch covered by integration only
    (workspace lint forbids in-process `std::env::set_var`).
  - Integration
    (`crates/selfdef-cli/tests/cli_modules_shared_lib.rs`):
    `dispatcher_exports_module_lib_env_var`,
    `module_sourcing_shared_lib_at_v1_succeeds`,
    `module_requesting_newer_lib_version_is_refused`.

## Deferred to follow-up

- **F-2026-050** (`agent-guard/uninstall.sh` enumerates policy
  filenames by hand). The SDD reserved a `module_render_files`
  helper for a follow-up PR; this implementation keeps the v1
  surface minimal. Tracked separately; ledger entry remains
  open.
- **F-2026-051** (`render_pod_scope` awk fragility). Partially
  closed: the shared lib doesn't ship YAML-aware editing helpers
  in v1. A future v2 of the library could ship `yq`- or
  `python`-backed helpers; tracked as a separate ledger entry.

## Problem

The audit's M-011 / **F-2026-081** flagged that every shipped
module reimplements the same helpers in its own
`install/lib.sh`:

- `log "$msg"` — stderr logger
- `emit_status "$status" "$message"` — write the structured
  status JSON line to stdout
- `die "$msg"` — emit_status failed + exit 1
- `run "$desc" -- <cmd...>` — dry-run-aware command wrapper
- `toml_get "$key" "$file"` — minimal TOML reader (one
  `key = "value"` per line)

Six modules carry their own copy
(`agent-guard`, `bridge-l2`, `integrity-sentinel`,
`observability`, `tetragon`, `vpn-bridge`); the seventh
(`detect-host`) has no scripts at all; the eighth and ninth
(`polarproxy`, `suricata`) have inline equivalents. Counting
the duplicate lines: ~30 lines × 6 modules = ~180 lines
duplicated.

The cost today:

- A bug fix in one helper (e.g. `toml_get` mishandling a
  value with `=` in it) has to be applied in six places.
- Helpers drift: `agent-guard`'s `lib.sh` has
  `resolve_action()` that no other module needs but
  contributes to the duplication tax in agent-guard.
- New modules paste the same skeleton, perpetuating the
  cycle.

The audit also identified two adjacent findings the shared
library can close as a side effect:

- **F-2026-050** (`agent-guard/install/uninstall.sh`
  enumerates policy filenames by hand). A shared
  `manifest_owned_files` helper would let the script
  discover its own outputs.
- **F-2026-051** (the `render_pod_scope` awk state machine
  is fragile). Less direct — a shared YAML-aware editor
  helper could reduce risk, but it's a bigger ask. Marked
  *partial close*; the SDD's D-3 expands on what's in
  scope here vs deferred.

## Goals

1. One installed copy of the shared helpers, sourced by
   every module's apply / check / uninstall scripts.
2. The shared library version-pins itself so a module
   built against v2 doesn't silently break under v1.
3. The library is a strict superset of today's per-module
   helpers — every existing helper works the same way.
4. Migrating a single module is a focused PR: source the
   shared lib, delete the local copy, run that module's
   tests.
5. Future modules pick up the library by default; the
   `init` scaffolding for a new module produces an
   apply.sh that already sources it.

## Non-goals

- A general "module SDK" with state management, retries,
  etc. The scope is shared helpers, not a framework.
- A Rust rewrite of the install scripts. Scripts stay
  bash; the library is bash.
- Removing the per-module `lib.sh` files entirely. Each
  module's `lib.sh` may still hold module-specific helpers
  (`agent-guard`'s `resolve_action`, `render_pod_scope`,
  `render_egress_allowlist`, etc.). The shared parts get
  factored out.
- A breaking change. Old modules built against per-module
  helpers must keep working at the same time as the
  shared lib lives on disk.

## Glossary

- **shared lib** — the new file shipped by selfdef itself:
  `/usr/share/selfdef/lib/module-lib.sh`.
- **module-local lib** — each module's existing
  `install/lib.sh`. Stays for module-specific helpers;
  shrinks as shared helpers move out.
- **library version** — a small integer stamped into the
  shared lib's header that scripts assert against.

## Current state

### Helper inventory

Hand-counted from `modules/*/install/lib.sh`:

| Helper | Modules carrying a copy |
| --- | --- |
| `log` | agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge |
| `emit_status` | agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge |
| `die` | agent-guard, integrity-sentinel, observability, tetragon, vpn-bridge |
| `run` | agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge |
| `toml_get` | agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge |

Module-specific helpers (stay):
- agent-guard: `resolve_action`, `render_policy`,
  `render_egress_allowlist`, `render_securemessage_endpoint`,
  `render_pod_scope`, `render_gpu_policy`.
- integrity-sentinel: `expand_paths`, `compute_baseline`,
  `emit_drift_event`.
- tetragon: `render_tetragon_config`.
- observability: `render_scrape_config`, `render_dashboard`.
- vpn-bridge: profile dispatcher logic (`apply.sh` itself,
  no `lib.sh`).

### Packaging surface

The `.deb` ships modules under
`/usr/share/selfdef/modules/<slug>/`. Adding a
`/usr/share/selfdef/lib/module-lib.sh` is a one-line
addition to the cargo-deb assets list (or the packaging
manifest).

## Design alternatives considered

### Alternative A — System-wide sourcing convention

Ship `/usr/share/selfdef/lib/module-lib.sh`. Every module's
`install/lib.sh` sources it at the top before defining
module-specific helpers.

```bash
# agent-guard/install/lib.sh, after migration
source /usr/share/selfdef/lib/module-lib.sh
# ... module-specific helpers below ...
```

**Pros**
- Single source of truth.
- Easy to upgrade in lockstep with the daemon (.deb
  controls the version).
- No build-time machinery; the existing scripts source
  the path directly.

**Cons**
- Hard-coded path. Modules in a dev workspace (running
  outside the .deb install) need an alternative source.
- A `selfdefctl modules apply` from a workspace can't
  trivially find the lib unless we plumb the path through.

### Alternative B — Environment-variable indirection

The CLI dispatcher (`crates/selfdef-cli/src/modules.rs`)
exports `SELFDEF_MODULE_LIB` pointing at the shared lib
location. Each module's `install/lib.sh` reads:

```bash
source "${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
```

The dispatcher resolves the path from a workspace-relative
location when running tests / dev, or the system path
otherwise.

**Pros**
- Workspace + system installs both work.
- One source line per module.
- The dispatcher already has a notion of "module sources"
  (it resolves the manifest dir); plumbing one more env
  var is small.

**Cons**
- Two paths to keep in sync (env var + fallback).
- Operator running a module script outside selfdefctl
  needs to set the env var themselves.

### Alternative C — Per-module symlink

Each module's directory carries a symlink
`install/shared-lib.sh -> ../../../../share/selfdef/lib/module-lib.sh`
(or workspace-relative). Modules source the symlink.

**Pros**
- No env var, no fallback.

**Cons**
- Symlinks across the .deb / packaging boundary are
  fragile.
- Workspace symlinks complicate git checkouts on Windows
  CI (we don't run Windows but the principle stings).
- N symlinks to maintain, one per module.

### Alternative D — Library inlining via xtask

A new `xtask` step (`xtask modules build`) reads each
module's `lib.sh`, inlines the shared helpers at build
time, and produces a self-contained `lib.sh` shipped in
the .deb. The source-tree per-module `lib.sh` files stay
small and reference shared symbols.

**Pros**
- Runtime: every module is self-contained. No path
  problems.
- Source: helpers live in one place.

**Cons**
- Build step. Operators building from source via plain
  `cargo deb` get stale modules unless they run
  `xtask modules build` first.
- New machinery to maintain (the xtask).
- Diffing the generated `lib.sh` files in PRs becomes
  noisy.

## Recommended design

**Alternative B**. Environment-variable indirection with a
sensible fallback.

Reasoning:
- A is close to right but breaks dev workflow without
  some workspace path injection.
- B is A with that injection.
- C and D both introduce machinery proportionally larger
  than the savings.

The dispatcher already exports `SELFDEF_<SLUG>_CONFIG` for
every module; adding `SELFDEF_MODULE_LIB` is the smallest
incremental change.

## Detailed design

### D-1 — Shared library at `/usr/share/selfdef/lib/module-lib.sh`

A new file in the source tree:
`packaging/lib/module-lib.sh`. Contents (paraphrased):

```bash
# /usr/share/selfdef/lib/module-lib.sh
#
# Shared helpers for selfdef install modules. Source from
# every module's apply.sh / check.sh / uninstall.sh after
# setting MODULE.
#
# Caller must have set:
#   MODULE       — module slug, e.g. "tetragon"
#   DRY_RUN      — "0" or "1"
# Caller may set:
#   SELFDEF_MODULE_LIB_VERSION_REQUIRED — minimum library
#       version required by the module. If unset, defaults
#       to 1.

SELFDEF_MODULE_LIB_VERSION=1

# Refuse to source if the module requested a newer version
# than we provide.
if [[ "${SELFDEF_MODULE_LIB_VERSION_REQUIRED:-1}" -gt \
      "${SELFDEF_MODULE_LIB_VERSION}" ]]; then
    echo "[${MODULE}] shared module-lib version mismatch: \
require >=${SELFDEF_MODULE_LIB_VERSION_REQUIRED}, have \
${SELFDEF_MODULE_LIB_VERSION}" >&2
    exit 99
fi

log() { echo "[${MODULE}] $*" >&2; }

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}

die() { emit_status "failed" "$*"; exit 1; }

run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
    fi
}

toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}
```

Version starts at 1. Each helper signature matches the
existing per-module implementations exactly so the
migration is mechanical.

### D-2 — CLI dispatcher sets `SELFDEF_MODULE_LIB`

`crates/selfdef-cli/src/modules.rs run_one()`
(approximate site lines 713-787) gains:

```rust
let lib_path = resolve_module_lib_path();
cmd.env("SELFDEF_MODULE_LIB", &lib_path);
```

`resolve_module_lib_path()`:
- Honour `SELFDEF_MODULE_LIB` from the parent process if
  set (operator override).
- Otherwise: in a workspace run
  (`CARGO_MANIFEST_DIR` resolves), use
  `<workspace>/packaging/lib/module-lib.sh`.
- Otherwise (installed system): use
  `/usr/share/selfdef/lib/module-lib.sh`.

The resolve helper has unit-test coverage parallel to
`resolve_dir` for modules.

### D-3 — Per-module migration

Each module's `install/lib.sh` becomes:

```bash
# Module-specific helpers for <slug>. Shared helpers (log,
# emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh.

# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
source "${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"

# ---- module-specific helpers below ----
# (resolve_action, render_policy, etc.)
```

Migration order (independent PRs, one per module so each is
reviewable):

1. tetragon
2. observability
3. integrity-sentinel
4. agent-guard
5. bridge-l2
6. vpn-bridge

Each migration PR:
- Replaces the per-module duplicate helpers with a `source`
  line.
- Runs the module's existing tests.
- Adds no behaviour changes.

`agent-guard`'s `uninstall.sh` (F-2026-050) can move to a
helper-discovered policy enumeration in a follow-up PR.
The shared lib gains a helper `module_render_files` that
takes a glob and returns the rendered destinations; the
uninstall script iterates the result. Out of scope for the
migration PRs themselves; tracked separately.

F-2026-051 (`render_pod_scope` awk fragility): not closed
by the shared lib in v1. A future v2 of the shared lib
could expose `yq`- or `python`-backed YAML editing
helpers, but that's a v2 design and not in scope here.
Listed as a partial close.

### D-4 — Library versioning policy

- Increment `SELFDEF_MODULE_LIB_VERSION` only on a
  **breaking change** to an existing helper signature.
- New helpers without breaking existing ones don't bump
  the version; modules that need them set their required
  version higher.
- Document the version + every helper in
  `docs/dev/module-helpers.md` (created in this SDD's
  implementation PR or the first migration PR).

### D-5 — Packaging

`packaging/debian/Cargo.toml`-or-equivalent gains an
assets entry:

```
("packaging/lib/module-lib.sh", "/usr/share/selfdef/lib/module-lib.sh", "0644")
```

Mode 0644: world-readable; only root writes (sourcing
doesn't require write access).

### D-6 — Test plan (implementation PR must satisfy)

1. Unit tests in `selfdef-cli/src/modules.rs`:
   - `resolve_module_lib_path()` returns the workspace path
     when `CARGO_MANIFEST_DIR` is set and the file exists.
   - Returns `/usr/share/selfdef/lib/module-lib.sh` when
     neither override nor workspace path exists (mocked
     filesystem).
   - Honours `SELFDEF_MODULE_LIB` override.
2. Integration test:
   - Existing `cli_modules_apply.rs` tests continue to
     pass with the new env var present.
   - A new test asserts a module sourcing the shared lib
     in a tempdir succeeds when `SELFDEF_MODULE_LIB` points
     at it; fails with version-mismatch exit code when the
     module requests a higher version.
3. Per-module test runs: every migrated module's existing
   tests stay green.

### D-7 — Rollback plan

If a migration PR breaks an unforeseen surface, revert is
mechanical: restore the per-module helpers and remove the
`source` line. Because the shared lib's helpers are
copies of the per-module helpers (same signatures, same
behaviour), the revert produces byte-identical script
behaviour pre- and post-migration.

## Rollout / migration

- Phase A: ship the shared library + dispatcher plumbing.
  No module migration in this PR. CI green; no behaviour
  change.
- Phase B: migrate one module (start with tetragon — small
  surface). PR is small; reviewer can check the diff is
  purely "delete copy + add source line".
- Phase C: repeat for the remaining five modules over a
  small number of PRs (one each or batched if reviewers
  prefer).
- Phase D: the new-module scaffolding (`xtask modules
  init`, if/when it lands) uses the shared lib by default.

The phases can land in separate PRs over multiple sessions
without coordinating with other SDDs.

## Risks

- **R-1 — the dispatcher's `CARGO_MANIFEST_DIR` resolution
  doesn't catch every dev path.** Mitigated by the
  `SELFDEF_MODULE_LIB` override; operators running module
  scripts standalone for debugging can set it.
- **R-2 — shared lib bug breaks every module at once.**
  Mitigated by the version pin and by keeping the shared
  helpers byte-identical with the existing per-module
  versions on first land (no semantic change).
- **R-3 — `agent-guard`'s `render_pod_scope` awk fragility
  isn't fixed here.** Acknowledged in D-3 as partial close
  of F-2026-051. A future v2 of the shared lib could add
  YAML-aware editing helpers; tracked separately.

## Open questions

- **Q-A** — Should the shared lib live in `packaging/lib/`
  (alongside other deb-distributed assets) or in a new
  top-level `share/selfdef-lib/`? **Answered (D-019, 2026-05-15)** —
  `packaging/lib/` (alongside other deb-distributed assets).
  _Original framing for history_: The packaging path is
  what the daemon ships today; reuse it unless a
  cross-package concern emerges.
- **Q-B** — Should `module-helpers.md` go under
  `docs/src/dev/` (visible to contributors writing
  modules) or under `docs/sdd/` (alongside design docs)?
  **Answered (D-020, 2026-05-15)** — `docs/src/dev/` with
  back-reference from the SDD. _Original framing for
  history_: Suggestion: dev, with a back-reference from the SDD.
- **Q-C** — Future v2 of the shared lib for YAML editing:
  bring `yq` in as a `requires` for affected modules, or
  ship a small in-house YAML editor in bash / python?
  **Answered (D-021, 2026-05-15)** — out of scope for v1;
  tracked. Decision deferred to a future v2 SDD when YAML-
  editing modules need it. _Original framing for history_:
  Out of scope here; tracked.

## Appendix — interaction with other SDDs

- **SDD-001 / SDD-002**: implementation PRs will touch
  agent-guard + tetragon + integrity-sentinel. Whether
  they land before or after this SDD's migration of those
  modules is sequencing — either order works. Suggested:
  SDD-001/002 first (the new features), this SDD's
  migration after (no behaviour change). The reverse
  works if implementation prefers a clean script before
  adding to it.
- **SDD-003**: vpn-bridge multi-instance plumbing touches
  the dispatcher; this SDD also touches the dispatcher.
  Same site (env var injection). Likely land SDD-003's
  changes first, then this SDD's smaller dispatcher add.
- **SDD-005**: dry-run-negative tests (D-2a) become
  shared via the test-common library, which is the test-
  side analogue of this SDD. The two compose.

## Follow-up findings (F-2027-045)

Phase 2 raised three findings against this SDD's surface; all
closed in tree. Listed here so future SDD readers can trace
the lineage from this design doc to the post-Phase-1
iterations. The authoritative per-module adoption table lives
in [`docs/dev/module-helpers.md`](../dev/module-helpers.md) §
"Per-module adoption" (F-2027-026).

- **F-2027-024** — the original v2 library landed with
  `agent-guard` as the only adopter. Phase 2 v2-helpers
  migration PR (#65) opted in five more script-based
  modules: `bridge-l2`, `integrity-sentinel`, `polarproxy`,
  `observability`, `tetragon`. Each retains a legacy-
  fallback branch in `uninstall.sh` so pre-v2 installs
  still uninstall cleanly. `suricata` is N/A (no rendered
  files outside its own dir); `vpn-bridge` is deferred (its
  dispatcher pattern delegates rendering to per-profile
  sourced scripts; migration needs to flow through each
  profile independently).
- **F-2027-026** — per-module READMEs were silent on
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED`. Phase 2 module-
  cleanup PR (#64) added the central adoption table in
  `docs/dev/module-helpers.md` instead of duplicating the
  line across 8 READMEs.
- **F-2027-027** — three modules' `check.sh` scripts
  (`bridge-l2`, `suricata`, `polarproxy`) missed the
  conventional `DRY_RUN=0` initialization that every other
  module's `check.sh` sets. Cosmetic but inconsistent with
  the v2 lib's caller contract. PR (#64) standardised all
  three.
