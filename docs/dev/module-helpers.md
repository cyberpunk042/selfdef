# Module helpers reference (SDD-006)

The selfdef install modules under `modules/<slug>/install/` source
a shared bash library that provides the five core helpers every
apply / check / uninstall script uses. This document is the
authoritative reference for that library: where it lives, what it
exports, how versioning works, and how to add new helpers.

## Source of truth

- **Workspace path**: `packaging/lib/module-lib.sh`
- **Installed path** (the `.deb` ships it here):
  `/usr/share/selfdef/lib/module-lib.sh`
- **Sourced via**: each module's `install/lib.sh` resolves the
  path in this order:
  1. `$SELFDEF_MODULE_LIB` if set and readable (selfdefctl
     exports this for every script it spawns).
  2. `<this lib.sh>/../../../packaging/lib/module-lib.sh` if it
     exists — catches workspace runs / integration tests / ad-hoc
     invocations from a checkout.
  3. `/usr/share/selfdef/lib/module-lib.sh` — system install.

The resolver is plain bash parameter expansion and `[[ -r ... ]]`
tests; it doesn't shell out to `dirname` or anything that would
fail when scripts run under a stripped `$PATH`.

## Caller contract

Before sourcing, the module's lib.sh must have set:

| Variable | Purpose |
| --- | --- |
| `MODULE` | Module slug (e.g. `"tetragon"`). Used by `log()` / `emit_status()` to identify the module in stderr lines and the final structured-status JSON. |
| `DRY_RUN` | `"0"` or `"1"`. When `"1"`, `run()` logs the command it would have executed and skips it. selfdefctl's dispatcher sets this from `SELFDEF_DRY_RUN`. |

Optional, set if you need a newer library version than the
default:

| Variable | Purpose |
| --- | --- |
| `SELFDEF_MODULE_LIB_VERSION_REQUIRED` | Minimum library version the module needs. Defaults to `1`. If the library on disk is older, sourcing exits 99 with a clear message. |

## Library version

```bash
SELFDEF_MODULE_LIB_VERSION=2
```

The version starts at `1`; the F-2026-050 follow-up bumped it
to `2` to add the manifest helpers (see v2 changes below).
Increment policy:

- **Bump on breaking change** to an existing helper signature
  (e.g. `run()` gains a required argument; `toml_get` changes
  return contract).
- **Bump on a new helper set that modules MUST require to
  function** (e.g. v2's `module_record_file` — agent-guard's
  uninstall depends on it via the manifest contract).
- **Don't bump on additive** changes that older modules
  wouldn't even know to look for. Modules that depend on the
  new helper set `SELFDEF_MODULE_LIB_VERSION_REQUIRED` higher;
  older modules keep working unchanged.

### v2 changes (SDD-006 F-2026-050 follow-up)

Added the **manifest helpers** so modules that render files
outside their own tree (TracingPolicies into
`/etc/tetragon/tetragon.tp.d/`, systemd units into
`/etc/systemd/system/`, …) don't have to hand-enumerate their
rendered outputs in `uninstall.sh`. `apply.sh` calls
`module_record_file <path>` for every file it writes;
`uninstall.sh` iterates `module_render_files` to get the full
list and removes each (then `module_clear_manifest` wipes the
record).

The manifest lives at
`${MODULE_INSTALLED_MANIFEST:-/var/lib/selfdef/installed/<MODULE>.manifest}`
(one absolute path per line). Tests override the env var to a
tempdir per fixture so they don't pollute the host's
`/var/lib/selfdef/installed/`.

### Per-module adoption (F-2027-026)

Authoritative table of which library version each shipped
module requires. Operators rarely care; contributors editing a
module's `apply.sh` / `uninstall.sh` need it to know which
helpers are reachable. Bump the module's
`SELFDEF_MODULE_LIB_VERSION_REQUIRED` when introducing a v2-only
helper.

| Module | Required version | Notes |
| --- | --- | --- |
| `agent-guard` | **2** | Uses `module_record_file` to track every TracingPolicy it renders into `/etc/tetragon/tetragon.tp.d/`; `uninstall.sh` walks the manifest. |
| `bridge-l2` | **2** | Migrated F-2027-024: tracks `NFT_RULESET_PATH` via the manifest. Pre-v2 fallback path retained for legacy installs. |
| `detect-host` | n/a | `[install] kind = "debian-package"`; no install scripts. |
| `integrity-sentinel` | **2** | Migrated F-2027-024: tracks the baseline path via the manifest. Legacy fallback retained. |
| `observability` | **2** | Migrated F-2027-024: tracks `SCRAPE_DST` + `DASHBOARD_DST` via the manifest. Legacy `bundled` / `external` fallbacks retained. |
| `polarproxy` | **2** | Migrated F-2027-024: tracks `UNIT_PATH` (always) + `NFT_RULESET_PATH` (host-tls-mitm only). Legacy fallback retained. |
| `suricata` | 1 | Doesn't render files outside its own template dir; v2 migration is a no-op (no manifest entries to track). |
| `tetragon` | **2** | Migrated F-2027-024: tracks `CONFIG_PATH` via the manifest. `policy_dir` and `event_log` are NOT tracked by design — they're operator-owned drop dirs that long outlive this module's installation. |
| `vpn-bridge` | 1 | Per-profile sub-scripts (`install/profiles/*.sh`) each own their own files; v2 migration would need to flow through the sourced profile scripts. Deferred to a follow-up. |

Bumping a module from v1 to v2 is mechanical:
1. Set `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` in the module's
   `install/lib.sh` shim.
2. In `apply.sh`, wrap every `install`/`mkdir`/`cp` of a
   rendered file with `module_record_file "<absolute path>"`.
3. Replace the hand-enumerated removals in `uninstall.sh` with
   `for f in $(module_render_files); do rm -f "$f"; done` plus
   `module_clear_manifest` at the end.
4. Add a `dry_run_must_be_a_noop` test pair (Pattern P-1 in
   `docs/dev/test-contract.md`) to confirm the manifest tracking
   doesn't escape the dry-run no-op contract.

## Exported helpers (v1)

### `log "$msg"`

Writes `[$MODULE] $msg` to **stderr**. Use for free-form trace
messages. Never appears in the structured-status JSON.

```bash
log "applying nftables ruleset"
log "DRY-RUN: would restart service"
```

### `emit_status "$status" "$message"`

Writes a single JSON line to **stdout** in the form

```json
{"module":"<slug>","status":"<status>","message":"<message>"}
```

Quote characters in `$message` are backslash-escaped. selfdefctl's
dispatcher reads the last stdout line as the canonical outcome.

Valid statuses (enforced by the dispatcher, not the helper):
`"ok"`, `"skipped"`, `"failed"`.

### `die "$msg"`

Convenience: `emit_status "failed" "$msg"` followed by `exit 1`.
Use anywhere a precondition is violated.

```bash
[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
```

### `run "$description" -- <cmd...>`

Dry-run-aware command wrapper.

- When `DRY_RUN=0` (the default): logs `$description` and
  executes the command.
- When `DRY_RUN=1`: logs `DRY-RUN: $description` followed by the
  command that **would** have run, prefixed with `$`, but does
  not execute it.

The `--` separator is optional but recommended for readability —
the helper accepts both forms.

```bash
run "install ruleset to $NFT_PATH" -- install -D -m 0644 "$src" "$NFT_PATH"
run "load ruleset" -- nft -f "$NFT_PATH"
```

### `toml_get "$key" "$file"`

Minimal TOML reader — handles `key = "value"` and `key = N` (one
key per line, no nested tables, no inline arrays). Returns the
value with surrounding quotes and trailing `# comments` stripped.
Exit code is `1` if the key isn't found; callers typically use
`|| echo "<default>"`.

```bash
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
```

For arrays, modules write their own helper (see
`modules/bridge-l2/install/lib.sh:toml_get_list`). Adding a
shared `toml_get_list` to the library is fine — bump the docs
here and add tests.

### `module_record_file "$path"` (v2)

Append `$path` to the per-module install manifest. Idempotent
(re-recording the same path is a no-op). Dry-run aware: when
`DRY_RUN=1`, logs the intent and skips the write.

Use it in `apply.sh` for every file you `install`/`cp`/`render`
outside the module's own tree:

```bash
install -m 0644 "$tmp" "$dst"
module_record_file "$dst"
```

The manifest lives at
`${MODULE_INSTALLED_MANIFEST:-/var/lib/selfdef/installed/<MODULE>.manifest}`.
Tests override `MODULE_INSTALLED_MANIFEST` per fixture for
hermetic execution.

### `module_render_files` (v2)

Print every recorded path, one per line. Use in `uninstall.sh`
to enumerate what needs cleaning up:

```bash
while IFS= read -r dst; do
    [[ -z "$dst" ]] && continue
    [[ -f "$dst" ]] && run "remove $dst" -- rm -f "$dst"
done < <(module_render_files)
module_clear_manifest
```

Empty output when no manifest exists (pre-first-apply or
pre-v2 install). Callers that need a legacy-enum fallback
check the call's output count and fall back when zero — see
`modules/agent-guard/install/uninstall.sh` for the canonical
migration shape.

### `module_clear_manifest` (v2)

Removes the per-module manifest. Call after iterating
`module_render_files` in `uninstall.sh`. Dry-run aware.

## Adding a module-specific helper

Your module's `install/lib.sh` sources the shared lib first, then
defines its own helpers below. They share the bash environment,
so they can call `log` / `die` / etc. freely.

```bash
# modules/<slug>/install/lib.sh
SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
# ... shared-lib resolver block (copy from another module) ...
source "$_selfdef_lib"
unset _selfdef_lib

# Module-specific helpers below.
my_helper() {
    local x="$1"
    [[ -n "$x" ]] || die "my_helper: missing arg"
    log "doing the thing with $x"
}
```

The dispatcher exports `SELFDEF_MODULE_LIB` for every script it
spawns. Integration tests running scripts directly hit the
workspace-fallback branch of the resolver. Operator debug runs
either set the env var manually or hit the installed-path branch.

## Overriding a shared helper

A module can re-define `log()` / `run()` / etc. after sourcing
the shared lib — bash takes the last definition. The bridge-l2
and polarproxy `uninstall.sh` scripts do this to keep their
`[<slug>:uninstall]` log prefix and lenient `run()` that
tolerates per-step failures.

Treat overrides as a code smell: prefer adding a new helper to
the shared lib (e.g. a `run_lenient`) if the pattern shows up in
more than one module.

## Adding a new helper to v1

For an additive helper (no signature change to existing helpers):

1. Add the function to `packaging/lib/module-lib.sh`. Keep it
   small and pure-bash where possible.
2. Add a section here documenting it.
3. Add a unit-style integration test in
   `crates/selfdef-cli/tests/module_shared_lib.rs` that sources
   the lib in a tempdir and exercises the helper end-to-end.
4. The first module that needs it doesn't need to bump
   `SELFDEF_MODULE_LIB_VERSION_REQUIRED` — additive helpers
   don't break older selfdef installs unless a module actually
   calls the new function.

## Adding a v2

For a breaking change:

1. Bump `SELFDEF_MODULE_LIB_VERSION` in
   `packaging/lib/module-lib.sh` to `2`.
2. Update this doc with a "v2 changes" section.
3. In every module that adopts the new signature, set
   `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2`. Older selfdef
   installs will refuse to source the lib with a clear error
   ("require >=2, have 1") rather than running the module
   against a mismatched helper.
4. Coordinate the `.deb` release so the new shared lib ships
   alongside the modules that depend on it.

## Packaging

The shared lib ships via the cargo-deb assets list. See
`Cargo.toml` (`[package.metadata.deb]`) for the entry:

```toml
("packaging/lib/module-lib.sh", "usr/share/selfdef/lib/module-lib.sh", "644"),
```

Mode `0644` — world-readable so scripts running as non-root (the
check.sh family) can source it; only root can edit it.
