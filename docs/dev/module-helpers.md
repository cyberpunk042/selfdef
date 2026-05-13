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
SELFDEF_MODULE_LIB_VERSION=1
```

The version starts at `1`. Increment policy:

- **Bump on breaking change** to an existing helper signature
  (e.g. `run()` gains a required argument; `toml_get` changes
  return contract).
- **Don't bump on additive** changes — new helpers don't break
  existing modules. Modules that depend on the new helper set
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED` higher; older modules
  keep working unchanged.

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
