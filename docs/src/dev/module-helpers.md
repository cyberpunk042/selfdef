# Shared module-script helpers

This page is the **mdbook-published entry point** for the shared
module-script library documentation. The canonical, living version
lives at
[`docs/dev/module-helpers.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/dev/module-helpers.md)
in the source tree; this page surfaces it here so contributors writing
modules can find it from the book.

## What ships

`packaging/lib/module-lib.sh` is sourced by every shipped module's
`install/{apply,check,uninstall}.sh` via the dispatcher-exported
`SELFDEF_MODULE_LIB` environment variable. The library provides five
core helpers:

| Helper | Purpose |
|---|---|
| `log "$msg"` | stderr logger with module-slug prefix |
| `emit_status "$status" "$message"` | structured JSON status line on stdout |
| `die "$msg"` | `emit_status "failed" "$msg"` + `exit 1` |
| `run "$desc" -- <cmd...>` | dry-run-aware command wrapper (no-op under `SELFDEF_DRY_RUN=1`) |
| `toml_get "$key" "$file"` | minimal one-line TOML reader |

The shared library version-pins itself
(`SELFDEF_MODULE_LIB_VERSION=1`); a module sourcing it at the wrong
major version exits with code 99 at source time. v2 introduces
`module_record_file` for tracking persistent files written, so
`uninstall.sh` can enumerate without hand-rolled lists.

## How to use it

The dispatcher's resolution path (`crates/selfdef-cli/src/modules.rs::resolve_module_lib_path`)
checks:

1. `SELFDEF_MODULE_LIB` env override (operator/test escape hatch).
2. Workspace path `packaging/lib/module-lib.sh` (during development).
3. Installed path `/usr/share/selfdef/lib/module-lib.sh` (production).

Modules source it with a `${BASH_SOURCE[0]%/*}` parameter-expansion
fallback to the workspace path (no `dirname` call so the resolver
works under stripped `$PATH`).

## Source of truth

The canonical doc — with the per-helper signature/contract, the
versioning policy, the per-module v2 adoption table, the override
patterns for `vpn-bridge`/`bridge-l2` uninstall, and the "adding a
new module-specific helper" recipe — is at
[`docs/dev/module-helpers.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/dev/module-helpers.md).

Design rationale:
[SDD-006](https://github.com/cyberpunk042/selfdef/blob/main/docs/sdd/006-shared-module-script-lib.md).
