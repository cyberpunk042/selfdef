# SDD-063 — Writable-directory policy helper (module-lib v4)

Status: accepted
Depends on: SDD-061 (shared watchdog scan helpers / module-lib v3)

## Implementation status

- [x] D-1 — `module-lib.sh` bumped to v4 with a new pure helper
      `selfdef_is_writable_dir`
- [x] D-2 — L2 bats coverage for the new helper
- [x] D-3 — migrate the three directory-valued watchdog checks
      (musl-ld-path, xorg-config ModulePath, sudo-conf plugin_dir) onto it

## Why now

SDD-061's `selfdef_is_writable_path` answers "is this path strictly
*under* an attacker-writable root" — it matches `^/(tmp|var/tmp|dev/shm|
home)/` and therefore REQUIRES a trailing component. That is exactly right
for FILE-valued checks (a `.so` / program path; a bare root as a file path
is nonsensical).

But several watchdogs check DIRECTORY-valued settings, where the dangerous
value can be the writable root ITSELF:

- `xorg-config` `ModulePath "/tmp"` — the root X server then loads modules
  from world-writable `/tmp`.
- `sudo-conf` `Path plugin_dir /tmp` — relative plugin names resolve from
  `/tmp`, loading attacker code into setuid-root sudo.
- `musl-ld-path` a search-path entry of exactly `/tmp` — the loader
  resolves libraries from there.

With only the file helper, `ModulePath "/tmp"` and `plugin_dir /tmp` are
SILENTLY MISSED (verified: both emit `ok`). `musl-ld-path` papered over
this with a local compound clause
(`selfdef_is_writable_path "$d" || [[ "$d" =~ ^/(tmp|…)$ ]]`) — a
per-module copy of policy, exactly the duplication SDD-061 set out to
remove.

## Goals

1. One shared helper for the directory case: matches a path that is AT or
   UNDER a writable root.
2. Migrate the three directory-valued checks onto it; delete musl's
   compound workaround.
3. Close the bare-root gap (a bare `/tmp` directory value now alerts).

## Non-goals

- Changing `selfdef_is_writable_path` semantics. File-valued checks keep
  the trailing-component requirement (no bare-root file paths, and a
  bare `/home` — which is root-owned, not world-writable — should not be
  flagged for the file case).

## Design

### D-1 — `selfdef_is_writable_dir`

```bash
selfdef_is_writable_dir() {
    [[ "${1:-}" =~ ^/(tmp|var/tmp|dev/shm|home)(/|$) ]]
}
```

`(/|$)` accepts both the bare root (`/tmp`) and any path under it
(`/tmp/x`). Pure + side-effect-free, same shape as the file helper.

`/home` bare is included for symmetry: while `/home` itself is root-owned,
no legitimate library/plugin directory is ever set to exactly `/home`, so
flagging it is a near-zero-FP, defence-in-depth signal — and keeping the
four roots uniform avoids a surprising asymmetry in the policy.

The library version bumps to **4** (additive; the v3 helpers are
unchanged). Modules that call `selfdef_is_writable_dir` require >=4 and
fail loud (`module_lib_outdated`) on an older library; modules that only
use the v3 helpers keep requiring >=3 (4>=3 passes).

### D-2 — test-first

L2 cases in `L2-module-lib-watchdog.bats`: the dir helper flags the four
bare roots AND paths under them, and does NOT flag standard system dirs,
empty, or relative paths.

### D-3 — migrate the directory-valued checks

- `musl-ld-path` — replace the compound clause with
  `selfdef_is_writable_dir "$dir"`; require lib v4.
- `xorg-config` — ModulePath dirs use `selfdef_is_writable_dir`; require v4.
- `sudo-conf` — `plugin_dir` value uses `selfdef_is_writable_dir`; require
  v4. (The `Plugin <.so>` path stays on the FILE helper.)

Each module's L2 suite re-run; xorg + sudo gain a bare-root alert test
(previously a silent gap), musl's existing bare-root test keeps passing.

## Testing

```
bats packaging/test/L2-module-lib-watchdog.bats
bats packaging/test/L2-{musl-ld-path,xorg-config,sudo-conf}-watchdog.bats
bash scripts/test/L1-module-contracts.sh
```

## References

- SDD-061 — shared watchdog scan helpers (the file helper this complements).
