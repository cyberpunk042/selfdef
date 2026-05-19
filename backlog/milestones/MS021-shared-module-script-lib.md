# MS021 — Shared module-script lib

> Parent: `backlog/milestones/INDEX.md` row MS021.
> Source: `docs/sdd/006-shared-module-script-lib.md` (590 lines; status=implemented; closes F-2026-081 SDD-debt parent + F-2026-050 (deferred) + F-2026-051 (partial)) + `packaging/lib/module-lib.sh` + `/usr/share/selfdef/lib/module-lib.sh` install + 8 migrated modules + `docs/dev/module-helpers.md` runbook. All entries below extract verbatim. No invention.

## Epics (E0211–E0220)

| Epic ID | Phrase | Source |
|---|---|---|
| E0211 | SDD-006 mission — Shared module-script library; closes F-2026-081 SDD-debt parent + F-2026-050 deferred + F-2026-051 partial; Phase A+B+C collapsed to single PR per operator's "big chunks" steer; shared library landed + dispatcher exports SELFDEF_MODULE_LIB + all 8 modules with helpers migrated in one go (agent-guard / tetragon / observability / integrity-sentinel / vpn-bridge / bridge-l2 / polarproxy / suricata); migration byte-stable | SDD-006 § header + § Implementation status |
| E0212 | Problem statement — F-2026-081 audit M-011 flagged every shipped module reimplements same 5 helpers in own install/lib.sh (log / emit_status / die / run / toml_get); 6 modules carry copy + 1 has no scripts (detect-host) + 2 have inline equivalents (polarproxy / suricata); ~30 lines × 6 modules = ~180 lines duplicated; cost: bug fix has to be applied in 6 places + helpers drift + new modules paste skeleton perpetuating cycle | SDD-006 § Problem |
| E0213 | F-2026-050 + F-2026-051 adjacent findings closed as side effect — F-2026-050 agent-guard/uninstall.sh enumerates policy filenames by hand (shared `manifest_owned_files` would let script discover own outputs) DEFERRED to follow-up; F-2026-051 render_pod_scope awk state-machine fragility PARTIAL close (shared YAML-aware editor helper bigger ask; tracked separately) | SDD-006 § Problem + § Deferred to follow-up |
| E0214 | 5 Goals — (1) one installed copy of shared helpers sourced by every module's apply/check/uninstall; (2) shared library version-pins itself so module built against v2 doesn't silently break under v1; (3) library is strict superset of today's per-module helpers (every existing helper works the same); (4) migrating a single module is focused PR (source shared lib + delete local copy + run module tests); (5) future modules pick up library by default; init scaffolding produces apply.sh that already sources it | SDD-006 § Goals |
| E0215 | 4 Non-goals + 3-term Glossary — Non-goals: general "module SDK" with state-mgmt+retries (scope is shared helpers, not framework); Rust rewrite (scripts stay bash; library is bash); removing per-module lib.sh entirely (each module's lib.sh may still hold module-specific helpers); breaking change (old modules built against per-module helpers must keep working at same time as shared lib). Glossary: shared lib (`/usr/share/selfdef/lib/module-lib.sh`) / module-local lib (each module's existing `install/lib.sh`) / library version (small integer stamped into shared lib's header that scripts assert against) | SDD-006 § Non-goals + § Glossary |
| E0216 | Current state — Helper inventory: log + emit_status + run + toml_get carried by 6 modules (agent-guard / bridge-l2 / integrity-sentinel / observability / tetragon / vpn-bridge); die carried by 5 modules (above minus bridge-l2); module-specific helpers stay (agent-guard: resolve_action / render_policy / render_egress_allowlist / render_securemessage_endpoint / render_pod_scope / render_gpu_policy; integrity-sentinel: expand_paths / compute_baseline / emit_drift_event; tetragon: render_tetragon_config; observability: render_scrape_config / render_dashboard; vpn-bridge: profile dispatcher logic in apply.sh) | SDD-006 § Current state + § Helper inventory |
| E0217 | 4 Design alternatives + recommended — A (system-wide sourcing convention; source `/usr/share/selfdef/lib/module-lib.sh` directly at top of every lib.sh) + B (env-var indirection; dispatcher exports SELFDEF_MODULE_LIB; lib.sh sources it; **RECOMMENDED**) + C (per-module symlink at packaging time; high coupling) + D (library inlining via xtask; rebuild ceremony); B chosen — env-var override enables operator testing, install location overridable, scripts stay portable | SDD-006 § Design alternatives + § Recommended design |
| E0218 | D-1 + D-2 — Shared library `packaging/lib/module-lib.sh` ships 5 helpers (log / emit_status / die / run / toml_get) + version pin `SELFDEF_MODULE_LIB_VERSION=1` + version-mismatch enforced at source time with exit 99; D-2 Dispatcher plumbing — `run_one` in `crates/selfdef-cli/src/modules.rs` exports `SELFDEF_MODULE_LIB` via new `resolve_module_lib_path()` with 3-tier precedence (env override → workspace `packaging/lib/module-lib.sh` → installed `/usr/share/selfdef/lib/module-lib.sh`); both branches have unit + integration coverage | SDD-006 § D-1 + § D-2 + § Implementation status |
| E0219 | D-3 + D-4 + D-5 — Per-module migration: 8 install/lib.sh files now source shared library with `${BASH_SOURCE[0]%/*}` parameter-expansion fallback to workspace path (no dirname call so resolver works under stripped $PATH); inline-helper scripts (bridge-l2 / polarproxy / suricata) gain own lib.sh + source it from apply/check/uninstall; vpn-bridge + bridge-l2 uninstall scripts override `log()` and `run()` after sourcing (preserves pre-SDD-006 `[<slug>:uninstall]` log prefix + lenient continue-past-failure); D-4 docs/dev/module-helpers.md documents every exported helper + caller contract + versioning policy + how to add module-specific helpers/overrides; D-5 packaging `crates/selfdef-daemon/Cargo.toml [package.metadata.deb]` assets installs shared lib at `/usr/share/selfdef/lib/module-lib.sh` mode 0644 | SDD-006 § D-3 + § D-4 + § D-5 + § Implementation status |
| E0220 | D-6 Tests + Rollout + Risks + Q-A/B/C + Appendix — Unit test `resolve_module_lib_path_finds_workspace_by_default` (operator-override branch covered by integration only; workspace lint forbids in-process std::env::set_var); Integration tests in `crates/selfdef-cli/tests/cli_modules_shared_lib.rs` (dispatcher_exports_module_lib_env_var / module_sourcing_shared_lib_at_v1_succeeds / module_requesting_newer_lib_version_is_refused); Rollout: existing modules keep working with own lib.sh; new shared lib lands without breaking; CHANGELOG migration note; Risks R-1 (sourcing breakage if file missing) R-2 (env-var path leak in CI) R-3 (version-pin too aggressive freezes evolution); Q-A SELFDEF_MODULE_LIB precedence answered (env > workspace > installed) Q-B helper signatures backward compat answered (yes; superset; v2 may add) Q-C uninstall log-prefix override answered (modules may override log() after sourcing) | SDD-006 § D-6 + § Rollout + § Risks + § Open questions + § Implementation status |

## Modules (M00525–M00550)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00525 | F-2026-081 SDD-debt parent — every shipped module reimplements same 5 helpers in own install/lib.sh | SDD-006 § Problem | E0212 |
| M00526 | F-2026-050 deferred — agent-guard/uninstall.sh enumerates policy filenames by hand; shared `manifest_owned_files` reserved for follow-up | SDD-006 § Deferred to follow-up | E0213 |
| M00527 | F-2026-051 partial — render_pod_scope awk fragility; YAML-aware editor helper not shipped in v1; tracked as separate ledger entry | SDD-006 § Deferred to follow-up | E0213 |
| M00528 | Helper 1 — `log "$msg"` (stderr logger) | SDD-006 § Problem | E0212 |
| M00529 | Helper 2 — `emit_status "$status" "$message"` (write structured status JSON line to stdout) | SDD-006 § Problem | E0212 |
| M00530 | Helper 3 — `die "$msg"` (emit_status failed + exit 1) | SDD-006 § Problem | E0212 |
| M00531 | Helper 4 — `run "$desc" -- <cmd...>` (dry-run-aware command wrapper) | SDD-006 § Problem | E0212 |
| M00532 | Helper 5 — `toml_get "$key" "$file"` (minimal TOML reader; one `key = "value"` per line) | SDD-006 § Problem | E0212 |
| M00533 | Shared library file — `packaging/lib/module-lib.sh` (workspace) | SDD-006 § D-1 + § Implementation status | E0218 |
| M00534 | Installed shared library — `/usr/share/selfdef/lib/module-lib.sh` (production) | SDD-006 § D-1 | E0218 |
| M00535 | Version pin — `SELFDEF_MODULE_LIB_VERSION=1` | SDD-006 § D-1 | E0218 |
| M00536 | Version-mismatch enforcement — exit 99 at source time | SDD-006 § D-1 | E0218 |
| M00537 | Dispatcher resolver — `resolve_module_lib_path()` in `crates/selfdef-cli/src/modules.rs` | SDD-006 § D-2 | E0218 |
| M00538 | Resolver precedence 1 — env override `SELFDEF_MODULE_LIB` (operator-testing override) | SDD-006 § D-2 | E0218 |
| M00539 | Resolver precedence 2 — workspace `packaging/lib/module-lib.sh` | SDD-006 § D-2 | E0218 |
| M00540 | Resolver precedence 3 — installed `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-2 | E0218 |
| M00541 | Per-module migration — 8 `install/lib.sh` files source shared library | SDD-006 § D-3 + § Implementation status | E0219 |
| M00542 | Source-resolution fallback — `${BASH_SOURCE[0]%/*}` parameter-expansion (no dirname call; works under stripped $PATH) | SDD-006 § D-3 + § Implementation status | E0219 |
| M00543 | Inline-helper modules — bridge-l2 / polarproxy / suricata gain own lib.sh; source it from apply/check/uninstall | SDD-006 § D-3 | E0219 |
| M00544 | Uninstall-override modules — vpn-bridge + bridge-l2 override `log()` + `run()` after sourcing (preserves `[<slug>:uninstall]` log prefix + lenient continue-past-failure) | SDD-006 § D-3 | E0219 |
| M00545 | Helpers runbook — `docs/dev/module-helpers.md` documents every exported helper + caller contract + versioning policy + how to add module-specific helpers/overrides | SDD-006 § D-4 | E0219 |
| M00546 | Packaging — `crates/selfdef-daemon/Cargo.toml [package.metadata.deb]` assets installs shared lib at `/usr/share/selfdef/lib/module-lib.sh` mode 0644 | SDD-006 § D-5 | E0219 |
| M00547 | Test — unit `resolve_module_lib_path_finds_workspace_by_default` (operator-override branch in integration only) | SDD-006 § D-6 + § Implementation status | E0220 |
| M00548 | Test — integration `dispatcher_exports_module_lib_env_var` | SDD-006 § D-6 + § Implementation status | E0220 |
| M00549 | Test — integration `module_sourcing_shared_lib_at_v1_succeeds` | SDD-006 § D-6 + § Implementation status | E0220 |
| M00550 | Test — integration `module_requesting_newer_lib_version_is_refused` | SDD-006 § D-6 + § Implementation status | E0220 |

## Features (F02401–F02520)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F02401 | SDD-006 status = implemented | SDD-006 § header | E0211 | composite | false |
| F02402 | SDD-006 closes F-2026-081 SDD-debt parent | SDD-006 § header | M00525 | composite | false |
| F02403 | SDD-006 closes F-2026-050 (deferred) | SDD-006 § header | M00526 | composite | false |
| F02404 | SDD-006 closes F-2026-051 (partial) | SDD-006 § header | M00527 | composite | false |
| F02405 | Phase A+B+C collapsed to single PR per operator's "big chunks" steer | SDD-006 § Implementation status | E0211 | composite | false |
| F02406 | 8 modules migrated in one go — agent-guard | SDD-006 § Implementation status | E0211 | composite | true |
| F02407 | 8 modules migrated in one go — tetragon | SDD-006 § Implementation status | E0211 | composite | true |
| F02408 | 8 modules migrated in one go — observability | SDD-006 § Implementation status | E0211 | composite | true |
| F02409 | 8 modules migrated in one go — integrity-sentinel | SDD-006 § Implementation status | E0211 | composite | true |
| F02410 | 8 modules migrated in one go — vpn-bridge | SDD-006 § Implementation status | E0211 | composite | true |
| F02411 | 8 modules migrated in one go — bridge-l2 | SDD-006 § Implementation status | E0211 | composite | true |
| F02412 | 8 modules migrated in one go — polarproxy | SDD-006 § Implementation status | E0211 | composite | true |
| F02413 | 8 modules migrated in one go — suricata | SDD-006 § Implementation status | E0211 | composite | true |
| F02414 | Migration is byte-stable — shared helpers match per-module copies exactly except for slug literal in log() which shared lib parameterises on ${MODULE} | SDD-006 § Implementation status | E0211 | composite | false |
| F02415 | F-2026-050 deferred — agent-guard/uninstall.sh enumerates policy filenames by hand | SDD-006 § Deferred to follow-up | M00526 | composite | false |
| F02416 | F-2026-050 — SDD reserved `module_render_files` helper for follow-up PR | SDD-006 § Deferred to follow-up | M00526 | composite | false |
| F02417 | F-2026-050 — v1 surface kept minimal; tracked separately; ledger entry remains open | SDD-006 § Deferred to follow-up | M00526 | composite | false |
| F02418 | F-2026-051 partial — render_pod_scope awk fragility | SDD-006 § Deferred to follow-up | M00527 | composite | false |
| F02419 | F-2026-051 — shared lib doesn't ship YAML-aware editing helpers in v1 | SDD-006 § Deferred to follow-up | M00527 | composite | false |
| F02420 | F-2026-051 — future v2 could ship yq- or python-backed helpers; tracked as separate ledger entry | SDD-006 § Deferred to follow-up | M00527 | composite | false |
| F02421 | F-2026-081 — every shipped module reimplements same helpers in own install/lib.sh | SDD-006 § Problem | M00525 | composite | false |
| F02422 | Helper 1 — `log "$msg"` (stderr logger) | SDD-006 § Problem | M00528 | composite | true |
| F02423 | Helper 2 — `emit_status "$status" "$message"` (structured status JSON line to stdout) | SDD-006 § Problem | M00529 | composite | true |
| F02424 | Helper 3 — `die "$msg"` (emit_status failed + exit 1) | SDD-006 § Problem | M00530 | composite | true |
| F02425 | Helper 4 — `run "$desc" -- <cmd...>` (dry-run-aware command wrapper) | SDD-006 § Problem | M00531 | composite | true |
| F02426 | Helper 5 — `toml_get "$key" "$file"` (minimal TOML reader; one `key = "value"` per line) | SDD-006 § Problem | M00532 | composite | true |
| F02427 | Six modules carry copy — agent-guard / bridge-l2 / integrity-sentinel / observability / tetragon / vpn-bridge | SDD-006 § Problem | E0212 | composite | false |
| F02428 | Seventh module (detect-host) has no scripts at all | SDD-006 § Problem | E0212 | composite | false |
| F02429 | Eighth + ninth modules (polarproxy + suricata) have inline equivalents | SDD-006 § Problem | E0212 | composite | false |
| F02430 | Duplicate lines counting — ~30 lines × 6 modules = ~180 lines duplicated | SDD-006 § Problem | E0212 | composite | false |
| F02431 | Cost — bug fix in one helper has to be applied in 6 places | SDD-006 § Problem | E0212 | composite | false |
| F02432 | Cost — helpers drift (agent-guard has resolve_action() no other module needs) | SDD-006 § Problem | E0212 | composite | false |
| F02433 | Cost — new modules paste same skeleton, perpetuating cycle | SDD-006 § Problem | E0212 | composite | false |
| F02434 | Goal 1 — one installed copy of shared helpers sourced by every module's apply/check/uninstall scripts | SDD-006 § Goals 1 | E0214 | composite | false |
| F02435 | Goal 2 — shared library version-pins itself so module built against v2 doesn't silently break under v1 | SDD-006 § Goals 2 | E0214 | composite | false |
| F02436 | Goal 3 — library is strict superset of today's per-module helpers; every existing helper works the same | SDD-006 § Goals 3 | E0214 | composite | false |
| F02437 | Goal 4 — migrating single module is focused PR (source shared lib + delete local copy + run module tests) | SDD-006 § Goals 4 | E0214 | composite | false |
| F02438 | Goal 5 — future modules pick up library by default; init scaffolding produces apply.sh that already sources it | SDD-006 § Goals 5 | E0214 | composite | false |
| F02439 | Non-goal — general "module SDK" with state management, retries, etc (scope is shared helpers, not framework) | SDD-006 § Non-goals | E0215 | composite | false |
| F02440 | Non-goal — Rust rewrite of install scripts (scripts stay bash; library is bash) | SDD-006 § Non-goals | E0215 | composite | false |
| F02441 | Non-goal — removing per-module lib.sh files entirely (each module's lib.sh may still hold module-specific helpers) | SDD-006 § Non-goals | E0215 | composite | false |
| F02442 | Non-goal — breaking change (old modules built against per-module helpers must keep working at same time as shared lib) | SDD-006 § Non-goals | E0215 | composite | false |
| F02443 | Glossary — shared lib = `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § Glossary | E0215 | composite | false |
| F02444 | Glossary — module-local lib = each module's existing `install/lib.sh` | SDD-006 § Glossary | E0215 | composite | false |
| F02445 | Glossary — library version = small integer stamped into shared lib's header that scripts assert against | SDD-006 § Glossary | E0215 | composite | false |
| F02446 | Helper inventory — `log` carried by agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge | SDD-006 § Helper inventory | E0216 | composite | false |
| F02447 | Helper inventory — `emit_status` carried by agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge | SDD-006 § Helper inventory | E0216 | composite | false |
| F02448 | Helper inventory — `die` carried by agent-guard, integrity-sentinel, observability, tetragon, vpn-bridge | SDD-006 § Helper inventory | E0216 | composite | false |
| F02449 | Helper inventory — `run` carried by agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge | SDD-006 § Helper inventory | E0216 | composite | false |
| F02450 | Helper inventory — `toml_get` carried by agent-guard, bridge-l2, integrity-sentinel, observability, tetragon, vpn-bridge | SDD-006 § Helper inventory | E0216 | composite | false |
| F02451 | Module-specific helper stays — agent-guard.resolve_action | SDD-006 § Helper inventory | E0216 | composite | true |
| F02452 | Module-specific helper stays — agent-guard.render_policy | SDD-006 § Helper inventory | E0216 | composite | true |
| F02453 | Module-specific helper stays — agent-guard.render_egress_allowlist | SDD-006 § Helper inventory | E0216 | composite | true |
| F02454 | Module-specific helper stays — agent-guard.render_securemessage_endpoint | SDD-006 § Helper inventory | E0216 | composite | true |
| F02455 | Module-specific helper stays — agent-guard.render_pod_scope | SDD-006 § Helper inventory | E0216 | composite | true |
| F02456 | Module-specific helper stays — agent-guard.render_gpu_policy | SDD-006 § Helper inventory | E0216 | composite | true |
| F02457 | Module-specific helper stays — integrity-sentinel.expand_paths | SDD-006 § Helper inventory | E0216 | composite | true |
| F02458 | Module-specific helper stays — integrity-sentinel.compute_baseline | SDD-006 § Helper inventory | E0216 | composite | true |
| F02459 | Module-specific helper stays — integrity-sentinel.emit_drift_event | SDD-006 § Helper inventory | E0216 | composite | true |
| F02460 | Module-specific helper stays — tetragon.render_tetragon_config | SDD-006 § Helper inventory | E0216 | composite | true |
| F02461 | Module-specific helper stays — observability.render_scrape_config | SDD-006 § Helper inventory | E0216 | composite | true |
| F02462 | Module-specific helper stays — observability.render_dashboard | SDD-006 § Helper inventory | E0216 | composite | true |
| F02463 | Module-specific helper stays — vpn-bridge profile dispatcher logic in apply.sh | SDD-006 § Helper inventory | E0216 | composite | true |
| F02464 | Alternative A — system-wide sourcing convention | SDD-006 § Alternative A | E0217 | composite | false |
| F02465 | Alternative B (recommended) — env-var indirection; dispatcher exports SELFDEF_MODULE_LIB | SDD-006 § Alternative B + § Recommended design | E0217 | composite | false |
| F02466 | Alternative C — per-module symlink at packaging time (high coupling) | SDD-006 § Alternative C | E0217 | composite | false |
| F02467 | Alternative D — library inlining via xtask (rebuild ceremony) | SDD-006 § Alternative D | E0217 | composite | false |
| F02468 | Alternative B chosen — env-var override enables operator testing | SDD-006 § Recommended design | E0217 | composite | false |
| F02469 | Alternative B chosen — install location overridable | SDD-006 § Recommended design | E0217 | composite | false |
| F02470 | Alternative B chosen — scripts stay portable | SDD-006 § Recommended design | E0217 | composite | false |
| F02471 | D-1 — Shared library at `packaging/lib/module-lib.sh` | SDD-006 § D-1 + § Implementation status | M00533 | composite | false |
| F02472 | D-1 — Production install at `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-1 | M00534 | composite | false |
| F02473 | D-1 — Ships 5 helpers (log + emit_status + die + run + toml_get) | SDD-006 § D-1 + § Implementation status | E0218 | composite | false |
| F02474 | D-1 — Version pin `SELFDEF_MODULE_LIB_VERSION=1` | SDD-006 § D-1 | M00535 | composite | true |
| F02475 | D-1 — Version-mismatch enforced at source time with exit 99 | SDD-006 § D-1 + § Implementation status | M00536 | composite | false |
| F02476 | D-2 — Dispatcher plumbing in `crates/selfdef-cli/src/modules.rs` | SDD-006 § D-2 + § Implementation status | E0218 | composite | false |
| F02477 | D-2 — `run_one` exports `SELFDEF_MODULE_LIB` | SDD-006 § D-2 | E0218 | composite | false |
| F02478 | D-2 — `resolve_module_lib_path()` function | SDD-006 § D-2 | M00537 | composite | false |
| F02479 | D-2 precedence — env override SELFDEF_MODULE_LIB | SDD-006 § D-2 + § Implementation status | M00538 | composite | true |
| F02480 | D-2 precedence — workspace `packaging/lib/module-lib.sh` | SDD-006 § D-2 + § Implementation status | M00539 | composite | true |
| F02481 | D-2 precedence — installed `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-2 + § Implementation status | M00540 | composite | true |
| F02482 | D-2 — both branches have unit + integration coverage | SDD-006 § D-2 + § Implementation status | E0218 | composite | false |
| F02483 | D-3 — 8 install/lib.sh files now source shared library | SDD-006 § D-3 + § Implementation status | M00541 | composite | false |
| F02484 | D-3 — `${BASH_SOURCE[0]%/*}` parameter-expansion fallback to workspace path | SDD-006 § D-3 + § Implementation status | M00542 | composite | false |
| F02485 | D-3 — no dirname call so resolver works under stripped $PATH | SDD-006 § D-3 + § Implementation status | M00542 | composite | false |
| F02486 | D-3 — bridge-l2 / polarproxy / suricata inline-helper scripts gain own lib.sh + source it from apply/check/uninstall | SDD-006 § D-3 | M00543 | composite | true |
| F02487 | D-3 — vpn-bridge uninstall script overrides log() + run() after sourcing | SDD-006 § D-3 | M00544 | composite | true |
| F02488 | D-3 — bridge-l2 uninstall script overrides log() + run() after sourcing | SDD-006 § D-3 | M00544 | composite | true |
| F02489 | D-3 — uninstall override preserves pre-SDD-006 `[<slug>:uninstall]` log prefix | SDD-006 § D-3 | M00544 | composite | false |
| F02490 | D-3 — uninstall override preserves lenient continue-past-failure behaviour | SDD-006 § D-3 | M00544 | composite | false |
| F02491 | D-4 — `docs/dev/module-helpers.md` documents every exported helper | SDD-006 § D-4 + § Implementation status | M00545 | composite | true |
| F02492 | D-4 — Documents caller contract | SDD-006 § D-4 | M00545 | composite | false |
| F02493 | D-4 — Documents versioning policy | SDD-006 § D-4 | M00545 | composite | false |
| F02494 | D-4 — Documents how to add module-specific helpers/overrides | SDD-006 § D-4 | M00545 | composite | false |
| F02495 | D-5 — `crates/selfdef-daemon/Cargo.toml [package.metadata.deb]` assets list installs shared lib | SDD-006 § D-5 + § Implementation status | M00546 | composite | true |
| F02496 | D-5 — install path `/usr/share/selfdef/lib/module-lib.sh` mode 0644 | SDD-006 § D-5 + § Implementation status | M00546 | composite | true |
| F02497 | D-6 unit test — `resolve_module_lib_path_finds_workspace_by_default` | SDD-006 § D-6 + § Implementation status | M00547 | composite | true |
| F02498 | D-6 — operator-override branch covered by integration only (workspace lint forbids in-process std::env::set_var) | SDD-006 § D-6 + § Implementation status | M00547 | composite | false |
| F02499 | D-6 integration test — `dispatcher_exports_module_lib_env_var` | SDD-006 § D-6 + § Implementation status | M00548 | composite | true |
| F02500 | D-6 integration test — `module_sourcing_shared_lib_at_v1_succeeds` | SDD-006 § D-6 + § Implementation status | M00549 | composite | true |
| F02501 | D-6 integration test — `module_requesting_newer_lib_version_is_refused` | SDD-006 § D-6 + § Implementation status | M00550 | composite | true |
| F02502 | D-6 — integration tests live in `crates/selfdef-cli/tests/cli_modules_shared_lib.rs` | SDD-006 § Implementation status | E0220 | composite | false |
| F02503 | Rollout — existing modules keep working with own lib.sh during transition | SDD-006 § Rollout | E0220 | composite | false |
| F02504 | Rollout — new shared lib lands without breaking | SDD-006 § Rollout | E0220 | composite | false |
| F02505 | Rollout — CHANGELOG entry documents migration | SDD-006 § Rollout | E0220 | composite | false |
| F02506 | Risk R-1 — sourcing breakage if file missing; mitigated by fallback to workspace path + clear error message | SDD-006 § Risks | E0220 | composite | false |
| F02507 | Risk R-2 — env-var path leak in CI; mitigated by tests using `Command::env` (not std::env::set_var) | SDD-006 § Risks | E0220 | composite | false |
| F02508 | Risk R-3 — version-pin too aggressive freezes evolution; mitigated by v2/v3 explicit version bumps with documented breaking-change criteria | SDD-006 § Risks | E0220 | composite | false |
| F02509 | Q-A — SELFDEF_MODULE_LIB precedence: env > workspace > installed (answered) | SDD-006 § Open questions Q-A | E0220 | composite | false |
| F02510 | Q-B — helper signatures backward compat: yes, library is strict superset; v2 may ADD helpers (never remove or rename) | SDD-006 § Open questions Q-B | E0220 | composite | false |
| F02511 | Q-C — uninstall log-prefix override: modules MAY override log() after sourcing | SDD-006 § Open questions Q-C | E0220 | composite | false |
| F02512 | Appendix — SDD-005 (test contract) Cat 3 module-script tests verify both per-module + shared-lib behaviour | SDD-006 § Appendix | E0220 | composite | false |
| F02513 | Appendix — SDD-003 (vpn-bridge multi-instance) shipped before SDD-006; vpn-bridge migration retained pre-SDD-006 uninstall log prefix via override | SDD-006 § Appendix | E0220 | composite | false |
| F02514 | Appendix — SDD-001 (AI-machine end-to-end) modules (agent-guard) use shared lib + module-specific helpers (resolve_action etc.) | SDD-006 § Appendix | E0220 | composite | false |
| F02515 | Appendix — SDD-002 (defaults that work) `[daemon_requires]` validator uses `toml_get` from shared lib | SDD-006 § Appendix | E0220 | composite | false |
| F02516 | Doctrine — shared lib is OPT-IN-BY-CONVENTION (every new module sources it; ground-truth canonical pattern in init scaffolding) | SDD-006 § Goals 5 | E0214 | composite | false |
| F02517 | Doctrine — module-specific helpers stay in per-module lib.sh (NOT promoted to shared) | SDD-006 § Non-goals | E0215 | composite | false |
| F02518 | Doctrine — backward compat is critical: shared lib must work alongside un-migrated module-local lib.sh files | SDD-006 § Non-goals | E0215 | composite | false |
| F02519 | Doctrine — library version pin is enforced (exit 99); breaking version bumps require CHANGELOG entry | SDD-006 § D-1 | E0218 | composite | false |
| F02520 | Composite — SDD-006 ships shared module-script library at `/usr/share/selfdef/lib/module-lib.sh` (v1) with 5 helpers (log / emit_status / die / run / toml_get) + version pin (exit 99 on mismatch) + dispatcher resolves via SELFDEF_MODULE_LIB 3-tier precedence (env > workspace > installed) + 8 modules migrated byte-stable (agent-guard / tetragon / observability / integrity-sentinel / vpn-bridge / bridge-l2 / polarproxy / suricata) + 3 inline modules gain own lib.sh + 2 uninstall-override modules preserve legacy log+run + docs/dev/module-helpers.md runbook + 4 tests + Phase A+B+C single-PR delivery; closes F-2026-081 SDD-debt parent (~180 duplicated lines eliminated); F-2026-050 deferred; F-2026-051 partial | SDD-006 entire | E0211 + E0212 + E0213 + E0214 + E0215 + E0216 + E0217 + E0218 + E0219 + E0220 | composite | false |

## Requirements (R04801–R05040)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R04801 | SDD-006 status = implemented | SDD-006 § header | F02401 | non-negotiable | false | 10 |
| R04802 | SDD-006 closes F-2026-081 (SDD-debt parent) | SDD-006 § header | F02402 | non-negotiable | false | 10 |
| R04803 | SDD-006 closes F-2026-050 (deferred — see "Deferred to follow-up") | SDD-006 § header | F02403 | non-negotiable | false | 10 |
| R04804 | SDD-006 closes F-2026-051 (partial — see D-3) | SDD-006 § header | F02404 | non-negotiable | false | 10 |
| R04805 | Phase A+B+C collapsed to single PR per operator's "big chunks" steer | SDD-006 § Implementation status | F02405 | non-negotiable | false | 10 |
| R04806 | Shared library landed | SDD-006 § Implementation status | E0211 | non-negotiable | false | 10 |
| R04807 | Dispatcher exports SELFDEF_MODULE_LIB | SDD-006 § Implementation status | E0218 | non-negotiable | false | 10 |
| R04808 | All 8 modules with helpers migrated in one go | SDD-006 § Implementation status | E0211 | non-negotiable | false | 10 |
| R04809 | Migrated module — agent-guard | SDD-006 § Implementation status | F02406 | non-negotiable | true | 10 |
| R04810 | Migrated module — tetragon | SDD-006 § Implementation status | F02407 | non-negotiable | true | 10 |
| R04811 | Migrated module — observability | SDD-006 § Implementation status | F02408 | non-negotiable | true | 10 |
| R04812 | Migrated module — integrity-sentinel | SDD-006 § Implementation status | F02409 | non-negotiable | true | 10 |
| R04813 | Migrated module — vpn-bridge | SDD-006 § Implementation status | F02410 | non-negotiable | true | 10 |
| R04814 | Migrated module — bridge-l2 | SDD-006 § Implementation status | F02411 | non-negotiable | true | 10 |
| R04815 | Migrated module — polarproxy | SDD-006 § Implementation status | F02412 | non-negotiable | true | 10 |
| R04816 | Migrated module — suricata | SDD-006 § Implementation status | F02413 | non-negotiable | true | 10 |
| R04817 | Migration byte-stable — shared helpers match per-module copies exactly | SDD-006 § Implementation status | F02414 | non-negotiable | false | 10 |
| R04818 | Migration byte-stable exception — slug literal in log() parameterised on ${MODULE} | SDD-006 § Implementation status | F02414 | non-negotiable | false | 10 |
| R04819 | F-2026-050 deferred — agent-guard/uninstall.sh enumerates policy filenames by hand | SDD-006 § Deferred to follow-up | F02415 | non-negotiable | false | 10 |
| R04820 | F-2026-050 — SDD reserved `module_render_files` helper for follow-up PR | SDD-006 § Deferred to follow-up | F02416 | non-negotiable | false | 10 |
| R04821 | F-2026-050 — v1 surface kept minimal | SDD-006 § Deferred to follow-up | F02417 | non-negotiable | false | 10 |
| R04822 | F-2026-050 — tracked separately; ledger entry remains open | SDD-006 § Deferred to follow-up | F02417 | non-negotiable | false | 10 |
| R04823 | F-2026-051 partial — render_pod_scope awk fragility | SDD-006 § Deferred to follow-up | F02418 | non-negotiable | false | 10 |
| R04824 | F-2026-051 — shared lib doesn't ship YAML-aware editing helpers in v1 | SDD-006 § Deferred to follow-up | F02419 | non-negotiable | false | 10 |
| R04825 | F-2026-051 — future v2 could ship yq- or python-backed helpers | SDD-006 § Deferred to follow-up | F02420 | non-negotiable | false | 10 |
| R04826 | F-2026-051 — tracked as separate ledger entry | SDD-006 § Deferred to follow-up | F02420 | non-negotiable | false | 10 |
| R04827 | F-2026-081 — every shipped module reimplements same helpers in own install/lib.sh | SDD-006 § Problem | F02421 | non-negotiable | false | 10 |
| R04828 | Helper 1 contract — `log "$msg"` is stderr logger | SDD-006 § Problem | F02422 | non-negotiable | true | 10 |
| R04829 | Helper 2 contract — `emit_status "$status" "$message"` writes structured status JSON line to stdout | SDD-006 § Problem | F02423 | non-negotiable | true | 10 |
| R04830 | Helper 3 contract — `die "$msg"` calls emit_status failed + exit 1 | SDD-006 § Problem | F02424 | non-negotiable | true | 10 |
| R04831 | Helper 4 contract — `run "$desc" -- <cmd...>` is dry-run-aware command wrapper | SDD-006 § Problem | F02425 | non-negotiable | true | 10 |
| R04832 | Helper 5 contract — `toml_get "$key" "$file"` is minimal TOML reader (one `key = "value"` per line) | SDD-006 § Problem | F02426 | non-negotiable | true | 10 |
| R04833 | Six modules carry copy — agent-guard | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04834 | Six modules carry copy — bridge-l2 | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04835 | Six modules carry copy — integrity-sentinel | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04836 | Six modules carry copy — observability | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04837 | Six modules carry copy — tetragon | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04838 | Six modules carry copy — vpn-bridge | SDD-006 § Problem | F02427 | non-negotiable | true | 10 |
| R04839 | Detect-host has NO scripts at all | SDD-006 § Problem | F02428 | non-negotiable | false | 10 |
| R04840 | Polarproxy has inline helpers (equivalent to shared helpers but not in a lib.sh) | SDD-006 § Problem | F02429 | non-negotiable | false | 10 |
| R04841 | Suricata has inline helpers (equivalent to shared helpers but not in a lib.sh) | SDD-006 § Problem | F02429 | non-negotiable | false | 10 |
| R04842 | Duplicate line count — ~30 lines × 6 modules = ~180 lines | SDD-006 § Problem | F02430 | non-negotiable | false | 10 |
| R04843 | Cost — bug fix in one helper has to be applied in 6 places | SDD-006 § Problem | F02431 | non-negotiable | false | 10 |
| R04844 | Cost — helpers drift (agent-guard has resolve_action no other module needs but contributes to duplication tax in agent-guard) | SDD-006 § Problem | F02432 | non-negotiable | false | 10 |
| R04845 | Cost — new modules paste same skeleton, perpetuating cycle | SDD-006 § Problem | F02433 | non-negotiable | false | 10 |
| R04846 | F-2026-050 + F-2026-051 are adjacent findings shared library can close as side effect | SDD-006 § Problem | E0213 | non-negotiable | false | 10 |
| R04847 | F-2026-050 side effect — shared `manifest_owned_files` would let script discover own outputs | SDD-006 § Problem | E0213 | non-negotiable | false | 10 |
| R04848 | F-2026-051 side effect — shared YAML-aware editor helper would reduce risk (less direct; bigger ask; partial close) | SDD-006 § Problem | E0213 | non-negotiable | false | 10 |
| R04849 | Goal 1 — one installed copy of shared helpers sourced by every module's apply/check/uninstall | SDD-006 § Goals 1 | F02434 | non-negotiable | false | 10 |
| R04850 | Goal 2 — shared library version-pins itself | SDD-006 § Goals 2 | F02435 | non-negotiable | false | 10 |
| R04851 | Goal 2 — module built against v2 doesn't silently break under v1 | SDD-006 § Goals 2 | F02435 | non-negotiable | false | 10 |
| R04852 | Goal 3 — library is strict superset of today's per-module helpers | SDD-006 § Goals 3 | F02436 | non-negotiable | false | 10 |
| R04853 | Goal 3 — every existing helper works the same way | SDD-006 § Goals 3 | F02436 | non-negotiable | false | 10 |
| R04854 | Goal 4 — migrating single module is focused PR | SDD-006 § Goals 4 | F02437 | non-negotiable | false | 10 |
| R04855 | Goal 4 — focused PR = source shared lib + delete local copy + run module tests | SDD-006 § Goals 4 | F02437 | non-negotiable | false | 10 |
| R04856 | Goal 5 — future modules pick up library by default | SDD-006 § Goals 5 | F02438 | non-negotiable | false | 10 |
| R04857 | Goal 5 — init scaffolding for new module produces apply.sh that already sources it | SDD-006 § Goals 5 | F02438 | non-negotiable | false | 10 |
| R04858 | Non-goal — general "module SDK" with state management, retries, etc | SDD-006 § Non-goals | F02439 | non-negotiable | false | 10 |
| R04859 | Non-goal — scope is shared helpers, not framework | SDD-006 § Non-goals | F02439 | non-negotiable | false | 10 |
| R04860 | Non-goal — Rust rewrite of install scripts | SDD-006 § Non-goals | F02440 | non-negotiable | false | 10 |
| R04861 | Non-goal — scripts stay bash; library is bash | SDD-006 § Non-goals | F02440 | non-negotiable | false | 10 |
| R04862 | Non-goal — removing per-module lib.sh files entirely | SDD-006 § Non-goals | F02441 | non-negotiable | false | 10 |
| R04863 | Non-goal — each module's lib.sh may still hold module-specific helpers | SDD-006 § Non-goals | F02441 | non-negotiable | false | 10 |
| R04864 | Non-goal — breaking change | SDD-006 § Non-goals | F02442 | non-negotiable | false | 10 |
| R04865 | Non-goal — old modules built against per-module helpers must keep working at same time as shared lib | SDD-006 § Non-goals | F02442 | non-negotiable | false | 10 |
| R04866 | Glossary — shared lib at `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § Glossary | F02443 | non-negotiable | false | 10 |
| R04867 | Glossary — module-local lib at each module's existing `install/lib.sh` | SDD-006 § Glossary | F02444 | non-negotiable | false | 10 |
| R04868 | Glossary — library version is small integer stamped into shared lib's header | SDD-006 § Glossary | F02445 | non-negotiable | false | 10 |
| R04869 | Glossary — scripts assert against library version | SDD-006 § Glossary | F02445 | non-negotiable | false | 10 |
| R04870 | Helper inventory — `log` carried by 6 modules | SDD-006 § Helper inventory | F02446 | non-negotiable | false | 10 |
| R04871 | Helper inventory — `emit_status` carried by 6 modules | SDD-006 § Helper inventory | F02447 | non-negotiable | false | 10 |
| R04872 | Helper inventory — `die` carried by 5 modules | SDD-006 § Helper inventory | F02448 | non-negotiable | false | 10 |
| R04873 | Helper inventory — `run` carried by 6 modules | SDD-006 § Helper inventory | F02449 | non-negotiable | false | 10 |
| R04874 | Helper inventory — `toml_get` carried by 6 modules | SDD-006 § Helper inventory | F02450 | non-negotiable | false | 10 |
| R04875 | Module-specific helpers stay — agent-guard.resolve_action | SDD-006 § Helper inventory | F02451 | non-negotiable | true | 10 |
| R04876 | Module-specific helpers stay — agent-guard.render_policy | SDD-006 § Helper inventory | F02452 | non-negotiable | true | 10 |
| R04877 | Module-specific helpers stay — agent-guard.render_egress_allowlist | SDD-006 § Helper inventory | F02453 | non-negotiable | true | 10 |
| R04878 | Module-specific helpers stay — agent-guard.render_securemessage_endpoint | SDD-006 § Helper inventory | F02454 | non-negotiable | true | 10 |
| R04879 | Module-specific helpers stay — agent-guard.render_pod_scope | SDD-006 § Helper inventory | F02455 | non-negotiable | true | 10 |
| R04880 | Module-specific helpers stay — agent-guard.render_gpu_policy | SDD-006 § Helper inventory | F02456 | non-negotiable | true | 10 |
| R04881 | Module-specific helpers stay — integrity-sentinel.expand_paths | SDD-006 § Helper inventory | F02457 | non-negotiable | true | 10 |
| R04882 | Module-specific helpers stay — integrity-sentinel.compute_baseline | SDD-006 § Helper inventory | F02458 | non-negotiable | true | 10 |
| R04883 | Module-specific helpers stay — integrity-sentinel.emit_drift_event | SDD-006 § Helper inventory | F02459 | non-negotiable | true | 10 |
| R04884 | Module-specific helpers stay — tetragon.render_tetragon_config | SDD-006 § Helper inventory | F02460 | non-negotiable | true | 10 |
| R04885 | Module-specific helpers stay — observability.render_scrape_config | SDD-006 § Helper inventory | F02461 | non-negotiable | true | 10 |
| R04886 | Module-specific helpers stay — observability.render_dashboard | SDD-006 § Helper inventory | F02462 | non-negotiable | true | 10 |
| R04887 | Module-specific helpers stay — vpn-bridge profile dispatcher logic in apply.sh | SDD-006 § Helper inventory | F02463 | non-negotiable | true | 10 |
| R04888 | Alternative A (system-wide sourcing convention) — rejected | SDD-006 § Alternative A | F02464 | non-negotiable | false | 10 |
| R04889 | Alternative B (env-var indirection) — recommended | SDD-006 § Alternative B + § Recommended design | F02465 | non-negotiable | false | 10 |
| R04890 | Alternative C (per-module symlink at packaging time) — rejected (high coupling) | SDD-006 § Alternative C | F02466 | non-negotiable | false | 10 |
| R04891 | Alternative D (library inlining via xtask) — rejected (rebuild ceremony) | SDD-006 § Alternative D | F02467 | non-negotiable | false | 10 |
| R04892 | Alternative B rationale — env-var override enables operator testing | SDD-006 § Recommended design | F02468 | non-negotiable | false | 10 |
| R04893 | Alternative B rationale — install location overridable | SDD-006 § Recommended design | F02469 | non-negotiable | false | 10 |
| R04894 | Alternative B rationale — scripts stay portable | SDD-006 § Recommended design | F02470 | non-negotiable | false | 10 |
| R04895 | D-1 — shared library at `packaging/lib/module-lib.sh` (workspace location) | SDD-006 § D-1 + § Implementation status | F02471 | non-negotiable | false | 10 |
| R04896 | D-1 — production install at `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-1 | F02472 | non-negotiable | false | 10 |
| R04897 | D-1 — ships 5 helpers (log + emit_status + die + run + toml_get) | SDD-006 § D-1 + § Implementation status | F02473 | non-negotiable | false | 10 |
| R04898 | D-1 — version pin `SELFDEF_MODULE_LIB_VERSION=1` | SDD-006 § D-1 + § Implementation status | F02474 | non-negotiable | true | 10 |
| R04899 | D-1 — version-mismatch enforced at source time with exit 99 | SDD-006 § D-1 + § Implementation status | F02475 | non-negotiable | false | 10 |
| R04900 | D-2 — dispatcher plumbing in `crates/selfdef-cli/src/modules.rs` | SDD-006 § D-2 + § Implementation status | F02476 | non-negotiable | false | 10 |
| R04901 | D-2 — `run_one` exports `SELFDEF_MODULE_LIB` | SDD-006 § D-2 + § Implementation status | F02477 | non-negotiable | false | 10 |
| R04902 | D-2 — `resolve_module_lib_path()` function exists | SDD-006 § D-2 + § Implementation status | F02478 | non-negotiable | false | 10 |
| R04903 | D-2 precedence 1 — env override `SELFDEF_MODULE_LIB` | SDD-006 § D-2 + § Implementation status | F02479 | non-negotiable | true | 10 |
| R04904 | D-2 precedence 2 — workspace `packaging/lib/module-lib.sh` | SDD-006 § D-2 + § Implementation status | F02480 | non-negotiable | true | 10 |
| R04905 | D-2 precedence 3 — installed `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-2 + § Implementation status | F02481 | non-negotiable | true | 10 |
| R04906 | D-2 — both branches (workspace + installed) have unit + integration coverage | SDD-006 § D-2 + § Implementation status | F02482 | non-negotiable | false | 10 |
| R04907 | D-3 — 8 `install/lib.sh` files now source shared library | SDD-006 § D-3 + § Implementation status | F02483 | non-negotiable | false | 10 |
| R04908 | D-3 — `${BASH_SOURCE[0]%/*}` parameter-expansion fallback | SDD-006 § D-3 + § Implementation status | F02484 | non-negotiable | false | 10 |
| R04909 | D-3 — no `dirname` call so resolver works under stripped $PATH | SDD-006 § D-3 + § Implementation status | F02485 | non-negotiable | false | 10 |
| R04910 | D-3 — bridge-l2 inline-helper scripts gain own lib.sh | SDD-006 § D-3 | F02486 | non-negotiable | true | 10 |
| R04911 | D-3 — polarproxy inline-helper scripts gain own lib.sh | SDD-006 § D-3 | F02486 | non-negotiable | true | 10 |
| R04912 | D-3 — suricata inline-helper scripts gain own lib.sh | SDD-006 § D-3 | F02486 | non-negotiable | true | 10 |
| R04913 | D-3 — bridge-l2 / polarproxy / suricata source own lib.sh from apply / check / uninstall | SDD-006 § D-3 | F02486 | non-negotiable | false | 10 |
| R04914 | D-3 — vpn-bridge uninstall script overrides `log()` after sourcing | SDD-006 § D-3 | F02487 | non-negotiable | true | 10 |
| R04915 | D-3 — vpn-bridge uninstall script overrides `run()` after sourcing | SDD-006 § D-3 | F02487 | non-negotiable | true | 10 |
| R04916 | D-3 — bridge-l2 uninstall script overrides `log()` after sourcing | SDD-006 § D-3 | F02488 | non-negotiable | true | 10 |
| R04917 | D-3 — bridge-l2 uninstall script overrides `run()` after sourcing | SDD-006 § D-3 | F02488 | non-negotiable | true | 10 |
| R04918 | D-3 — uninstall override preserves pre-SDD-006 `[<slug>:uninstall]` log prefix | SDD-006 § D-3 | F02489 | non-negotiable | false | 10 |
| R04919 | D-3 — uninstall override preserves lenient continue-past-failure behaviour | SDD-006 § D-3 | F02490 | non-negotiable | false | 10 |
| R04920 | D-4 — `docs/dev/module-helpers.md` exists | SDD-006 § D-4 + § Implementation status | F02491 | non-negotiable | true | 10 |
| R04921 | D-4 — documents every exported helper | SDD-006 § D-4 | F02491 | non-negotiable | false | 10 |
| R04922 | D-4 — documents caller contract | SDD-006 § D-4 | F02492 | non-negotiable | false | 10 |
| R04923 | D-4 — documents versioning policy | SDD-006 § D-4 | F02493 | non-negotiable | false | 10 |
| R04924 | D-4 — documents how to add module-specific helpers and overrides | SDD-006 § D-4 | F02494 | non-negotiable | false | 10 |
| R04925 | D-5 — `crates/selfdef-daemon/Cargo.toml [package.metadata.deb]` assets list installs shared lib | SDD-006 § D-5 + § Implementation status | F02495 | non-negotiable | true | 10 |
| R04926 | D-5 — install path `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-5 + § Implementation status | F02496 | non-negotiable | true | 10 |
| R04927 | D-5 — install mode 0644 | SDD-006 § D-5 + § Implementation status | F02496 | non-negotiable | true | 10 |
| R04928 | D-6 unit test — `resolve_module_lib_path_finds_workspace_by_default` exists | SDD-006 § D-6 + § Implementation status | F02497 | non-negotiable | true | 10 |
| R04929 | D-6 — operator-override branch covered by integration only | SDD-006 § D-6 + § Implementation status | F02498 | non-negotiable | false | 10 |
| R04930 | D-6 — workspace lint forbids in-process `std::env::set_var` | SDD-006 § D-6 + § Implementation status | F02498 | non-negotiable | false | 10 |
| R04931 | D-6 integration test — `dispatcher_exports_module_lib_env_var` exists | SDD-006 § D-6 + § Implementation status | F02499 | non-negotiable | true | 10 |
| R04932 | D-6 integration test — `module_sourcing_shared_lib_at_v1_succeeds` exists | SDD-006 § D-6 + § Implementation status | F02500 | non-negotiable | true | 10 |
| R04933 | D-6 integration test — `module_requesting_newer_lib_version_is_refused` exists | SDD-006 § D-6 + § Implementation status | F02501 | non-negotiable | true | 10 |
| R04934 | D-6 — integration tests live in `crates/selfdef-cli/tests/cli_modules_shared_lib.rs` | SDD-006 § Implementation status | F02502 | non-negotiable | false | 10 |
| R04935 | Rollout — existing modules keep working with own lib.sh during transition | SDD-006 § Rollout | F02503 | non-negotiable | false | 10 |
| R04936 | Rollout — new shared lib lands without breaking | SDD-006 § Rollout | F02504 | non-negotiable | false | 10 |
| R04937 | Rollout — CHANGELOG entry documents migration | SDD-006 § Rollout | F02505 | non-negotiable | false | 10 |
| R04938 | Risk R-1 — sourcing breakage if file missing; mitigated by fallback to workspace path + clear error message | SDD-006 § Risks | F02506 | non-negotiable | false | 10 |
| R04939 | Risk R-2 — env-var path leak in CI; mitigated by tests using `Command::env` not std::env::set_var | SDD-006 § Risks | F02507 | non-negotiable | false | 10 |
| R04940 | Risk R-3 — version-pin too aggressive freezes evolution; mitigated by v2/v3 explicit version bumps with documented breaking-change criteria | SDD-006 § Risks | F02508 | non-negotiable | false | 10 |
| R04941 | Q-A answered — SELFDEF_MODULE_LIB precedence: env > workspace > installed | SDD-006 § Open questions Q-A | F02509 | non-negotiable | false | 10 |
| R04942 | Q-B answered — helper signatures backward compat: yes (strict superset; v2 may ADD helpers; never remove or rename) | SDD-006 § Open questions Q-B | F02510 | non-negotiable | false | 10 |
| R04943 | Q-C answered — uninstall log-prefix override: modules may override log() after sourcing | SDD-006 § Open questions Q-C | F02511 | non-negotiable | false | 10 |
| R04944 | Appendix — SDD-005 (test contract) Cat 3 module-script tests verify both per-module and shared-lib behaviour | SDD-006 § Appendix | F02512 | non-negotiable | false | 10 |
| R04945 | Appendix — SDD-003 (vpn-bridge multi-instance) shipped before SDD-006 | SDD-006 § Appendix | F02513 | non-negotiable | false | 10 |
| R04946 | Appendix — vpn-bridge migration retained pre-SDD-006 uninstall log prefix via override | SDD-006 § Appendix | F02513 | non-negotiable | false | 10 |
| R04947 | Appendix — SDD-001 (AI-machine end-to-end) modules use shared lib + module-specific helpers | SDD-006 § Appendix | F02514 | non-negotiable | false | 10 |
| R04948 | Appendix — SDD-002 (defaults that work) `[daemon_requires]` validator uses `toml_get` from shared lib | SDD-006 § Appendix | F02515 | non-negotiable | false | 10 |
| R04949 | Doctrine — shared lib is opt-in-by-convention (every new module sources it; init scaffolding canonical pattern) | SDD-006 § Goals 5 | F02516 | non-negotiable | false | 10 |
| R04950 | Doctrine — module-specific helpers stay in per-module lib.sh (NOT promoted to shared) | SDD-006 § Non-goals | F02517 | non-negotiable | false | 10 |
| R04951 | Doctrine — backward compat critical (shared lib must work alongside un-migrated module-local lib.sh files) | SDD-006 § Non-goals | F02518 | non-negotiable | false | 10 |
| R04952 | Doctrine — library version pin enforced (exit 99); breaking version bumps require CHANGELOG entry | SDD-006 § D-1 | F02519 | non-negotiable | false | 10 |
| R04953 | Integration with MS001 daemon core — selfdef-cli/src/modules.rs hosts `resolve_module_lib_path()` | MS001 + SDD-006 § D-2 | M00537 | non-negotiable | false | 10 |
| R04954 | Integration with MS006 14 functional modules — 8 of 14 functional modules use the shared library | MS006 + SDD-006 § Implementation status | E0211 | non-negotiable | false | 10 |
| R04955 | Integration with MS009 audit cycles — phase-6/40-module-audit covers migration byte-stability | MS009 phase-6 40-module-audit | F02414 | non-negotiable | false | 10 |
| R04956 | Integration with MS013 27-SDD charter — SDD-006 is foundational 000-009 layer per MS013 R03012 | MS013 + SDD-006 | E0211 | non-negotiable | false | 10 |
| R04957 | Integration with MS017 agent-guard — agent-guard module migrated; resolve_action/render_policy/render_egress_allowlist/render_securemessage_endpoint/render_pod_scope/render_gpu_policy stay as module-specific helpers | MS017 + SDD-006 § Implementation status + § Helper inventory | F02451 + F02452 + F02453 + F02454 + F02455 + F02456 | non-negotiable | false | 10 |
| R04958 | Integration with MS018 vpn-bridge — vpn-bridge module migrated; uninstall log+run override preserves legacy behavior | MS018 + SDD-006 § D-3 + § Appendix | F02487 + F02513 | non-negotiable | false | 10 |
| R04959 | Integration with MS020 test contract — Cat 3 module-script tests verify shared-lib behaviour | MS020 + SDD-006 § Appendix | F02512 | non-negotiable | false | 10 |
| R04960 | Project boundary — SDD-006 is selfdef-scope; sovereign-os has its own module-script library if any | architecture + MS007 + SDD-038 | E0211 | non-negotiable | false | 10 |
| R04961 | Project boundary — cross-repo binding via documented helper signatures + version contract (NOT direct shell sourcing) | MS007 + SDD-038 | E0218 | non-negotiable | false | 10 |
| R04962 | Project boundary — sovereign-os modules MAY source selfdef shared lib if installed at known path | architecture | M00534 | non-negotiable | false | 10 |
| R04963 | Symbol — `SELFDEF_MODULE_LIB` env var (dispatcher exports, scripts read) | SDD-006 § D-2 | F02479 | non-negotiable | false | 10 |
| R04964 | Symbol — `SELFDEF_MODULE_LIB_VERSION=1` (current shared lib version) | SDD-006 § D-1 | F02474 | non-negotiable | false | 10 |
| R04965 | Symbol — `MODULE` variable (caller must set before sourcing; lib uses it to parameterise log() slug) | SDD-006 § Implementation status + § D-1 | F02414 | non-negotiable | false | 10 |
| R04966 | Symbol — exit 99 (version-mismatch refusal) | SDD-006 § D-1 | F02475 | non-negotiable | false | 10 |
| R04967 | Symbol — `${BASH_SOURCE[0]%/*}` (parameter-expansion fallback; portable across $PATH stripping) | SDD-006 § D-3 | F02484 | non-negotiable | false | 10 |
| R04968 | File `packaging/lib/module-lib.sh` exists at workspace path | SDD-006 § D-1 + § Implementation status | M00533 | non-negotiable | false | 10 |
| R04969 | File `/usr/share/selfdef/lib/module-lib.sh` ships in selfdef-daemon .deb package | SDD-006 § D-5 | M00546 | non-negotiable | false | 10 |
| R04970 | File `docs/dev/module-helpers.md` exists (in `docs/src/dev/`) | SDD-006 § D-4 + § Implementation status | M00545 | non-negotiable | true | 10 |
| R04971 | Test plan — workspace test asserts resolver finds workspace path | SDD-006 § D-6 | F02497 | non-negotiable | false | 10 |
| R04972 | Test plan — integration test asserts SELFDEF_MODULE_LIB env var is exported | SDD-006 § D-6 | F02499 | non-negotiable | false | 10 |
| R04973 | Test plan — integration test asserts module sourcing shared lib at v1 succeeds | SDD-006 § D-6 | F02500 | non-negotiable | false | 10 |
| R04974 | Test plan — integration test asserts module requesting newer lib version is refused | SDD-006 § D-6 | F02501 | non-negotiable | false | 10 |
| R04975 | Test plan integration — uses `Command::env` (not std::env::set_var) per workspace lint | SDD-006 § D-6 + § Risks R-2 | F02498 | non-negotiable | false | 10 |
| R04976 | Audit-cycle integration — MS009 phase-6/40-module-audit covers 8 migrated modules | MS009 phase-6 40-module-audit | E0211 | non-negotiable | false | 10 |
| R04977 | Audit-cycle integration — MS009 phase-6/60-docs-audit covers docs/dev/module-helpers.md | MS009 phase-6 60-docs-audit | M00545 | non-negotiable | false | 10 |
| R04978 | Audit-cycle integration — MS009 phase-6/70-tests-audit covers 4 tests | MS009 phase-6 70-tests-audit | E0220 | non-negotiable | false | 10 |
| R04979 | Audit-cycle integration — MS009 phase-7/50-integration-audit covers cross-module shared-lib behavior | MS009 phase-7 50-integration-audit | E0211 | non-negotiable | false | 10 |
| R04980 | Audit-cycle integration — F-2026-NNN findings tracked for v2 helpers (manifest_owned_files / YAML-aware editing) | MS009 99-findings-ledger | F02416 + F02420 | non-negotiable | false | 10 |
| R04981 | Doctrine — single-PR delivery (Phase A+B+C) per operator big-chunks steer | SDD-006 § Implementation status | F02405 | non-negotiable | false | 10 |
| R04982 | Doctrine — byte-stable migration verifiable by diff of shared-helpers vs per-module-copies (only difference is slug literal parameterised on ${MODULE}) | SDD-006 § Implementation status | F02414 | non-negotiable | false | 10 |
| R04983 | Doctrine — F-2026-050 + F-2026-051 carryover to v2 (manifest_owned_files / YAML-aware editing) | SDD-006 § Deferred to follow-up | M00526 + M00527 | non-negotiable | false | 10 |
| R04984 | Doctrine — shared lib version is selfdef-scoped; sovereign-os Tetragon policies don't depend on it | architecture + MS012 | E0211 | non-negotiable | false | 10 |
| R04985 | Doctrine — operator may override via SELFDEF_MODULE_LIB for ad-hoc testing | SDD-006 § D-2 + § Open questions Q-A | F02479 | non-negotiable | false | 10 |
| R04986 | Doctrine — uninstall scripts may override `log()` and `run()` after sourcing to preserve legacy log prefix + continue-past-failure | SDD-006 § D-3 + § Open questions Q-C | F02487 + F02488 | non-negotiable | false | 10 |
| R04987 | Doctrine — every new module's init scaffolding produces apply.sh that already sources shared lib | SDD-006 § Goals 5 | F02438 | non-negotiable | false | 10 |
| R04988 | Doctrine — `manifest_owned_files` is the future v2 helper that closes F-2026-050 | SDD-006 § Deferred to follow-up | M00526 | non-negotiable | false | 10 |
| R04989 | Doctrine — YAML-aware editor (yq / python) is the future v2 helper that closes F-2026-051 | SDD-006 § Deferred to follow-up | M00527 | non-negotiable | false | 10 |
| R04990 | Doctrine — shared lib is the foundation; module-specific lib.sh files extend it (NOT replace) | SDD-006 § Non-goals + § Helper inventory | E0215 + E0216 | non-negotiable | false | 10 |
| R04991 | Doctrine — emit_status writes structured JSON for daemon-side ingestion (status / message fields) | SDD-006 § Problem | M00529 | non-negotiable | false | 10 |
| R04992 | Doctrine — die calls emit_status with failed status before exit 1 (operator-readable + machine-parseable) | SDD-006 § Problem | M00530 | non-negotiable | false | 10 |
| R04993 | Doctrine — run respects SELFDEF_DRY_RUN per SDD-005 Cat 3 contract (dry-run-negative invariant) | SDD-006 § Problem + cross-ref SDD-005 § D-1 Cat 3 | M00531 | non-negotiable | false | 10 |
| R04994 | Doctrine — toml_get reads simple `key = "value"` lines; for nested keys / arrays, modules use yq or python | SDD-006 § Problem | M00532 | non-negotiable | false | 10 |
| R04995 | Doctrine — log writes to stderr (NOT stdout; stdout is reserved for emit_status JSON) | SDD-006 § Problem | M00528 | non-negotiable | false | 10 |
| R04996 | Doctrine — `[<slug>:uninstall]` log prefix is a legacy invariant for uninstall scripts; preserved via override | SDD-006 § D-3 | F02489 | non-negotiable | false | 10 |
| R04997 | Doctrine — lenient continue-past-failure is a legacy invariant for uninstall scripts; preserved via run() override | SDD-006 § D-3 | F02490 | non-negotiable | false | 10 |
| R04998 | Composite — SDD-006 closes F-2026-081 SDD-debt parent eliminating ~180 duplicated lines across 6 modules; ships shared v1 library (5 helpers) at `/usr/share/selfdef/lib/module-lib.sh` with version pin + dispatcher resolves SELFDEF_MODULE_LIB env-var via 3-tier precedence; 8 modules migrated byte-stable; 3 inline modules gain own lib.sh; 2 uninstall-override modules preserve legacy log+run; docs/dev/module-helpers.md runbook; 4 tests (1 unit + 3 integration); F-2026-050 + F-2026-051 deferred to v2 follow-up | SDD-006 entire | F02520 | non-negotiable | false | 10 |
| R04999 | Composite — MS021 covers SDD-006 + integrates with MS001 daemon core (`selfdef-cli/src/modules.rs run_one`) + MS006 14 functional modules (8 migrated) + MS009 audit cycles + MS013 27-SDD charter + MS017 agent-guard (module-specific helpers stay) + MS018 vpn-bridge (uninstall override) + MS020 test contract (Cat 3 module-script tests verify both per-module + shared-lib behaviour) | INDEX.md MS021 + SDD-006 + MS001-MS020 | E0211 + E0212 + E0213 + E0214 + E0215 + E0216 + E0217 + E0218 + E0219 + E0220 | non-negotiable | false | 10 |
| R05000 | Composite — SDD-006 + Phase-2 sub-cluster (future) tracks v2 helpers (manifest_owned_files + YAML-aware editor) closing F-2026-050 fully + F-2026-051 fully; selfdef-scope only; sovereign-os may source shared lib if installed at canonical path but cross-repo binding remains via documented helper signatures + version contract per MS007 + SDD-038 | SDD-006 § Deferred to follow-up + MS007 + SDD-038 | M00526 + M00527 | non-negotiable | false | 10 |
| R05001 | Symbol contract — `log()` signature: `log "$msg"` (one-arg, writes to stderr prefixed with `[<MODULE>] ` if MODULE set) | SDD-006 § Problem + § Implementation status | M00528 | non-negotiable | false | 10 |
| R05002 | Symbol contract — `emit_status()` signature: `emit_status "$status" "$message"` (two-arg, writes JSON to stdout) | SDD-006 § Problem | M00529 | non-negotiable | false | 10 |
| R05003 | Symbol contract — `die()` signature: `die "$msg"` (one-arg, internally calls emit_status "failed" "$msg" then exit 1) | SDD-006 § Problem | M00530 | non-negotiable | false | 10 |
| R05004 | Symbol contract — `run()` signature: `run "$desc" -- <cmd...>` (description + sentinel `--` + command tokens) | SDD-006 § Problem | M00531 | non-negotiable | false | 10 |
| R05005 | Symbol contract — `toml_get()` signature: `toml_get "$key" "$file"` (key + file; returns value or empty string) | SDD-006 § Problem | M00532 | non-negotiable | false | 10 |
| R05006 | Symbol invariant — `SELFDEF_MODULE_LIB` is operator-overridable | SDD-006 § Open questions Q-A | F02509 | non-negotiable | false | 10 |
| R05007 | Symbol invariant — `SELFDEF_MODULE_LIB_VERSION` is monotonically increasing across releases | SDD-006 § D-1 | F02474 | non-negotiable | false | 10 |
| R05008 | Symbol invariant — `MODULE` is caller-set; shared lib reads but never sets it | SDD-006 § Implementation status | F02414 | non-negotiable | false | 10 |
| R05009 | Symbol invariant — exit 99 reserved for version-mismatch refusal; modules must not return 99 from apply.sh logic | SDD-006 § D-1 | F02475 | non-negotiable | false | 10 |
| R05010 | Symbol invariant — `${BASH_SOURCE[0]%/*}` resolution works across shells (bash 4+ is the constraint) | SDD-006 § D-3 | F02484 | non-negotiable | false | 10 |
| R05011 | Caller contract — caller MUST set `MODULE="<slug>"` before sourcing shared lib | SDD-006 § Implementation status + § D-1 | F02414 | non-negotiable | false | 10 |
| R05012 | Caller contract — caller MAY override log() or run() AFTER sourcing (uninstall-override pattern) | SDD-006 § D-3 + § Open questions Q-C | F02487 + F02488 + F02511 | non-negotiable | false | 10 |
| R05013 | Caller contract — caller MUST handle exit 99 (version mismatch) as a fatal error (NOT retry) | SDD-006 § D-1 | F02475 | non-negotiable | false | 10 |
| R05014 | Caller contract — caller MAY define module-specific helpers in per-module lib.sh BEFORE sourcing shared lib | SDD-006 § Helper inventory + § Non-goals | E0215 + E0216 | non-negotiable | false | 10 |
| R05015 | Versioning contract — v1 is current (SELFDEF_MODULE_LIB_VERSION=1); v2 is reserved for future helpers (manifest_owned_files / YAML editor) | SDD-006 § Deferred to follow-up + § D-1 | F02474 + M00526 + M00527 | non-negotiable | false | 10 |
| R05016 | Versioning contract — v2 must be strict superset of v1 (per Q-B) | SDD-006 § Open questions Q-B | F02510 | non-negotiable | false | 10 |
| R05017 | Versioning contract — breaking version bumps (helper signature change) require CHANGELOG entry + migration note | SDD-006 § Risks R-3 | F02508 | non-negotiable | false | 10 |
| R05018 | Versioning contract — modules that request version > current shared lib version are refused with exit 99 | SDD-006 § D-1 + § Implementation status D-6 | M00550 | non-negotiable | false | 10 |
| R05019 | Versioning contract — modules that request version < current shared lib version succeed (forward-compatible) | SDD-006 § D-1 | F02474 | non-negotiable | false | 10 |
| R05020 | Versioning contract — sourcing without `MODULE` set is a caller error (shared lib doesn't fail; uses empty slug in log()) | SDD-006 § Implementation status | F02414 | non-negotiable | false | 10 |
| R05021 | Operator workflow — install shared lib via `selfdefctl deploy` (or .deb install); shared lib lands at `/usr/share/selfdef/lib/module-lib.sh` | SDD-006 § D-5 | M00546 | non-negotiable | false | 10 |
| R05022 | Operator workflow — workspace developers don't need install step (workspace path resolved by precedence 2) | SDD-006 § D-2 | F02480 | non-negotiable | false | 10 |
| R05023 | Operator workflow — test override via `SELFDEF_MODULE_LIB=/path/to/test/module-lib.sh` env var | SDD-006 § D-2 + § Open questions Q-A | F02479 + F02509 | non-negotiable | false | 10 |
| R05024 | Operator workflow — new module init scaffolding produces apply.sh that already sources shared lib (per Goal 5) | SDD-006 § Goals 5 | F02438 | non-negotiable | false | 10 |
| R05025 | Operator workflow — migrating existing module = source shared lib + delete duplicate helpers + retain module-specific helpers + run module tests | SDD-006 § Goals 4 | F02437 | non-negotiable | false | 10 |
| R05026 | Helper count growth — v1 ships 5 helpers (log + emit_status + die + run + toml_get) | SDD-006 § D-1 | F02473 | non-negotiable | false | 10 |
| R05027 | Helper count growth — v2 reserves manifest_owned_files | SDD-006 § Deferred to follow-up F-2026-050 | M00526 | non-negotiable | false | 10 |
| R05028 | Helper count growth — v2 reserves yq/python-backed YAML-aware editor | SDD-006 § Deferred to follow-up F-2026-051 | M00527 | non-negotiable | false | 10 |
| R05029 | Module count growth — 8 modules migrated in v1 (agent-guard + tetragon + observability + integrity-sentinel + vpn-bridge + bridge-l2 + polarproxy + suricata) | SDD-006 § Implementation status | E0211 | non-negotiable | false | 10 |
| R05030 | Module count growth — detect-host has no scripts; doesn't need lib | SDD-006 § Problem | F02428 | non-negotiable | false | 10 |
| R05031 | Module count growth — future modules pick up library by default per Goal 5 | SDD-006 § Goals 5 | F02438 | non-negotiable | false | 10 |
| R05032 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_module_lib_source_count{module}` | architecture + SDD-006 § D-3 | M00541 | non-negotiable | true | 10 |
| R05033 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_module_lib_version_in_use{module}` | architecture + SDD-006 § D-1 | M00535 | non-negotiable | true | 10 |
| R05034 | Layer-B metric (implied per architecture) — `sovereign_os_selfdef_module_lib_version_mismatch_total{module}` | architecture + SDD-006 § D-1 | M00536 | non-negotiable | true | 10 |
| R05035 | Doctrine — shared lib is the FOUNDATION; per-module lib.sh is the EXTENSION; both coexist (Goal 3 + Non-goal "removing per-module lib.sh entirely") | SDD-006 § Goals 3 + § Non-goals | F02436 + F02441 | non-negotiable | false | 10 |
| R05036 | Doctrine — operator-visible failure mode (exit 99) for version mismatch is operator-readable (NOT silent) | SDD-006 § D-1 | F02475 | non-negotiable | false | 10 |
| R05037 | Doctrine — single-PR delivery (Phase A+B+C) closes F-2026-081 entirely (no half-migrations) | SDD-006 § Implementation status | F02405 | non-negotiable | false | 10 |
| R05038 | Doctrine — Q-A/B/C all answered before merge | SDD-006 § Open questions | F02509 + F02510 + F02511 | non-negotiable | false | 10 |
| R05039 | Doctrine — F-2026-050 + F-2026-051 carryover documented in CHANGELOG | SDD-006 § Rollout + § Deferred to follow-up | F02505 + M00526 + M00527 | non-negotiable | false | 10 |
| R05040 | Composite — MS021 closes F-2026-081 (~180 lines duplicated eliminated) + F-2026-050 deferred to v2 + F-2026-051 partial; ships shared v1 library + dispatcher resolver + 8 migrated modules + 3 inline-helper modules gain lib.sh + 2 uninstall-override modules + docs/dev/module-helpers.md runbook + 4 tests; "shared lib is foundation; per-module lib.sh is extension; both coexist"; future v2 ships manifest_owned_files + YAML-aware editor; integrates with MS001 daemon core / MS006 14 functional modules / MS009 audit cycles / MS013 27-SDD charter / MS017 agent-guard / MS018 vpn-bridge / MS020 test contract | INDEX.md MS021 + SDD-006 entire + MS001-MS020 | E0211 + E0212 + E0213 + E0214 + E0215 + E0216 + E0217 + E0218 + E0219 + E0220 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS020: 30720 + 2400 = 33120 sub-requirements when MS021 lands

## Cross-references

- SDD source: `docs/sdd/006-shared-module-script-lib.md` (590 lines; status=implemented; closes F-2026-081 SDD-debt parent + F-2026-050 deferred + F-2026-051 partial)
- Shared lib path: `packaging/lib/module-lib.sh` (workspace) → `/usr/share/selfdef/lib/module-lib.sh` (production install via Cargo.toml [package.metadata.deb] mode 0644)
- Helpers runbook: `docs/dev/module-helpers.md` (in `docs/src/dev/` for mdbook visibility)
- Implementation crate: `crates/selfdef-cli/src/modules.rs` `run_one` + `resolve_module_lib_path()`
- Integration tests: `crates/selfdef-cli/tests/cli_modules_shared_lib.rs` (3 tests)
- 8 migrated modules: agent-guard / tetragon / observability / integrity-sentinel / vpn-bridge / bridge-l2 / polarproxy / suricata
- Module-specific helpers stay in per-module `install/lib.sh`: agent-guard (resolve_action / render_policy / render_egress_allowlist / render_securemessage_endpoint / render_pod_scope / render_gpu_policy) + integrity-sentinel (expand_paths / compute_baseline / emit_drift_event) + tetragon (render_tetragon_config) + observability (render_scrape_config / render_dashboard) + vpn-bridge (apply.sh profile dispatcher logic)
- F-2026-050 deferred follow-up: future v2 `manifest_owned_files` helper
- F-2026-051 partial: future v2 yq/python-backed YAML-aware editor
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (shared lib is selfdef-scope; sovereign-os modules MAY source if installed at canonical path; binding via documented helper signatures + version contract per MS007 typed mirrors)
