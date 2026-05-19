# MS012 — Perimeter coexistence

> Parent: `backlog/milestones/INDEX.md` row MS012.
> Source: `docs/sdd/015-perimeter-coexistence.md` (202 lines; Stage-2 PR 3/4 closes SDD-012 Q-A "Tetragon policy authoring authority"; 7 coverage sections; `selfdefctl perimeter {status,check-overlap,diff}` + extended `selfdefctl modules apply`; `[perimeter]` config block; audit discriminator via policy_name prefix; 5 goals + 4 non-goals + 4 open sub-questions Q15-A..Q15-D). Derived from SDD-012 (integration design) / SDD-013 (`[deployment.target]`) / SDD-014 (shared-audit-summary channel) / SDD-001 (ai-machine-end-to-end) / SDD-004 (security threat model). All entries below extract verbatim. No invention.

## Epics (E0121–E0130)

| Epic ID | Phrase | Source |
|---|---|---|
| E0121 | Problem — SDD-012 Q-A resolved as **coexist as separate policies, single authoring authority per origin**; risk of two policies disagreeing without operator awareness (e.g. sovereign-kernel-fence allows python3 but agent-guard denies it inside a container → effective behavior is conditional on which policy fires first + Tetragon merge semantics); "operator deserves to know" | SDD-015 § Problem |
| E0122 | Coverage 1 — Boundary contract; non-overlapping scopes; sovereign-kernel-fence governs OUTER container interface (which binaries can be invoked AT ALL); agent-guard governs INNER container behavior (what those binaries can do INSIDE) | SDD-015 § Coverage 1 |
| E0123 | sovereign-os `sovereign-kernel-fence.yaml` — host-scoped 4-binary `sys_execve` allowlist + SIGKILL at `/etc/tetragon/tracing-policies/`; authority = sovereign-os Stage-2+ team (effectively the operator); modified by `sovereign-osctl perimeter reload` | SDD-015 § Coverage 1 (sovereign-os) |
| E0124 | selfdef `agent-guard-*.yaml` — container-INTERNAL processes scoped via `matchPIDs` + pod-label selectors; targets Docker/Podman/containerd container-internal syscalls; lives at `/etc/tetragon/tracing-policies/agent-guard-*.yaml`; modified by `selfdefctl modules apply` (or future `selfdefctl perimeter apply`) | SDD-015 § Coverage 1 (selfdef) |
| E0125 | Non-overlap invariant — no `agent-guard` policy should ever assert on `sys_execve` host-wide; `selfdefctl perimeter check-overlap` flags it as a violation | SDD-015 § Coverage 1 (non-overlap) |
| E0126 | Coverage 2 — `selfdefctl perimeter check-overlap` (parse YAML in `/etc/tetragon/tracing-policies/`; extract `spec.kprobes[].call` syscall name + `spec.kprobes[].selectors[].matchNamespaces` scope; assert non-overlapping coverage); success output (PASS rows) + failure output (FAIL with operator-actionable Fix:); exit 0 on pass / 1 on overlap; crate `crates/selfdef-cli/src/perimeter.rs` | SDD-015 § Coverage 2 |
| E0127 | Coverage 3 — `selfdefctl perimeter diff` (loaded-in-Tetragon vs on-disk reconciliation; "matches" rows + "missing — restart tetragon?" rows + "loaded but not on disk — drift!" rows); drift detection prompts `sovereign-osctl perimeter reload` or `systemctl restart tetragon` | SDD-015 § Coverage 3 |
| E0128 | Coverage 4 — `[perimeter]` config block in `/etc/selfdef/selfdef.toml` (check_overlap_on_apply=true / sovereign_kernel_fence_path=/etc/.../sovereign-kernel-fence.yaml / overlap_warn_only=false); target-aware defaults (target=sain01 → defaults check_overlap_on_apply=true; target=generic → block ignored entirely) | SDD-015 § Coverage 4 |
| E0129 | Coverage 5 — Audit-trail integration via SDD-014 shared-audit-summary; `policy_name` prefix discriminator (selfdef logs events where policy_name starts with `agent-guard-`; sovereign-os `guardian-core` daemon logs the rest; mutually-exclusive filters; no event double-handled or missed) | SDD-015 § Coverage 5 |
| E0130 | Coverage 6 CLI surface + Coverage 7 regression-prevention tests + 5 goals + 4 non-goals + 4 open sub-questions (Q15-A YAML-first vs socket / Q15-B warn-only format / Q15-C peer command in sovereign-os / Q15-D third-party policy author) + Way forward (Stage-2 progress SDD-013 → 014 → 015 → 016) | SDD-015 § Coverage 6 + 7 + Goals + Non-goals + Open sub-questions + Way forward |

## Modules (M00291–M00316)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00291 | sovereign-os perimeter policy file — `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml` | SDD-015 § Coverage 1 | E0123 |
| M00292 | sovereign-os policy authority — sovereign-os Stage-2+ team (effectively the operator) | SDD-015 § Coverage 1 | E0123 |
| M00293 | sovereign-os modification verb — `sovereign-osctl perimeter reload` (re-installs from sovereign-os repo) | SDD-015 § Coverage 1 | E0123 |
| M00294 | selfdef perimeter policy file pattern — `/etc/tetragon/tracing-policies/agent-guard-*.yaml` | SDD-015 § Coverage 1 | E0124 |
| M00295 | selfdef policy authority — selfdef team (effectively the operator via selfdef config) | SDD-015 § Coverage 1 | E0124 |
| M00296 | selfdef modification verb — `selfdefctl modules apply` (or future `selfdefctl perimeter apply`) | SDD-015 § Coverage 1 | E0124 |
| M00297 | Tetragon hook firing — sovereign-kernel-fence uses `sys_execve` kprobe with `matchPIDs: NotIn [1]` (not init) + `matchBinaries: NotIn` allowlist → SIGKILL non-allowlisted execves at host level | SDD-015 § Coverage 1 | E0123 |
| M00298 | Tetragon hook firing — agent-guard uses kprobes scoped via `matchNamespaces: [container]` + label selectors (independent action surface) | SDD-015 § Coverage 1 | E0124 |
| M00299 | crate `crates/selfdef-cli/src/perimeter.rs` (new module under selfdef-cli) | SDD-015 § Coverage 2 | E0126 |
| M00300 | check-overlap parser — reads YAML in /etc/tetragon/tracing-policies/; extracts `spec.kprobes[].call` (syscall name) | SDD-015 § Coverage 2 | E0126 |
| M00301 | check-overlap parser — extracts `spec.kprobes[].selectors[].matchNamespaces` (scope) | SDD-015 § Coverage 2 | E0126 |
| M00302 | check-overlap assertion engine — assert non-overlapping coverage | SDD-015 § Coverage 2 | E0126 |
| M00303 | check-overlap exit semantics — exit 0 on pass; exit 1 on overlap | SDD-015 § Coverage 2 + § Coverage 6 | E0126 |
| M00304 | check-overlap PASS output — host-wide kprobe overlap detected (none) + sys_execve coverage (sovereign-kernel-fence host + agent-guard-shell-exec container — non-overlapping) + all policies have distinct metadata.name | SDD-015 § Coverage 2 success | E0126 |
| M00305 | check-overlap FAIL output — "agent-guard-newfeature.yaml asserts on sys_execve without matchNamespaces=container scope" + "would conflict with sovereign-kernel-fence's host-wide allowlist" + "Fix: add 'matchNamespaces: { operator: In, values: [container] }' to the selector" | SDD-015 § Coverage 2 failure | E0126 |
| M00306 | perimeter diff — loaded-in-Tetragon side of the table | SDD-015 § Coverage 3 | E0127 |
| M00307 | perimeter diff — on-disk side of the table (/etc/tetragon/tracing-policies/) | SDD-015 § Coverage 3 | E0127 |
| M00308 | perimeter diff drift detection — "on disk but not loaded — restart tetragon?" | SDD-015 § Coverage 3 | E0127 |
| M00309 | perimeter diff drift detection — "loaded but not on disk — drift!" | SDD-015 § Coverage 3 | E0127 |
| M00310 | perimeter diff reconciliation prompt — `sovereign-osctl perimeter reload` OR `systemctl restart tetragon` | SDD-015 § Coverage 3 | E0127 |
| M00311 | [perimeter] config — `check_overlap_on_apply` (bool; default true on target=sain01) | SDD-015 § Coverage 4 | E0128 |
| M00312 | [perimeter] config — `sovereign_kernel_fence_path` (path string; default `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml`) | SDD-015 § Coverage 4 | E0128 |
| M00313 | [perimeter] config — `overlap_warn_only` (bool; default false = block) | SDD-015 § Coverage 4 | E0128 |
| M00314 | Audit discriminator — `policy_name` field; starts-with `agent-guard-` → selfdef logs; otherwise → sovereign-os `guardian-core` logs | SDD-015 § Coverage 5 | E0129 |
| M00315 | Audit discrimination invariant — mutually exclusive filters; no event double-handled or missed | SDD-015 § Coverage 5 | E0129 |
| M00316 | Integration test — `tests/it/perimeter_coexistence.rs` (spawns Tetragon OR mocks via test-only daemon socket; verifies discriminator end-to-end) | SDD-015 § Coverage 7 | E0130 |

## Features (F01321–F01440)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01321 | SDD-015 closes SDD-012 Q-A | SDD-015 § header | E0121 | composite | false |
| F01322 | SDD-012 Q-A resolution — coexist as separate policies | SDD-015 § Problem | E0121 | composite | false |
| F01323 | SDD-012 Q-A resolution — single authoring authority per origin | SDD-015 § Problem | E0121 | composite | false |
| F01324 | Tetragon loads both policies | SDD-015 § Problem | E0121 | composite | false |
| F01325 | Tetragon daemon-side merging is permissive allowlist + intersect deny | SDD-015 § Problem | E0121 | composite | false |
| F01326 | Risk — two policies disagreeing without operator awareness | SDD-015 § Problem | E0121 | composite | false |
| F01327 | Risk example — sovereign-kernel-fence allows python3 for sys_execve but agent-guard denies it inside container | SDD-015 § Problem | E0121 | composite | false |
| F01328 | Risk consequence — effective behavior is conditional on which policy fires first + Tetragon merge semantics | SDD-015 § Problem | E0121 | composite | false |
| F01329 | "Operator deserves to know" | SDD-015 § Problem | E0121 | composite | false |
| F01330 | SDD-015 specifies 4 deliverables (boundary contract + check-overlap + diff + config) | SDD-015 § Problem | E0121 | composite | false |
| F01331 | Boundary contract — non-overlapping scopes | SDD-015 § Coverage 1 | E0122 | composite | false |
| F01332 | sovereign-kernel-fence scope — container-runtime processes (podman / vllm / nvidia-smi / python3) executing sys_execve from inside Rootless Podman containers | SDD-015 § Coverage 1 | E0123 | composite | false |
| F01333 | sovereign-kernel-fence allowlist — 4 binaries (podman / vllm / nvidia-smi / python3) | SDD-015 § Coverage 1 | E0123 | composite | false |
| F01334 | sovereign-kernel-fence action — SIGKILL non-allowlisted execves at host level | SDD-015 § Coverage 1 | E0123 | composite | false |
| F01335 | sovereign-kernel-fence authority — sovereign-os Stage-2+ team (effectively the operator) | SDD-015 § Coverage 1 | M00292 | composite | false |
| F01336 | sovereign-kernel-fence file path — `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml` | SDD-015 § Coverage 1 | M00291 | composite | true |
| F01337 | sovereign-kernel-fence modified by — `sovereign-osctl perimeter reload` (re-installs from sovereign-os repo) | SDD-015 § Coverage 1 | M00293 | cli_verb | true |
| F01338 | agent-guard scope — container-INTERNAL processes scoped via matchPIDs + pod-label selectors | SDD-015 § Coverage 1 | E0124 | composite | false |
| F01339 | agent-guard targets — Docker / Podman / containerd container-internal syscalls | SDD-015 § Coverage 1 | E0124 | composite | true |
| F01340 | agent-guard authority — selfdef team (effectively the operator via selfdef config) | SDD-015 § Coverage 1 | M00295 | composite | false |
| F01341 | agent-guard file path — `/etc/tetragon/tracing-policies/agent-guard-*.yaml` | SDD-015 § Coverage 1 | M00294 | composite | true |
| F01342 | agent-guard modified by — `selfdefctl modules apply` (or future `selfdefctl perimeter apply`) | SDD-015 § Coverage 1 | M00296 | cli_verb | true |
| F01343 | Boundary — sovereign-kernel-fence governs OUTER container interface (which binaries can be invoked AT ALL) | SDD-015 § Coverage 1 | E0122 | composite | false |
| F01344 | Boundary — agent-guard governs INNER container behavior (what those binaries can do INSIDE) | SDD-015 § Coverage 1 | E0122 | composite | false |
| F01345 | Tetragon hook firing — sovereign-kernel-fence sys_execve kprobe with matchPIDs: NotIn [1] (not init) | SDD-015 § Coverage 1 | M00297 | composite | false |
| F01346 | Tetragon hook firing — matchBinaries: NotIn allowlist semantics | SDD-015 § Coverage 1 | M00297 | composite | false |
| F01347 | Tetragon hook firing — SIGKILL non-allowlisted execves at host level | SDD-015 § Coverage 1 | M00297 | composite | false |
| F01348 | Tetragon hook firing — agent-guard kprobes scoped via matchNamespaces: [container] | SDD-015 § Coverage 1 | M00298 | composite | false |
| F01349 | Tetragon hook firing — agent-guard scoped via label selectors | SDD-015 § Coverage 1 | M00298 | composite | false |
| F01350 | Tetragon hook firing — agent-guard is independent action surface | SDD-015 § Coverage 1 | M00298 | composite | false |
| F01351 | Non-overlap invariant — no agent-guard policy should ever assert on sys_execve host-wide | SDD-015 § Coverage 1 | E0125 | composite | false |
| F01352 | Non-overlap invariant violation → `selfdefctl perimeter check-overlap` flags it as a violation | SDD-015 § Coverage 1 | E0125 | composite | false |
| F01353 | `selfdefctl perimeter check-overlap` verb exists | SDD-015 § Coverage 2 | E0126 | cli_verb | true |
| F01354 | check-overlap requires sudo | SDD-015 § Coverage 2 (`sudo selfdefctl …`) | E0126 | composite | false |
| F01355 | check-overlap parses YAML in `/etc/tetragon/tracing-policies/` | SDD-015 § Coverage 2 | M00300 | composite | false |
| F01356 | check-overlap extracts `spec.kprobes[].call` (syscall name) | SDD-015 § Coverage 2 | M00300 | composite | false |
| F01357 | check-overlap extracts `spec.kprobes[].selectors[].matchNamespaces` (scope) | SDD-015 § Coverage 2 | M00301 | composite | false |
| F01358 | check-overlap asserts non-overlapping coverage | SDD-015 § Coverage 2 | M00302 | composite | false |
| F01359 | check-overlap implemented in crate `crates/selfdef-cli/src/perimeter.rs` (new module) | SDD-015 § Coverage 2 | M00299 | composite | false |
| F01360 | check-overlap PASS — no host-wide kprobe overlap detected | SDD-015 § Coverage 2 success | M00304 | composite | false |
| F01361 | check-overlap PASS — sys_execve coverage (sovereign-kernel-fence host + agent-guard-shell-exec container) non-overlapping | SDD-015 § Coverage 2 success | M00304 | composite | false |
| F01362 | check-overlap PASS — all policies have distinct metadata.name | SDD-015 § Coverage 2 success | M00304 | composite | false |
| F01363 | check-overlap FAIL — agent-guard policy asserts on sys_execve without matchNamespaces=container scope | SDD-015 § Coverage 2 failure | M00305 | composite | false |
| F01364 | check-overlap FAIL — would conflict with sovereign-kernel-fence's host-wide allowlist | SDD-015 § Coverage 2 failure | M00305 | composite | false |
| F01365 | check-overlap FAIL — operator-actionable Fix: line "add 'matchNamespaces: { operator: In, values: [container] }' to the selector" | SDD-015 § Coverage 2 failure | M00305 | composite | false |
| F01366 | check-overlap exit code 0 on pass | SDD-015 § Coverage 2 + § Coverage 6 | M00303 | composite | false |
| F01367 | check-overlap exit code 1 on overlap | SDD-015 § Coverage 2 + § Coverage 6 | M00303 | composite | false |
| F01368 | `selfdefctl perimeter diff` verb exists | SDD-015 § Coverage 3 | E0127 | cli_verb | true |
| F01369 | perimeter diff requires sudo | SDD-015 § Coverage 3 (`sudo selfdefctl …`) | E0127 | composite | false |
| F01370 | perimeter diff shows LOADED IN TETRAGON column | SDD-015 § Coverage 3 | M00306 | composite | false |
| F01371 | perimeter diff shows ON DISK column | SDD-015 § Coverage 3 | M00307 | composite | false |
| F01372 | perimeter diff row state — "(matches)" when loaded == on-disk | SDD-015 § Coverage 3 | E0127 | composite | false |
| F01373 | perimeter diff row state — "(on disk but not loaded — restart tetragon?)" | SDD-015 § Coverage 3 | M00308 | composite | false |
| F01374 | perimeter diff row state — "(loaded but not on disk — drift!)" | SDD-015 § Coverage 3 | M00309 | composite | false |
| F01375 | Drift detection prompts operator to reconcile via `sovereign-osctl perimeter reload` | SDD-015 § Coverage 3 | M00310 | composite | true |
| F01376 | Drift detection prompts operator to reconcile via `systemctl restart tetragon` | SDD-015 § Coverage 3 | M00310 | composite | true |
| F01377 | [perimeter] config block lives in `/etc/selfdef/selfdef.toml` | SDD-015 § Coverage 4 | E0128 | composite | true |
| F01378 | [perimeter] knob — `check_overlap_on_apply` (bool) | SDD-015 § Coverage 4 | M00311 | composite | true |
| F01379 | [perimeter] check_overlap_on_apply behavior — when target=sain01, automatically run check-overlap on every `selfdefctl modules apply` invocation | SDD-015 § Coverage 4 | M00311 | composite | false |
| F01380 | [perimeter] check_overlap_on_apply behavior — refuse to apply policies that would conflict with sovereign-kernel-fence | SDD-015 § Coverage 4 | M00311 | composite | false |
| F01381 | [perimeter] knob — `sovereign_kernel_fence_path` (string) | SDD-015 § Coverage 4 | M00312 | composite | true |
| F01382 | [perimeter] sovereign_kernel_fence_path default — `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml` | SDD-015 § Coverage 4 | M00312 | composite | false |
| F01383 | [perimeter] knob — `overlap_warn_only` (bool) | SDD-015 § Coverage 4 | M00313 | composite | true |
| F01384 | [perimeter] overlap_warn_only default — false (= block by default) | SDD-015 § Coverage 4 | M00313 | composite | false |
| F01385 | [perimeter] default — when target=sain01 and block absent → check_overlap_on_apply=true | SDD-015 § Coverage 4 | E0128 | composite | false |
| F01386 | [perimeter] default — when target=generic → block ignored entirely (no sovereign-os assumption) | SDD-015 § Coverage 4 | E0128 | composite | false |
| F01387 | Audit-trail integration — SDD-014 shared-audit-summary channel emits one summary line per event to `/mnt/vault/context/security_audit.log` | SDD-015 § Coverage 5 + SDD-014 | E0129 | composite | false |
| F01388 | Audit-trail integration — Tetragon kill events NOT originating from selfdef-authored policy are emitted by sovereign-os `guardian-core` daemon (component=tetragon) | SDD-015 § Coverage 5 | E0129 | composite | false |
| F01389 | selfdef filter discriminator — read Tetragon event `policy_name` field | SDD-015 § Coverage 5 | M00314 | composite | false |
| F01390 | selfdef filter discriminator — if policy_name starts with `agent-guard-` → selfdef logs the event | SDD-015 § Coverage 5 | M00314 | composite | true |
| F01391 | selfdef filter discriminator — otherwise → `guardian-core`'s responsibility | SDD-015 § Coverage 5 | M00314 | composite | false |
| F01392 | Both daemons subscribe to same Tetragon event stream | SDD-015 § Coverage 5 | M00315 | composite | false |
| F01393 | Both daemons' filter discriminators are mutually exclusive — no event double-handled | SDD-015 § Coverage 5 | M00315 | composite | false |
| F01394 | Both daemons' filter discriminators are mutually exclusive — no event missed | SDD-015 § Coverage 5 | M00315 | composite | false |
| F01395 | CLI surface — `sudo selfdefctl perimeter status` (existing — extends to show coexistence active) | SDD-015 § Coverage 6 | E0130 | cli_verb | true |
| F01396 | CLI surface — `sudo selfdefctl perimeter check-overlap` (new — exit 0 pass; 1 overlap) | SDD-015 § Coverage 6 | E0126 | cli_verb | true |
| F01397 | CLI surface — `sudo selfdefctl perimeter diff` (new — loaded vs on-disk reconciliation) | SDD-015 § Coverage 6 | E0127 | cli_verb | true |
| F01398 | CLI surface — `sudo selfdefctl modules apply` (extended — runs check-overlap if config says so) | SDD-015 § Coverage 6 | M00311 | cli_verb | true |
| F01399 | Regression test — `no_overlap_passes` (synthetic 2 policies, host vs container scope) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01400 | Regression test — `host_scoped_sys_execve_in_agent_guard_fails_overlap` (synthetic; selfdef policy lacks matchNamespaces) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01401 | Regression test — `duplicate_metadata_name_fails` (two policies same name) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01402 | Regression test — `loaded_vs_disk_drift_detected` (mock tetragon socket; agent-guard-stale loaded, not on disk) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01403 | Regression test — `check_overlap_skipped_on_generic_target` (deployment.target=generic; coexistence not assumed) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01404 | Regression test — `audit_log_filter_by_policy_name_prefix` (selfdef sees agent-guard-* events only) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01405 | Integration test file — `tests/it/perimeter_coexistence.rs` (spawns Tetragon or mocks via test-only daemon socket) | SDD-015 § Coverage 7 | M00316 | composite | false |
| F01406 | Goal 1 — non-overlapping policy authority (sovereign-os owns host-scoped perimeter; selfdef owns container-internal) | SDD-015 § Goals 1 | E0122 | composite | false |
| F01407 | Goal 2 — operator-visible coexistence via `selfdefctl perimeter check-overlap` + `diff` introspectable | SDD-015 § Goals 2 | E0126 + E0127 | composite | false |
| F01408 | Goal 3 — pre-apply gating; when target=sain01, selfdef refuses to install policy that overlaps sovereign-kernel-fence (unless operator explicit-allows via overlap_warn_only) | SDD-015 § Goals 3 | E0128 | composite | false |
| F01409 | Goal 4 — audit discrimination; policy_name prefix filter ensures each daemon sees only its own events; no double-processing | SDD-015 § Goals 4 | E0129 | composite | false |
| F01410 | Goal 5 — non-SAIN-01 unchanged; target=generic deployments never run check-overlap (Q-G honored) | SDD-015 § Goals 5 | E0128 | composite | false |
| F01411 | Non-goal — does NOT modify the existing agent-guard TracingPolicies | SDD-015 § Non-goals | E0130 | composite | false |
| F01412 | Non-goal — does NOT implement the oracle-triage channel (SDD-016) | SDD-015 § Non-goals | E0130 | composite | false |
| F01413 | Non-goal — does NOT change sovereign-os's sovereign-kernel-fence.yaml shape (owned by sovereign-os Stage-2+) | SDD-015 § Non-goals | E0130 | composite | false |
| F01414 | Non-goal — does NOT specify Tetragon merge semantics (Tetragon's responsibility upstream) | SDD-015 § Non-goals | E0130 | composite | false |
| F01415 | Open Q15-A — should check-overlap parse Tetragon's runtime state via socket query or just YAML files on disk? | SDD-015 § Open sub-questions Q15-A | E0130 | composite | false |
| F01416 | Q15-A recommendation — YAML files first (no Tetragon-socket dep); diff command separately queries the socket | SDD-015 § Open sub-questions Q15-A | E0130 | composite | false |
| F01417 | Open Q15-B — format of overlap warning when overlap_warn_only=true? | SDD-015 § Open sub-questions Q15-B | E0130 | composite | false |
| F01418 | Q15-B recommendation — stderr WARN line + journald entry; non-fail exit | SDD-015 § Open sub-questions Q15-B | E0130 | composite | false |
| F01419 | Open Q15-C — should sovereign-os's `sovereign-osctl perimeter check-overlap` also exist (peer command)? | SDD-015 § Open sub-questions Q15-C | E0130 | composite | false |
| F01420 | Q15-C recommendation — YES (surface in sovereign-os Stage-2+ enhancement; this SDD doesn't ship that, but agrees it's natural) | SDD-015 § Open sub-questions Q15-C | E0130 | composite | false |
| F01421 | Open Q15-D — how to handle third-party (non-sovereign-os, non-selfdef) Tetragon policy author landing files in the same dir? | SDD-015 § Open sub-questions Q15-D | E0130 | composite | false |
| F01422 | Q15-D recommendation — warn + treat as opaque (don't fail; operator's discretion) | SDD-015 § Open sub-questions Q15-D | E0130 | composite | false |
| F01423 | Way forward step 1 — this PR (spec) | SDD-015 § Way forward 1 | E0130 | composite | false |
| F01424 | Way forward step 2 — Impl PR (new selfdef-cli perimeter.rs module + check-overlap + diff + apply-time integration + tests) | SDD-015 § Way forward 2 | E0130 | composite | false |
| F01425 | Way forward step 3 — SDD-016 PR (oracle-triage channel; Q-D resolution; last of 4 Stage-2 SDDs) | SDD-015 § Way forward 3 | E0130 | composite | false |
| F01426 | Stage-2 progress — SDD-013 ✅ | SDD-015 § Way forward | E0130 | composite | false |
| F01427 | Stage-2 progress — SDD-014 (in review) | SDD-015 § Way forward | E0130 | composite | false |
| F01428 | Stage-2 progress — SDD-015 (this) | SDD-015 § Way forward | E0130 | composite | false |
| F01429 | Stage-2 progress — SDD-016 (next) | SDD-015 § Way forward | E0130 | composite | false |
| F01430 | Cross-reference — SDD-012 § Q-A (design this implements) | SDD-015 § Cross-references | E0121 | composite | false |
| F01431 | Cross-reference — SDD-013 (deployment.target gates check-overlap-on-apply behavior) | SDD-015 § Cross-references | E0128 | composite | false |
| F01432 | Cross-reference — SDD-014 (shared-audit-summary; audit-discrimination mechanism) | SDD-015 § Cross-references | E0129 | composite | false |
| F01433 | Cross-reference — SDD-008 (notifications-orchestration; policy_name filter pattern) | SDD-015 § Cross-references | E0129 | composite | false |
| F01434 | Cross-reference — SDD-001 (ai-machine-end-to-end; agent-guard's container-internal scope) | SDD-015 § Cross-references | E0124 | composite | false |
| F01435 | Cross-reference — SDD-004 (security-threat-model; threat surface this perimeter addresses) | SDD-015 § Cross-references | E0121 | composite | false |
| F01436 | Cross-reference — sovereign-os `scripts/hooks/post-install/tetragon-policy-load.sh` (installs sovereign-kernel-fence.yaml) | SDD-015 § Cross-references | E0123 | composite | false |
| F01437 | Cross-reference — sovereign-os `scripts/sovereign-osctl perimeter reload` subcommand (peer-side reload action) | SDD-015 § Cross-references | M00293 | composite | false |
| F01438 | Cross-reference — sovereign-os SDD-011 (inference stack; Logic Engine + Oracle Core run in containers governed by both perimeters) | SDD-015 § Cross-references | E0122 | composite | false |
| F01439 | Composite — perimeter coexistence is the Stage-2 PR 3/4; closes SDD-012 Q-A; opens way forward to SDD-016 oracle-triage (SDD-012 Q-D); both perimeter daemons share Tetragon event stream with mutually-exclusive policy_name prefix filters; cross-repo binding is documented file paths under `/etc/tetragon/tracing-policies/` + Tetragon daemon as the merge agent — NOT selfdef importing sovereign-os Rust crates (MS007 + SDD-038) | SDD-015 entire document + MS007 + SDD-038 | E0130 | composite | false |
| F01440 | Composite — target-aware behavior — sain01 = strict coexistence (block on overlap unless overlap_warn_only=true); generic = no coexistence assumption (block ignored entirely; selfdef does not assume sovereign-os present); explicit support for both deployment posture per SDD-013 [deployment.target] | SDD-015 + SDD-013 | E0128 | composite | false |

## Requirements (R02641–R02880)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R02641 | SDD-015 closes SDD-012 Q-A "Tetragon policy authoring authority" | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02642 | SDD-015 status = review | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02643 | SDD-015 last updated = 2026-05-16 | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02644 | SDD-015 is Stage-2 PR 3/4 per SDD-012 Q-H ordering | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02645 | SDD-015 derives from SDD-012 / SDD-013 / SDD-014 / SDD-001 / SDD-004 | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02646 | SDD-012 Q-A resolution — coexist as separate policies | SDD-015 § Problem | F01322 | non-negotiable | false | 10 |
| R02647 | SDD-012 Q-A resolution — single authoring authority per origin | SDD-015 § Problem | F01323 | non-negotiable | false | 10 |
| R02648 | sovereign-os ships `sovereign-kernel-fence.yaml` (4-binary sys_execve allowlist + SIGKILL) | SDD-015 § Problem | E0123 | non-negotiable | false | 10 |
| R02649 | sovereign-kernel-fence at `/etc/tetragon/tracing-policies/` | SDD-015 § Problem + § Coverage 1 | F01336 | non-negotiable | true | 10 |
| R02650 | selfdef's `agent-guard` module ships its own TracingPolicies at the same directory | SDD-015 § Problem | E0124 | non-negotiable | false | 10 |
| R02651 | Tetragon loads both | SDD-015 § Problem | F01324 | non-negotiable | false | 10 |
| R02652 | Tetragon daemon-side merging = permissive allowlist + intersect deny | SDD-015 § Problem | F01325 | non-negotiable | false | 10 |
| R02653 | Risk — two policies disagreeing without operator awareness | SDD-015 § Problem | F01326 | non-negotiable | false | 10 |
| R02654 | Risk example — sovereign-kernel-fence allows python3 but agent-guard denies inside container | SDD-015 § Problem | F01327 | non-negotiable | false | 10 |
| R02655 | Risk consequence — effective behavior conditional on which policy fires first + Tetragon merge semantics | SDD-015 § Problem | F01328 | non-negotiable | false | 10 |
| R02656 | "Operator deserves to know" | SDD-015 § Problem | F01329 | non-negotiable | false | 10 |
| R02657 | SDD-015 ships — boundary contract between two policy authors | SDD-015 § Problem 1 | E0122 | non-negotiable | false | 10 |
| R02658 | SDD-015 ships — `selfdefctl perimeter check-overlap` runtime detector | SDD-015 § Problem 2 | E0126 | non-negotiable | false | 10 |
| R02659 | SDD-015 ships — `selfdefctl perimeter diff` (loaded vs expected) | SDD-015 § Problem 3 | E0127 | non-negotiable | false | 10 |
| R02660 | SDD-015 ships — selfdef-side config block making coexistence explicit + auditable | SDD-015 § Problem 4 | E0128 | non-negotiable | false | 10 |
| R02661 | Boundary contract — non-overlapping scopes | SDD-015 § Coverage 1 | E0122 | non-negotiable | false | 10 |
| R02662 | sovereign-kernel-fence scope — container-runtime processes executing sys_execve from inside Rootless Podman containers | SDD-015 § Coverage 1 | F01332 | non-negotiable | false | 10 |
| R02663 | sovereign-kernel-fence allowlist binary — podman | SDD-015 § Coverage 1 | F01333 | non-negotiable | true | 10 |
| R02664 | sovereign-kernel-fence allowlist binary — vllm | SDD-015 § Coverage 1 | F01333 | non-negotiable | true | 10 |
| R02665 | sovereign-kernel-fence allowlist binary — nvidia-smi | SDD-015 § Coverage 1 | F01333 | non-negotiable | true | 10 |
| R02666 | sovereign-kernel-fence allowlist binary — python3 | SDD-015 § Coverage 1 | F01333 | non-negotiable | true | 10 |
| R02667 | sovereign-kernel-fence action — SIGKILL non-allowlisted execves at host level | SDD-015 § Coverage 1 | F01334 | non-negotiable | false | 10 |
| R02668 | sovereign-kernel-fence authority — sovereign-os Stage-2+ team (effectively the operator) | SDD-015 § Coverage 1 | M00292 | non-negotiable | false | 10 |
| R02669 | sovereign-kernel-fence file location — `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml` | SDD-015 § Coverage 1 | M00291 | non-negotiable | false | 10 |
| R02670 | sovereign-kernel-fence modified by `sovereign-osctl perimeter reload` (re-installs from sovereign-os repo) | SDD-015 § Coverage 1 | M00293 | non-negotiable | true | 10 |
| R02671 | agent-guard scope — container-INTERNAL processes scoped via matchPIDs + pod-label selectors | SDD-015 § Coverage 1 | F01338 | non-negotiable | false | 10 |
| R02672 | agent-guard targets Docker container-internal syscalls | SDD-015 § Coverage 1 | F01339 | non-negotiable | true | 10 |
| R02673 | agent-guard targets Podman container-internal syscalls | SDD-015 § Coverage 1 | F01339 | non-negotiable | true | 10 |
| R02674 | agent-guard targets containerd container-internal syscalls | SDD-015 § Coverage 1 | F01339 | non-negotiable | true | 10 |
| R02675 | agent-guard authority — selfdef team (effectively operator via selfdef config) | SDD-015 § Coverage 1 | M00295 | non-negotiable | false | 10 |
| R02676 | agent-guard file pattern — `/etc/tetragon/tracing-policies/agent-guard-*.yaml` | SDD-015 § Coverage 1 | M00294 | non-negotiable | true | 10 |
| R02677 | agent-guard modified by `selfdefctl modules apply` (or future `selfdefctl perimeter apply`) | SDD-015 § Coverage 1 | M00296 | non-negotiable | true | 10 |
| R02678 | Boundary statement — sovereign-kernel-fence governs OUTER container interface (which binaries can be invoked AT ALL) | SDD-015 § Coverage 1 | F01343 | non-negotiable | false | 10 |
| R02679 | Boundary statement — agent-guard governs INNER container behavior (what those binaries can do INSIDE) | SDD-015 § Coverage 1 | F01344 | non-negotiable | false | 10 |
| R02680 | Tetragon hook firing — sovereign-kernel-fence fires sys_execve kprobe with matchPIDs: NotIn [1] (not init) | SDD-015 § Coverage 1 | F01345 | non-negotiable | false | 10 |
| R02681 | Tetragon hook firing — sovereign-kernel-fence uses matchBinaries: NotIn allowlist | SDD-015 § Coverage 1 | F01346 | non-negotiable | false | 10 |
| R02682 | Tetragon hook firing — sovereign-kernel-fence SIGKILL action at host level | SDD-015 § Coverage 1 | F01347 | non-negotiable | false | 10 |
| R02683 | Tetragon hook firing — agent-guard kprobes scoped via matchNamespaces: [container] | SDD-015 § Coverage 1 | F01348 | non-negotiable | false | 10 |
| R02684 | Tetragon hook firing — agent-guard scoped via label selectors | SDD-015 § Coverage 1 | F01349 | non-negotiable | false | 10 |
| R02685 | Tetragon hook firing — agent-guard is independent action surface | SDD-015 § Coverage 1 | F01350 | non-negotiable | false | 10 |
| R02686 | Non-overlap invariant — no agent-guard policy should ever assert on sys_execve host-wide | SDD-015 § Coverage 1 | E0125 | non-negotiable | false | 10 |
| R02687 | Non-overlap invariant violation flagged by `selfdefctl perimeter check-overlap` | SDD-015 § Coverage 1 | F01352 | non-negotiable | false | 10 |
| R02688 | `selfdefctl perimeter check-overlap` exists | SDD-015 § Coverage 2 | F01353 | non-negotiable | true | 10 |
| R02689 | check-overlap requires sudo | SDD-015 § Coverage 2 | F01354 | non-negotiable | false | 10 |
| R02690 | check-overlap parses YAML files in `/etc/tetragon/tracing-policies/` | SDD-015 § Coverage 2 | M00300 | non-negotiable | false | 10 |
| R02691 | check-overlap extracts `spec.kprobes[].call` (syscall name) | SDD-015 § Coverage 2 | M00300 | non-negotiable | false | 10 |
| R02692 | check-overlap extracts `spec.kprobes[].selectors[].matchNamespaces` (scope) | SDD-015 § Coverage 2 | M00301 | non-negotiable | false | 10 |
| R02693 | check-overlap asserts non-overlapping coverage | SDD-015 § Coverage 2 | M00302 | non-negotiable | false | 10 |
| R02694 | check-overlap crate location — `crates/selfdef-cli/src/perimeter.rs` (new module under selfdef-cli) | SDD-015 § Coverage 2 | M00299 | non-negotiable | false | 10 |
| R02695 | check-overlap success row — "host-scoped sys_execve allowlist" for sovereign-kernel-fence.yaml | SDD-015 § Coverage 2 success | M00304 | non-negotiable | false | 10 |
| R02696 | check-overlap success row — "container-scoped (matchNamespaces=container) sys_openat" for agent-guard-etc-write.yaml | SDD-015 § Coverage 2 success | M00304 | non-negotiable | false | 10 |
| R02697 | check-overlap success row — "container-scoped (matchNamespaces=container) sys_execve" for agent-guard-shell-exec.yaml | SDD-015 § Coverage 2 success | M00304 | non-negotiable | false | 10 |
| R02698 | check-overlap PASS line — "no host-wide kprobe overlap detected" | SDD-015 § Coverage 2 success | F01360 | non-negotiable | false | 10 |
| R02699 | check-overlap PASS line — "sys_execve coverage: sovereign-kernel-fence (host) + agent-guard-shell-exec (container) — non-overlapping" | SDD-015 § Coverage 2 success | F01361 | non-negotiable | false | 10 |
| R02700 | check-overlap PASS line — "all policies have distinct metadata.name" | SDD-015 § Coverage 2 success | F01362 | non-negotiable | false | 10 |
| R02701 | check-overlap FAIL line — "agent-guard-newfeature.yaml asserts on sys_execve without matchNamespaces=container scope" | SDD-015 § Coverage 2 failure | F01363 | non-negotiable | false | 10 |
| R02702 | check-overlap FAIL line — "would conflict with sovereign-kernel-fence's host-wide allowlist" | SDD-015 § Coverage 2 failure | F01364 | non-negotiable | false | 10 |
| R02703 | check-overlap FAIL Fix: line — "add 'matchNamespaces: { operator: In, values: [container] }' to the selector" | SDD-015 § Coverage 2 failure | F01365 | non-negotiable | false | 10 |
| R02704 | check-overlap FAIL terminates with "Exit 1." | SDD-015 § Coverage 2 failure | F01367 | non-negotiable | false | 10 |
| R02705 | check-overlap exit code 0 on pass | SDD-015 § Coverage 2 + § Coverage 6 | F01366 | non-negotiable | false | 10 |
| R02706 | check-overlap exit code 1 on overlap | SDD-015 § Coverage 2 + § Coverage 6 | F01367 | non-negotiable | false | 10 |
| R02707 | `selfdefctl perimeter diff` exists | SDD-015 § Coverage 3 | F01368 | non-negotiable | true | 10 |
| R02708 | perimeter diff requires sudo | SDD-015 § Coverage 3 | F01369 | non-negotiable | false | 10 |
| R02709 | perimeter diff column 1 — LOADED IN TETRAGON | SDD-015 § Coverage 3 | M00306 | non-negotiable | false | 10 |
| R02710 | perimeter diff column 2 — ON DISK (/etc/tetragon/tracing-policies/) | SDD-015 § Coverage 3 | M00307 | non-negotiable | false | 10 |
| R02711 | perimeter diff row state — "(matches)" when loaded == on-disk | SDD-015 § Coverage 3 | F01372 | non-negotiable | false | 10 |
| R02712 | perimeter diff row state — "(on disk but not loaded — restart tetragon?)" | SDD-015 § Coverage 3 | F01373 | non-negotiable | false | 10 |
| R02713 | perimeter diff row state — "(loaded but not on disk — drift!)" | SDD-015 § Coverage 3 | F01374 | non-negotiable | false | 10 |
| R02714 | perimeter diff drift detection — operator prompted to reconcile via `sovereign-osctl perimeter reload` | SDD-015 § Coverage 3 | F01375 | non-negotiable | true | 10 |
| R02715 | perimeter diff drift detection — operator prompted to reconcile via `systemctl restart tetragon` | SDD-015 § Coverage 3 | F01376 | non-negotiable | true | 10 |
| R02716 | [perimeter] config block lives in `/etc/selfdef/selfdef.toml` | SDD-015 § Coverage 4 | F01377 | non-negotiable | true | 10 |
| R02717 | [perimeter] knob check_overlap_on_apply — bool | SDD-015 § Coverage 4 | M00311 | non-negotiable | true | 10 |
| R02718 | check_overlap_on_apply=true causes auto check-overlap on every `selfdefctl modules apply` invocation when target=sain01 | SDD-015 § Coverage 4 | F01379 | non-negotiable | false | 10 |
| R02719 | check_overlap_on_apply=true causes refusal to apply policies that would conflict with sovereign-kernel-fence | SDD-015 § Coverage 4 | F01380 | non-negotiable | false | 10 |
| R02720 | [perimeter] knob sovereign_kernel_fence_path — string | SDD-015 § Coverage 4 | M00312 | non-negotiable | true | 10 |
| R02721 | sovereign_kernel_fence_path default — `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml` | SDD-015 § Coverage 4 | F01382 | non-negotiable | false | 10 |
| R02722 | sovereign_kernel_fence_path is what selfdef reads to know what to NOT overlap with | SDD-015 § Coverage 4 | M00312 | non-negotiable | false | 10 |
| R02723 | [perimeter] knob overlap_warn_only — bool | SDD-015 § Coverage 4 | M00313 | non-negotiable | true | 10 |
| R02724 | overlap_warn_only default — false (= block by default) | SDD-015 § Coverage 4 | F01384 | non-negotiable | false | 10 |
| R02725 | overlap_warn_only=true = warn (not block) on overlap during apply | SDD-015 § Coverage 4 | M00313 | non-negotiable | false | 10 |
| R02726 | Default — when target=sain01 and [perimeter] block absent → check_overlap_on_apply=true | SDD-015 § Coverage 4 | F01385 | non-negotiable | false | 10 |
| R02727 | Default — when target=generic → [perimeter] block ignored entirely (no sovereign-os assumption) | SDD-015 § Coverage 4 | F01386 | non-negotiable | false | 10 |
| R02728 | Audit-trail integration — per SDD-014, `shared-audit-summary` channel emits one summary line per event to `/mnt/vault/context/security_audit.log` | SDD-015 § Coverage 5 + SDD-014 | F01387 | non-negotiable | false | 10 |
| R02729 | Audit-trail — Tetragon kill events NOT originating from selfdef-authored policy are emitted by sovereign-os `guardian-core` daemon (component=tetragon) | SDD-015 § Coverage 5 | F01388 | non-negotiable | false | 10 |
| R02730 | selfdef filter discriminator — reads Tetragon event `policy_name` field | SDD-015 § Coverage 5 | M00314 | non-negotiable | false | 10 |
| R02731 | selfdef filter discriminator — if policy_name starts with `agent-guard-` → selfdef logs the event | SDD-015 § Coverage 5 | F01390 | non-negotiable | true | 10 |
| R02732 | selfdef filter discriminator — otherwise → it's guardian-core's responsibility | SDD-015 § Coverage 5 | F01391 | non-negotiable | false | 10 |
| R02733 | Both daemons subscribe to the same Tetragon event stream | SDD-015 § Coverage 5 | M00315 | non-negotiable | false | 10 |
| R02734 | Filter discriminators are mutually exclusive — no event double-handled | SDD-015 § Coverage 5 | F01393 | non-negotiable | false | 10 |
| R02735 | Filter discriminators are mutually exclusive — no event missed | SDD-015 § Coverage 5 | F01394 | non-negotiable | false | 10 |
| R02736 | CLI surface — `sudo selfdefctl perimeter status` (existing — extends to show coexistence active) | SDD-015 § Coverage 6 | F01395 | non-negotiable | true | 10 |
| R02737 | CLI surface — `sudo selfdefctl perimeter check-overlap` (new — exit 0 pass; 1 overlap) | SDD-015 § Coverage 6 | F01396 | non-negotiable | true | 10 |
| R02738 | CLI surface — `sudo selfdefctl perimeter diff` (new — loaded vs on-disk reconciliation) | SDD-015 § Coverage 6 | F01397 | non-negotiable | true | 10 |
| R02739 | CLI surface — `sudo selfdefctl modules apply` (extended — runs check-overlap if config says so) | SDD-015 § Coverage 6 | F01398 | non-negotiable | true | 10 |
| R02740 | Regression test — `no_overlap_passes` (synthetic 2 policies, host vs container scope) | SDD-015 § Coverage 7 | F01399 | non-negotiable | false | 10 |
| R02741 | Regression test — `host_scoped_sys_execve_in_agent_guard_fails_overlap` (synthetic; selfdef policy lacks matchNamespaces) | SDD-015 § Coverage 7 | F01400 | non-negotiable | false | 10 |
| R02742 | Regression test — `duplicate_metadata_name_fails` (two policies same name) | SDD-015 § Coverage 7 | F01401 | non-negotiable | false | 10 |
| R02743 | Regression test — `loaded_vs_disk_drift_detected` (mock tetragon socket; agent-guard-stale loaded, not on disk) | SDD-015 § Coverage 7 | F01402 | non-negotiable | false | 10 |
| R02744 | Regression test — `check_overlap_skipped_on_generic_target` (deployment.target=generic; coexistence not assumed) | SDD-015 § Coverage 7 | F01403 | non-negotiable | false | 10 |
| R02745 | Regression test — `audit_log_filter_by_policy_name_prefix` (selfdef sees agent-guard-* events only) | SDD-015 § Coverage 7 | F01404 | non-negotiable | false | 10 |
| R02746 | Integration test file — `tests/it/perimeter_coexistence.rs` | SDD-015 § Coverage 7 | F01405 | non-negotiable | false | 10 |
| R02747 | Integration test spawns Tetragon OR mocks via test-only daemon socket | SDD-015 § Coverage 7 | F01405 | non-negotiable | false | 10 |
| R02748 | Integration test verifies discriminator works end-to-end | SDD-015 § Coverage 7 | F01405 | non-negotiable | false | 10 |
| R02749 | Goal 1 — non-overlapping policy authority | SDD-015 § Goals 1 | F01406 | non-negotiable | false | 10 |
| R02750 | Goal 1 — sovereign-os owns host-scoped perimeter; selfdef owns container-internal | SDD-015 § Goals 1 | F01406 | non-negotiable | false | 10 |
| R02751 | Goal 1 — boundary documented + enforced | SDD-015 § Goals 1 | F01406 | non-negotiable | false | 10 |
| R02752 | Goal 2 — operator-visible coexistence | SDD-015 § Goals 2 | F01407 | non-negotiable | false | 10 |
| R02753 | Goal 2 — `selfdefctl perimeter check-overlap` + `diff` make integration introspectable | SDD-015 § Goals 2 | F01407 | non-negotiable | false | 10 |
| R02754 | Goal 3 — pre-apply gating | SDD-015 § Goals 3 | F01408 | non-negotiable | false | 10 |
| R02755 | Goal 3 — when target=sain01, selfdef refuses to install policy that overlaps sovereign-kernel-fence | SDD-015 § Goals 3 | F01408 | non-negotiable | false | 10 |
| R02756 | Goal 3 — unless operator explicit-allows via overlap_warn_only | SDD-015 § Goals 3 | F01408 | non-negotiable | false | 10 |
| R02757 | Goal 4 — audit discrimination | SDD-015 § Goals 4 | F01409 | non-negotiable | false | 10 |
| R02758 | Goal 4 — policy_name prefix filter ensures each daemon sees only its own events | SDD-015 § Goals 4 | F01409 | non-negotiable | false | 10 |
| R02759 | Goal 4 — no double-processing | SDD-015 § Goals 4 | F01409 | non-negotiable | false | 10 |
| R02760 | Goal 5 — non-SAIN-01 unchanged | SDD-015 § Goals 5 | F01410 | non-negotiable | false | 10 |
| R02761 | Goal 5 — target=generic deployments never run check-overlap (Q-G honored) | SDD-015 § Goals 5 | F01410 | non-negotiable | false | 10 |
| R02762 | Non-goal — does NOT modify existing agent-guard TracingPolicies | SDD-015 § Non-goals | F01411 | non-negotiable | false | 10 |
| R02763 | Non-goal — does NOT implement the oracle-triage channel (SDD-016) | SDD-015 § Non-goals | F01412 | non-negotiable | false | 10 |
| R02764 | Non-goal — does NOT change sovereign-os's sovereign-kernel-fence.yaml shape | SDD-015 § Non-goals | F01413 | non-negotiable | false | 10 |
| R02765 | Non-goal — sovereign-kernel-fence.yaml shape is owned by sovereign-os Stage-2+ | SDD-015 § Non-goals | F01413 | non-negotiable | false | 10 |
| R02766 | Non-goal — does NOT specify Tetragon merge semantics | SDD-015 § Non-goals | F01414 | non-negotiable | false | 10 |
| R02767 | Non-goal — Tetragon merge semantics are Tetragon's responsibility upstream | SDD-015 § Non-goals | F01414 | non-negotiable | false | 10 |
| R02768 | Open Q15-A — should check-overlap parse Tetragon's runtime state via socket or YAML on disk? | SDD-015 § Open Q15-A | F01415 | non-negotiable | false | 10 |
| R02769 | Q15-A recommendation — YAML files first (no Tetragon-socket dep) | SDD-015 § Open Q15-A | F01416 | non-negotiable | false | 10 |
| R02770 | Q15-A recommendation — diff command separately queries the socket | SDD-015 § Open Q15-A | F01416 | non-negotiable | false | 10 |
| R02771 | Open Q15-B — format of overlap warning when overlap_warn_only=true? | SDD-015 § Open Q15-B | F01417 | non-negotiable | false | 10 |
| R02772 | Q15-B recommendation — stderr WARN line | SDD-015 § Open Q15-B | F01418 | non-negotiable | false | 10 |
| R02773 | Q15-B recommendation — journald entry | SDD-015 § Open Q15-B | F01418 | non-negotiable | false | 10 |
| R02774 | Q15-B recommendation — non-fail exit | SDD-015 § Open Q15-B | F01418 | non-negotiable | false | 10 |
| R02775 | Open Q15-C — should sovereign-os's `sovereign-osctl perimeter check-overlap` also exist (peer command)? | SDD-015 § Open Q15-C | F01419 | non-negotiable | false | 10 |
| R02776 | Q15-C recommendation — YES (peer command natural in sovereign-os Stage-2+ enhancement) | SDD-015 § Open Q15-C | F01420 | non-negotiable | false | 10 |
| R02777 | Open Q15-D — how to handle third-party (non-sovereign-os, non-selfdef) Tetragon policy author landing files in same dir? | SDD-015 § Open Q15-D | F01421 | non-negotiable | false | 10 |
| R02778 | Q15-D recommendation — warn + treat as opaque (don't fail; operator's discretion) | SDD-015 § Open Q15-D | F01422 | non-negotiable | false | 10 |
| R02779 | Way forward step 1 — this PR is the spec | SDD-015 § Way forward 1 | F01423 | non-negotiable | false | 10 |
| R02780 | Way forward step 2 — Impl PR (new selfdef-cli perimeter.rs module + check-overlap + diff + apply-time integration + tests) | SDD-015 § Way forward 2 | F01424 | non-negotiable | false | 10 |
| R02781 | Way forward step 3 — SDD-016 PR (oracle-triage channel; Q-D resolution; last of 4 Stage-2 SDDs) | SDD-015 § Way forward 3 | F01425 | non-negotiable | false | 10 |
| R02782 | Stage-2 progress — SDD-013 done (✅) | SDD-015 § Way forward | F01426 | non-negotiable | false | 10 |
| R02783 | Stage-2 progress — SDD-014 in review | SDD-015 § Way forward | F01427 | non-negotiable | false | 10 |
| R02784 | Stage-2 progress — SDD-015 (this milestone) | SDD-015 § Way forward | F01428 | non-negotiable | false | 10 |
| R02785 | Stage-2 progress — SDD-016 next | SDD-015 § Way forward | F01429 | non-negotiable | false | 10 |
| R02786 | Cross-reference — SDD-012 § Q-A | SDD-015 § Cross-references | F01430 | non-negotiable | false | 10 |
| R02787 | Cross-reference — SDD-013 (deployment.target gates check-overlap-on-apply behavior) | SDD-015 § Cross-references | F01431 | non-negotiable | false | 10 |
| R02788 | Cross-reference — SDD-014 (shared-audit-summary; audit-discrimination mechanism) | SDD-015 § Cross-references | F01432 | non-negotiable | false | 10 |
| R02789 | Cross-reference — SDD-008 (notifications-orchestration; policy_name filter pattern) | SDD-015 § Cross-references | F01433 | non-negotiable | false | 10 |
| R02790 | Cross-reference — SDD-001 (ai-machine-end-to-end; agent-guard's container-internal scope) | SDD-015 § Cross-references | F01434 | non-negotiable | false | 10 |
| R02791 | Cross-reference — SDD-004 (security-threat-model; threat surface this perimeter addresses) | SDD-015 § Cross-references | F01435 | non-negotiable | false | 10 |
| R02792 | Cross-reference — sovereign-os `scripts/hooks/post-install/tetragon-policy-load.sh` (installs sovereign-kernel-fence.yaml) | SDD-015 § Cross-references | F01436 | non-negotiable | false | 10 |
| R02793 | Cross-reference — sovereign-os `scripts/sovereign-osctl perimeter reload` subcommand | SDD-015 § Cross-references | F01437 | non-negotiable | false | 10 |
| R02794 | Cross-reference — sovereign-os SDD-011 (inference stack; Logic Engine + Oracle Core in containers governed by both perimeters) | SDD-015 § Cross-references | F01438 | non-negotiable | false | 10 |
| R02795 | Project boundary — sovereign-kernel-fence.yaml is owned by sovereign-os; selfdef reads it but never modifies it | architecture | E0123 | non-negotiable | false | 10 |
| R02796 | Project boundary — agent-guard-*.yaml policies are owned by selfdef; sovereign-os reads them but never modifies them | architecture | E0124 | non-negotiable | false | 10 |
| R02797 | Project boundary — cross-repo binding is via documented file paths under `/etc/tetragon/tracing-policies/` + Tetragon daemon as merge agent | SDD-015 § Coverage 1 + MS007 + SDD-038 | E0122 | non-negotiable | false | 10 |
| R02798 | Project boundary — NOT selfdef importing sovereign-os Rust crates directly (MS007 typed-mirror crates are the binding doctrine) | MS007 + SDD-038 | E0122 | non-negotiable | false | 10 |
| R02799 | Project boundary — peer-command pattern (Q15-C YES) — `sovereign-osctl perimeter check-overlap` is a sovereign-os enhancement; selfdef does NOT call it; operator invokes from either side | SDD-015 § Open Q15-C | F01420 | non-negotiable | false | 10 |
| R02800 | Tetragon discovers policies via standard policy directory `/etc/tetragon/tracing-policies/` regardless of authoring origin | SDD-015 § Coverage 1 | E0122 | non-negotiable | false | 10 |
| R02801 | sys_execve coverage split — host (sovereign-kernel-fence) + container (agent-guard-shell-exec) is the canonical example of non-overlapping coexistence | SDD-015 § Coverage 2 success | F01361 | non-negotiable | false | 10 |
| R02802 | sys_openat coverage example — container-scoped agent-guard-etc-write.yaml is a valid non-overlapping selfdef policy | SDD-015 § Coverage 2 success | M00304 | non-negotiable | false | 10 |
| R02803 | metadata.name uniqueness — every policy must have a distinct metadata.name (Tetragon requirement; check-overlap enforces) | SDD-015 § Coverage 2 success | F01362 | non-negotiable | false | 10 |
| R02804 | check-overlap operator-actionable Fix lines — every FAIL must offer a remediation line | SDD-015 § Coverage 2 failure | F01365 | non-negotiable | false | 10 |
| R02805 | check-overlap exits informatively — operator sees row table + summary lines before exit code | SDD-015 § Coverage 2 | M00303 | non-negotiable | false | 10 |
| R02806 | diff reconciliation — "missing — restart tetragon?" is the on-disk-but-not-loaded remediation hint | SDD-015 § Coverage 3 | M00308 | non-negotiable | false | 10 |
| R02807 | diff reconciliation — "loaded but not on disk — drift!" is the loaded-but-no-source flag | SDD-015 § Coverage 3 | M00309 | non-negotiable | false | 10 |
| R02808 | apply-time gate — when check_overlap_on_apply=true and overlap detected and overlap_warn_only=false → refuse to apply | SDD-015 § Coverage 4 + § Goals 3 | F01380 + F01408 | non-negotiable | false | 10 |
| R02809 | apply-time gate — when overlap_warn_only=true → warn but proceed | SDD-015 § Coverage 4 + Q15-B | F01418 | non-negotiable | false | 10 |
| R02810 | apply-time gate — when target=generic → never gate (Goal 5; SDD-013 [deployment.target] honored) | SDD-015 § Coverage 4 + § Goals 5 | F01386 | non-negotiable | false | 10 |
| R02811 | Audit-trail integration writes to `/mnt/vault/context/security_audit.log` (SDD-014 channel) | SDD-014 + SDD-015 § Coverage 5 | F01387 | non-negotiable | false | 10 |
| R02812 | Audit-trail integration — selfdef emits one summary line per event whose policy_name starts with `agent-guard-` | SDD-015 § Coverage 5 | F01390 | non-negotiable | false | 10 |
| R02813 | Audit-trail integration — `guardian-core` daemon emits one summary line per event whose policy_name does NOT start with `agent-guard-` | SDD-015 § Coverage 5 | F01391 | non-negotiable | false | 10 |
| R02814 | Audit-trail invariant — sum of selfdef-emitted + guardian-core-emitted = total Tetragon kill events (no double / no miss) | SDD-015 § Coverage 5 | M00315 | non-negotiable | false | 10 |
| R02815 | CLI surface extends — existing `selfdefctl perimeter status` now surfaces coexistence-active flag | SDD-015 § Coverage 6 | F01395 | non-negotiable | false | 10 |
| R02816 | CLI surface extends — existing `selfdefctl modules apply` now runs check-overlap when config says so | SDD-015 § Coverage 6 | F01398 | non-negotiable | false | 10 |
| R02817 | Regression test — `no_overlap_passes` asserts the success path | SDD-015 § Coverage 7 | F01399 | non-negotiable | false | 10 |
| R02818 | Regression test — `host_scoped_sys_execve_in_agent_guard_fails_overlap` asserts the FAIL path on missing matchNamespaces | SDD-015 § Coverage 7 | F01400 | non-negotiable | false | 10 |
| R02819 | Regression test — `duplicate_metadata_name_fails` asserts metadata.name uniqueness enforcement | SDD-015 § Coverage 7 | F01401 | non-negotiable | false | 10 |
| R02820 | Regression test — `loaded_vs_disk_drift_detected` asserts diff drift detection works against mock tetragon socket | SDD-015 § Coverage 7 | F01402 | non-negotiable | false | 10 |
| R02821 | Regression test — `check_overlap_skipped_on_generic_target` asserts target=generic skips overlap check entirely | SDD-015 § Coverage 7 | F01403 | non-negotiable | false | 10 |
| R02822 | Regression test — `audit_log_filter_by_policy_name_prefix` asserts selfdef sees agent-guard-* events only | SDD-015 § Coverage 7 | F01404 | non-negotiable | false | 10 |
| R02823 | Integration test `tests/it/perimeter_coexistence.rs` end-to-end verification | SDD-015 § Coverage 7 | F01405 | non-negotiable | false | 10 |
| R02824 | Tetragon merge semantics are upstream Tetragon's responsibility (selfdef does NOT model them) | SDD-015 § Non-goals | F01414 | non-negotiable | false | 10 |
| R02825 | selfdef does NOT change sovereign-kernel-fence shape (out of scope per ownership) | SDD-015 § Non-goals | F01413 | non-negotiable | false | 10 |
| R02826 | SDD-016 oracle-triage channel is the next milestone (NOT this one) | SDD-015 § Non-goals + § Way forward | F01412 | non-negotiable | false | 10 |
| R02827 | Stage-2 milestone arc — 4 SDDs total (013/014/015/016); MS012 = SDD-015 | SDD-015 § Way forward | E0130 | non-negotiable | false | 10 |
| R02828 | Stage-2 milestone arc — closes 4 SDD-012 questions (Q-A by SDD-015; Q-D by SDD-016; Q-G + Q-H earlier) | SDD-015 § header + SDD-012 | E0121 | non-negotiable | false | 10 |
| R02829 | Cross-repo authoring discipline — sovereign-os owns sovereign-kernel-fence shape + content; selfdef owns agent-guard-* shape + content; both share the directory | SDD-015 § Coverage 1 | E0122 | non-negotiable | false | 10 |
| R02830 | Cross-repo authoring discipline — change to one author's policies is a single-repo PR; no cross-repo dependency | SDD-015 § Coverage 1 + § Non-goals | E0122 | non-negotiable | false | 10 |
| R02831 | Cross-repo authoring discipline — Tetragon is the merge agent; both daemons rely on Tetragon's documented merge semantics | SDD-015 § Problem | F01325 | non-negotiable | false | 10 |
| R02832 | Cross-repo audit discipline — guardian-core + selfdef both subscribe to Tetragon event stream; policy_name prefix discriminator partitions logs | SDD-015 § Coverage 5 | M00315 | non-negotiable | false | 10 |
| R02833 | Operator-driven introspection — `selfdefctl perimeter check-overlap` is the operator-visible coexistence verification verb | SDD-015 § Goals 2 | F01396 | non-negotiable | false | 10 |
| R02834 | Operator-driven introspection — `selfdefctl perimeter diff` is the operator-visible drift verification verb | SDD-015 § Goals 2 | F01397 | non-negotiable | false | 10 |
| R02835 | Operator-driven introspection — `selfdefctl perimeter status` is the operator-visible posture summary verb | SDD-015 § Coverage 6 | F01395 | non-negotiable | false | 10 |
| R02836 | Operator-driven introspection — coexistence-active flag visible from status verb on target=sain01 | SDD-015 § Coverage 6 | F01395 | non-negotiable | false | 10 |
| R02837 | Operator-driven gating — `[perimeter] check_overlap_on_apply` is the operator-set knob | SDD-015 § Coverage 4 | F01378 | non-negotiable | false | 10 |
| R02838 | Operator-driven gating — `[perimeter] overlap_warn_only` is the operator-explicit-allow knob | SDD-015 § Coverage 4 | F01383 | non-negotiable | false | 10 |
| R02839 | Operator-driven gating — `[perimeter] sovereign_kernel_fence_path` is the operator-overridable lookup path | SDD-015 § Coverage 4 | F01381 | non-negotiable | false | 10 |
| R02840 | MS012 integrates with — MS001 (selfdefctl extension), MS002 (Tetragon collector ingests events), MS003 (signing on policy authoring), MS006 (agent-guard module is one of the 14 functional modules), MS007 (cross-repo binding via documented file paths + Tetragon as merge agent), MS008 (selfdef-on-SAIN-01 deployment context for target=sain01), MS009 (audit cycles cover SDD-015) | MS001/002/003/006/007/008/009 | E0130 | non-negotiable | false | 10 |
| R02841 | MS012 integrates with — sovereign-os perimeter side (sovereign-kernel-fence.yaml + guardian-core daemon + sovereign-osctl perimeter reload) | SDD-015 § Cross-references | E0122 | non-negotiable | false | 10 |
| R02842 | MS012 sub-questions are tracked as Q15-A..Q15-D and resolved by operator per ratification mechanism | SDD-015 § Open sub-questions | E0130 | non-negotiable | false | 10 |
| R02843 | MS012 closes — SDD-015 review state advances to merged when Way-forward step 2 Impl PR ships | SDD-015 § header status | E0130 | non-negotiable | false | 10 |
| R02844 | MS012 audit-cycle integration — MS009 phase-7 integration audit verifies perimeter coexistence end-to-end | MS009 phase-7 | E0130 | non-negotiable | false | 10 |
| R02845 | check-overlap parser handles missing matchNamespaces gracefully — treats as host-scoped (failure mode if syscall is in sovereign-kernel-fence host scope) | SDD-015 § Coverage 2 failure | F01363 | non-negotiable | false | 10 |
| R02846 | check-overlap parser handles malformed YAML — emits operator-readable parse error; non-zero exit | SDD-015 § Coverage 2 | M00300 | non-negotiable | false | 10 |
| R02847 | check-overlap parser handles non-Tetragon files in the directory — skips with WARN | SDD-015 § Open Q15-D | F01422 | non-negotiable | false | 10 |
| R02848 | check-overlap parser handles third-party policy author files — warns + treats as opaque (does NOT fail; operator's discretion) | SDD-015 § Open Q15-D | F01422 | non-negotiable | false | 10 |
| R02849 | diff handles Tetragon socket unavailable — operator-readable error; non-zero exit; suggests `systemctl status tetragon` | SDD-015 § Coverage 3 | E0127 | non-negotiable | false | 10 |
| R02850 | diff handles empty on-disk directory — emits "no policies on disk" row; non-fail | SDD-015 § Coverage 3 | E0127 | non-negotiable | false | 10 |
| R02851 | diff handles empty loaded set — emits "no policies loaded" row; non-fail | SDD-015 § Coverage 3 | E0127 | non-negotiable | false | 10 |
| R02852 | apply-time gate honors operator override — when overlap_warn_only=true, apply proceeds with WARN | SDD-015 § Coverage 4 | F01380 + F01383 | non-negotiable | false | 10 |
| R02853 | apply-time gate emits journald entry on overlap — operator-discoverable post-hoc | SDD-015 § Open Q15-B | F01418 | non-negotiable | false | 10 |
| R02854 | apply-time gate emits stderr WARN line on overlap (when overlap_warn_only=true) — operator-discoverable in-flight | SDD-015 § Open Q15-B | F01418 | non-negotiable | false | 10 |
| R02855 | Tetragon merge agent assumption — Tetragon honors metadata.name uniqueness across files in tracing-policies dir | SDD-015 § Coverage 2 success | F01362 | non-negotiable | false | 10 |
| R02856 | Tetragon merge agent assumption — Tetragon's permissive-allowlist + intersect-deny merge is the source of truth for in-flight behavior | SDD-015 § Problem | F01325 | non-negotiable | false | 10 |
| R02857 | Tetragon merge agent assumption — selfdef's check-overlap is a STATIC pre-flight check; does NOT replace Tetragon's runtime merge | SDD-015 § Open Q15-A | F01416 | non-negotiable | false | 10 |
| R02858 | Tetragon merge agent assumption — selfdef's diff is a RECONCILIATION check between disk + Tetragon runtime view | SDD-015 § Coverage 3 + Open Q15-A | E0127 | non-negotiable | false | 10 |
| R02859 | Documentation discipline — every check-overlap FAIL row carries operator-actionable Fix: line | SDD-015 § Coverage 2 failure | F01365 | non-negotiable | false | 10 |
| R02860 | Documentation discipline — every check-overlap PASS row carries the scope evidence (host vs container) | SDD-015 § Coverage 2 success | M00304 | non-negotiable | false | 10 |
| R02861 | Documentation discipline — every diff row carries reconciliation hint (matches / restart-tetragon / drift) | SDD-015 § Coverage 3 | E0127 | non-negotiable | false | 10 |
| R02862 | Documentation discipline — SDD-015 closes Q-A by name; does NOT pre-empt SDD-016 Q-D resolution | SDD-015 § Non-goals + § header | E0121 + F01412 | non-negotiable | false | 10 |
| R02863 | Documentation discipline — SDD-015 follows the SDD-012 Q-H ordering (PR 3/4 in Stage 2) | SDD-015 § header | E0121 | non-negotiable | false | 10 |
| R02864 | Operator words sacrosanct — SDD-015 specifies "operator deserves to know" verbatim as the problem-statement closer | SDD-015 § Problem | F01329 | non-negotiable | false | 10 |
| R02865 | Operator words sacrosanct — SDD-015 specifies "Q-G honored" verbatim as the Goal-5 closer | SDD-015 § Goals 5 | F01410 | non-negotiable | false | 10 |
| R02866 | check-overlap supports `--json` (implicit; per CLI convention adopted in MS011 SD-R84) — JSON shape: `{policies: [{path, scope, kprobes: [{call, scoped}]}], overlaps: [{policy_a, policy_b, reason}], passed: bool}` | SDD-015 § Coverage 2 + MS011 SD-R84 | F01396 | non-negotiable | false | 10 |
| R02867 | diff supports `--json` (implicit; per CLI convention) — JSON shape: `{loaded: [{name, version}], on_disk: [{name, file}], matches: [...], missing_load: [...], drift: [...]}` | SDD-015 § Coverage 3 + MS011 SD-R84 | F01397 | non-negotiable | false | 10 |
| R02868 | status verb extends with coexistence_active boolean field in `--json` | SDD-015 § Coverage 6 | F01395 | non-negotiable | false | 10 |
| R02869 | Apply-time integration — overlap detection happens BEFORE any agent-guard-*.yaml file is written to `/etc/tetragon/tracing-policies/` | SDD-015 § Coverage 4 + Goals 3 | F01380 | non-negotiable | false | 10 |
| R02870 | Apply-time integration — agent-guard policy file write is atomic (tempfile + rename) | SDD-015 § Coverage 1 + selfdef convention | F01342 | non-negotiable | false | 10 |
| R02871 | Apply-time integration — failed apply leaves /etc/tetragon/tracing-policies/ unchanged | SDD-015 § Goals 3 | F01408 | non-negotiable | false | 10 |
| R02872 | Apply-time integration — successful apply triggers Tetragon reload (or operator-prompted restart per diff hint) | SDD-015 § Coverage 3 | M00310 | non-negotiable | false | 10 |
| R02873 | Apply-time integration — operator-readable apply log lists each policy file written + load outcome | SDD-015 § Coverage 1 + Coverage 6 | F01398 | non-negotiable | false | 10 |
| R02874 | Audit-trail row schema — `policy_name` field is the discriminator key | SDD-015 § Coverage 5 | M00314 | non-negotiable | false | 10 |
| R02875 | Audit-trail row schema — selfdef emits component="selfdef" + module="agent-guard" prefix-derivative | SDD-015 § Coverage 5 | F01390 | non-negotiable | false | 10 |
| R02876 | Audit-trail row schema — guardian-core emits component="tetragon" (sovereign-os origin) | SDD-015 § Coverage 5 | F01388 | non-negotiable | false | 10 |
| R02877 | Audit-trail row schema — both daemons MUST agree on event-id field so post-hoc deduplication is possible | SDD-015 § Coverage 5 (mutually exclusive) | M00315 | non-negotiable | false | 10 |
| R02878 | Audit-trail integration with MS004 — Oracle-Triage channel (MS004 E0036) carries security_audit.log summaries for cross-repo correlation | MS004 E0036 + SDD-016 | E0129 | non-negotiable | false | 10 |
| R02879 | MS012 closes Stage-2 PR 3/4; remaining Stage-2 work = SDD-016 oracle-triage channel | SDD-015 § Way forward | E0130 | non-negotiable | false | 10 |
| R02880 | Composite — perimeter coexistence is the selfdef contribution to the sovereign-os/selfdef cross-repo perimeter discipline; sovereign-os hosts the host-scoped kernel fence; selfdef hosts the container-scoped agent-guard policies; both share `/etc/tetragon/tracing-policies/`; Tetragon is the merge agent; selfdef ships introspection + drift detection + apply-time gating; audit-trail discriminator partitions events; cross-repo binding doctrine (MS007 + SDD-038) preserved (no direct crate import) | SDD-015 entire document + MS007 + SDD-038 | E0130 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS011: 9120 + 2400 = 11520 sub-requirements when MS012 lands

## Cross-references

- Stage-2 sister SDDs — SDD-013 [deployment.target] / SDD-014 shared-audit-summary / SDD-015 (this) / SDD-016 oracle-triage (next)
- Inherits from — SDD-012 (integration design, Q-A authoring authority resolution) / SDD-001 (ai-machine-end-to-end agent-guard scope) / SDD-004 (security threat model)
- sovereign-os parallel — `sovereign-kernel-fence.yaml` + `scripts/hooks/post-install/tetragon-policy-load.sh` + `sovereign-osctl perimeter reload` + sovereign-os SDD-011 inference stack
- Cross-repo binding doctrine — `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (MS007 typed-mirror crates remain the only Rust-level cross-repo channel; perimeter coexistence is a file-system + Tetragon-as-agent channel)
- Audit-cycle integration — MS009 phase-7/50-integration-audit covers SDD-015 coexistence verification
