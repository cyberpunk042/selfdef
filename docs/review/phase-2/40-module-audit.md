# Phase 2 — Module audit

> Scope (per the Phase 2 charter): the new
> `require_signed_policies` knob in `tetragon`, the v2 manifest
> helpers across all shipped modules, vpn-bridge per-profile
> instanced. Per-area ids prefix `M2-` and roll up to the ledger
> as `F-2027-NNN`.
>
> What this audit doesn't re-litigate: Phase 1's module audit
> (every `F-2026-NNN` module finding closed during the previous
> cycle — module-script library extraction, vpn-bridge profile
> dispatcher, dry-run-noop contracts). If a Phase 1 fix is
> broken, that's a new `F-2027-NNN` with a back-reference.

## Headlines

- **No blockers, no important findings**. All 9 shipped modules
  carry a manifest (`module.toml`), a README, and (with one
  documented exception) the standard `install/{apply,check,
  uninstall,lib}.sh` quartet.
- **6 nice findings** clustered into three themes:
  - **v2 manifest helpers**: only `agent-guard` actually uses
    `module_record_file` / `module_render_files`; the other
    seven script-based modules still hand-curate their
    uninstall.sh paths, recreating the drift risk SDD-006 v2
    was designed to remove.
  - **Doc surface**: per-module READMEs are silent on the
    `SELFDEF_MODULE_LIB_VERSION_REQUIRED` knob and the v2
    helpers it gates. New contributors don't know which
    helpers they can rely on.
  - **Defense-in-depth gaps**: a few small bash-injection
    holes where operator-controlled strings flow into
    nftables / shell expansions without the existing
    `safe_name` validator.
- The crate-explorer findings (F-2027-011 through F-2027-021)
  are all closed. The recent-PRs explorer's 10 findings are
  closed except F-2027-010 (SDD-debt).

## Inventory

9 shipped modules. File-presence matrix:

| slug | manifest | README | apply | check | uninstall | lib shim |
| --- | --- | --- | --- | --- | --- | --- |
| `agent-guard` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `bridge-l2` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `detect-host` | ✔ | ✔ | — | — | — | — |
| `integrity-sentinel` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `observability` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `polarproxy` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `suricata` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `tetragon` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `vpn-bridge` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

`detect-host` ships no install scripts because its manifest
declares `[install] kind = "debian-package"` — the install is
the install of `selfdef-daemon` itself. See M2-001 below.

## Per-area observations

### Scope 1 — tetragon `require_signed_policies`

The knob landed in F-2026-024 (Phase 1, closed) and was extended
in F-2027-006 (Phase 2, closed by the `keys verify-dir` PR).
Current wiring is end-to-end clean. One small UX note:

- `modules/tetragon/install/apply.sh:49` — when signature
  verification fails, the script does a recover-step that
  re-runs `selfdefctl keys verify-dir "$POLICY_DIR" || true` to
  show the operator which file(s) failed, then `die`s with the
  generic line "one or more policy file(s) in $POLICY_DIR
  failed signature verification". The recover-step prints to
  stdout but the `die` message doesn't repeat it — an operator
  who's only looking at the final error line has to scroll back
  through the script's output to find which files. Replace the
  `|| true` with a `tee`-and-capture so the `die` message can
  embed the first failing file in the message itself. **(M2-002)**

### Scope 2 — v2 manifest helpers

SDD-006 v2 added `module_record_file`, `module_render_files`,
and `module_clear_manifest` to `packaging/lib/module-lib.sh`.
Modules opt in by setting
`SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` in their `lib.sh`
shim. Survey of current adoption:

```sh
$ grep -l "SELFDEF_MODULE_LIB_VERSION_REQUIRED=2" modules/*/install/lib.sh
modules/agent-guard/install/lib.sh
```

Only `agent-guard` opts in. The other seven script-based modules
declare `=1` (or leave it unset, which defaults to 1) and
hand-curate their uninstall lists:

- `modules/bridge-l2/install/uninstall.sh:16,50` — hard-codes
  `NFT_RULESET_PATH="/etc/nftables.d/selfdef-bridge.conf"` and
  `rm -f` of the same. If `apply.sh` ever splits the ruleset
  across multiple files or moves the directory, `uninstall.sh`
  silently leaks the new ones. **(M2-003)**
- `modules/observability/install/uninstall.sh:20-35` — `SCRAPE_DST`
  and `DASHBOARD_DST` are duplicated from `apply.sh`'s defaults
  with the same per-profile override pattern. Two views of "what
  did we write?". **(M2-004)**
- `modules/tetragon/install/uninstall.sh:22-28` — same drift
  shape: hard-codes the four paths (config, policy_dir,
  event_log, service_unit) with conditional config overrides.
  The signing knob added a fifth (the public-key path) but
  uninstall doesn't touch it; that's correct (operator owns
  the key), but the duplication pattern is fragile.
  **(M2-005)**

The fix shape is the same for all three: opt into v2, replace
the hand-curated paths with `module_render_files` (read the
manifest), and remove the duplication. Defer to a follow-up PR
that batches the seven modules together; each module's
migration is small (~20 lines) but they don't cluster
otherwise.

### Scope 3 — vpn-bridge per-profile instanced

The CLI side (`crates/selfdef-cli/src/modules.rs::resolve_active`)
is correct: refuses `vpn-bridge#<inst>` when the chosen profile
sets `instanced = false`, falls back to the manifest's default
profile when the per-instance config doesn't override, and
skips silently with `continue` if the resolved profile name is
empty (no manifest default + no config override). Three tests
(`profile_instanced_*` in `crates/selfdef-cli/src/modules.rs`)
cover the matrix.

The bash side (`modules/vpn-bridge/install/profiles/relay-via-server.sh`)
correctly reads `$SELFDEF_INSTANCE_ID` for per-instance defaults
(interface, nftables table name, state path). One
defense-in-depth gap:

- `modules/vpn-bridge/install/profiles/relay-via-server.sh:23` —
  `INST="${SELFDEF_INSTANCE_ID:-}"` is interpolated directly
  into the nftables table name (`selfdef_vpn_bridge_${INST}`)
  and the per-instance config path
  (`/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf`) without
  going through the `safe_name` validator that
  `modules/vpn-bridge/install/lib.sh:33-36` provides. Operator-
  controlled strings only, so this is defense-in-depth, not a
  bug — but if a future config-reload path lets the daemon
  inject instance IDs (e.g. from an API endpoint), the gap
  would matter. `safe_name "$INST"` at the top of
  `_relay_inst_defaults` is the obvious place. **(M2-006)**

### Scope 4 — `detect-host` exception

- `modules/detect-host/module.toml` declares
  `[install] kind = "debian-package"` and ships no install
  scripts. The flag is documented in the manifest's source
  comment as "no shell scripts to run" — the install of this
  module is the install of `selfdef-daemon` itself. This is the
  only module using `kind = "debian-package"`; every other
  module uses `kind = "script"` (or implicitly the script
  pattern). The `selfdefctl modules apply` dispatcher handles
  the two cases differently (the debian-package branch checks
  `dpkg -l selfdef-daemon` and exits clean if present). Worth
  documenting the contract somewhere central — either in
  `docs/dev/modules.md` (which doesn't cover the
  `debian-package` kind today) or as a brief note in
  `detect-host`'s README pointing at the contract. **(M2-001)**

### Scope 5 — per-module README doc gaps

- Zero modules' READMEs mention `SELFDEF_MODULE_LIB_VERSION_REQUIRED`
  or the v2 helpers (`module_record_file`,
  `module_render_files`, `module_clear_manifest`). `agent-guard`
  is the one module that uses them, but its README doesn't
  say so. Without that pointer, a new contributor reading any
  module's `lib.sh` shim sees `SELFDEF_MODULE_LIB_VERSION_REQUIRED=1`
  and won't realise there's a v2 they could opt into. Either
  add a one-line "Built against module-lib v1" / "v2" line to
  each README, or document the contract once in
  `docs/dev/module-helpers.md` and have READMEs link to it.
  **(M2-007)**

## Triage

Every observation is **nice**. The cluster shape mirrors the
crate-explorer cluster: most are documentation / drift-risk
mitigation; one (M2-006) is a small defense-in-depth tightening.

Closing-PR candidates:

- **v2-helpers migration** — M2-003 + M2-004 + M2-005. One PR
  opts the three callout modules (bridge-l2, observability,
  tetragon) into v2 and replaces hand-curated uninstall paths
  with `module_render_files`. Should batch the other four
  (integrity-sentinel, polarproxy, suricata, vpn-bridge) in the
  same PR for uniformity.
- **vpn-bridge instance-ID validation** — M2-006. Tiny patch
  (one line + a test).
- **doc-surface** — M2-001 + M2-002 + M2-007. Three docs touches
  (per-module READMEs, `docs/dev/modules.md`, the tetragon
  signing-failure error message).

All 6 entries land in the Phase 2 findings ledger as
F-2027-022 through F-2027-027 with `nice` severity and an
"implement" or "doc" next-phase.
