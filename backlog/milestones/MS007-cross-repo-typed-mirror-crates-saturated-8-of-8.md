# MS007 — 8/8 SATURATED cross-repo typed-mirror crates — auth-tier / bashrc-install / history-sink / dashboard-manifest / surface-manifest / ux-checklist / audit-manifest / doc-manifest

> Parent: `backlog/milestones/INDEX.md` row MS007.
> Source: existing 8 crates `crates/selfdef-{auth-tier,bashrc-install,history-sink,dashboard-manifest,surface-manifest,ux-checklist,audit-manifest,doc-manifest}` + meta-crate `crates/selfdef-cross-repo-saturation` + SDD-038 cross-repo binding doctrine + sovereign-os tests/lint/test_cross_repo_saturation_invariant.py (R473).

## Epics (E0071–E0080)

| Epic ID | Phrase | Source |
|---|---|---|
| E0071 | Cross-repo binding doctrine — selfdef-side typed-mirror per sovereign-os compliance instrument | SDD-038 |
| E0072 | SD-R-AUTH-TIER-1 — `selfdef-auth-tier` typed 6-variant `AuthTier` enum mirroring sovereign-os R450 (E11.M7) | `crates/selfdef-auth-tier` + R450 |
| E0073 | SD-R-BASHRC-1 — `selfdef-bashrc-install` operator-facing bashrc installer mirroring sovereign-os R447 (E11.M6) | `crates/selfdef-bashrc-install` + R447 |
| E0074 | SD-R-EVENT-LOG-1 — `selfdef-history-sink` HistoryEvent JSONL emit mirroring sovereign-os R448 (E11.M5) | `crates/selfdef-history-sink` + R448 |
| E0075 | SD-R-DASHBOARD-MANIFEST-1 — `selfdef-dashboard-manifest` DashboardSpec mirroring sovereign-os R452 (E11.M2) | `crates/selfdef-dashboard-manifest` + R452 |
| E0076 | SD-R-MULTI-SURFACE-AUDIT-1 — `selfdef-surface-manifest` 8-surface taxonomy mirroring sovereign-os R453 (E11.M3) | `crates/selfdef-surface-manifest` + R453 |
| E0077 | SD-R-UX-CHECKLIST-1 — `selfdef-ux-checklist` 6-dimension UxChecklist mirroring sovereign-os R457 (E11.M10) | `crates/selfdef-ux-checklist` + R457 |
| E0078 | SD-R-AUDIT-1 — `selfdef-audit-manifest` 8-pattern AuditManifest mirroring sovereign-os R456 (E11.M11) | `crates/selfdef-audit-manifest` + R456 |
| E0079 | SD-R-DOC-MANIFEST-1 — `selfdef-doc-manifest` 6-kind DocManifest mirroring sovereign-os R454 (E11.M1) | `crates/selfdef-doc-manifest` + R454 |
| E0080 | Saturation invariant — `selfdef-cross-repo-saturation` meta-crate depending on all 8 + 10 integration tests; sister to sovereign-os R473 test_cross_repo_saturation_invariant.py | `crates/selfdef-cross-repo-saturation` + sovereign-os R473 |

## Modules (M00161–M00186)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00161 | Typed-mirror crate trait — public-API surface stability per SDD-038 | SDD-038 + each crate | E0071 |
| M00162 | Typed-mirror crate convention — `crates/selfdef-<name>/` + Cargo.toml + src/lib.rs + tests/ + README.md | repo | E0071 |
| M00163 | SD-R-XXX binding ID — canonical bridge layer (separate from this catalog's E/M/F/R numbering) | SDD-038 | E0071 |
| M00164 | AuthTier 6-variant enum — no-auth / basic / advanced / social / enterprise / network-level | `crates/selfdef-auth-tier` + R450 | E0072 |
| M00165 | AuthTier per-variant API — `level()` / `requires()` / `provides()` / `discovery_shape()` / `operator_named()` / `typical_use()` / `operator_named_warning()` | `crates/selfdef-auth-tier` | E0072 |
| M00166 | AuthTier serde — kebab-case + rejects unknown variants | `crates/selfdef-auth-tier` | E0072 |
| M00167 | AuthTier `AUTH_TIERS` const — re-exports `TIER_NAMES` for dashboard-manifest crate consumption | `crates/selfdef-auth-tier` | E0072 |
| M00168 | bashrc installer harness — operator-facing `selfdefctl-bashrc-install.sh` bash script + Rust harness | `crates/selfdef-bashrc-install` + packaging/bash/ | E0073 |
| M00169 | bashrc installer aliases — 10 operator-discoverable aliases (sosctl / soshelp / sosstatus / sosmodels / soshealth / sosdoctor / sosthermal / soswatt / soshist / sosmorning) | `crates/selfdef-bashrc-install` + R447 | E0073 |
| M00170 | bashrc installer completion — bash completion covering 25+ top-level subcommands | `crates/selfdef-bashrc-install` + R447 | E0073 |
| M00171 | HistoryEvent schema — operator-named fields for `/var/log/sovereign-os/modules.jsonl` JSONL sink | `crates/selfdef-history-sink` + R448 | E0074 |
| M00172 | HistoryEvent emit — append-only JSONL writer with file-rotation policy | `crates/selfdef-history-sink` | E0074 |
| M00173 | DashboardSpec — typed dashboard contract (`auth_tier: AuthTier` typed field per SD-R-AUTH-TIER-1 cross-binding) | `crates/selfdef-dashboard-manifest` + R452 | E0075 |
| M00174 | DashboardSpec routing-table — per-dashboard {port, healthz_path, subpath, label, source_repo} | `crates/selfdef-dashboard-manifest` | E0075 |
| M00175 | SurfaceManifest — 8-surface §1g taxonomy (core / cli / tui / api / mcp / dashboard / webapp / service) preserving operator §1g verbatim ORDER | `crates/selfdef-surface-manifest` + R453 | E0076 |
| M00176 | SurfaceManifest SurfaceState enum — Shipped / Waived / Planned + Waived-requires-reason rule | `crates/selfdef-surface-manifest` | E0076 |
| M00177 | UxChecklist 6-dimension — action-budget / discoverable / recoverable / next-step / operator-named / readable-30s | `crates/selfdef-ux-checklist` + R457 | E0077 |
| M00178 | UxChecklist DimensionState enum — Pass / Fail / NA + Fail-OR-NA-requires-reason rule | `crates/selfdef-ux-checklist` | E0077 |
| M00179 | AuditManifest 8-pattern — todo-no-anchor / empty-stub / skipped-no-followup / surface-gap / doc-gap / mandate-todo / minimize-phrase / partial-status | `crates/selfdef-audit-manifest` + R456 | E0078 |
| M00180 | AuditManifest count-gt-0-requires-note discipline | `crates/selfdef-audit-manifest` | E0078 |
| M00181 | DocManifest 6-kind — readme / sdd / helptext / metric-inventory / mandate-row / man-page | `crates/selfdef-doc-manifest` + R454 | E0079 |
| M00182 | DocManifest DocState enum — Shipped / Waived / Planned + Shipped-requires-path + Waived-requires-reason | `crates/selfdef-doc-manifest` | E0079 |
| M00183 | Saturation meta-crate — `selfdef-cross-repo-saturation` depending on all 8 typed-mirror crates | `crates/selfdef-cross-repo-saturation` | E0080 |
| M00184 | Saturation 10-test set — per-binding integration test (8) + 8/8-saturation invariant test + cross-binding round-trip test | `crates/selfdef-cross-repo-saturation/tests/` | E0080 |
| M00185 | Saturation lint — sovereign-os `tests/lint/test_cross_repo_saturation_invariant.py` (R473) fails on any new sovereign-os instrument without selfdef-side mirror | sovereign-os R473 + selfdef SD-R-SATURATION-1 | E0080 |
| M00186 | Saturation registry table — 8-row table mapping `sovereign-os consumer` ↔ `cross-repo binding ID` ↔ `selfdef-side crate` (canonical at `selfdef/backlog/README.md` Cross-repo binding table) | `backlog/README.md` + `docs/sdd/038-cross-repo-binding-doctrine.md` | E0080 |

## Features (F00721–F00840)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00721 | Cross-repo binding doctrine — selfdef-side typed-mirror crate per sovereign-os compliance instrument | SDD-038 | E0071 | composite | false |
| F00722 | Cross-repo binding doctrine — every new sovereign-os instrument requires its typed selfdef-side mirror in the same arc | SDD-038 | E0071 | composite | false |
| F00723 | Cross-repo binding doctrine — SD-R-XXX binding IDs preserved separately from MS-prefixed catalog IDs | SDD-038 | M00163 | composite | false |
| F00724 | Cross-repo binding doctrine — failure of saturation invariant blocks PR at CI (R473) | sovereign-os R473 | M00185 | composite | false |
| F00725 | Typed-mirror crate convention — `crates/selfdef-<name>/Cargo.toml` declares `[package.metadata.selfdef.binding] sd_r_id = "SD-R-...-1"` | M00162 | M00162 | composite | true |
| F00726 | Typed-mirror crate convention — every crate has `src/lib.rs` exposing typed mirror surface | M00162 | M00162 | composite | false |
| F00727 | Typed-mirror crate convention — every crate has `tests/` directory with integration test mirroring sovereign-os R### test | M00162 | M00162 | composite | false |
| F00728 | Typed-mirror crate convention — every crate has README.md citing sovereign-os R-anchor + cross-repo binding ID | M00162 | M00162 | composite | true |
| F00729 | AuthTier variant — `no-auth` (level=0) | R450 + M00164 | M00164 | composite | false |
| F00730 | AuthTier variant — `basic` (level=1) | R450 + M00164 | M00164 | composite | false |
| F00731 | AuthTier variant — `advanced` (level=2) | R450 + M00164 | M00164 | composite | false |
| F00732 | AuthTier variant — `social` (level=3) | R450 + M00164 | M00164 | composite | false |
| F00733 | AuthTier variant — `enterprise` (level=4) | R450 + M00164 | M00164 | composite | false |
| F00734 | AuthTier variant — `network-level` (level=5) | R450 + M00164 | M00164 | composite | false |
| F00735 | AuthTier API — `level() -> u8` | M00165 | M00165 | composite | false |
| F00736 | AuthTier API — `requires() -> &'static [&'static str]` | M00165 | M00165 | composite | false |
| F00737 | AuthTier API — `provides() -> &'static str` | M00165 | M00165 | composite | false |
| F00738 | AuthTier API — `discovery_shape() -> &'static str` | M00165 | M00165 | composite | false |
| F00739 | AuthTier API — `operator_named() -> bool` | M00165 | M00165 | composite | false |
| F00740 | AuthTier API — `typical_use() -> &'static str` | M00165 | M00165 | composite | false |
| F00741 | AuthTier API — `operator_named_warning() -> &'static str` | M00165 | M00165 | composite | false |
| F00742 | AuthTier serde — kebab-case representation | M00166 | M00166 | composite | false |
| F00743 | AuthTier serde — rejects unknown variants (no silent default) | M00166 | M00166 | composite | false |
| F00744 | AuthTier `AUTH_TIERS` const — re-exports `TIER_NAMES` for dashboard-manifest | M00167 | M00167 | composite | false |
| F00745 | bashrc installer — `selfdefctl-bashrc-install.sh` bash script at `packaging/bash/` | M00168 | M00168 | composite | false |
| F00746 | bashrc installer Rust harness — 14 integration tests (R447) | M00168 | M00168 | composite | false |
| F00747 | bashrc alias — `sosctl` | M00169 | M00169 | composite | true |
| F00748 | bashrc alias — `soshelp` | M00169 | M00169 | composite | true |
| F00749 | bashrc alias — `sosstatus` | M00169 | M00169 | composite | true |
| F00750 | bashrc alias — `sosmodels` | M00169 | M00169 | composite | true |
| F00751 | bashrc alias — `soshealth` | M00169 | M00169 | composite | true |
| F00752 | bashrc alias — `sosdoctor` | M00169 | M00169 | composite | true |
| F00753 | bashrc alias — `sosthermal` | M00169 | M00169 | composite | true |
| F00754 | bashrc alias — `soswatt` | M00169 | M00169 | composite | true |
| F00755 | bashrc alias — `soshist` | M00169 | M00169 | composite | true |
| F00756 | bashrc alias — `sosmorning` | M00169 | M00169 | composite | true |
| F00757 | bashrc completion — 25+ top-level subcommand completion | M00170 | M00170 | composite | false |
| F00758 | bashrc completion — 2nd-level completion (profiles / whitelabel / perimeter / models / morning-brief / bashrc) | M00170 | M00170 | composite | true |
| F00759 | bashrc installer sentinel — bounded begin/end markers for idempotent install | M00168 | M00168 | composite | false |
| F00760 | bashrc installer DRY_RUN — `SELFDEF_BASHRC_INSTALL_DRY_RUN` env-toggleable | M00168 | M00168 | profile | true |
| F00761 | bashrc installer zsh-compat — `SELFDEF_BASHRC_PATH` env override | M00168 | M00168 | profile | true |
| F00762 | HistoryEvent schema — append-only JSONL at `/var/log/sovereign-os/modules.jsonl` | M00171 | M00171 | composite | false |
| F00763 | HistoryEvent emit — `emit()` function appending one JSONL line per event | M00172 | M00172 | composite | false |
| F00764 | HistoryEvent file-rotation — operator-tunable max-size or max-age | M00172 | M00172 | profile | true |
| F00765 | DashboardSpec typed `auth_tier: AuthTier` field (refactored from String per pre-Phase-7 cleanup) | M00173 | M00173 | composite | false |
| F00766 | DashboardSpec routing-table field — `port` | M00174 | M00174 | data_model | false |
| F00767 | DashboardSpec routing-table field — `healthz_path` | M00174 | M00174 | data_model | false |
| F00768 | DashboardSpec routing-table field — `subpath` | M00174 | M00174 | data_model | false |
| F00769 | DashboardSpec routing-table field — `label` | M00174 | M00174 | data_model | false |
| F00770 | DashboardSpec routing-table field — `source_repo` | M00174 | M00174 | data_model | false |
| F00771 | SurfaceManifest §1g surface — `core` (position 1) | M00175 | M00175 | composite | false |
| F00772 | SurfaceManifest §1g surface — `cli` (position 2) | M00175 | M00175 | composite | false |
| F00773 | SurfaceManifest §1g surface — `tui` (position 3) | M00175 | M00175 | composite | false |
| F00774 | SurfaceManifest §1g surface — `api` (position 4) | M00175 | M00175 | composite | false |
| F00775 | SurfaceManifest §1g surface — `mcp` (position 5) | M00175 | M00175 | composite | false |
| F00776 | SurfaceManifest §1g surface — `dashboard` (position 6) | M00175 | M00175 | composite | false |
| F00777 | SurfaceManifest §1g surface — `webapp` (position 7) | M00175 | M00175 | composite | false |
| F00778 | SurfaceManifest §1g surface — `service` (position 8) | M00175 | M00175 | composite | false |
| F00779 | SurfaceManifest `§1g_position` field — preserves operator §1g verbatim ORDER | M00175 | M00175 | data_model | false |
| F00780 | SurfaceManifest SurfaceState — `Shipped` (canonical) | M00176 | M00176 | composite | false |
| F00781 | SurfaceManifest SurfaceState — `Waived` (with `reason` required) | M00176 | M00176 | composite | true |
| F00782 | SurfaceManifest SurfaceState — `Planned` (declared but not yet shipped) | M00176 | M00176 | composite | true |
| F00783 | UxChecklist dimension — `action-budget` (operator reaches goal in N or fewer actions) | M00177 | M00177 | composite | false |
| F00784 | UxChecklist dimension — `discoverable` (surface enumerable from sovereign-osctl help) | M00177 | M00177 | composite | false |
| F00785 | UxChecklist dimension — `recoverable` (destructive ops preview-before-apply triple-gate) | M00177 | M00177 | composite | false |
| F00786 | UxChecklist dimension — `next-step` (verbs surface `next_action` / `next:` / `Run:` hints) | M00177 | M00177 | composite | false |
| F00787 | UxChecklist dimension — `operator-named` (operator §1g/§1h verbatim preserved in surface) | M00177 | M00177 | composite | false |
| F00788 | UxChecklist dimension — `readable-30s` (help text ≤ 500 chars dense + ≥ 3 lines) | M00177 | M00177 | composite | false |
| F00789 | UxChecklist DimensionState — `Pass` | M00178 | M00178 | composite | false |
| F00790 | UxChecklist DimensionState — `Fail` (with `reason` required) | M00178 | M00178 | composite | true |
| F00791 | UxChecklist DimensionState — `NA` (with `reason` required) | M00178 | M00178 | composite | true |
| F00792 | AuditManifest pattern — `todo-no-anchor` (TODO/FIXME without R-number/SDD anchor) | M00179 | M00179 | composite | false |
| F00793 | AuditManifest pattern — `empty-stub` (Python pass-only function body) | M00179 | M00179 | composite | false |
| F00794 | AuditManifest pattern — `skipped-no-followup` (`skipped`/`deferred`/`stub` without ticket ref) | M00179 | M00179 | composite | false |
| F00795 | AuditManifest pattern — `surface-gap` (module below R453 surface-map threshold) | M00179 | M00179 | composite | false |
| F00796 | AuditManifest pattern — `doc-gap` (module below R454 doc-coverage threshold) | M00179 | M00179 | composite | false |
| F00797 | AuditManifest pattern — `mandate-todo` (mandate row still TODO) | M00179 | M00179 | composite | false |
| F00798 | AuditManifest pattern — `minimize-phrase` (code/comment contains `for now`/`minimize`/etc) | M00179 | M00179 | composite | false |
| F00799 | AuditManifest pattern — `partial-status` (mandate row status=`partial` or `in-flight`) | M00179 | M00179 | composite | false |
| F00800 | AuditManifest count-gt-0-requires-note rule — operator-readable note per non-zero count | M00180 | M00180 | composite | false |
| F00801 | DocManifest kind — `readme` | M00181 | M00181 | composite | false |
| F00802 | DocManifest kind — `sdd` | M00181 | M00181 | composite | false |
| F00803 | DocManifest kind — `helptext` | M00181 | M00181 | composite | false |
| F00804 | DocManifest kind — `metric-inventory` | M00181 | M00181 | composite | false |
| F00805 | DocManifest kind — `mandate-row` | M00181 | M00181 | composite | false |
| F00806 | DocManifest kind — `man-page` | M00181 | M00181 | composite | false |
| F00807 | DocManifest DocState — `Shipped` (with `path` required) | M00182 | M00182 | composite | false |
| F00808 | DocManifest DocState — `Waived` (with `reason` required) | M00182 | M00182 | composite | true |
| F00809 | DocManifest DocState — `Planned` (declared but not yet shipped) | M00182 | M00182 | composite | true |
| F00810 | Saturation meta-crate dependency — `selfdef-auth-tier` | M00183 | M00183 | composite | false |
| F00811 | Saturation meta-crate dependency — `selfdef-bashrc-install` | M00183 | M00183 | composite | false |
| F00812 | Saturation meta-crate dependency — `selfdef-history-sink` | M00183 | M00183 | composite | false |
| F00813 | Saturation meta-crate dependency — `selfdef-dashboard-manifest` | M00183 | M00183 | composite | false |
| F00814 | Saturation meta-crate dependency — `selfdef-surface-manifest` | M00183 | M00183 | composite | false |
| F00815 | Saturation meta-crate dependency — `selfdef-ux-checklist` | M00183 | M00183 | composite | false |
| F00816 | Saturation meta-crate dependency — `selfdef-audit-manifest` | M00183 | M00183 | composite | false |
| F00817 | Saturation meta-crate dependency — `selfdef-doc-manifest` | M00183 | M00183 | composite | false |
| F00818 | Saturation 10-integration-test — per-binding 1 test (8) + 8/8 saturation invariant test + cross-binding round-trip test | M00184 | M00184 | composite | false |
| F00819 | Saturation lint at sovereign-os — `tests/lint/test_cross_repo_saturation_invariant.py` (R473) | sovereign-os R473 | M00185 | composite | false |
| F00820 | Saturation registry table — 8-row mapping at `backlog/README.md` + `docs/sdd/038-cross-repo-binding-doctrine.md` | M00186 | M00186 | composite | false |
| F00821 | Cross-repo binding workflow — when new sovereign-os instrument added, selfdef-side mirror authored in same arc | SDD-038 | E0080 | composite | false |
| F00822 | Cross-repo binding workflow — saturation invariant test fails at sovereign-os CI on missing selfdef-side mirror | sovereign-os R473 | E0080 | composite | false |
| F00823 | Cross-repo binding workflow — README cross-repo binding table updated in same arc | `README.md` | E0080 | composite | true |
| F00824 | Cross-repo binding workflow — operator-readable PR review checklist | `docs/contributing/cross-repo-binding-checklist.md` | E0080 | composite | true |
| F00825 | API `GET /v1/cross-repo/bindings` (lists 8 typed-mirror crates + saturation status) | `crates/selfdef-api` | E0080 | api_endpoint | true |
| F00826 | API `GET /v1/cross-repo/saturation` (returns SATURATED / DEGRADED with operator-readable diff) | `crates/selfdef-api` | M00185 | api_endpoint | true |
| F00827 | CLI `selfdefctl cross-repo list` (lists 8 typed-mirror bindings + saturation status) | `crates/selfdef-cli` | E0080 | cli_verb | true |
| F00828 | CLI `selfdefctl cross-repo verify` (runs saturation 10-test integration locally) | `crates/selfdef-cli` | M00184 | cli_verb | true |
| F00829 | CLI `selfdefctl cross-repo diff` (compares sovereign-os instrument set vs selfdef-side mirror set) | `crates/selfdef-cli` | M00185 | cli_verb | true |
| F00830 | Dashboard — Cross-repo binding overview (8 typed-mirror crates with their SD-R-XXX IDs + sovereign-os R-anchor + last-test-run) | `dashboard/` | E0080 | dashboard | true |
| F00831 | Dashboard — Saturation status badge (SATURATED / DEGRADED) on every selfdef-side affordance | `dashboard/` | M00185 | dashboard | true |
| F00832 | Metric `selfdef_cross_repo_binding_count` (= 8 when SATURATED) | `crates/selfdef-cross-repo-saturation` | M00183 | observability_metric | true |
| F00833 | Metric `selfdef_cross_repo_saturation_test_total{outcome}` | `crates/selfdef-cross-repo-saturation` | M00184 | observability_metric | true |
| F00834 | Test — typed-mirror crate API stability across version bumps | tests/ | M00161 | test | false |
| F00835 | Test — AuthTier serde round-trip for all 6 variants | tests/ | F00742 | test | false |
| F00836 | Test — DashboardSpec rejects unknown auth_tier string (typed enum gate) | tests/ | M00173 | test | false |
| F00837 | Test — SurfaceManifest §1g position preserves operator ORDER | tests/ | F00779 | test | false |
| F00838 | Test — UxChecklist Fail/NA requires reason (enforced by enum) | tests/ | M00178 | test | false |
| F00839 | Test — AuditManifest non-zero count requires note (lint-time) | tests/ | M00180 | test | false |
| F00840 | Test — Saturation invariant fails when any of 8 bindings is missing | tests/ | M00185 | test | false |

## Requirements (R01441–R01680)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R01441 | Selfdef has exactly 8 typed-mirror cross-repo binding crates | repo `crates/selfdef-{auth-tier,bashrc-install,history-sink,dashboard-manifest,surface-manifest,ux-checklist,audit-manifest,doc-manifest}` | E0071 | non-negotiable | false | 10 |
| R01442 | Each typed-mirror crate has stable public API per SDD-038 | SDD-038 | M00161 | non-negotiable | false | 10 |
| R01443 | Each typed-mirror crate lives at `crates/selfdef-<name>/` | repo | M00162 | non-negotiable | false | 10 |
| R01444 | Each typed-mirror crate has Cargo.toml | repo | M00162 | non-negotiable | false | 10 |
| R01445 | Each typed-mirror crate has src/lib.rs exposing typed mirror surface | repo | F00726 | non-negotiable | false | 10 |
| R01446 | Each typed-mirror crate has tests/ directory with integration test mirroring sovereign-os R### test | repo | F00727 | non-negotiable | false | 10 |
| R01447 | Each typed-mirror crate has README.md citing sovereign-os R-anchor + cross-repo binding ID | repo | F00728 | non-negotiable | true | 10 |
| R01448 | SD-R-XXX cross-repo binding IDs are the canonical bridge layer (SEPARATE from MS-catalog E/M/F/R numbering) | SDD-038 | M00163 | non-negotiable | false | 10 |
| R01449 | SD-R-AUTH-TIER-1 — `selfdef-auth-tier` typed `AuthTier` enum | `crates/selfdef-auth-tier` | E0072 | non-negotiable | false | 10 |
| R01450 | AuthTier 6-variant enum — `no-auth` / `basic` / `advanced` / `social` / `enterprise` / `network-level` | R450 | M00164 | non-negotiable | false | 10 |
| R01451 | AuthTier variant `no-auth` level=0 | M00164 | F00729 | non-negotiable | false | 10 |
| R01452 | AuthTier variant `basic` level=1 | M00164 | F00730 | non-negotiable | false | 10 |
| R01453 | AuthTier variant `advanced` level=2 | M00164 | F00731 | non-negotiable | false | 10 |
| R01454 | AuthTier variant `social` level=3 | M00164 | F00732 | non-negotiable | false | 10 |
| R01455 | AuthTier variant `enterprise` level=4 | M00164 | F00733 | non-negotiable | false | 10 |
| R01456 | AuthTier variant `network-level` level=5 | M00164 | F00734 | non-negotiable | false | 10 |
| R01457 | AuthTier API `level()` returns u8 monotonic | M00165 | F00735 | non-negotiable | false | 10 |
| R01458 | AuthTier API `requires()` returns prerequisite tier names | M00165 | F00736 | non-negotiable | false | 10 |
| R01459 | AuthTier API `provides()` returns operator-readable capability summary | M00165 | F00737 | non-negotiable | false | 10 |
| R01460 | AuthTier API `discovery_shape()` returns operator-readable discovery hint | M00165 | F00738 | non-negotiable | false | 10 |
| R01461 | AuthTier API `operator_named()` returns whether tier is operator-§1g-named | M00165 | F00739 | non-negotiable | false | 10 |
| R01462 | AuthTier API `typical_use()` returns operator-readable use-case | M00165 | F00740 | non-negotiable | false | 10 |
| R01463 | AuthTier API `operator_named_warning()` returns operator-readable warning per tier | M00165 | F00741 | non-negotiable | false | 10 |
| R01464 | AuthTier serde — kebab-case representation | M00166 | F00742 | non-negotiable | false | 10 |
| R01465 | AuthTier serde — rejects unknown variants pre-validate (no silent default) | M00166 | F00743 | non-negotiable | false | 10 |
| R01466 | AuthTier `AUTH_TIERS` const re-exports `TIER_NAMES` for dashboard-manifest cross-binding | M00167 | F00744 | non-negotiable | false | 10 |
| R01467 | SD-R-BASHRC-1 — `selfdef-bashrc-install` operator-facing bashrc installer | `crates/selfdef-bashrc-install` | E0073 | non-negotiable | true | 10 |
| R01468 | bashrc installer script lives at `packaging/bash/selfdefctl-bashrc-install.sh` | M00168 | F00745 | non-negotiable | false | 10 |
| R01469 | bashrc installer Rust harness has 14 integration tests (R447) | M00168 | F00746 | non-negotiable | false | 10 |
| R01470 | bashrc alias — `sosctl` | R447 | F00747 | non-negotiable | true | 10 |
| R01471 | bashrc alias — `soshelp` | R447 | F00748 | non-negotiable | true | 10 |
| R01472 | bashrc alias — `sosstatus` | R447 | F00749 | non-negotiable | true | 10 |
| R01473 | bashrc alias — `sosmodels` | R447 | F00750 | non-negotiable | true | 10 |
| R01474 | bashrc alias — `soshealth` | R447 | F00751 | non-negotiable | true | 10 |
| R01475 | bashrc alias — `sosdoctor` | R447 | F00752 | non-negotiable | true | 10 |
| R01476 | bashrc alias — `sosthermal` | R447 | F00753 | non-negotiable | true | 10 |
| R01477 | bashrc alias — `soswatt` | R447 | F00754 | non-negotiable | true | 10 |
| R01478 | bashrc alias — `soshist` | R447 | F00755 | non-negotiable | true | 10 |
| R01479 | bashrc alias — `sosmorning` | R447 | F00756 | non-negotiable | true | 10 |
| R01480 | bashrc completion — 25+ top-level subcommand completion | R447 | F00757 | non-negotiable | false | 10 |
| R01481 | bashrc completion — 2nd-level completion (profiles / whitelabel / perimeter / models / morning-brief / bashrc) | R447 | F00758 | non-negotiable | true | 10 |
| R01482 | bashrc installer sentinel — bounded begin/end markers for idempotent install | R447 | F00759 | non-negotiable | false | 10 |
| R01483 | bashrc installer DRY_RUN — `SELFDEF_BASHRC_INSTALL_DRY_RUN` env-toggleable | R447 | F00760 | non-negotiable | true | 10 |
| R01484 | bashrc installer zsh-compat — `SELFDEF_BASHRC_PATH` env override | R447 | F00761 | non-negotiable | true | 10 |
| R01485 | SD-R-EVENT-LOG-1 — `selfdef-history-sink` HistoryEvent JSONL emit | `crates/selfdef-history-sink` | E0074 | non-negotiable | true | 10 |
| R01486 | HistoryEvent sink path — `/var/log/sovereign-os/modules.jsonl` (per R448) | R448 | F00762 | non-negotiable | true | 10 |
| R01487 | HistoryEvent emit — append-only JSONL writer | M00172 | F00763 | non-negotiable | false | 10 |
| R01488 | HistoryEvent file-rotation policy operator-tunable | M00172 | F00764 | non-negotiable | true | 10 |
| R01489 | SD-R-DASHBOARD-MANIFEST-1 — `selfdef-dashboard-manifest` typed DashboardSpec | `crates/selfdef-dashboard-manifest` | E0075 | non-negotiable | false | 10 |
| R01490 | DashboardSpec.auth_tier — typed `AuthTier` (NOT String) per pre-Phase-7 refactor | M00173 | F00765 | non-negotiable | false | 10 |
| R01491 | DashboardSpec.auth_tier depends on `selfdef-auth-tier` crate (cross-binding to SD-R-AUTH-TIER-1) | M00173 | F00765 | non-negotiable | false | 10 |
| R01492 | DashboardSpec routing-table field — `port` | M00174 | F00766 | non-negotiable | false | 10 |
| R01493 | DashboardSpec routing-table field — `healthz_path` | M00174 | F00767 | non-negotiable | false | 10 |
| R01494 | DashboardSpec routing-table field — `subpath` | M00174 | F00768 | non-negotiable | false | 10 |
| R01495 | DashboardSpec routing-table field — `label` | M00174 | F00769 | non-negotiable | false | 10 |
| R01496 | DashboardSpec routing-table field — `source_repo` | M00174 | F00770 | non-negotiable | false | 10 |
| R01497 | SD-R-MULTI-SURFACE-AUDIT-1 — `selfdef-surface-manifest` 8-surface §1g taxonomy | `crates/selfdef-surface-manifest` | E0076 | non-negotiable | false | 10 |
| R01498 | SurfaceManifest §1g surface — `core` (position 1) | M00175 | F00771 | non-negotiable | false | 10 |
| R01499 | SurfaceManifest §1g surface — `cli` (position 2) | M00175 | F00772 | non-negotiable | false | 10 |
| R01500 | SurfaceManifest §1g surface — `tui` (position 3) | M00175 | F00773 | non-negotiable | false | 10 |
| R01501 | SurfaceManifest §1g surface — `api` (position 4) | M00175 | F00774 | non-negotiable | false | 10 |
| R01502 | SurfaceManifest §1g surface — `mcp` (position 5) | M00175 | F00775 | non-negotiable | false | 10 |
| R01503 | SurfaceManifest §1g surface — `dashboard` (position 6) | M00175 | F00776 | non-negotiable | false | 10 |
| R01504 | SurfaceManifest §1g surface — `webapp` (position 7) | M00175 | F00777 | non-negotiable | false | 10 |
| R01505 | SurfaceManifest §1g surface — `service` (position 8) | M00175 | F00778 | non-negotiable | false | 10 |
| R01506 | SurfaceManifest `§1g_position` field preserves operator §1g verbatim ORDER | M00175 | F00779 | non-negotiable | false | 10 |
| R01507 | SurfaceManifest SurfaceState — `Shipped` | M00176 | F00780 | non-negotiable | false | 10 |
| R01508 | SurfaceManifest SurfaceState — `Waived` with `reason` required | M00176 | F00781 | non-negotiable | true | 10 |
| R01509 | SurfaceManifest SurfaceState — `Planned` declared but not yet shipped | M00176 | F00782 | non-negotiable | true | 10 |
| R01510 | SD-R-UX-CHECKLIST-1 — `selfdef-ux-checklist` 6-dimension UxChecklist | `crates/selfdef-ux-checklist` | E0077 | non-negotiable | false | 10 |
| R01511 | UxChecklist dimension — `action-budget` (operator reaches goal in N or fewer actions) | M00177 | F00783 | non-negotiable | false | 10 |
| R01512 | UxChecklist dimension — `discoverable` (surface enumerable from sovereign-osctl help) | M00177 | F00784 | non-negotiable | false | 10 |
| R01513 | UxChecklist dimension — `recoverable` (destructive ops preview-before-apply triple-gate) | M00177 | F00785 | non-negotiable | false | 10 |
| R01514 | UxChecklist dimension — `next-step` (verbs surface `next_action` / `next:` / `Run:` hints) | M00177 | F00786 | non-negotiable | false | 10 |
| R01515 | UxChecklist dimension — `operator-named` (operator §1g/§1h verbatim preserved) | M00177 | F00787 | non-negotiable | false | 10 |
| R01516 | UxChecklist dimension — `readable-30s` (help text ≤ 500 chars dense + ≥ 3 lines) | M00177 | F00788 | non-negotiable | false | 10 |
| R01517 | UxChecklist DimensionState — `Pass` | M00178 | F00789 | non-negotiable | false | 10 |
| R01518 | UxChecklist DimensionState — `Fail` with `reason` required | M00178 | F00790 | non-negotiable | true | 10 |
| R01519 | UxChecklist DimensionState — `NA` with `reason` required | M00178 | F00791 | non-negotiable | true | 10 |
| R01520 | SD-R-AUDIT-1 — `selfdef-audit-manifest` 8-pattern AuditManifest | `crates/selfdef-audit-manifest` | E0078 | non-negotiable | false | 10 |
| R01521 | AuditManifest pattern — `todo-no-anchor` | M00179 | F00792 | non-negotiable | false | 10 |
| R01522 | AuditManifest pattern — `empty-stub` | M00179 | F00793 | non-negotiable | false | 10 |
| R01523 | AuditManifest pattern — `skipped-no-followup` | M00179 | F00794 | non-negotiable | false | 10 |
| R01524 | AuditManifest pattern — `surface-gap` | M00179 | F00795 | non-negotiable | false | 10 |
| R01525 | AuditManifest pattern — `doc-gap` | M00179 | F00796 | non-negotiable | false | 10 |
| R01526 | AuditManifest pattern — `mandate-todo` | M00179 | F00797 | non-negotiable | false | 10 |
| R01527 | AuditManifest pattern — `minimize-phrase` | M00179 | F00798 | non-negotiable | false | 10 |
| R01528 | AuditManifest pattern — `partial-status` | M00179 | F00799 | non-negotiable | false | 10 |
| R01529 | AuditManifest count-gt-0-requires-note discipline enforced | M00180 | F00800 | non-negotiable | false | 10 |
| R01530 | SD-R-DOC-MANIFEST-1 — `selfdef-doc-manifest` 6-kind DocManifest | `crates/selfdef-doc-manifest` | E0079 | non-negotiable | false | 10 |
| R01531 | DocManifest kind — `readme` | M00181 | F00801 | non-negotiable | false | 10 |
| R01532 | DocManifest kind — `sdd` | M00181 | F00802 | non-negotiable | false | 10 |
| R01533 | DocManifest kind — `helptext` | M00181 | F00803 | non-negotiable | false | 10 |
| R01534 | DocManifest kind — `metric-inventory` | M00181 | F00804 | non-negotiable | false | 10 |
| R01535 | DocManifest kind — `mandate-row` | M00181 | F00805 | non-negotiable | false | 10 |
| R01536 | DocManifest kind — `man-page` | M00181 | F00806 | non-negotiable | false | 10 |
| R01537 | DocManifest DocState — `Shipped` with `path` required | M00182 | F00807 | non-negotiable | false | 10 |
| R01538 | DocManifest DocState — `Waived` with `reason` required | M00182 | F00808 | non-negotiable | true | 10 |
| R01539 | DocManifest DocState — `Planned` declared but not yet shipped | M00182 | F00809 | non-negotiable | true | 10 |
| R01540 | Saturation meta-crate `selfdef-cross-repo-saturation` exists at `crates/selfdef-cross-repo-saturation/` | repo | M00183 | non-negotiable | false | 10 |
| R01541 | Saturation meta-crate depends on all 8 typed-mirror crates | M00183 | E0080 | non-negotiable | false | 10 |
| R01542 | Saturation meta-crate has 10 integration tests | M00184 | F00818 | non-negotiable | false | 10 |
| R01543 | Saturation lint at sovereign-os — `tests/lint/test_cross_repo_saturation_invariant.py` (R473) | sovereign-os R473 | M00185 | non-negotiable | false | 10 |
| R01544 | Saturation lint fails on any new sovereign-os compliance instrument without selfdef-side mirror | sovereign-os R473 | F00822 | non-negotiable | false | 10 |
| R01545 | Saturation registry table 8-row mapping at `backlog/README.md` Cross-repo binding section | `backlog/README.md` | M00186 | non-negotiable | false | 10 |
| R01546 | Saturation registry table also at `docs/sdd/038-cross-repo-binding-doctrine.md` | `docs/sdd/038-cross-repo-binding-doctrine.md` | M00186 | non-negotiable | true | 10 |
| R01547 | Saturation status: SATURATED 8/8 as of MS007 authoring (2026-05-19) | this milestone | E0080 | non-negotiable | false | 10 |
| R01548 | Cross-repo binding workflow — when new sovereign-os instrument added, selfdef-side mirror authored in same arc | SDD-038 | F00821 | non-negotiable | false | 10 |
| R01549 | Cross-repo binding workflow — README cross-repo binding table updated in same arc | `README.md` | F00823 | non-negotiable | true | 10 |
| R01550 | API `GET /v1/cross-repo/bindings` lists 8 typed-mirror crates + saturation status | `crates/selfdef-api` | F00825 | non-negotiable | true | 10 |
| R01551 | API `GET /v1/cross-repo/saturation` returns SATURATED / DEGRADED with operator-readable diff | `crates/selfdef-api` | F00826 | non-negotiable | true | 10 |
| R01552 | CLI `selfdefctl cross-repo list` lists 8 typed-mirror bindings + saturation status | `crates/selfdef-cli` | F00827 | non-negotiable | true | 10 |
| R01553 | CLI `selfdefctl cross-repo verify` runs saturation 10-test integration locally | `crates/selfdef-cli` | F00828 | non-negotiable | true | 10 |
| R01554 | CLI `selfdefctl cross-repo diff` compares sovereign-os instrument set vs selfdef-side mirror set | `crates/selfdef-cli` | F00829 | non-negotiable | true | 10 |
| R01555 | Dashboard — Cross-repo binding overview (8 typed-mirror crates with SD-R-XXX IDs + sovereign-os R-anchor + last-test-run) | `dashboard/` | F00830 | non-negotiable | true | 10 |
| R01556 | Dashboard — Saturation status badge (SATURATED / DEGRADED) on every selfdef-side affordance | `dashboard/` | F00831 | non-negotiable | true | 10 |
| R01557 | Metric `selfdef_cross_repo_binding_count` (= 8 when SATURATED) | `crates/selfdef-cross-repo-saturation` | F00832 | non-negotiable | true | 10 |
| R01558 | Metric `selfdef_cross_repo_saturation_test_total{outcome}` | `crates/selfdef-cross-repo-saturation` | F00833 | non-negotiable | true | 10 |
| R01559 | Test — typed-mirror crate API stability across version bumps | tests/ | F00834 | non-negotiable | false | 10 |
| R01560 | Test — AuthTier serde round-trip for all 6 variants | tests/ | F00835 | non-negotiable | false | 10 |
| R01561 | Test — DashboardSpec rejects unknown auth_tier string (typed enum gate) | tests/ | F00836 | non-negotiable | false | 10 |
| R01562 | Test — SurfaceManifest §1g position preserves operator ORDER | tests/ | F00837 | non-negotiable | false | 10 |
| R01563 | Test — UxChecklist Fail/NA requires reason (enforced by enum) | tests/ | F00838 | non-negotiable | false | 10 |
| R01564 | Test — AuditManifest non-zero count requires note (lint-time) | tests/ | F00839 | non-negotiable | false | 10 |
| R01565 | Test — Saturation invariant fails when any of 8 bindings is missing | tests/ | F00840 | non-negotiable | false | 10 |
| R01566 | Anti-pattern — Selfdef NEVER imports sovereign-os crate code directly (only via typed-mirror) | architecture | E0071 | non-negotiable | false | 10 |
| R01567 | Anti-pattern — Sovereign-os NEVER imports selfdef-integration crate code directly (only via typed-mirror) | architecture | E0071 | non-negotiable | false | 10 |
| R01568 | Anti-pattern — Typed-mirror crate NEVER drifts from sovereign-os instrument's canonical contract | SDD-038 | M00161 | non-negotiable | false | 10 |
| R01569 | Anti-pattern — Saturation invariant NEVER silently degrades (always operator-visible) | M00185 | F00822 | non-negotiable | false | 10 |
| R01570 | Anti-pattern — Cross-repo binding ID NEVER reassigned (operator-stated SD-R-XXX IDs are stable) | SDD-038 | M00163 | non-negotiable | false | 10 |
| R01571 | Anti-pattern — Typed-mirror crate NEVER changes public API without operator-confirmed version bump | M00161 | F00834 | non-negotiable | false | 10 |
| R01572 | Anti-pattern — Saturation registry table NEVER edited outside the same PR adding the new binding | M00186 | F00821 | non-negotiable | false | 10 |
| R01573 | Anti-pattern — Cross-repo binding workflow NEVER skips operator-readable PR review checklist | F00824 | F00824 | non-negotiable | false | 10 |
| R01574 | Documentation — SDD-038 cross-repo binding doctrine canonical at `docs/sdd/038-cross-repo-binding-doctrine.md` | repo | E0080 | non-negotiable | false | 10 |
| R01575 | Documentation — Each typed-mirror crate README cites sovereign-os R-anchor + cross-repo binding ID | F00728 | F00728 | non-negotiable | true | 10 |
| R01576 | Documentation — Cross-repo binding table maintained at `backlog/README.md` + `selfdef/README.md` cross-repo section | repo | M00186 | non-negotiable | true | 10 |
| R01577 | Documentation — Operator-facing PR review checklist at `docs/contributing/cross-repo-binding-checklist.md` | F00824 | F00824 | non-negotiable | true | 10 |
| R01578 | Documentation — Saturation invariant test referenced from both `selfdef/crates/selfdef-cross-repo-saturation/tests/` AND `sovereign-os/tests/lint/test_cross_repo_saturation_invariant.py` | M00185 | F00819 | non-negotiable | false | 10 |
| R01579 | Project boundary — Cross-repo binding crates are selfdef-domain typed-mirrors of sovereign-os contracts (NOT sovereign-os crate code) | architecture | E0071 | non-negotiable | false | 10 |
| R01580 | Project boundary — When sovereign-os adds a new compliance instrument, the typed-mirror crate is authored in selfdef-repo within the same arc | SDD-038 | F00821 | non-negotiable | false | 10 |
| R01581 | Project boundary — Cross-repo binding NEVER routes runtime data (only typed contracts) | architecture | E0071 | non-negotiable | false | 10 |
| R01582 | Project boundary — Oracle-Triage integration (MS004 E0036) is the ONLY runtime cross-repo bridge; cross-repo binding crates are the COMPILE-TIME typed contracts | MS004 E0036 + SDD-038 | E0071 | non-negotiable | false | 10 |
| R01583 | Composite — 8 typed-mirror crates form the compile-time cross-repo binding layer | this milestone | E0080 | non-negotiable | false | 10 |
| R01584 | Composite — 1 meta-crate + 1 sovereign-os lint together enforce saturation invariant | M00183 + M00185 | E0080 | non-negotiable | false | 10 |
| R01585 | Composite — Saturation 8/8 is the operator-stated invariant (current status verified empirically 2026-05-19) | repo | E0080 | non-negotiable | false | 10 |
| R01586 | Composite — When 9th binding is required, the saturation invariant fails until selfdef-side mirror is shipped | F00822 | E0080 | non-negotiable | false | 10 |
| R01587 | Composite — Cross-repo binding doctrine is the canonical mechanism for selfdef↔sovereign-os contract evolution | SDD-038 | E0071 | non-negotiable | false | 10 |
| R01588 | L1 lint — every typed-mirror crate has Cargo.toml | tests/lint | R01444 | non-negotiable | false | 10 |
| R01589 | L1 lint — every typed-mirror crate has src/lib.rs | tests/lint | R01445 | non-negotiable | false | 10 |
| R01590 | L1 lint — every typed-mirror crate has tests/ directory | tests/lint | R01446 | non-negotiable | false | 10 |
| R01591 | L1 lint — every typed-mirror crate has README.md | tests/lint | R01447 | non-negotiable | true | 10 |
| R01592 | L1 lint — every typed-mirror crate's README cites sovereign-os R-anchor | tests/lint | F00728 | non-negotiable | true | 10 |
| R01593 | L1 lint — every typed-mirror crate's README cites cross-repo binding ID | tests/lint | F00728 | non-negotiable | true | 10 |
| R01594 | L1 lint — saturation meta-crate Cargo.toml lists all 8 typed-mirror crates as dependencies | tests/lint | M00183 | non-negotiable | false | 10 |
| R01595 | L1 lint — saturation registry table at `backlog/README.md` has 8 rows | tests/lint | M00186 | non-negotiable | false | 10 |
| R01596 | L3 smoke — saturation 10-test set passes on daemon build | tests/ | F00818 | non-negotiable | false | 10 |
| R01597 | L3 smoke — sovereign-os R473 saturation invariant test passes on sovereign-os build | sovereign-os R473 | M00185 | non-negotiable | false | 10 |
| R01598 | L5 real-substrate — typed-mirror crates' integration tests run against real sovereign-os runtime endpoints | tests/ | F00818 | non-negotiable | true | 10 |
| R01599 | Cross-repo binding workflow — operator commit message references SD-R-XXX ID when authoring/modifying typed-mirror crate | git convention | F00821 | non-negotiable | true | 10 |
| R01600 | Cross-repo binding workflow — typed-mirror crate version bumps follow semver (MAJOR.MINOR.PATCH) | repo | F00834 | non-negotiable | false | 10 |
| R01601 | Cross-repo binding workflow — breaking API change requires MAJOR bump + operator-confirmed migration plan | repo | F00834 | non-negotiable | false | 10 |
| R01602 | Cross-repo binding workflow — non-breaking API addition requires MINOR bump | repo | F00834 | non-negotiable | false | 10 |
| R01603 | Cross-repo binding workflow — bug fix requires PATCH bump | repo | F00834 | non-negotiable | false | 10 |
| R01604 | UX — Dashboard SATURATED badge color = green | `dashboard/` | F00831 | non-negotiable | true | 10 |
| R01605 | UX — Dashboard DEGRADED badge color = red (with operator-readable diff link) | `dashboard/` | F00831 | non-negotiable | true | 10 |
| R01606 | UX — `selfdefctl cross-repo list` output ≤ 1 screen on SATURATED case | `crates/selfdef-cli` | F00827 | preferable | true | 10 |
| R01607 | UX — `selfdefctl cross-repo verify` runs in ≤ 10s on green case | `crates/selfdef-cli` | F00828 | preferable | true | 10 |
| R01608 | UX — `selfdefctl cross-repo diff` shows operator-readable per-binding diff | `crates/selfdef-cli` | F00829 | non-negotiable | true | 10 |
| R01609 | UX — `selfdefctl --json` output available for every cross-repo verb | `crates/selfdef-cli` | E0080 | non-negotiable | true | 10 |
| R01610 | Cross-repo binding registry table column 1 — sovereign-os consumer (e.g. `bashrc-install.sh`) | M00186 | F00820 | non-negotiable | false | 10 |
| R01611 | Cross-repo binding registry table column 2 — cross-repo binding ID (e.g. `SD-R-BASHRC-1`) | M00186 | F00820 | non-negotiable | false | 10 |
| R01612 | Cross-repo binding registry table column 3 — selfdef-side crate (e.g. `selfdef-bashrc-install`) | M00186 | F00820 | non-negotiable | false | 10 |
| R01613 | Cross-repo binding registry — 8 rows verbatim per SDD-038 doctrine | M00186 | F00820 | non-negotiable | false | 10 |
| R01614 | Cross-repo binding integration — each typed-mirror crate is included in `selfdef-cli` command surface where applicable | `crates/selfdef-cli` | E0080 | non-negotiable | true | 10 |
| R01615 | Cross-repo binding integration — each typed-mirror crate is included in `selfdef-api` REST surface where applicable | `crates/selfdef-api` | E0080 | non-negotiable | true | 10 |
| R01616 | Cross-repo binding integration — each typed-mirror crate emits Prometheus metric where applicable | per-crate | E0080 | non-negotiable | true | 10 |
| R01617 | Saturation status persistence — meta-crate `selfdef-cross-repo-saturation` exposes `saturation_status()` returning `Saturated{count:8}` | M00183 | F00832 | non-negotiable | false | 10 |
| R01618 | Saturation status persistence — `saturation_status()` returns `Degraded{missing: Vec<String>}` when invariant violated | M00183 | F00833 | non-negotiable | false | 10 |
| R01619 | Saturation status persistence — `saturation_status()` is exposed via API + CLI + dashboard | M00183 | F00825 + F00827 + F00830 | non-negotiable | true | 10 |
| R01620 | Saturation status persistence — `saturation_status()` cached for 60s (operator-tunable refresh) | M00183 | E0080 | preferable | true | 10 |
| R01621 | Cross-repo binding workflow — when sovereign-os instrument is renamed, typed-mirror crate's cross-repo binding ID is preserved (binding ID stable) | M00163 | F00821 | non-negotiable | false | 10 |
| R01622 | Cross-repo binding workflow — when sovereign-os instrument adds a field, typed-mirror crate adds the field in MINOR bump | repo | F00834 | non-negotiable | false | 10 |
| R01623 | Cross-repo binding workflow — when sovereign-os instrument removes a field, typed-mirror crate keeps the field deprecated for ≥ 1 MAJOR version | repo | F00834 | non-negotiable | false | 10 |
| R01624 | Cross-repo binding workflow — typed-mirror crate's `version` field in Cargo.toml MUST match the cross-repo binding ID's documented version | M00163 | F00834 | non-negotiable | false | 10 |
| R01625 | Cross-repo binding workflow — saturation invariant test result MUST be checked in CI on every PR touching either repo | sovereign-os R473 | F00819 | non-negotiable | false | 10 |
| R01626 | Cross-repo binding workflow — failing saturation invariant blocks the PR | sovereign-os R473 | F00822 | non-negotiable | false | 10 |
| R01627 | Cross-repo binding workflow — operator-discoverable failure message names the missing typed-mirror | sovereign-os R473 | F00822 | non-negotiable | true | 10 |
| R01628 | Cross-repo binding workflow — failing saturation invariant emits SD-R-SATURATION-VIOLATION event to `selfdef-bus` | sovereign-os R473 | F00822 | non-negotiable | true | 10 |
| R01629 | Composite — MS007 ships the saturation invariant + 8 typed-mirror crates | this milestone | E0080 | non-negotiable | false | 10 |
| R01630 | Composite — MS007 establishes the canonical mechanism for selfdef↔sovereign-os contract evolution | this milestone | E0080 | non-negotiable | false | 10 |
| R01631 | Composite — Future cross-repo bindings (SD-R-9 / SD-R-10 / etc) MUST be added via the MS007 mechanism | this milestone | E0080 | non-negotiable | false | 10 |
| R01632 | Composite — Saturation invariant transition (SATURATED → DEGRADED → SATURATED again) is operator-audit-trail-logged | M00185 | F00822 | non-negotiable | false | 10 |
| R01633 | Composite — MS007 is the canonical answer to operator question "did the cross-repo binding land" | this milestone | E0080 | non-negotiable | false | 10 |
| R01634 | Composite — MS007 implements operator's standing requirement (R102 of MS001): cross-repo saturation invariant must remain SATURATED | MS001 R102 | E0080 | non-negotiable | false | 10 |
| R01635 | Composite — MS007 enforces operator's standing requirement (R103 of MS001): cross-repo saturation invariant enforced by sovereign-os test | MS001 R103 | M00185 | non-negotiable | false | 10 |
| R01636 | Cross-repo binding governance — operator approves each new cross-repo binding ID before authoring | SDD-038 | E0080 | non-negotiable | false | 10 |
| R01637 | Cross-repo binding governance — cross-repo binding ID retired by operator-confirmed decision logbook entry | SDD-038 | E0080 | non-negotiable | true | 10 |
| R01638 | Cross-repo binding governance — typed-mirror crate version-bump rationale recorded in decision logbook | repo | F00834 | non-negotiable | true | 10 |
| R01639 | Cross-repo binding governance — operator may issue moratorium on new bindings via standing directive | SDD-038 | E0080 | preferable | true | 10 |
| R01640 | Cross-repo binding governance — saturation invariant violation triggers SDD-008 notification per critical-severity routing rule | SDD-008 | F00822 | non-negotiable | true | 10 |
| R01641 | Cross-repo binding integration — `AuthTier` enum referenced by MS004 E0036 Oracle-Triage cross-repo integration | M00164 + MS004 | E0072 | non-negotiable | true | 10 |
| R01642 | Cross-repo binding integration — `HistoryEvent` referenced by MS002 collector fabric and MS003 store | M00171 + MS002 + MS003 | E0074 | non-negotiable | false | 10 |
| R01643 | Cross-repo binding integration — `DashboardSpec` referenced by MS001 dashboard + MS005 notifier dashboard surfaces | M00173 + MS001 + MS005 | E0075 | non-negotiable | true | 10 |
| R01644 | Cross-repo binding integration — `SurfaceManifest` referenced by every operator-facing module per UX standard | M00175 | E0076 | non-negotiable | true | 10 |
| R01645 | Cross-repo binding integration — `UxChecklist` referenced by every operator-facing CLI verb per UX standard | M00177 | E0077 | non-negotiable | true | 10 |
| R01646 | Cross-repo binding integration — `AuditManifest` consumed by MS006 14 functional modules per anti-minimization discipline | M00179 + MS006 | E0078 | non-negotiable | true | 10 |
| R01647 | Cross-repo binding integration — `DocManifest` consumed by every selfdef + sovereign-os documentation surface | M00181 | E0079 | non-negotiable | true | 10 |
| R01648 | Cross-repo binding integration — `selfdef-bashrc-install` consumed by `selfdefctl init` workflow | M00168 + MS001 | E0073 | non-negotiable | true | 10 |
| R01649 | Cross-repo binding intelligence — when binding integration changes typed surface, cross-repo binding ID version bumps and operator-readable migration note is added | SDD-038 | F00834 | non-negotiable | false | 10 |
| R01650 | Cross-repo binding intelligence — when binding integration deprecates a typed surface, the typed surface remains for ≥ 1 MAJOR version with operator-readable deprecation warning | repo | F00834 | non-negotiable | false | 10 |
| R01651 | Cross-repo binding intelligence — typed-mirror crate compile-fails with operator-readable error when downstream code uses removed field | repo | E0080 | non-negotiable | false | 10 |
| R01652 | Cross-repo binding intelligence — typed-mirror crate documents migration shape in CHANGELOG.md per crate | repo | F00834 | non-negotiable | true | 10 |
| R01653 | UX — `selfdefctl cross-repo upgrade --dry-run` previews typed-mirror crate version-bump impact across downstream consumers | `crates/selfdef-cli` | F00829 | preferable | true | 10 |
| R01654 | UX — `selfdefctl cross-repo migrate --binding <SD-R-XXX>` applies migration steps with operator triple-gate | `crates/selfdef-cli` | E0080 | preferable | true | 10 |
| R01655 | UX — `selfdefctl cross-repo audit` operator-discoverable cross-repo binding integrity check | `crates/selfdef-cli` | F00828 | non-negotiable | true | 10 |
| R01656 | UX — Dashboard cross-repo binding panel surfaces operator-readable per-binding state | `dashboard/` | F00830 | non-negotiable | true | 10 |
| R01657 | UX — Dashboard cross-repo binding panel surfaces operator-actionable migration hint when version bump pending | `dashboard/` | F00830 | preferable | true | 10 |
| R01658 | Composite — MS007 establishes that cross-repo typed bindings ARE the project-boundary mechanism between selfdef and sovereign-os (not direct imports) | this milestone | E0071 | non-negotiable | false | 10 |
| R01659 | Composite — MS007 makes the saturation invariant operator-audit-able from either repo | this milestone | M00185 | non-negotiable | false | 10 |
| R01660 | Composite — MS007 satisfies operator's R471/R472/R473 (collector fabric NEVER imports sovereign-os; sovereign-os NEVER imports selfdef collector) by providing the canonical typed-mirror bridge | MS002 R471-R473 | E0071 | non-negotiable | false | 10 |
| R01661 | Composite — MS007 ships current saturation status SATURATED 8/8 verified by ls crates/selfdef-{auth-tier,bashrc-install,history-sink,dashboard-manifest,surface-manifest,ux-checklist,audit-manifest,doc-manifest,cross-repo-saturation} | repo | E0080 | non-negotiable | false | 10 |
| R01662 | Composite — MS007 completes the cross-repo binding catalog; remaining 35 selfdef milestones (MS008-MS042) cover other selfdef-domain scope | INDEX.md | E0080 | non-negotiable | false | 10 |
| R01663 | Future binding workflow — operator stores 9th binding intent in operator-pending-decisions queue | architecture | F00821 | non-negotiable | true | 10 |
| R01664 | Future binding workflow — agent surfaces saturation-invariant violation in next cycle's progress report | architecture | F00822 | non-negotiable | true | 10 |
| R01665 | Future binding workflow — agent does NOT silently author 9th binding (operator-stated commitment required) | architecture | E0080 | non-negotiable | false | 10 |
| R01666 | Future binding workflow — when operator commits to 9th binding, MS007 catalog entry is added retroactively (not invalidated) | this milestone | E0080 | non-negotiable | false | 10 |
| R01667 | Future binding workflow — typed-mirror crate scaffolding generator `selfdefctl cross-repo scaffold <SD-R-XXX>` automates 4-file boilerplate (Cargo.toml + src/lib.rs + tests/ + README.md) | `crates/selfdef-cli` | E0080 | preferable | true | 10 |
| R01668 | Future binding workflow — scaffolding generator emits operator-readable next-step (publish to crates registry / open PR / etc) | `crates/selfdef-cli` | E0080 | preferable | true | 10 |
| R01669 | Cross-repo binding test orchestration — saturation 10-test runs in `cargo test -p selfdef-cross-repo-saturation` | M00184 | F00818 | non-negotiable | false | 10 |
| R01670 | Cross-repo binding test orchestration — sovereign-os R473 test runs in `pytest tests/lint/test_cross_repo_saturation_invariant.py` | sovereign-os R473 | M00185 | non-negotiable | false | 10 |
| R01671 | Cross-repo binding test orchestration — both tests run on every PR touching either repo (CI gate) | architecture | F00822 | non-negotiable | false | 10 |
| R01672 | Cross-repo binding test orchestration — local pre-commit hook runs both tests when binding file changes | architecture | F00822 | preferable | true | 10 |
| R01673 | Cross-repo binding test orchestration — failure surfaces in dashboard + notifier per SDD-008 critical-severity routing rule | SDD-008 | F00822 | non-negotiable | true | 10 |
| R01674 | Cross-repo binding documentation — every typed-mirror crate's README ends with "Cross-repo binding: SD-R-XXX-N ↔ sovereign-os R### ↔ MS007 row X" canonical reference | per-crate README.md | F00728 | non-negotiable | true | 10 |
| R01675 | Cross-repo binding documentation — top-level README.md surfaces cross-repo binding count + saturation status in repo-status section | `README.md` | E0080 | non-negotiable | true | 10 |
| R01676 | Cross-repo binding documentation — selfdef CHANGELOG.md surfaces every binding addition / version bump / retirement | `CHANGELOG.md` | F00834 | non-negotiable | true | 10 |
| R01677 | Cross-repo binding documentation — operator-discoverable index of all SD-R-XXX IDs at `docs/sdd/038-cross-repo-binding-doctrine.md` | repo | F00820 | non-negotiable | false | 10 |
| R01678 | Cross-repo binding doctrine — typed-mirror crate is the COMPILE-TIME boundary (sovereign-os and selfdef share TYPES but NOT CRATE CODE) | SDD-038 | E0071 | non-negotiable | false | 10 |
| R01679 | Cross-repo binding doctrine — runtime cross-repo bridge is the Oracle-Triage integration (MS004 E0036); MS007 is the compile-time pair | MS004 E0036 + this milestone | E0071 | non-negotiable | false | 10 |
| R01680 | Composite — 8/8 SATURATED cross-repo typed-mirror crates form the compile-time project-boundary contract between selfdef and sovereign-os; the catalog catalog-identification phase explicitly enumerates them so future operator-stated bindings extend the saturation invariant without breaking it | this milestone | E0080 | non-negotiable | false | 10 |

— End of MS007 milestone file.
