# selfdef-side backlog for sovereign-os Epic E11 ("Ultimate Sovereign OS" expansion)

> **Canonical operator-verbatim** lives in
> `cyberpunk042/sovereign-os` →
> `docs/standing-directives/2026-05-17-operator-mandate.md` § 1
> (subsections §1.0 through §1h at this writing).
>
> This document tracks the **selfdef-side counterpart** of each
> sovereign-os E11.M Module. It accumulates inside the never-ending
> PR `cyberpunk042/selfdef#199`
> (branch `claude/general-session-Wk97z`).

## Cross-repo Module map (sovereign-os ↔ selfdef)

| sovereign-os E11.M | selfdef-side counterpart | selfdef status |
|---|---|---|
| **E11.M1** — Documentation through-and-through (operator's "high standards" bar) | selfdef README.md scaling pass + per-module README + per-feature README; every selfdef module ships docs that follow operator-named SDD discipline | TODO (SD-R-DOCS-1 seed) |
| **E11.M2** — Master-dashboard / reverse-proxy aggregator (nginx or alternative) | selfdef dashboards (per-module ports) MUST publish a `dashboard-manifest.toml` declaring their port + auth tier + path — sovereign-os reverse-proxy reads the manifest set to construct the aggregate | ✓ shipped (SD-R-DASHBOARD-MANIFEST-1: `crates/selfdef-dashboard-manifest` NEW crate — `DashboardManifest` type + TOML loader + `validate()` enforcing port≥1024 + healthz_path leading-slash + subpath leading-AND-trailing-slash + non-empty module/label + `auth_tier ∈ AUTH_TIERS` (mirrors sovereign-os R450 6-tier ladder) + `surfaces[] ⊆ SURFACES` (mirrors sovereign-os R453 8-surface taxonomy); 13 unit tests + 8 integration tests covering verbatim-order constants + valid-manifest parse + 7 negative-cases (unknown-auth-tier / unknown-surface / privileged-port / unterminated-subpath / relative-healthz / empty-module / empty-label / future-schema-version) + serde round-trip + path loader + ioerror-when-missing; `AUTH_TIERS` + `SURFACES` constants compile-time-checked against the sovereign-os verbatim §1g ordering — drift between repos = test failure on both sides) |
| **E11.M3** — Multi-surface delivery (core/CLI/TUI/API/MCP/Dashboard/Web App/Service) | every selfdef module MUST ship core + CLI + at least 2 of {TUI, API, MCP, Dashboard}; per-module surface manifest declares which surfaces present (and waiver if absent) | TODO (SD-R-MULTI-SURFACE-AUDIT-1) |
| **E11.M4** — Nvidia Nemotron 3 / Nano Omni integration | selfdef model-catalog entry + selfdef model-registry support; research model size/quant/license/hardware-fit; slot into operator-named SAIN-01 hardware profile if operator picks it | TODO (SD-R-NEMOTRON3-1 — research + catalog) |
| **E11.M5** — Global history (delta/differentials) | selfdef-side history surface: every module emits an event log (module-installed, feature-toggled, profile-switched, etc.) feeding the sovereign-os aggregator via JSONL stream | ✓ shipped (SD-R-EVENT-LOG-1: `crates/selfdef-history-sink` NEW crate — `HistoryEvent` struct + `emit()` / `emit_default()` + `validate()` + `resolve_log_path()` + `DEFAULT_MODULES_LOG = "/var/log/sovereign-os/modules.jsonl"` (path matches sovereign-os `_read_modules` reader EXACTLY) + `ENV_MODULES_LOG = "SOVEREIGN_OS_MODULES_LOG"` env-override + `STATUSES` const (5-entry operator-named enum: ok/started/failed/skipped/rolled-back; drift breaks the sovereign-os global-history delta histogram) + builder-style `.with_actor()` + `.with_detail()` + append-only + auto-mkdir-parent + best-effort fsync. Required fields: timestamp/source/module/event/status (source MUST be `"modules"` per the sovereign-os reader bucket). 9 unit + 7 integration tests = 16 total: STATUSES order matches sovereign-os reader + DEFAULT_MODULES_LOG path matches sovereign-os reader (contract-binding asserts) + now() fills timestamp + validate accepts minimal + rejects unknown status / wrong source / empty module / empty event + builder chains + env-override + emit writes one line per call + appends does not truncate + creates parent directory + rejects invalid event before writing + detail round-trips via serde + emit_default uses resolve_log_path. rustfmt + clippy -D warnings clean.) |
| **E11.M6** — bashrc opt-in configuration | `selfdefctl bashrc install`: autocompletes + aliases for selfdef commands; idempotent + reversible (`bashrc uninstall`) | TODO (SD-R-BASHRC-1) |
| **E11.M7** — Auth tier ladder | per-dashboard auth tier: no-auth → basic → advanced → social → enterprise → network-level; per-module config declares its baseline; operator-overrideable | TODO (SD-R-AUTH-TIER-1) |
| **E11.M8** — Network-topology + Opnsense connector | **selfdef MAY ship the Opnsense connector** as a selfdef module — detects Opnsense state, integrates via API key, surfaces connectivity health; module-catalog entry: `opnsense-connector` | TODO (SD-R-OPNSENSE-CONNECTOR-1) |
| **E11.M9** — Edge-firewall alternative on workstation | **selfdef edge-firewall module** (IPS-class, optional, performance-cost disclosed); compatible with cheap+fanless edge variants; module-catalog entry: `workstation-edge-firewall` | TODO (SD-R-EDGE-FIREWALL-1) |
| **E11.M10** — UX Design stage upstream | applies to every selfdef module + dashboard; per-module UX-pass checklist (recoverable mistakes, ≤N actions to goal, discoverable next steps) | TODO (SD-R-UX-CHECKLIST-1) |
| **E11.M11** — Anti-minimization continued audit | selfdef per-module audit pass: "have we covered all angles? if so, can we improve it?"; output: per-module improvement backlog | TODO (SD-R-AUDIT-1) |
| **E11.M12** — selfdef branch + never-ending PR setup | **DONE** — branch `claude/general-session-Wk97z` + PR #199 (draft, accumulating); this document IS the second accumulating artifact | ✓ shipped (PR #199) |

## selfdef-native rounds (not directly tied to a sovereign-os E11.M)

| ID | Module | Status |
|---|---|---|
| SD-R-NATIVE-WASM-AOT | Wasm-to-AVX-512 AOT pipeline (operator-named §1a; relevant for selfdef module hot-load on sain-01) | TODO |
| SD-R-NATIVE-1BIT | 1-bit model + 512-bit ZMM register exploitation (operator-named §1a; selfdef may surface hardware-tuned binaries) | TODO |
| SD-R-NATIVE-HOTSWAP | Hot-swap modes: CPU profile / GPU profile / workload mode hotswap with auto options (operator-named §1c/d/e) | TODO |
| SD-R-NATIVE-PSU | Sub-feature: PSU + APC integration with power management + scheduled-shutdown at battery-threshold default profile (operator-named §1c/d/e) | TODO |
| SD-R-NATIVE-XMP-OC | XMP profile + OC profile detection + room-estimation @ 100% usage + real-time tracking + intelligence (operator-named §1c/d/e) | TODO |

## Working rules (carried from PR #199 anchor)

- Append-only progress; no force-push.
- Draft state is FINE (operator authorized: "not blocked at draft").
- Sovereign-os mandate doc remains the canonical operator-verbatim
  record; do NOT re-paste operator-verbatim text into selfdef.
- selfdef-side SDDs continue (SDD discipline applies to both repos).
- Cross-repo binding: every selfdef round MUST reference the
  sovereign-os E11.M ID it implements (or new ID to add).
- Per § 6 mandate anti-corruption invariants: NO rewriting operator
  verbatim, NO deleting TODO Modules without operator confirmation.

## Triage cadence

This document gets refreshed at every milestone of the
sovereign-os R-arc that lands a new §1<letter> subsection. The
operator's §1g, §1h are already mapped above. Future §1<i>+
additions cascade into new rows.
