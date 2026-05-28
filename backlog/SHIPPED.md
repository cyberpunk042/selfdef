# selfdef · backlog/SHIPPED.md

> **Production-shipped state tracker against `backlog/INDEX.md`.** Auto-maintained as commits land on the selfdef PR branch. Surfaces, per milestone, which catalogued R-rows have reached production code (with test coverage + Cargo-deb-installed asset) versus which remain catalogued-only.
>
> The catalogue itself is `backlog/INDEX.md` (48 milestones × 240 R-rows = 11,520 R-rows total). This file is the orthogonal "delivery state" view per the operator's standing constraint:
>
> > *"You cannot mark something done if it hasn't reached Prod."*
>
> *Shipped* here means: shipped to a commit on the development branch, with passing tests on the affected crate, with a deb-asset entry where applicable, and (for cross-repo R-rows) with the sovereign-os consumer side wired. *Catalogued-only* means: R-row exists in `backlog/milestones/MS*.md` but the production code path for that row hasn't landed yet.

## Roll-up

| State | R-rows | % of 11,520 |
|---|---:|---:|
| Catalogued (total) | 11,520 | 100% |
| Shipped (production code + tests + packaging) | partial — tracked per-milestone below | — |
| Catalogued-only | balance | — |

Per-milestone shipped surfaces are enumerated below in commit-order so the trajectory across the multi-year project is auditable.

## MS043 — IPS operator surface (CLI + TUI + dashboard-mirror exports)

**Catalogued:** 240 R-rows (R10081..R10320). See `backlog/milestones/MS043-ips-operator-surface-cli-tui-and-dashboard-mirrors.md`.

**Shipped this milestone:**

| R-row range | Surface | Commits (selfdef branch) | Tests | Packaging |
|---|---|---|---|---|
| R10281 + R10297 | `selfdef-cli-mirror` schema crate publishes the live clap-tree via `CliMirrorSnapshot 1.0.0`, doctrine verbatim "Fullstack at the edges" | crate ships in workspace as `selfdef-cli-mirror` | 5 schema tests (in-crate) | linked via workspace dep |
| R10281 (producer wiring) | `selfdefctl cli-mirror snapshot --output PATH` operator-controlled producer with atomic tempfile + rename; `DEFAULT_STATE_PATH` const shared between producer + daemon consumer | `a2fc563` | 7 publisher tests (resident-cache + shell-out fallback + schema-drift refusal) | n/a (verb in shipped binary) |
| R10281 (one-shot trigger) | `selfdef-cli-mirror-emit.service` systemd one-shot kicked from `packaging/debian/postinst`; resident-store at `/var/lib/selfdef/cli-mirror.json` becomes hot at install/upgrade | `1d86857` | 8 unit-file contract tests (User=selfdef, Type=oneshot, hardening posture, Environment= matches crate const) | Cargo.toml deb-assets row → `/lib/systemd/system/` |
| R10281 (lifecycle) | postrm cleanup — `purge` arm disables + stops + removes drop-in dir; `remove` arm stops without disabling (reinstall=upgrade contract) | `e9bfd4a` | 9 postrm contract tests (sibling-template parity + var-lib wipe ordering + reinstall-upgrade preservation) | postrm shipped via existing debian/postrm asset |
| R10281 (triage) | `selfdefctl cli-mirror doctor` — 4 checks (schema-version / resident-store / systemd-unit / published-mirror) + 3-tier severity + json/table modes + cross-cutting `selfdefctl doctor` roll-up with opt-in/opt-out gating | `d49c0b6` + `0ad9fc0` | 11 doctor unit + 11 cli_doctor integration tests | verb in shipped binary |
| R10281 (observability) | `cli-mirror doctor --textfile PATH` emits 4 node_exporter-compatible gauge series; `selfdef-cli-mirror-doctor.{service,timer}` runs every 60s with SuccessExitStatus=0 1 2 | `e9ab056` | 8 textfile render unit + 10 timer/service contract tests | 2 new Cargo.toml deb-assets rows |
| R10281 (docs) | `docs/operator/m060-cockpit-mirror-producers.md` (215-line operator runbook) + README + ARCHITECTURE.md references | `fdbef1b` + `6365fa4` | n/a (markdown) | doc files shipped |

**Cross-milestone observability widening (MS027 × MS043 × M060):**

| R-row family | Surface | Commits | Tests |
|---|---|---|---|
| R10281 (chain-wide observability) | `selfdefctl m060-doctor --textfile PATH` covers all 6 mirror domains (D-02/D-13/D-14/D-15/D-17/D-18) with 6 gauge series each; `selfdef-m060-doctor.{service,timer}` runs every 60s at 70s boot-offset | `ce58154` | 8 m060_doctor unit + 10 chain-doctor unit-contract + 2 added postrm contract tests |

## MS007 — Cross-repo typed-mirror crates

**Catalogued:** 240 R-rows. The 8-of-8 SATURATED set listed in the milestone title pairs with the typed-mirror surface.

**Shipped this milestone:**

| R-row range | Surface | Status |
|---|---|---|
| `selfdef-cli-mirror::DEFAULT_STATE_PATH` const | shared producer/consumer/unit const for the resident-store path — eliminates drift across producer (selfdefctl), consumer (selfdefd publisher), unit Environment=, and Grafana alert thresholds | shipped under commit `a2fc563`; locked by `m060_cli_mirror_emit_unit_contract.rs` test asserting unit Environment matches the const |

## MS027 — Observability module (selfdef-side)

**Catalogued:** 240 R-rows (E0271..E0280 + module rows M00683+).

**Shipped this milestone:**

| R-row range | Surface | Commits |
|---|---|---|
| E0279 (was: "Alert rules out-of-scope for v0.1") | Alert rules NOW shipped on the sovereign-os consumer side — 3 cli-mirror-specific alerts (`M060CliMirrorChainDegraded`, `M060CliMirrorChainBroken`, `M060CliMirrorObserverSilent`) + 5 existing chain-wide alerts. Pairs with the textfile metrics this repo emits. | selfdef commits `e9ab056` + `ce58154` (producers); sovereign-os commit `bf98e2a` (rules) |
| (orthogonal) | Grafana dashboard `sovereign-os-m060-cli-mirror.json` rendering selfdef's `selfdef_cli_mirror_doctor_*` series. Operator imports into Grafana via Settings → JSON Model. | sovereign-os commit `2a44536` |

## Pending milestones (catalogued, no production rows shipped this session)

MS001-MS006, MS008-MS042, MS044-MS048 — still catalogued; production-shipped state TBD. Future deliveries on this branch append rows here in the same shape so the SHIPPED column always tracks reality.

## How this file is maintained

1. **Every production commit** that lands a catalogued R-row appends a row to the relevant milestone section above with: R-row range, surface description, commit hash(es), tests added, packaging delta.
2. **No invention** — every row references real commits + tests + assets. Audits cross-check against `git log` + the Cargo.toml deb-assets array + `tests/` directory.
3. **Never marks done** what isn't in production — the operator's R10081 constraint is sacrosanct. Half-shipped (e.g. code without tests, code without packaging) gets a parenthetical "partial — pending X" note, not a "shipped" row.

This file pairs with sovereign-os's parallel `backlog/SHIPPED.md` for consumer-side surfaces. Both repos' INDEX + SHIPPED files together give the operator the catalogue-vs-shipped delta at any commit.
