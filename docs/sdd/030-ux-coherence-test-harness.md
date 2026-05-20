# SDD-030 — UX coherence test harness (CLI + TUI + minimal-web) — MS045

> Status: **draft** — Stage-1 (consolidator for MS043 operator-surface UX)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-20
> Implements milestone: MS045 (catalogued in `backlog/milestones/MS045-ux-coherence-test-harness-cli-tui-minimal-web.md`)
> Source: operator standing direction 2026-05-19 *"be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist"* + MS043 operator-surface R-rows + MS046/MS047/MS044 ad-hoc L2 bats suites
> Companions: SDD-027 (friction-audit L2), SDD-028 (perimeter L2), SDD-029 (guardian L2)

> Note: numbered SDD-030 because docs/sdd/045-*.md is reserved for the
> milestone-name-aligned slot if/when MS045 needs a Stage-2 expansion;
> this Stage-1 lands in numerical order.

## Problem

MS046, MS047, MS044 (the three-watchdog trio) each ship their own bats L2 test suite:
- `packaging/test/L2-friction-audit.bats` (20 tests, MS046 R-rows)
- `packaging/test/L2-perimeter.bats` (23 tests, MS047 R-rows)
- `packaging/test/L2-guardian.bats` (35 tests, MS044 R-rows)

That's **78 L2 tests**, each anchored to a specific R-row, validating verbatim YAML structure / systemd hardening / postinst-postrm wiring. But they only run when an operator manually invokes `bats packaging/test/L2-*.bats`. The CLI surface (`selfdefctl <verb> --help` listing the expected subverb count) and the L1 yaml-lint (`scripts/test/L1-perimeter-yaml-lint.sh`) live in scattered locations with no single entry-point.

MS043's 240 R-rows include UX-correctness assertions (CLI startup `<` 50ms p95, `--json` everywhere, TUI keyboard shortcuts, WCAG 2.1 AA contrast). Those R-rows are currently aspirational — no automated check enforces them at every commit.

MS045 catalog defines 240 R-rows binding the **automated TDD harness** layer.

This SDD describes a tractable **Stage-1 production slice**: a single orchestrator script that runs every existing L1/L2 gate, plus a layer of new CLI-surface coherence tests that lock the `selfdefctl <verb> --help` subverb counts the SDDs promise.

## Required coverage (Stage-1 slice)

### Deliverable 1 — Orchestrator `scripts/test/coherence.sh`

**Path:** `scripts/test/coherence.sh`

Single entry-point that runs:
1. Every `scripts/test/L1-*.sh` (yaml-lint + future L1 schema gates)
2. Every `packaging/test/L2-*.bats` (postinst / unit / YAML structural)
3. New CLI subverb-count check (delegated to Deliverable 3)

Exit 0 only if every layer exits 0. Prints a one-line summary per layer.

### Deliverable 2 — CLI subverb-count gates `scripts/test/L1-cli-surface.sh`

**Path:** `scripts/test/L1-cli-surface.sh`

Verifies that each SDD-promised subverb count is present in `--help` output:

| Command | SDD | Expected subverb count |
|---|---|---|
| `selfdefctl friction-audit --help` | SDD-027 | 3 (show / history / replay) |
| `selfdefctl perimeter --help` | SDD-028 | 7 (check-overlap / status + show / history / extend / revoke / audit-cycle) |
| `selfdefctl guardian --help` | SDD-029 | 4 (show / history / replay / rollback) |
| `selfdefctl hardware --help` | SDD-017 | n (current — auto-detected, baseline locked) |

Fails loudly when an SDD adds a subverb but the binary's `--help` doesn't list it (drift detector).

### Deliverable 3 — HTTP-API endpoint gates `scripts/test/L1-api-endpoints.sh`

**Path:** `scripts/test/L1-api-endpoints.sh`

Verifies the axum Router declares the SDD-promised routes. Reads `crates/selfdef-api/src/lib.rs` and counts `.route("/v1/<feature>", ...)` lines:

| Route | SDD |
|---|---|
| `/v1/friction-audit` + `/v1/friction-audit/history` | SDD-027 D6 |
| `/v1/perimeter` + `/v1/perimeter/history` | SDD-028 D8 |
| `/v1/guardian` + `/v1/guardian/history` | SDD-029 D8 |

Static check — no actual HTTP server needs to come up.

### Deliverable 4 — Cargo-test bridge

The orchestrator should also wrap `cargo test --workspace -p selfdef-friction-audit-mirror -p selfdef-perimeter-mirror -p selfdef-guardian-mirror -p selfdef-friction-audit -p selfdef-perimeter -p selfdef-guardian -p selfdef-api` so the three-watchdog trio's full unit-coverage (~127 tests) is gated alongside the bats layer.

### Deliverable 5 — `Makefile` target

**Path:** `Makefile` (extend existing)

Add `make coherence` (or update the existing `make test` to wire through `scripts/test/coherence.sh`).

### Deliverable 6 — Operator runbook (info-hub)

**Path:** `~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md`

When `make coherence` fails, the runbook explains which layer failed + which R-row + how to fix.

### Deliverable 7 — Future-round L3+ gates

L3 (nspawn) — boot-replay of friction-audit + perimeter + guardian inside systemd-nspawn (operator-hardware-gated)
L4 (znver5) — full SAIN-01 hardware run (operator-hardware-gated)
L5 (chaos) — kill-and-recover of each watchdog (operator-hardware-gated)

These are explicitly Stage-2+ — they need real hardware and operator orchestration. Stage-1 ships L1+L2 only.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Orchestrator exists | `test -x scripts/test/coherence.sh` |
| L1 CLI surface gate exists | `test -x scripts/test/L1-cli-surface.sh` |
| L1 API endpoint gate exists | `test -x scripts/test/L1-api-endpoints.sh` |
| All gates exit 0 on current main | `bash scripts/test/coherence.sh` exit 0 |
| Operator runbook exists | `test -f ~/devops-solutions-information-hub/wiki/runbooks/ux-coherence-failures.md` |

## Implementation order

1. Deliverable 2 (CLI surface gate) — locks the current subverb counts as the baseline
2. Deliverable 3 (API endpoint gate) — locks the current axum routes
3. Deliverable 1 (orchestrator) — composes 2+3 + existing L1 + L2 + cargo-test
4. Deliverable 5 (Makefile target)
5. Deliverable 6 (operator runbook)
6. Deliverable 4 (cargo-test bridge) is inline in Deliverable 1
7. Deliverable 7 (L3+) — future round, hardware-gated

This SDD authorizes Stage-2 implementation. Mark DONE only when all Stage-1 deliverables are in production.

— End of SDD-030 / MS045 Stage-1.
