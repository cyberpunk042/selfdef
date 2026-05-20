# SDD-031 — Goldilocks Scheduler — hardware-aware resource routing (MS048)

> Status: **draft** — Stage-1 (closes the avx-plus-plus dump tail backward-sweep loop)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-20
> Implements milestone: MS048 (catalogued in `backlog/milestones/MS048-goldilocks-scheduler-hardware-aware-resource-routing.md`)
> Source: avx-plus-plus dump tail lines 18000-18250 (5 scheduling surfaces + 7-axis objective + Key Scheduling Law)
> Companions: SDD-027 (friction-audit), SDD-028 (perimeter), SDD-029 (guardian) — all sister patterns; SDD-030 (UX coherence harness — locks the surface)
> Backward-sweep anchor: `~/devops-solutions-information-hub/wiki/log/2026-05-20-avx-plus-plus-dump-tail-backward-sweep-review.md` (commit a300ddc)

## Problem

The avx-plus-plus dump's closing 250 lines specify a concrete scheduling architecture — 5 surfaces (Blackwell GPU + KV/Context + Memory + Tool + Backpressure), a 7-axis objective function, per-profile rule sets that elaborate MS040's six profiles, and a Key Scheduling Law ("Never let expensive cognition wait on cheap preparation. Never let cheap speculation commit without expensive verification when risk demands it.").

MS048 catalogs 247 R-rows binding the verbatim dump content. This SDD describes a **tractable Stage-1 production slice** that ships the scheduler authority surface using the same proven 10-deliverable pattern as MS046/MS047/MS044 — mirror crate + runtime crate + CLI + HTTP API + Debian packaging + systemd unit + test contract + operator runbooks + sovereign-os cockpit panel + daemon integration.

## Required coverage (Stage-1 slice)

### Deliverable 1 — Mirror crate `selfdef-scheduler-mirror`

**Crate path:** `crates/selfdef-scheduler-mirror/`
**License:** AGPL-3.0-or-later
**Pattern:** MS007 read-only typed-mirror (cross-references the three trio mirrors).

Exports `Decision { request_id, profile, route, axis_scores: AxisScores, ts_ms, hostname, signer_kid_policy, override_signer_kid? }`, `Profile` enum (Fast / Careful / Private / Autonomous / Experimental / Production), `Route` enum (Blackwell / Rtx3090 / Cpu / Hybrid / Hibernate), `AxisScores { latency, cost, risk, energy, human_attention, hardware_pressure, compound }`, `BackpressureState { blackwell_vram_high, gpu3090_busy, cpu_pressure, ram_pressure, io_pressure, human_gate_queue_high }` per MS048 R11462-R11465.

### Deliverable 2 — Runtime crate `selfdef-scheduler`

**Crate path:** `crates/selfdef-scheduler/`

- Per-profile rule registry (verbatim sain-01 §10 + dump 18000-18100 six rule sets)
- 7-axis objective evaluator (weighted sum with per-profile weight matrix)
- 5 backpressure surfaces with hysteresis (PSI source stubs; real-source bridge in D7)
- Decision emitter — appends to ZFS audit log + emits MS027 trace span
- Replay engine (counterfactual: replay decision against alternate profile)
- Audit chain integrity (SHA-256 chained — same pattern as Guardian/perimeter)
- Stubbable Effector trait for unit-testability (no real PSI/DCGM/podman in tests)

### Deliverable 3 — CLI subcommand `selfdefctl scheduler`

**Path:** subcommand added to `crates/selfdef-cli/src/main.rs`

7 subverbs per MS048 R11423-R11430:
- `selfdefctl scheduler show [--json]` — current state + last 16 decisions + backpressure
- `selfdefctl scheduler history [--limit N] [--json]`
- `selfdefctl scheduler explain <request-id> [--json]`
- `selfdefctl scheduler replay <request-id> [--profile P] [--json]`
- `selfdefctl scheduler weights show --profile <p> [--json]`
- `selfdefctl scheduler force <request-id> --route R` (Ring 0 + MS003)
- `selfdefctl scheduler audit-cycle replay [--json]`

### Deliverable 4 — HTTP API endpoints

5 routes per MS048 R11431-R11436:
- `GET /v1/scheduler`
- `GET /v1/scheduler/history?limit=N`
- `GET /v1/scheduler/backpressure`
- `GET /v1/scheduler/weights?profile=P`
- `GET /v1/scheduler/explain/:request-id`

### Deliverable 5 — Systemd unit `selfdef-scheduler.service`

**Path:** `packaging/systemd/selfdef-scheduler.service`

Per MS048 R11454-R11458. Type=simple, Restart=always, After=tetragon.service + zfs-mount.service + selfdef-guardian.service. Ring 0 (User=root). Hardening identical to selfdef-guardian.service (proven pattern).

### Deliverable 6 — Debian packaging

`postinst` installs unit + creates `/var/cache/selfdef/scheduler/{ring,decisions}` and `/mnt/vault/context/` (if mountpoint). `postrm` purge cleans up. Cargo-deb assets ship the unit.

### Deliverable 7 — Test contract

L1: cargo unit tests + coherence harness extensions (CLI surface 7 subverbs, HTTP API 5 routes, dashboard section)
L2: bats tests for systemd unit + postinst/postrm
L3 (operator-hardware-gated): nspawn boot-time decision replay
L4 (operator-hardware-gated): znver5 real PSI+DCGM
L5 (chaos): kill scheduler mid-decision, verify Restart=always + audit chain intact

### Deliverable 8 — Operator runbooks (info-hub)

5 runbooks per MS048 R11448-R11453:
- `scheduler-not-running.md`
- `scheduler-backpressure-stuck-open.md`
- `scheduler-weight-matrix-rotation.md` (MS003 multi-sig)
- `scheduler-audit-log-corruption.md`
- `scheduler-force-override-investigation.md`

### Deliverable 9 — Sovereign-os cockpit panel

**Crate path (sovereign-os):** `crates/sovereign-cockpit-scheduler-panel/`
**License:** MIT OR Apache-2.0
**Cross-repo discipline:** ZERO selfdef-crate deps; reads selfdef-emitted JSON at filesystem boundary.

### Deliverable 10 — Daemon integration

`selfdefd` boot observability logs scheduler state alongside trio (friction-audit + perimeter + guardian + scheduler — now 4-watchdog visibility set).

### Deliverable 11 — `selfdefctl trio` extension

`selfdefctl trio` extends to render scheduler alongside the three watchdogs (per MS048 R11446). Becomes `selfdefctl trio` showing the 4-tier IPS state at-a-glance.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Mirror crate compiles + tests | `cargo test -p selfdef-scheduler-mirror` exit 0 |
| Runtime crate compiles + tests | `cargo test -p selfdef-scheduler` exit 0 |
| CLI subverb count locked at 7 | L1-cli-surface.sh enforces |
| HTTP routes locked at 5 | L1-api-endpoints.sh enforces |
| Systemd unit hardening | L2 bats verifies (systemd-analyze) |
| Debian postinst clean | ShellCheck |
| Dashboard scheduler section | L1-dashboard-sections.sh enforces |
| Sovereign-os panel compiles + tests | `cargo test -p sovereign-cockpit-scheduler-panel` exit 0 |
| 5 operator runbooks exist | Info-hub `ls scheduler-*.md` returns 5 |
| Daemon surfaces scheduler at boot | `journalctl -u selfdefd \| grep scheduler` |

## Implementation order (per MS046/MS047/MS044 proven workflow)

1. Deliverable 1 (mirror crate) — runtime-agnostic, no deps
2. Deliverable 2 (runtime crate) — depends on 1
3. Deliverable 5 (systemd unit) + 6 (Debian packaging)
4. Deliverable 7-L2 (bats — systemd surface)
5. Deliverable 3 (CLI subcommand) — depends on 1+2
6. Deliverable 4 (HTTP API endpoints) — depends on 2
7. Deliverable 10 (daemon integration) — depends on 2
8. Deliverable 11 (selfdefctl trio extension)
9. Deliverable 9 (sovereign-os panel) — depends on 1 (mirror)
10. Deliverable 8 (operator runbooks) — operator-supervised
11. Coherence harness updates (L1-cli-surface.sh, L1-api-endpoints.sh, L1-dashboard-sections.sh) — locks the surface

This SDD authorizes Stage-2 implementation. Mark DONE only when all eleven deliverables are in production AND the operator-supervised authoring of `wiki/spine/doctrine/peace-machine-and-core-law.md` (per backward-sweep review item #4) has landed.

— End of SDD-031.
