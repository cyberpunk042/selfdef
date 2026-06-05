# MS048 Goldilocks Scheduler — Cross-Repo Integration Contract

> The "combine" seam of the two ultimate solutions: how the **sovereign-os
> runtime** (Solution 1) consumes the **selfdef** (Solution 2) IPS-side
> Goldilocks Scheduler. This contract is grounded in the real, shipped
> `selfdef-scheduler-decide` binary (MS048) — it is the producer-side contract
> that binding exposes, not a proposed design.
>
> **Project-boundary discipline** (operator: *"Respect the projects. If I talk
> about an IPS feature its obviously not in Sovereign-OS"*): the scheduler
> **decision** lives in selfdef. sovereign-os **invokes** it read-only and
> **renders** its output (cockpit / Grafana / alert already shipped). The
> runtime never re-implements the routing decision.

## The seam

```text
sovereign-os runtime gateway                 selfdef IPS host
(Solution 1)                                 (Solution 2)
────────────────────────                     ──────────────────────────
a model request arrives
  → build a task descriptor  ── invoke ──▶   selfdef-scheduler-decide
    (profile + 4 model axes)                   · poll live substrate (PSI/DCGM/human-gate)
                                                · score_current_substrate (7-axis objective)
                                                · recommend_route (Key Scheduling Law)
                                                · decide_persist_and_emit
                                                    → audit chain + ring + OCSF
  ◀── Decision JSON ──────────────────────────  print Decision to stdout
  → gateway honors the route
    (or defers on Hibernate)
```

## Producer contract (selfdef-scheduler-decide)

**Invocation** (one-shot, per request):

```sh
echo '<task-json>' | selfdef-scheduler-decide
# or
selfdef-scheduler-decide --task-file /path/to/task.json
```

Config + env knobs are shared with `selfdef-scheduler-textfile`
(`/etc/selfdef/scheduler.toml`, `SELFDEF_SCHEDULER_*`).

**Task descriptor (input)** — the scheduling "request":

| field | type | required | meaning |
|---|---|---|---|
| `request_id` | string | no (generated) | correlation id; appears in the Decision + OCSF `finding_info.uid` |
| `profile` | string | **yes** | `fast` \| `careful` \| `private` \| `autonomous` \| `experimental` \| `production` |
| `latency` | f32 [0,1] | no (0.5) | model-estimated latency score (1.0 = fast) |
| `cost` | f32 [0,1] | no (0.5) | model-estimated cost score (1.0 = cheap) |
| `risk` | f32 [0,1] | no (0.5) | model-estimated risk score (1.0 = low risk) |
| `energy` | f32 [0,1] | no (0.5) | model-estimated energy score (1.0 = low energy) |

The two substrate axes (`hardware_pressure`, `human_attention`) are **always
measured from the live poll** and never accepted from the task — the box is
authoritative for what it can measure.

**Decision (output, stdout JSON)** — the MS048 `Decision` schema (R11462-R11465):

| field | meaning |
|---|---|
| `request_id` | echo of the task id |
| `profile` | profile in effect |
| `route` | `Blackwell` (oracle) \| `Rtx3090` (scout) \| `Cpu` (cortex) \| `Hybrid` \| `Hibernate` (deferred) |
| `axis_scores` | the 7 axes + `compound` |
| `backpressure` | the 6 surfaces at decision time |
| `rationale` | route + Key Scheduling Law clause + reason |
| `ts_ms` / `hostname` / `signer_kid_policy` | provenance |

**Exit codes**: `0` success (Decision printed); `2` bad input (unknown profile /
malformed JSON); `1` decide/persist failure.

## Consumer obligations (sovereign-os runtime)

1. **Honor `Hibernate`** — when the route is `Hibernate` the scheduler is
   deferring (Key Scheduling Law safety stop or all tiers pressured). The
   gateway must NOT force the request onto a tier; it queues/retries (the
   `SelfdefSchedulerHighHibernateRate` alert fires on sustained deferral).
2. **Map route → backend** — `Blackwell`→oracle tier, `Rtx3090`→scout tier,
   `Cpu`→deterministic-cortex tier (the runtime's own backend selection per
   SDD-011 consumes this hardware-tier hint).
3. **Read-only** — the runtime consumes the Decision; it never writes selfdef
   IPS state. Observability of decisions is already wired
   (cockpit `scheduler-status.py` card 40 · Grafana decision panels · the
   `selfdef_scheduler_decisions_*` metrics).

## What is already shipped vs. what this contract anticipates

| Piece | Status |
|---|---|
| `selfdef-scheduler-decide` producer | **shipped** (MS048; real-run verified end-to-end into audit+ring+OCSF) |
| Decision schema + persistence + observability (HTTP/Grafana/alert/cockpit/runbook) | **shipped** (both repos) |
| sovereign-os gateway calling the binary per request | **anticipated** — the runtime-side wiring; this contract is the interface it binds to (sister to SDD-038 cross-repo binding doctrine) |

## Cross-references

- `crates/selfdef-scheduler/src/bin/selfdef-scheduler-decide.rs` — the producer
- `crates/selfdef-scheduler/src/decide.rs` — `decide_persist_and_emit`
- `crates/selfdef-scheduler/src/scheduling_law.rs` — the Key Scheduling Law
- `docs/operator/ms048-scheduler-failure-modes.md` — failure-mode runbook (§12 deferral)
- `packaging/config/scheduler.toml.example` — config + both-binaries usage
- `cyberpunk042/sovereign-os` SDD-038 — cross-repo binding doctrine (the consumer side)

We do not minimize anything.
