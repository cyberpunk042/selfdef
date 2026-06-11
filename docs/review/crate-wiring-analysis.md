# Crate-wiring analysis — catalog → code, quantified (2026-06-10)

> Answers the operator's standing question: *"Actually built into running
> code → partial (selfdef)... 557 crates but ~98% single-file glue."* This
> measures exactly how partial, and which crates are the "running system"
> vs the catalogued-but-unwired lattice.

## Headline

| Metric | Count | % |
|---|---|---|
| Workspace `selfdef-*` crates | 560 | 100% |
| **Wired** — reachable from the 3 binaries (selfdefd · selfdefctl · ssh-wrap) | **89** | **16%** |
| **Orphaned** — compiled as crates, NOT in any binary's dep tree | **471** | **84%** |

Method: `cargo metadata --no-deps` for the member set; `cargo tree -p
selfdef-daemon -p selfdef-cli -p selfdef-ssh-wrap --prefix none` for the
binary-reachable union; set-difference for orphans.

## The running system (89 wired crates)

The daemon's real spine: `api` + the 14 effector `*-backend`s, `bus`, the
registries/mirrors, and **all real event collectors** — `collector-{auditd,
canary, ebpf, eventstream, journald, suricata, tetragon, util}` (gap #3's
Tetragon collector IS built + wired), plus the security-hardened state
primitives audited this cycle (ssh-wrap policy, slo/histogram/window
counters, store, perimeter, etc.).

## The orphaned lattice (471 crates) — by family

```
 36 policy     23 substrate  20 decision   15 action    13 grant
 12 actor      11 prompt     11 llm        10 tool        7 evidence
  7 audit       6 event       5 trust       5 mcp         4 trace/sandbox/network …
```

These are the catalogued capabilities materialised as single-file crates
(policies, taxonomies, decision primitives, actor/grant/trust models) that
**compile and test in isolation but are not consumed by the running
binaries.** The 7 `collector-*` orphans are policy crates misnamed
`collector-*` (staleness-policy, jitter-policy, budget-guard, coalescing,
quarantine-ledger, source-taxonomy, arming-state), not event sources.

## What this means

- **Not dead code / not a defect**: each orphan compiles + tests; this is
  the deliberate "catalog as crate lattice" pattern. The gap is *integration*,
  not *existence*.
- **The remaining build work = wiring the policy lattice into the daemon's
  decision path** (correlator/responder/authority). That is the major,
  non-decision-free effort the operator's "engine not assembled / thin
  lattice" note refers to — it needs direction on *which* policies the
  daemon should enforce and *how they compose*, not a mechanical sweep.
- Security posture is unaffected: the attacker-reachable surface is the 89
  wired crates, which are the ones audited this cycle.
