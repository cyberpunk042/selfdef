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

## Caveat: orphaned ≠ missing capability (verify before wiring)

A chunk of the 471 orphans are **alternative implementations of capabilities
the daemon already provides via a different (often stronger) mechanism** —
not missing functionality. Concrete example found 2026-06-10:

- `selfdef-action-denylist` (default-allow except denied) looks like an
  obvious "wire it into the responder's pre-action gate." But the
  `Responder` already holds `allowed_actions: HashSet<String>` — an
  **allowlist** (default-deny: only explicitly-allowed actions fire), which
  is *stricter*. Wiring the denylist would be redundant at best, and a
  regression if it displaced the allowlist (default-allow is weaker than
  default-deny for a destructive IPS).

**Implication for the integration roadmap:** closing the catalog→code gap is
NOT a mechanical "wire every orphan" sweep. Each orphan needs a per-crate
judgment — *is this a genuinely missing capability, or a catalogued
alternative to something already wired?* — before integration. The headline
"84% orphaned" therefore overstates missing functionality; the true
"missing capability" subset is smaller and must be identified case-by-case.
This is design work that needs operator direction on which capabilities are
wanted, not an autonomous bulk wiring.

## Recommended #1 integration target: decision-discipline (decision-* lattice)

Classified the orphaned `decision-*` family (20 crates) — and unlike
`action-denylist`, this is a **genuine missing capability**, the highest-value
catalog→code gap found:

**Gap (verified):** the `Responder` fires destructive actions (kill /
quarantine / isolate / egress-lockdown) with **no rate-limiting, no
repeat-suppression, no per-profile budget, and no cool-off** — grep of the
responder shows zero throttle/dedup/budget/debounce logic (its only `dedup`
deduplicates log strings). Meanwhile the entire decision-discipline lattice
that would supply this is built-but-unwired: `decision-router`,
`decision-throttle`, `decision-budget`, `decision-cache`, `decision-delay-policy`,
`decision-conflict-detector`, `decision-watchdog`, `decision-explainer`,
plus `fixed-window-counter` — all orphaned. **Operational risk:** a noisy or
attacker-crafted event burst can make the daemon hammer the same destructive
action with no ceiling.

**Integration point:** `selfdef-decision-router::route(input: &RouterInput,
floor: &TrustFloorManifest) -> Result<RouterOutput, RouterError>` is the
designed composite gate — it returns the final `Outcome` (from
`selfdef-policy-decision`) after composing the sub-policies. Wire it at the
responder's action-dispatch chokepoint: build a `RouterInput` from the
event/action/side-effect-class, call `route(...)` against a config-loaded
`TrustFloorManifest`, and honor the `Outcome` (Allow → fire; Throttle/Deny/
Defer → skip+log+emit a policy event).

**Why it's safe to wire:** throttle/budget/dedup/cool-off only ever *reduce*
the action set — for a destructive IPS the fail-safe direction (worst case:
a legitimate action is delayed = availability cost, never a security hole).
An empty/permissive default trust-floor = current behavior (no regression);
tightening it is opt-in.

**Scope:** multi-crate (responder dispatch + `RouterInput` construction +
`TrustFloorManifest` config plumbing + tests). Sized for a session with full
context budget, not a tail-end increment. This is the concrete "build the
engine into running code" first step — recommended ahead of any further
orphan wiring.

## Meta-pattern (after classifying action-* / decision-* / grant-*)

A consistent shape explains the 471 orphans — and it's exactly the operator's
"real daemon + real modules, **thin crate lattice / engine not assembled**":

> **The "verbs" are wired; the "discipline" is orphaned.**

The daemon has the primitive mechanisms — fire an action (responder +
effectors), issue/revoke a grant (grants API + registry), store an event,
run a collector, gate an action by allowlist. What's overwhelmingly orphaned
is the **policy/discipline lattice that composes those verbs into governed
behavior**: throttle / budget / dedup / cool-off / conflict-detection over
decisions; cooldown / overlap / spend-ledger / cascade over grants; the
`policy-*`, `substrate-*`, `trust-*` composition layers.

Classification so far:
- `action-denylist` → **redundant** (responder's `allowed_actions` allowlist is stricter).
- `decision-*` (20) → **genuine gap, highest priority** — responder fires
  destructive actions with no decision-discipline; `decision-router` is the wiring point.
- `grant-*` (13) → **partial gap** — basic issue/revoke wired; grant-governance
  (cooldown/overlap/spend/cascade) orphaned. Lower stakes (operator-mediated).

**Roadmap consequence:** "build into running code" ≠ wire 471 crates. It =
wire the *discipline layer* onto the already-working verbs, highest-stakes
first (decision-discipline over destructive actions). Each layer is a scoped,
fail-safe-direction integration (the discipline only ever *restricts* the
verbs). The per-family classification above is the prioritization input; the
remaining families (`policy-*` 36, `substrate-*` 23, `actor-*` 12, …) follow
the same verb-vs-discipline split and can be triaged the same way.

## Precise scope for the #1 target (code-verified at the responder)

Correcting the earlier shorthand: the `Responder` is *not* discipline-free —
`handle_finding` (the dispatch chokepoint) already applies a per-action
**deadline** (no-hang), a **severity floor** (F-2026-092: only High+ findings
auto-fire), and the `allowed_actions` **allowlist**. The specific missing
discipline is **rate-limiting: throttle / repeat-dedup / per-profile budget /
cool-off** — nothing stops the same destructive action re-firing on the same
target across a burst of findings.

Wiring detail (the real cost, verified): `handle_finding(&self)` runs shared
from the bus consumer loop, so a throttle/dedup cache needs **interior-mutable
state** (`Mutex<HashMap<Key, Instant/Count>>` on `Responder`), plus a
**dedup-key design** — the meaningful key is `(action.name(), target)` where
`target` is the event's pid / src-ip / user, i.e. per-action target
extraction (the same fields each action pulls internally). Default window /
budget are sensible-default + opt-in-config. Fail-safe direction holds
(suppression only skips a *duplicate*; the first action already fired).

So the #1 integration is: `decision-throttle` + `decision-cache` (or the
composite `decision-router`) wired at `handle_finding`, keyed on
`(action, event-target)`, with interior-mutable state. Concrete, fail-safe,
and now precisely located — but a real change (concurrency + key design +
tests), not a tail-end increment.

## Update (2026-06-10): #1 target — COMPLETE subsystem built into the running daemon

The #1 catalog→code gap (the responder firing destructive actions with no
rate-limiting) is now closed by a complete, correct, 6-layer decision-discipline
**circuit-breaker subsystem** in the running daemon:

1. **Burst-dedup** (per-target): suppress the same `(action, target=pid|src-ip|
   user)` within `[responder].dedup_window_secs`.
2. **Rate-cap circuit-breaker** (global): suppress beyond
   `[responder].max_destructive_actions_per_min` per rolling 60s — catches a
   multi-target FLOOD that per-target dedup can't.
3. **Autonomous-scoping** (correctness): both gates apply ONLY to the autonomous
   bus path; operator-commanded `fire`/panic bypasses them (like the severity
   floor), so an emergency fires everything. Test-locked.
4. **Config**: both knobs, `#[serde(default)]` (existing configs → disabled),
   daemon applies + logs when enabled.
5. **Observability**: `selfdef_responder_suppressed_destructive_total` on
   `/metrics` + the `SelfdefResponderCircuitBreakerTripped` Prometheus alert.
6. **Docs**: both knobs documented in `config/selfdef.toml.example`.

All default-off (zero imposed behavior change); only destructive actions
affected (notify/snapshot/forensic never suppressed); lock held only
synchronously, never across `.await`; self-pruning state. Test-locked end to end
(`tests/dedup.rs`, 7 tests incl. the panic-bypass) + the metrics render path;
responder suite green; clippy clean. Commits `f306848` → `3f4f67b`.

**This proves the catalog→code integration pattern end to end** — *identify
discipline → wire into the verb default-off → autonomous-scope → serde-safe
config → metric → alert → docs → test.* The remaining decision-discipline
(per-profile budget, cool-off, the `decision-router` composite that would unify
these gates) and the analogous **grant-governance** layer (cooldown / overlap /
spend onto the already-wired grants verb) each extend this same proven
foundation; each is a clean next increment.

**Correctness follow-up (2026-06-11, F-2026-112):** code-review of the shipped
burst-dedup gate found it recorded the dedup entry *before* executing the action,
so a FAILED destructive action (e.g. `kill_pid` that lost the race) was wrongly
dedup-suppressed on retry — shielding a surviving target. Fixed: the dedup record
is committed only on `Status::Success`; failed/timed-out actions stay retryable,
while the rate-cap (still counting attempts) bounds any hammering. Failing-first
test-locked (`dedup_does_not_suppress_retry_of_a_failed_destructive_action`). This
is the kind of per-gate correctness audit each discipline layer needs after wiring,
not just the initial integration.

## Update (2026-06-11): block_ip effector wired into the running daemon

First effector wired from the orphaned lattice into the responder action vec.
Of the unwired destructive effectors, `block_ip` is the ONLY one with a real
(non-simulated) backend — `selfdef-blockset-backend`'s `NftablesBackend` (real
`nft` calls; the rest — quarantine / netns / freeze / cap-drop / env-scrub /
socket-fd — are `InMemory` simulations awaiting their MS5a production adapters).

What landed:
- `selfdef-daemon` now depends on `selfdef-blockset-backend` with the
  `nftables-backend` feature, constructs `NftablesBackend` + `BlockIpAction`
  (Responder tier, 1h kernel-TTL), and registers it in the action vec.
- `NftablesBackend::ensure_table()` (new) idempotently creates the
  `inet selfdef-blocks` table + hooked `input` drop chain + v4/v6 timeout sets.
- **Non-behavior-changing**: `allowed_actions` defaults to `["notify"]`, so
  `block_ip` is registered-but-inert. Only when an operator allowlists it does
  the daemon run the bootstrap (best-effort; needs `nft` + CAP_NET_ADMIN) and
  the action fire. Special/infra addresses are refused (F-2026-116).

This is the concrete shape of "wire a verb into running code" for an effector
that actually does real work. The remaining effector-wiring is **blocked on the
real backends existing** — the simulations can't be meaningfully wired until
their MS5a production adapters (real cgroup-freeze, real netns, …) are built.
That backend-implementation effort, not glue-wiring, is the next real-depth step.

## Update (2026-06-11): grant-governance — overlap gate wired into issuance

The **grant-side analogue of the responder circuit-breaker** named earlier in
this doc as "a clean next increment". The grant-issuance verb
(`POST /v1/grants/issue`, `selfdef-api/src/grants.rs`) was wired but
**ungoverned** — a holder of the control capability could mint an unbounded
sprawl of overlapping / escalating grants, each widening the sandbox. The
orphaned `selfdef-grant-overlap-detector` crate held the real overlap logic
(path-prefix for filesystem, domain-suffix for network, exact for the rest) but
nothing called it.

What landed:
- `selfdef-api` now depends on `selfdef-grant-overlap-detector`. After
  `issue()` mints the candidate (still `Pending`), the handler projects it as
  active and scans it against the registry's existing **active** grants via
  `selfdef_grant_overlap_detector::scan` (single source of truth — the live
  registry, no second state file).
- New `[grants].overlap_policy` config (`off` | `warn` | `refuse`), mapped by
  the daemon onto an api-local `GrantsOverlapPolicy` (so `selfdef-api` keeps no
  `selfdef-config` dependency). Threaded into `ApiState` via
  `with_grants_overlap_policy`.
- `refuse` → 409 and the mint is **never persisted** (load is per-request, so
  dropping the unsaved registry discards it). `warn` → issue + WARN log.
- **Fail-safe + default-off**: `off` is the default (historical behavior). The
  gate only ever blocks *adding* an overlapping grant — it can never narrow or
  revoke existing access — so the failure direction is always toward *less*
  privilege, never a lockout.
- Test-locked (`candidate_overlap_*` + `refuse_skips_save_off_persists`,
  4 new tests driving the registry + gate exactly as the handler does);
  api suite 221 green, config 75 green, clippy clean.

This proves the **grant-governance** layer extends the same proven integration
pattern (identify discipline → wire into the verb default-off → serde-safe
config → docs → test) onto the grants verb.

**Second governance crate wired (same commit family):**
`selfdef-grant-issuance-cooldown` now backs a `[grants].issuance_cooldown_secs`
knob (default `0` = off). When `> 0`, `issue()` refuses (HTTP 429) re-minting a
grant of *identical identity* (`actor|kind|scope`) within the window — seeded
from the most-recent prior issuance found in the registry (single source of
truth again; the orphaned crate's `classify` does the verdict). This catches
re-mint churn of an already-expired/revoked grant that the active-only overlap
gate cannot. Fail-safe + default-off; 2 new tests
(`cooldown_blocks_in_window_clears_after`, `cooldown_ignores_distinct_identity`).

The remaining grant-governance crates (`grant-spend-*` for byte/issuance budget
caps, `grant-batch-policy`) are the next increments on this same foundation;
each is a clean default-off addition to the same handler.
