# SDD-051 — Policy and trace — every action observable + governed (MS033)

> Status: **implemented** — 36 `selfdef-policy-*` crates shipped
> covering the Phase-3 (Policy And Trace) doctrine from dump
> 16210-16250. Stage-2 SDD authored retroactively to document the
> cluster architecture.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS033 (catalogued in
> `backlog/milestones/MS033-policy-and-trace.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain),
> SDD-043 (commit-authority — every policy mutation is a Commit),
> SDD-049 (authority + profiles — policy changes gated through
> authority rings).
> Cross-repo: sovereign-os policy canon (M056) mirrored via MS007.

## Problem

The IPS enforces dozens of orthogonal policy dimensions. Without a
unified policy architecture:

1. **Drift** — each policy crate evolves independently; cross-policy
   composition becomes accidental.
2. **No conflict detection** — two policies could allow + deny the
   same action; runtime picks one at random.
3. **No mutation discipline** — policy bundles change atomically OR
   the daemon enters a torn state.
4. **No trace** — when a decision refuses an action, the operator
   has no way to walk back through which policy fired + why.
5. **No staging** — operator can't dry-run a policy change before
   it goes live.

## Goals

Per dump 16210-16250 + the 36 shipped policy crates:

1. **Conflict detection** between policy declarations
   (`selfdef-policy-conflict-detector` + `-conflict-resolver`).
2. **Bundle discipline** — policies ship as signed bundles
   (`selfdef-policy-bundle-signature` + `-bundle-pack` +
   `-bundle-staging`).
3. **Mutation atomicity** — `selfdef-policy-mutation-record` +
   `-revert-window` + `-grace-period` enforce that policy updates
   either land atomically or leave no trace.
4. **Trace** — every policy decision produces a record via
   `selfdef-policy-decision` + `-decision-batcher`.
5. **Staging** — `selfdef-policy-dry-run` + `-shadow-mode` +
   `-rollout-stage` let operators preview a policy change without
   committing it.
6. **Spec validation** — `selfdef-policy-spec-validator` +
   `-shape-checker` reject malformed policy declarations at
   load-time.
7. **Lifecycle** — `selfdef-policy-cooldown-window` +
   `-change-window` + `-sunset-policy` + `-traffic-ramp` model
   policy evolution over time.
8. **Storage** — `selfdef-policy-cas-store` (content-addressed),
   `-cache-key`, `-bus` (event distribution),
   `-delta-feed` (incremental updates).
9. **Cross-cutting** — `selfdef-policy-budget-ledger`,
   `-blast-radius-cap`, `-namespace-policy`, `-version-pin`,
   `-feature-flag`, `-diff-classifier`, `-test-harness`.

## Non-goals

- This SDD does NOT enumerate every public function in each crate
  (~36 crates, hundreds of fns).
- It does NOT cover sovereign-os's parallel policy canon (M056);
  selfdef applies policies to IPS-side decisions only.

## Alternative designs considered

**Alt 1 (rejected): one big `selfdef-policy` crate.** Trivially
extensible. Rejected — 36 dimensions in one crate produces a
~10000-line lib that nobody can review.

**Alt 2 (rejected): per-decision-type crate (`selfdef-allow-tool`,
`selfdef-deny-network`, etc).** Rejected — same decision logic
duplicated for every action class.

**Alt 3 (CHOSEN): per-policy-dimension crate.** Each orthogonal
policy concern (conflict detection, dry-run, sunset, staging, ...)
lives in its own crate. Callers compose only the dimensions they
need. The drift cost is bounded because each crate has a narrow
contract.

## Recommended design

### Crate clusters (36 shipped crates)

**Conflict + decision**:
- `selfdef-policy-decision` — typed Decision result
- `selfdef-policy-conflict-detector` — flags two-policy contradictions
- `selfdef-policy-conflict-resolver` — operator-chosen resolution

**Bundle + signing**:
- `selfdef-policy-bundle-signature`
- `selfdef-policy-bundle-pack`
- `selfdef-policy-bundle-staging`

**Mutation discipline**:
- `selfdef-policy-mutation-record`
- `selfdef-policy-revert-window`
- `selfdef-policy-grace-period`

**Dry-run + staging**:
- `selfdef-policy-dry-run`
- `selfdef-policy-shadow-mode`
- `selfdef-policy-rollout-stage`
- `selfdef-policy-traffic-ramp`

**Spec validation**:
- `selfdef-policy-spec-validator`
- `selfdef-policy-shape-checker`

**Lifecycle / time-window**:
- `selfdef-policy-cooldown-window`
- `selfdef-policy-change-window`
- `selfdef-policy-sunset-policy`

**Storage + distribution**:
- `selfdef-policy-cas-store`
- `selfdef-policy-cache-key`
- `selfdef-policy-bus`
- `selfdef-policy-delta-feed`
- `selfdef-policy-decision-batcher`

**Cross-cutting controls**:
- `selfdef-policy-budget-ledger`
- `selfdef-policy-blast-radius-cap`
- `selfdef-policy-namespace-policy`
- `selfdef-policy-version-pin`
- `selfdef-policy-feature-flag`
- `selfdef-policy-diff-classifier`
- `selfdef-policy-test-harness`

### Caller contract

Every policy-evaluating call site MUST:

1. Resolve the policy bundle for the active namespace (via
   `selfdef-policy-namespace-policy`).
2. Verify the bundle signature (`selfdef-policy-bundle-signature`).
3. Run spec validation if the bundle was just loaded.
4. Evaluate the decision, producing a typed
   `selfdef-policy-decision`.
5. Emit a trace record via `selfdef-policy-decision-batcher`.
6. If the decision REFUSES an action, audit through SDD-043 +
   surface to the operator with cited policy id.

## Implementation status

**Crates**: 36 shipped under `crates/selfdef-policy-*`. Each crate
has its own unit tests. Cluster-level integration test coverage
is uneven (a follow-up arc could ship a composite
`crates/selfdef-policy-suite/` integration test that exercises the
end-to-end policy-evaluation flow).

**Caller integration**: existing IPS decision points already route
through individual policy crates. The composite trace surface
remains the operator-visible gap.

**Operator surfaces**: deferred (D-1, D-2 below).

## Open questions

- **D-1**: `selfdefctl policy {clusters, crates, namespace <ns>,
  trace <decision-id>}` CLI? **Recommendation: yes**, ship the
  `clusters` + `crates` subverbs first as discovery surface.
- **D-2**: `GET /v1/policy` HTTP discovery returning the 9 crate-
  cluster names + each cluster's member crates + the caller-contract
  6-step sequence? **Recommendation: yes** after D-1.
- **D-3**: Live policy-trace surface — `GET /v1/policy/trace/:id`
  walking back through the decision chain that fired? **Recommendation:
  yes**, separate arc; needs the existing batcher to buffer traces
  for retrospective walk.
- **D-4**: Cluster-level integration test crate
  `selfdef-policy-suite`? **Recommendation: yes**, ship as a follow-
  up. Verifies the 36 crates compose correctly under realistic
  policy-bundle scenarios.
