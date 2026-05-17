# SDD-021 — Cycle 4 vectors (post-SDD-020 partial-closure forward-looking spec)

> Status: **draft** — captures fresh cycle-3 learnings (SD-R54..R58)
> + lays out unscoped cycle-4 design vectors operators may ratify.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-17 (cycle 3 in progress).
> Builds on: SDD-018 (cycle-1+2 gate doctrine); SDD-019 (cycle-3
> forward-looking, 6/6 closed in cycle 2+3); SDD-020 (cycle-3
> forward-looking, 3/6 closed in cycle 2+3).

## Why this SDD exists

SDD-019 + SDD-020 established the pattern: each cycle's closing spec
carries the next cycle's vectors. SDD-021 continues — captures the
cycle-4 vectors that emerged from cycle 3's mid-stretch (SD-R54..R58).

## Doctrine layer state

| SDD | Cycle | Status |
|-----|-------|--------|
| SDD-018 (gate doctrine) | cycle 1+2 | active doctrine |
| SDD-019 (cycle-3 forward) | cycle 2 | 6/6 ✓ all closed |
| SDD-020 (cycle-3 forward) | cycle 3 | 3/6 ✓ V-1, V-2, V-5; V-3/V-4/V-6 open |
| SDD-021 (cycle-4 forward) | cycle 3 | this SDD |

The forward-looking SDD is now a STANDING ARTIFACT — every cycle ships
one + closes most vectors before the next cycle opens.

## SDD-020 carry-over to cycle 4

| Vector | Priority | Notes |
|--------|----------|-------|
| V-3 custom predicates | LOW | YAGNI; defer unless real module needs it |
| V-4 [requires_rbac] | LOW | k8s-only; deferred |
| V-6 thermal trend | LOW | Needs daemon-side ring buffer; deferred |

## Cycle-4 vectors (W-N, NEW)

These emerged from cycle 3's surface-build:

### W-1 — Tensor-parallel slice-plan schema doc

SD-R58 emits `/etc/selfdef/tensor-parallel/slice-plan.json` with an
implicit schema. Cycle 4: write a JSON schema file at
docs/schemas/tensor-parallel-slice-plan.schema.json + lockstep test
(same pattern as SD-R46 closed SDD-019 T-6 for the bitnet schedule).

  - Recommendation: HIGH; small effort; preserves the operator-stable
    contract the future TP runtime will read.

### W-2 — Module signing key rotation

SD-R55 trusts a single pubkey at /etc/selfdef/keys/policy.pub. Cycle 4:
support a keyring directory + multiple trust roots so operators can
rotate keys without re-signing every module manifest in lockstep.

  - Recommendation: MEDIUM; closes the "operator rotated the signing
    key, now nothing applies" failure mode.

### W-3 — Cross-host fleet aggregation API

R187 cycle2-status runs per-host. Cycle 4: a sovereign-os-side fleet
aggregator that reads cycle2-status JSON from N hosts (via SSH or
operator-supplied transport) + presents fleet-wide rollups.

  - Recommendation: MEDIUM; closes the "I have 50 SAIN-01 boxes, how
    do they compare?" question.

### W-4 — selfdef integration test against a real BitNet runtime

The cycle-2 + cycle-3 module manifests + tests are mock-driven. Cycle 4:
a Layer 4 (real-hardware) integration test that compiles + runs a tiny
BitNet model on SAIN-01 + asserts the schedule.json + slice-plan.json
are honored.

  - Recommendation: HIGH for SAIN-01 operators; depends on real
    hardware (no CI runner — operator-driven).

### W-5 — Module manifest sigstore / cosign alternative

SD-R55 chose minisign for parity with SDD-006 rule signing. Cycle 4:
optional sigstore/cosign verifier alongside (operators inside
sigstore-aware ecosystems get keyless OIDC-bound signatures).

  - Recommendation: LOW; minisign covers the operator's stated
    workflow. Layer on if real demand surfaces.

### W-6 — Per-module resource quotas

Apply currently runs without rlimit/cgroup constraints. Cycle 4:
optional `[resources]` block declaring `cpu_max`, `memory_max`,
`io_weight` for the apply.sh subprocess. Composes with systemd
PrivateTmp/ProtectSystem (already in many existing modules).

  - Recommendation: MEDIUM; closes "a bad module shouldn't be able
    to OOM the host during apply."

## Cycle-4 priority ranking

| Priority | Vector | Rationale |
|----------|--------|-----------|
| HIGH     | W-1 slice-plan schema | Small + locks down operator-stable contract |
| HIGH     | W-4 real-hardware test | SAIN-01 operator value; runs only on real box |
| MEDIUM   | W-2 key rotation | Closes operational failure mode |
| MEDIUM   | W-3 fleet aggregation | Multi-host fleet observability |
| MEDIUM   | W-6 resource quotas | Defense in depth on apply.sh |
| LOW      | W-5 sigstore | Only when operators ask for it |

## Non-goals for cycle 4

Inherits SDD-018 § Non-goals + SDD-020 § Non-goals + adds:
- Multi-master signing infrastructure (operators run their own minisign
  per-org — no central authority).
- Cross-cluster operator surfaces (selfdef stays single-host).
- BitNet kernel authorship in-repo (we consume Microsoft's BitNet
  + don't fork it).

## How operators ratify

Same pattern: edit this file → replace "Recommendation:" with "Decision:"
on each W-N. Cycle-4 implementation rounds reference the decisions.

The doctrine layer keeps moving with the code. SDD-022 will close
cycle 4 + open cycle 5. The arc never closes; the SDDs do.
