# SDD-047 — Sandbox tiers — 5-tier capability ladder + promotion gates (MS032)

> Status: **implemented** — 5 crates shipped covering the sandbox-tier
> doctrine:
>  - `selfdef-sandbox-tier-policy` (272 LOC, 15 tests) — Tier0..Tier4
>    enum + capability tuples + promotion-gate enforcement
>  - `selfdef-sandbox-dispatcher` (269 LOC, 14 tests) — routes
>    sandbox operations to the active tier
>  - `selfdef-sandbox-fs-isolation` (227 LOC) — per-tier filesystem
>    mount strategy
>  - `selfdef-sandbox-network-isolation` (188 LOC) — per-tier network
>    namespace strategy
>  - `selfdef-sandbox-mirror` (441 LOC) — cross-repo state projection
>
> Stage-2 SDD authored retroactively over the shipped crate set.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS032 (catalogued in
> `backlog/milestones/MS032-sandbox-tiers.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain),
> SDD-043 (commit-authority — tier promotions are PolicyUpdate
> commits, often high-risk), SDD-044 (capability tokens — operator
> approval surfaces as MS003-signed token), SDD-045 (filesystem
> boundary — Tier2+ uses explicit exchange dirs), SDD-046 (network
> boundary — Tier3+ uses NetworkProfile).
> Cross-repo: sovereign-os sandbox-execution canon (Phase 4) mirrored
> via MS007 typed-mirror bridge.

## Problem

Sandboxed agent code runs at different levels of trust + capability.
Without a typed tier ladder + promotion-gate discipline:

1. **Implicit promotion** — code starts in a wide sandbox + escalates
   over time; nobody can audit when the elevation happened.
2. **No demotion path** — once a sandbox has network egress, there's
   no clean way to drop it back to chroot.
3. **No double-operator gate** — high-tier promotions go through
   with the same friction as routine demotions.
4. **No capability tuple per tier** — every call site re-decides
   what "Tier 3" means; capability drift inevitable.
5. **No cross-cycle binding** — sandbox tiers can't compose with
   network profiles (MS038) or capability tokens (MS035) without
   typed identity.

## Goals

1. 5-tier capability ladder per dump 16252-16277 (Phase 4: Sandbox
   Execution):

   | tier | scope                                                  |
   |------|--------------------------------------------------------|
   | Tier0| pure read-only observe; no subprocess; no network; no FS write |
   | Tier1| minimal — limited capabilities                          |
   | Tier2| chroot + read-only host FS mount; no network; no persistence |
   | Tier3| controlled network egress (per SDD-046 NetworkProfile)   |
   | Tier4| full sandbox with persistent state                       |

2. Per-tier `TierCapabilities` tuple: subprocess_allowed +
   network_allowed + persistent_allowed + host_fs_readable.

3. Promotion-gate ladder per `PromotionGate` enum:
   - `Routine` — no extra check (typically demotion)
   - `SingleOperator` — single MS003-signed approval
   - `DoubleOperator` — two distinct MS003 signatures (high-tier)
   - `Forbidden` — transition refused unconditionally

4. Refuse self-transitions (Tier2 → Tier2 is always an error).
5. Refuse missing-approval transitions (count of presented MS003
   signatures must meet `PromotionGate`).
6. Audit every promotion + demotion via SDD-043 CommitEnvelope
   (commit_type = `PolicyUpdate`).
7. Mirror tier state to sovereign-os via SDD-044/MS007 typed-mirror.

## Non-goals

- This SDD does NOT cover the specific VFIO 3090 / browser-GUI /
  CRIU / ZFS-clone tier ENCODINGS (those are per-tier strategy
  implementations).
- It does NOT cover the operator's git-on-host workflow.

## Alternative designs considered

**Alt 1 (rejected): single boolean `sandbox_strict`.** Trivially
collapses 5 tiers into one bit. Rejected — operator wants a
spectrum, not a switch.

**Alt 2 (rejected): per-tool sandbox profiles.** Tool author picks
their own sandbox shape. Rejected — invites privilege creep + no
central enforcement.

**Alt 3 (CHOSEN): typed `SandboxTier` enum + `TierCapabilities`
tuple + `PromotionGate` enforcement.** Tiers are linearly ordered
+ enforced at the boundary; capability tuples are uniform; the
promotion ladder gates escalation through MS003 signatures + SDD-043
commit envelope.

## Recommended design

### Types (shipped in `crates/selfdef-sandbox-tier-policy/src/lib.rs`)

```rust
pub enum SandboxTier { Tier0, Tier1, Tier2, Tier3, Tier4 }

pub struct TierCapabilities {
    pub subprocess_allowed: bool,
    pub network_allowed: bool,
    pub persistent_allowed: bool,
    pub host_fs_readable: bool,
}

pub enum PromotionGate { Routine, SingleOperator, DoubleOperator, Forbidden }
```

### Caller contract

Every sandbox-tier transition MUST:

1. Read the requested transition (from, to) from operator command.
2. Look up the `PromotionGate` for (from, to) — the policy table
   owns this mapping per dump 16265-16270.
3. Refuse if `Forbidden`.
4. Refuse if signature count < required.
5. Construct SDD-043 `CommitEnvelope` with commit_type =
   `PolicyUpdate`; populate the high-risk triple-gate from the
   operator-approval + snapshot + test/eval evidence (every
   promotion above SingleOperator is automatically high-risk per
   SDD-043 F04874).
6. Call `selfdef_commit_authority::validate()` — refuse on Err.
7. Persist the transition + ENABLE the new TierCapabilities via the
   dispatcher.

### Companion crates

- `selfdef-sandbox-dispatcher` — receives a sandbox operation (read,
  write, subprocess, network) + the active SandboxTier; routes
  to the correct subsystem (or refuses).
- `selfdef-sandbox-fs-isolation` — per-tier filesystem mount strategy:
  Tier0/1 = no FS access; Tier2 = chroot + read-only host overlay;
  Tier3/4 = explicit-exchange dirs (per SDD-045).
- `selfdef-sandbox-network-isolation` — per-tier network namespace:
  Tier0..2 = no netns; Tier3 = netns + NetworkProfile gate per
  SDD-046; Tier4 = netns + AuthenticatedBrowser profile.
- `selfdef-sandbox-mirror` — cross-repo state projection.

## Implementation status

**Crates**: 5 shipped, ~1400 LOC + 29 unit tests passing.

**Caller integration**: deferred. Existing call sites that need
sandboxing (notifier exec, perimeter-extension verification,
module-author check.sh) should migrate to dispatch through
`selfdef-sandbox-dispatcher`.

**Operator surfaces**: deferred (D-1, D-2 below).

## Test requirements

- 15 unit tests in `selfdef-sandbox-tier-policy` cover transitions
  + promotion-gate enforcement + capability-tuple lookups. ✅ shipped.
- 14 unit tests in `selfdef-sandbox-dispatcher` cover route-by-tier
  semantics. ✅ shipped.
- Integration test refusing on missing-approval + forbidden +
  self-transition. ⏳ deferred to caller-integration arc.

## Rollout

Retroactive SDD over shipped crate code.

## Open questions

- **D-1**: `selfdefctl sandbox-tiers {list, capabilities, transitions,
  promotion-gate <from> <to>}` CLI surface? **Recommendation: yes**,
  follows the SDD-043/044/045/046 D-1 pattern.
- **D-2**: `GET /v1/sandbox-tiers` HTTP discovery? **Recommendation:
  yes** after D-1. Returns the 5 tiers + their TierCapabilities + the
  full promotion-gate matrix as JSON.
- **D-3**: Live sandbox observability — what active sandboxes does
  the daemon currently know about? `GET /v1/sandbox-tiers/active`
  returning the current tier per active VM/container? **Recommendation:
  yes**, separate from D-2 (D-2 is static schema; this is live state).
- **D-4**: Default deny-list for forbidden transitions — should
  Tier0→Tier4 always be `Forbidden` (no skip-tier), or always
  `DoubleOperator`? **Recommendation: Forbidden** — multi-step
  promotion is auditable; skip-tier hides intent.
