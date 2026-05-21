# SDD-049 — Authority tiers + trust rings — IPS-side projection (MS039 + MS040)

> Status: **implemented** — 5 authority crates shipped covering the
> 7-level authority tier ladder + 6-profile authority matrix:
>  - `selfdef-mode-transition-authority` (227 LOC) — execution-mode
>    transition matrix with Forbidden / DirectShift / SnapshotRequired
>    / Routine gates
>  - `selfdef-toggle-audit-authority` (270 LOC) — operator toggle
>    + audit-log emission policy
>  - `selfdef-config-mutation-authority` (225 LOC) — config-mutation
>    authorization
>  - `selfdef-recovery-snapshot-authority` (257 LOC) — ZFS snapshot
>    authority pre-mutation
>  - `selfdef-profile-authority-gate` (660 LOC) — 6-profile
>    authority matrix per MS040 dump 17468-17500
>
> Stage-2 SDD authored retroactively over the 5-crate set. Spans MS039
> (7 authority levels + 5 trust rings) AND MS040 (authority + profiles
> — same dump section + closely-coupled implementation).
>
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestones: MS039 + MS040 (catalogued in
> `backlog/milestones/MS039-seven-authority-levels-and-trust-rings.md`
> + `backlog/milestones/MS040-authority-and-profiles.md`)
> Builds on: SDD-004, SDD-007, SDD-043 (commit-authority — high-risk
> classifier F04872 keys off L6 Persist authority level), SDD-044
> (capability-tokens), SDD-046 (network-boundary F04527/F04528 binds
> to authority rings), SDD-047 (sandbox-tiers Tier A/B/C/D bind to
> authority).
> Cross-repo: sovereign-os authority canon (M056) mirrored via MS007.

## Problem

The IPS makes authorization decisions across a 7-level + 5-ring
matrix with 6 operator-selectable profiles. Without typed authority
discipline:

1. **Implicit elevation** — code can silently get L4 authority
   when the operator only granted L2; no audit trail.
2. **No profile envelopes** — `private` mode could accidentally
   execute L5 cloud calls; `peak-inference` mode forbidden from
   making policy mutations.
3. **No snapshot-before-mutation gate** — durable changes go
   through without recovery-snapshot evidence.
4. **No mode-transition matrix** — operator switches from `private`
   to `fast` and L5 capability comes online instantly; no double-
   gate, no audit.
5. **No cross-cycle binding to network / sandbox** — Ring N must
   compose with NetworkProfile + SandboxTier predictably.

## Goals (MS039 — 7 authority levels)

The 7-level ladder per dump 17215-17532:

| Level | Scope                                                     |
|-------|-----------------------------------------------------------|
| L0    | observe-only (no side effects)                            |
| L1    | local in-process state (no FS / network / subprocess)     |
| L2    | local FS reads, NO writes (R09202)                        |
| L3    | local FS writes within workspace (per SDD-045)            |
| L4    | external network egress (per SDD-046)                     |
| L5    | external state mutation (cloud APIs, write-acked)         |
| L6    | persistent durable changes (every commit through SDD-043) |

## Goals (MS039 — 5 trust rings)

Ring 0 (most trusted) … Ring 4 (least trusted), each ring composing
with an authority level cap:

| Ring | Scope                                  | L-cap |
|------|----------------------------------------|-------|
| Ring 0| operator-direct (cockpit + console)   | L6    |
| Ring 1| daemon-internal                       | L5    |
| Ring 2| operator-sandboxed agent              | L4    |
| Ring 3| third-party tool plugin              | L3    |
| Ring 4| external untrusted code              | L1    |

## Goals (MS040 — 6-profile authority matrix)

Per dump 17468-17500 + R09361-R09600:

| profile      | max L | ring-cap | sandbox req | gate                  |
|--------------|-------|----------|-------------|-----------------------|
| `private`    | L1    | Ring 2   | Tier A      | operator approval     |
| `fast`       | L4    | Ring 2   | Tier A      | TTL ≤ 60s default     |
| `careful`    | L5    | Ring 2   | Tier A or B | oracle + tests + sim  |
| `paranoid`   | L4    | Ring 1   | Tier A      | double-operator       |
| `production` | L6    | Ring 0   | Tier B      | full commit-authority |
| `experimental`| L5   | Ring 3   | Tier C      | high cycle budget     |

## Goals (transition discipline)

`TransitionGate` enum per mode-transition-authority:
- `Forbidden` — refused unconditionally
- `DirectShift` — explicit operator acknowledgement
- `SnapshotRequired` — ZFS snapshot evidence required
- `Routine` — no extra gate

## Non-goals

- This SDD does NOT cover the runtime VM-side projection of the
  authority graph (that's sovereign-os M056 canonical).
- It does NOT cover the OAuth / SSO / OIDC integration for operator
  identity (separate identity-resolution arc).

## Alternative designs considered

**Alt 1 (rejected): single `is_admin: bool` field.** Trivially
collapses the 7-level ladder. Rejected — no audit, no profile
envelopes, no cross-cycle binding.

**Alt 2 (rejected): inline enum at every call site.** Per-call-site
enforcement leads to drift. Rejected — central crate owns the
matrix; call sites consume.

**Alt 3 (CHOSEN): 5 dedicated authority crates + profile-authority-
gate composite.** Each crate owns one decision class (transitions,
toggles, config-mutations, recovery-snapshots, profile envelopes);
composes into the 6-profile matrix.

## Recommended design

### Type signatures (cross-crate)

```rust
// selfdef-mode-transition-authority
pub enum TransitionGate {
    Forbidden,
    DirectShift,
    SnapshotRequired,
    Routine,
}

// selfdef-profile-authority-gate
pub enum Profile { Private, Fast, Careful, Paranoid, Production, Experimental }
pub enum AuthorityLevel { L0, L1, L2, L3, L4, L5, L6 }
pub enum TrustRing { Ring0, Ring1, Ring2, Ring3, Ring4 }
pub struct ProfileEnvelope {
    pub profile: Profile,
    pub max_level: AuthorityLevel,
    pub ring_cap: TrustRing,
    pub sandbox_requirement: SandboxTier,
    pub gate: ProfileGate,
}
impl ProfileEnvelope {
    pub fn matrix() -> [ProfileEnvelope; 6];
    pub fn for_profile(profile: Profile) -> ProfileEnvelope;
    pub fn permits(self, level: AuthorityLevel, ring: TrustRing) -> bool;
}
```

### Caller contract

Every IPS authorization decision MUST:

1. Determine the active `Profile` from operator config /
   capability token / mode-switch state.
2. Look up the `ProfileEnvelope` via `for_profile()`.
3. Verify `envelope.permits(requested_level, requesting_ring)`;
   refuse with operator-readable error citing the matrix row.
4. If the operation is a transition: consult
   `mode-transition-authority::gate(from, to)` for the
   TransitionGate; refuse `Forbidden`; require evidence per
   `DirectShift` / `SnapshotRequired` per the matching crate.
5. Audit via SDD-043 `CommitEnvelope` (commit_type =
   `PolicyUpdate` for transitions / toggles; `FileWrite` for
   config mutations; `ToolSideEffect` for L4 egress).

## Implementation status

**Crates**: 5 shipped, ~1639 LOC. Per-crate test coverage:
- mode-transition-authority: matrix + gate-classify
- toggle-audit-authority: toggle policy + audit-emission
- config-mutation-authority: refusal predicates + mode-aware
- recovery-snapshot-authority: snapshot-before-mutation gate
- profile-authority-gate: 6-profile matrix + permits predicate

**Caller integration**: deferred. Natural first integration target
is the perimeter-extend-signed flow (already operator-driven +
MS003-signed; would route through profile-authority-gate's
permits + SDD-043 commit-authority).

**Operator surfaces**: deferred (D-1, D-2 below).

## Test requirements

- Unit tests across the 5 crates cover the 7-level ladder, 5-ring
  composition, 6-profile matrix, 4-gate TransitionGate
  classification. ✅ shipped.
- Integration test for end-to-end (profile → permits → transition
  → snapshot → commit envelope). ⏳ deferred to caller-integration
  arc.

## Rollout

Retroactive SDD over shipped crate code.

## Open questions

- **D-1**: `selfdefctl authority {levels, rings, profiles, matrix,
  gate <from> <to>}` CLI? **Recommendation: yes**, biggest discovery
  surface yet (7+5+6+4 enumerations) but follows established
  pattern from SDD-043..048 D-1.
- **D-2**: `GET /v1/authority` HTTP discovery returning the full
  matrix (7 levels × 5 rings × 6 profiles × 4 TransitionGate
  variants)? **Recommendation: yes** after D-1.
- **D-3**: Live authority state — `GET /v1/authority/active`
  returning the operator's current Profile + capability-token's
  Ring + AuthorityLevel? **Recommendation: yes**, separate from
  D-2 (D-2 is static matrix; this is live operator state).
- **D-4**: Mode-transition log persistence — should every transition
  through `mode-transition-authority` land in the chained-audit
  log (per SDD-007)? **Recommendation: yes**, mode transitions are
  durable changes → SDD-043 PolicyUpdate commits → chained audit
  per SDD-007 invariant.
