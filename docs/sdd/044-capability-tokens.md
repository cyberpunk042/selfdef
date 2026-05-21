# SDD-044 — Capability tokens — typed authority handles (MS035)

> Status: **implemented** — `selfdef-capability-token-store` crate
> (215 LOC, 9 passing tests) + `selfdef-capability-word` crate (496
> LOC) + `selfdef-capability-mirror` crate (416 LOC) +
> `selfdef-tool-capability-policy` crate (12 tests) +
> `selfdef-profile-authority-gate` crate (660 LOC) shipped. Stage-2
> SDD authored retroactively over the shipped Rust crates to close
> the "code exists but no SDD" gap identified in the 2026-05-21
> MS013 charter-tracking survey.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS035 (catalogued in
> `backlog/milestones/MS035-capability-tokens-typed-authority-handles.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain
> integrity), SDD-043 (commit-authority — uses capability tokens
> as the `actor` field's authority handle).
> Cross-repo: sovereign-os capability-token canon (MS007 typed-mirror
> bridge); selfdef applies tokens to IPS-side authorization decisions
> only.

## Problem

The IPS issues durable changes through many code paths (perimeter
extensions, scheduler force-routes, modules apply, capability
revocations). Each path needs to answer "is this actor authorized
to do this thing right now?" Without typed capability tokens:

1. **Implicit authority** — every call site has to re-construct an
   authority check, inviting drift + bypass.
2. **No scope discipline** — a process given "read events" could
   be silently elevated to "kill processes" without an explicit
   capability handle.
3. **No revocation flow** — operator-issued authority can't be
   pulled back surgically; the choice is "rotate everything" or
   "leave it."
4. **No expiry** — credentials live forever, against the principle
   of least authority + bounded blast radius.
5. **No mirror** — sovereign-os can't observe selfdef's authority
   state for cross-repo posture views without a typed mirror.

## Goals

1. Issue typed capability tokens with `{id, holder, scopes:BTreeSet,
   expires_at_ms, revoked}` (R03492-R03495 of dump 3489-3527).
2. Verify with a 5-verdict response: `Ok` / `Expired` / `Revoked`
   / `Unknown` / `MissingScope` — the call site sees exactly which
   precondition failed.
3. Bounded TTL (expires_at_ms is non-optional — every token has an
   expiry).
4. Revocation flow — operator can revoke a specific token by id
   without rotating the whole store.
5. Audit-chain integration — every issue + revoke is a Commit per
   SDD-043 (commit_type = CapabilityRegistry per future expansion;
   modeled today as PolicyUpdate).
6. Cross-repo mirror — `selfdef-capability-mirror` projects token
   state for sovereign-os consumption via MS007 typed-mirror bridge.
7. Scope vocabulary discipline — `selfdef-capability-word` provides
   the canonical scope strings; ad-hoc strings rejected.

## Non-goals

- This SDD does NOT cover the operator's own GitHub-PAT / Cloudflare-
  token / Tailscale-key lifecycle. Those are configured at the daemon
  level; capability tokens model the daemon's INTERNAL authority
  handles only.
- Multi-host token federation is deferred. The MS035 catalog scopes
  to a single host's IPS instance; sovereign-os's MS056 canon owns
  cross-host federation.

## Alternative designs considered

**Alt 1 (rejected): role-based string tags.** "If holder == 'admin'
then allow X". Rejected — no expiry, no revocation, no scope
intersection, no audit trail.

**Alt 2 (rejected): wide JWT tokens.** Self-contained tokens with
embedded claims. Rejected — no revocation flow without a deny-list
ledger, plus they're large and frequently leaked through logs.

**Alt 3 (CHOSEN): server-side capability store with typed verdicts.**
Tokens live in the daemon-owned `CapabilityTokenStore`; each call
site presents the id + needed scope; the store returns a typed
`CheckVerdict`. Combined with `selfdef-capability-word` for scope
discipline + `selfdef-capability-mirror` for cross-repo state.

## Recommended design

### Types (shipped)

```rust
// selfdef-capability-token-store
pub struct Token {
    pub id: String,
    pub holder: String,
    pub scopes: BTreeSet<String>,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

pub enum CheckVerdict { Ok, Expired, Revoked, Unknown, MissingScope }

pub struct CapabilityTokenStore {
    pub schema_version: String,
    pub tokens: BTreeMap<String, Token>,
}

impl CapabilityTokenStore {
    pub fn new() -> Self { ... }
    pub fn issue(&mut self, id, holder, scopes, expires_at_ms) -> Result<()>;
    pub fn revoke(&mut self, id) -> Result<()>;
    pub fn check(&self, id, scope, now_ms) -> CheckVerdict;
}
```

### Companion crates

- `selfdef-capability-word` — canonical scope vocabulary; every
  scope string passed to `issue()` must come from this enumeration.
  Today: 496 LOC + classifier helpers.
- `selfdef-capability-mirror` — typed read-only projection for
  sovereign-os consumption via MS007 typed-mirror bridge. 416 LOC.
- `selfdef-tool-capability-policy` — per-tool capability requirements
  (12 tests). When a tool is invoked, the policy crate looks up
  required scopes, then the call site calls `check()` against the
  presented token.
- `selfdef-profile-authority-gate` — gates profile transitions on
  the holding actor's capability scopes (660 LOC).

### Caller contract

Every IPS authority-decision point MUST:

1. Determine the required scope from `selfdef-capability-word`.
2. Read the token id from the operator-presented header / config.
3. Call `store.check(id, scope, now_ms)`.
4. Branch on `CheckVerdict`:
   - `Ok` → proceed; audit the action via SDD-043 commit envelope.
   - `Expired` / `Revoked` / `Unknown` / `MissingScope` → refuse;
     log the verdict to the audit chain; return operator-readable
     error citing the verdict.

## Implementation status

**Crates**: shipped + tested:
- `selfdef-capability-token-store` (215 LOC, 9 tests)
- `selfdef-capability-word` (496 LOC)
- `selfdef-capability-mirror` (416 LOC)
- `selfdef-tool-capability-policy` (12 tests)
- `selfdef-profile-authority-gate` (660 LOC)

**Caller integration**: deferred. Same sequence as SDD-043 — get the
crates right + tested, then migrate call sites. The natural first
caller-integration target is the `selfdefctl perimeter
extend --signed` flow (already operator-driven + MS003-signed).

**Operator surfaces**: deferred (D-1, D-2 below).

## Test requirements

- 9 unit tests in `selfdef-capability-token-store` cover issue +
  revoke + check across all 5 verdict variants. ✅ shipped.
- 12 unit tests in `selfdef-tool-capability-policy` cover per-tool
  scope requirements. ✅ shipped.
- Integration test verifying a mocked call site refuses to proceed
  on non-`Ok` verdicts. ⏳ deferred to caller-integration arc.

## Rollout

This SDD is authored retroactively over shipped crate code. No new
rollout for the crates themselves. Caller-integration is the
operator-supervised follow-up arc.

## Open questions

- **D-1**: Should `selfdefctl capability-tokens {list, issue, revoke,
  check <id> <scope>}` ship as a CLI surface? **Recommendation: yes,
  Stage-3 follow-up**. Mirrors the `selfdefctl commit-authority`
  pattern from SDD-043 D-1; lets operators inspect + manage tokens
  offline without daemon access.
- **D-2**: `GET /v1/capability-tokens` HTTP discovery surface
  exposing the scope vocabulary (from `selfdef-capability-word`)
  + the CheckVerdict enum? **Recommendation: yes after D-1 CLI**,
  same pattern as SDD-043 D-3.
- **D-3**: Persistence model — `CapabilityTokenStore` is currently
  in-memory. Operator-issued tokens lost on daemon restart. Should
  the store back to disk (`/var/lib/selfdef/capability-tokens.json`,
  signed) + reload on start? **Recommendation: yes**; defer to a
  dedicated arc (touches MS003 signing chain + boot-time
  initialization).
- **D-4**: Token-issue authorization — who can call `store.issue()`?
  The current crate trusts the caller. **Recommendation**: gate via
  the existing CommitAuthority high-risk classifier — token issuance
  IS a durable change (PolicyUpdate commit_type) so the SDD-043
  triple-gate applies.
