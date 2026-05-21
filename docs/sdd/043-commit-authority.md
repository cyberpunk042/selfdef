# SDD-043 — Commit authority — IPS-side durable-change discipline (MS041)

> Status: **implemented** — `selfdef-commit-authority` crate (473 LOC,
> 22 passing tests) shipped, captures the 8 commit types + 5 mandatory
> fields + 3 high-risk gates + classifier rules per the avx-plus-plus
> dump lines 17389-17421 + MS041 catalog. Operator-facing HTTP surface
> + dashboard panel deferred per Stage-3 follow-up; the crate is the
> mandatory consumption point for any selfdef component making a
> durable change (network rules, filesystem mounts, capability
> registry mutations, sandbox tier upgrades, audit catalog edits).
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21 (Stage-2 SDD authored retroactively over
> shipped crate code — closes the "code exists but no SDD" gap
> identified in the 2026-05-21 MS013 charter-tracking survey).
> Implements milestone: MS041 (catalogued in
> `backlog/milestones/MS041-commit-authority-durable-change-discipline.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain
> integrity), SDD-014 (shared-audit-summary channel)
> Cross-repo: sovereign-os M056 is the canonical-authority model;
> selfdef receives the typed mirror via MS007 + enforces commit-
> authority for its OWN durable mutations only (project-boundary rule
> from operator standing direction 2026-05-19).

## Problem

The IPS makes durable changes — network-boundary rule installs,
filesystem-boundary mount additions, capability-token registry
mutations, sandbox-tier upgrades, audit-catalog edits, signing-key
rotations. Each one is a "commit" per the dump's doctrine
("A commit is any durable change" — dump 17389). Without a uniform
envelope discipline:

1. Operators can't audit who made what change (no actor field).
2. Post-incident analysis can't determine intent (no reason field).
3. Rollback is ad-hoc (no rollback_status field).
4. Cross-cutting trace (MS049 trace_ref) can't be threaded through.
5. High-risk changes go through with the same friction as low-risk
   ones (no classifier; no triple-gate enforcement).

## Goals

1. Enforce a uniform `CommitEnvelope` shape across every IPS durable
   mutation point. 5 mandatory fields per R09602..R09606 (actor,
   reason, policy_decision, rollback_status, trace_ref) on every
   commit; refuses to mint without them.
2. Classify high-risk commits via F04871..F04875: adapter
   promotion = always, L6 Persist = always, cloud exposure = always,
   production L5 = always, autonomous L5 outside predeclared gate
   = always.
3. Enforce the high-risk triple-gate per R09607..R09609 + E0420
   (snapshot + test/eval + oracle-or-human).
4. Sign every envelope with MS003 (commit signatures are MANDATORY,
   not optional).
5. Refuse `rollback_status=Unavailable` on high-risk commits per
   F04852 (you cannot make a high-risk durable change without a way
   to undo it).
6. Preserve the doctrinal phrase verbatim per R09601 — runtime
   `assert_doctrine_intact("A commit is any durable change")`
   guards against silent drift in code comments or test fixtures.

## Non-goals

- This SDD does NOT cover cross-repo commit semantics — those live
  in sovereign-os M056 (canonical authority model). Selfdef receives
  the M056 contract via MS007 typed mirrors + applies it to IPS-side
  mutations only.
- This SDD does NOT cover operator-driven git-commit discipline
  (that's the operator's own workflow). The commit envelope models
  daemon-internal durable changes.
- No GUI / dashboard surface in this round; operator-discovery via
  `selfdefctl` + future HTTP `GET /v1/commit-authority` are
  Stage-3 follow-ups (D-1, D-2 below).

## Alternative designs considered

**Alt 1 (rejected): inline `(actor, reason, …)` tuple at every call
site.** Initially appealing — no new crate. Rejected because:
- 8 commit types × per-call-site enforcement means 8+ places need
  to be kept in lockstep on every doctrine change.
- No central place to enforce the high-risk classifier.
- Signature verification logic gets duplicated.

**Alt 2 (rejected): macro-based commit-envelope-builder.** Macros hide
the field-by-field contract; operators reading the source can't see
the 5 mandatory fields without expanding the macro. The struct-based
approach (`CommitEnvelope { actor, reason, … }`) is read-trivial.

**Alt 3 (CHOSEN): `selfdef-commit-authority` crate with
`CommitEnvelope` struct + `validate(env)` + `is_high_risk(env)`.**
Every IPS durable-change call site constructs an envelope and calls
`validate()` before persisting. The classifier and gate logic live
in one place. 22 unit tests cover every error path.

## Recommended design

### Types (shipped in `crates/selfdef-commit-authority/src/lib.rs`)

```rust
pub enum CommitType {
    FileWrite,
    MemoryWrite,
    PolicyUpdate,
    ProfileUpdate,
    AdapterPromotion,
    CloudExposureLog,
    ToolSideEffect,
    WorkflowCompletion,
}

pub enum RollbackStatus {
    Reversible,        // operator can undo via `selfdefctl rollback <commit>`
    Reversed,          // already undone (audit log entry)
    Unavailable,       // no rollback path — F04852 refuses high-risk
}

pub enum PolicyOutcome { Allowed, AllowedWithCaveats, Denied }

pub struct HighRiskGate {
    pub snapshot_id: String,
    pub test_eval_id: String,
    pub oracle_or_human: String,
}

pub struct CommitEnvelope {
    pub commit_type: CommitType,
    pub actor: String,           // MS003 fingerprint
    pub reason: String,           // human-readable
    pub policy_decision: PolicyOutcome,
    pub rollback_status: RollbackStatus,
    pub trace_ref: String,        // MS049 trace
    pub high_risk_gate: Option<HighRiskGate>,
    pub profile: Profile,
    pub authority_level: AuthorityLevel,
    pub within_autonomous_gate: bool,
    pub signature: String,        // MS003 over canonical-JSON
}
```

### Public functions

- `is_high_risk(&CommitEnvelope) -> bool` — per F04871..F04875
  classifier.
- `validate(&CommitEnvelope) -> Result<(), CommitError>` — refuses
  empty-mandatory-field, missing-signature, missing-triple-gate-
  when-high-risk, rollback-unavailable-on-high-risk.
- `assert_doctrine_intact(observed: &str) -> Result<(), CommitError>` —
  guards the doctrinal phrase against silent drift.

### Caller contract

Every IPS durable-change point MUST:

1. Construct a `CommitEnvelope` with all 5 mandatory fields populated.
2. Call `is_high_risk()` to classify; if true, populate
   `high_risk_gate` with all 3 triple-gate evidence items.
3. Sign with MS003 over the canonical-JSON encoding (excluding the
   `signature` field).
4. Call `validate()` and refuse-to-commit on any `Err(_)`.
5. Persist the envelope to the audit chain (SDD-007 chain integrity).

## Implementation status

**Crate**: `crates/selfdef-commit-authority/` — 473 LOC, 22 passing
unit tests covering every classifier branch + every error path +
doctrine-drift detection.

**Caller integration**: deferred. The current 30+ shipped sandbox /
authority / boundary crates do not yet route durable changes
through this envelope. Migration is the operator-supervised
follow-up arc; each call site needs an audit + envelope-construction
patch. This is a deliberate sequence — get the contract crate right
+ tested first, then wire callers.

## Test requirements

- 22 existing unit tests in the crate cover every classifier branch +
  every `validate()` error variant + doctrine-drift detection.
  ✅ shipped + passing.
- Integration test verifying that a mocked "durable change" call
  site refuses to persist when validate() returns Err. ⏳ deferred
  to D-2 (caller integration arc).

## Rollout

This SDD is authored retroactively over shipped crate code; the
crate has been usable since its initial scaffold. No new rollout
required for the crate itself. Caller-integration rollout is
sequenced as an operator-supervised arc.

## Open questions

- **D-1**: Should `selfdefctl commit-authority {types, validate <file>,
  classify <file>}` ship as a CLI surface? **Recommendation: yes,
  small Stage-3 follow-up** — gives operators offline-validation of
  envelope drafts against the crate's contract.
- **D-2**: Caller-integration arc ordering — which durable-change
  point gets migrated first? **Recommendation**: the perimeter
  extension-create flow (`selfdefctl perimeter extend --signed`)
  is a natural first target since it's already operator-driven,
  signed via MS003, and has a clear actor + reason.
- **D-3**: HTTP discovery surface — `GET /v1/commit-authority` for
  returning the schema as JSON (commit_types + policy_outcomes +
  rollback_statuses + high_risk_rules). **Recommendation**: defer
  until D-1 CLI surface lands — same shape, smaller blast radius.
