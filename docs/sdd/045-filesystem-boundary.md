# SDD-045 — Filesystem boundary — explicit-exchange directory discipline (MS037)

> Status: **implemented** — `selfdef-filesystem-boundary` crate (496
> LOC) shipped with the full E0371-E0376 doctrine encoded:
> 3-dir exchange + 6-step host import pipeline + 5-field patch
> schema + 6-check application predicates + 2 verbatim doctrinal
> phrases. Stage-2 SDD authored retroactively over the shipped crate.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS037 (catalogued in
> `backlog/milestones/MS037-filesystem-boundary.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain),
> SDD-043 (commit-authority — every patch application is a Commit),
> SDD-044 (capability tokens — patch-application authority gated
> via tokens).
> Cross-repo: sovereign-os filesystem-boundary canon mirrored via
> MS007 typed-mirror bridge.

## Problem

The IPS lets agent code (running in a sandboxed VM per MS032) propose
filesystem mutations on the host. Without explicit-exchange
discipline:

1. **Implicit writes** — agents could write anywhere the VM can see,
   bypassing host policy.
2. **No diff visibility** — operators can't see what changed before
   the change lands; post-hoc audit only.
3. **No oracle gate** — risk-flagged patches go through with the
   same friction as routine renames.
4. **No path-traversal defense** — naïve `cp` could escape the
   workspace via `../` or symlinks.
5. **No proposal/final distinction** — VM-written state becomes
   binding without operator confirmation.

## Goals

1. Enforce a 3-directory explicit-exchange protocol per E0372 dump
   3556-3558:
   - `/ai-exchange/inbox`  — host → VM input drop (M00942)
   - `/ai-exchange/outbox` — VM → host output drop (M00943)
   - `/ai-exchange/artifacts` — binary outputs (M00944)
2. Run every host-side patch through a 6-step import pipeline per
   E0374 dump 3566-3572:
   parse → scan → diff → policy-check → oracle-review (conditional)
   → commit.
3. Validate patches against a 5-field schema per E0375 dump
   3578-3584: unified diff, metadata, declared files touched, test
   notes, risk flags.
4. Run 6 application predicates per E0376 dump 3588-3594:
   paths inside workspace / no forbidden files / diff parses /
   policy allows writes / branch budget permits / user approval if
   required.
5. Preserve doctrines verbatim per E0371 + E0373:
   - "Use explicit exchange directories"
   - "VM writes proposals, not final state"

## Non-goals

- This SDD does NOT cover sandbox-VM filesystem layout (that's MS032
  sandbox-tier-policy + the per-tier mount strategy).
- It does NOT cover encrypted-at-rest disciplines (separate arc).
- It does NOT cover operator's git-on-host workflow — the boundary
  is between SANDBOXED AGENT WORK and HOST STATE; operator-driven
  git commits to the host directly are out of scope.

## Alternative designs considered

**Alt 1 (rejected): bind-mount the workspace into the VM.** Lets the
agent write anywhere in the workspace. Rejected — no diff visibility,
no oracle gate, no proposal/final distinction.

**Alt 2 (rejected): per-file shared memory pipe.** Each file gets a
named pipe between VM and host. Rejected — doesn't scale beyond a
handful of files; doesn't carry test-notes / risk-flags metadata.

**Alt 3 (CHOSEN): explicit exchange directories + patch envelopes.**
VM writes to `outbox/` as unified-diff patch envelopes. Host pulls
+ scans + diffs + policy-checks + (conditionally) oracle-reviews +
commits via SDD-043 envelope. Combined with `selfdef-filesystem-
boundary::assert_path_inside_workspace` for traversal defense.

## Recommended design

### Types (shipped in `crates/selfdef-filesystem-boundary/src/lib.rs`)

```rust
pub enum ExchangeDir {
    Inbox,      // /ai-exchange/inbox
    Outbox,     // /ai-exchange/outbox
    Artifacts,  // /ai-exchange/artifacts
}

pub enum ImportStep {
    Parse, Scan, Diff, PolicyCheck, OracleReview, Commit,
}

pub struct PatchEnvelope {
    pub unified_diff: String,
    pub metadata: BTreeMap<String, String>,
    pub declared_files_touched: BTreeSet<String>,
    pub test_notes: String,
    pub risk_flags: BTreeSet<String>,
}

pub struct PredicateChecks {
    pub paths_inside_workspace: bool,
    pub no_forbidden_files: bool,
    pub diff_parses: bool,
    pub policy_allows_writes: bool,
    pub branch_budget_permits: bool,
    pub user_approval_required: bool,
    pub user_approval_granted: bool,
}
```

### Public functions

- `assert_path_inside_workspace(workspace, candidate)` — defeats
  directory traversal + symlink escape.
- `validate_patch(env, workspace)` — runs the 5-field schema
  validation + asserts every `declared_files_touched` path is
  inside the workspace.
- `advance_step(current, target)` — enforces the 6-step pipeline
  ordering; refuses backward jumps + skips.
- `assert_application_ready(checks)` — refuses the commit step
  unless all 6 application predicates are satisfied.
- `assert_doctrines_intact(explicit, vm_writes)` — drift-detect
  guard for the 2 verbatim doctrinal phrases.

### Caller contract

Every host-side patch application MUST:

1. Read the patch from `outbox/` as a `PatchEnvelope`.
2. Validate via `validate_patch()`.
3. Advance through `ImportStep::Parse → Scan → Diff → PolicyCheck`
   (always); → `OracleReview` (conditional on `risk_flags`); → `Commit`.
4. Construct `PredicateChecks` with the 6 booleans observed at the
   commit-time gate.
5. Call `assert_application_ready()` and refuse-to-commit on Err.
6. On success: construct an SDD-043 `CommitEnvelope` (commit_type =
   `FileWrite`); call `selfdef_commit_authority::validate()`; if
   high-risk, populate the triple-gate from the oracle-review +
   test-notes + user-approval evidence.

## Implementation status

**Crate**: shipped (496 LOC). 6 public functions + 4 type
enumerations + 2 doctrine-phrase constants.

**Caller integration**: deferred. The host-side patch-application
pipeline is the natural first caller; it doesn't yet route through
this crate — it should.

**Operator surfaces**: deferred (D-1, D-2 below).

## Test requirements

- Unit tests covering each public function's error paths. ✅
  shipped (verified by `cargo test -p selfdef-filesystem-boundary`).
- Integration test verifying a mocked patch flow refuses on each
  predicate failure. ⏳ deferred to caller-integration arc.

## Rollout

Retroactive SDD over shipped crate code. No new rollout for the
crate itself.

## Open questions

- **D-1**: `selfdefctl filesystem-boundary {doctrine, validate
  <patch>, predicates <json>}` CLI surface? **Recommendation: yes**,
  mirrors SDD-043 D-1 / SDD-044 D-1 patterns.
- **D-2**: `GET /v1/filesystem-boundary` HTTP discovery surface
  returning the 3-dir layout + 6-step pipeline + 5-field schema +
  6 predicates as JSON? **Recommendation: yes** after D-1.
- **D-3**: How does the workspace path get into the crate? Today
  it's a parameter to `assert_path_inside_workspace`. Should the
  daemon's `selfdef-config` block carry the workspace path, and
  the crate read it from there? **Recommendation: yes**, defer to
  caller-integration arc.
- **D-4**: Forbidden-file list — `no_forbidden_files` predicate is
  authored by the caller today. Should there be a canonical
  default deny-list (`.ssh/`, `.gnupg/`, `/etc/shadow`, etc.) in
  the crate? **Recommendation: yes**, ship as a const list with
  operator override via config.
