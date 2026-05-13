# SDD-005 — Test contract for the daemon ↔ module seam

> Status: draft
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-082, and scopes the implementation
> work for F-2026-030, F-2026-031, F-2026-032, F-2026-033,
> F-2026-034, F-2026-035, F-2026-036.

## Problem

The Phase 1 audit's PR retrospective
(`docs/review/70-recent-prs-audit.md`) called out a recurring
pattern across PRs #21, #22, #23: tests verified the *unit*,
not the *flow*. The integrity-sentinel emit test wrote to a
tempdir; the `/metrics` integration test asserted substring
matches; the AI-machine track shipped without an end-to-end
test that would have caught I-007 + I-008.

That pattern is logged as **F-2026-082** (SDD-debt): "Tests
verified the unit, not the flow. Need a design doc on what
'integration-tested' means at the daemon ↔ module seam."

The audit's tests-section also flagged six concrete missing
tests / loose assertions:

- **F-2026-030** — every `module_*.rs` test runs apply.sh
  with `SELFDEF_DRY_RUN=1` but never asserts that dry-run
  produces zero side effects. A regression making dry-run
  mutate state passes silently.
- **F-2026-031** — `m12_api.rs`'s `/metrics` test asserts
  `Content-Type` with `starts_with("text/plain")` and the
  body with substring presence. Format violations could
  pass.
- **F-2026-032** — no test asserts `/metrics` accepts a
  Read-only bearer token.
- **F-2026-033** — no SIGHUP-while-processing test for the
  correlator. Hot-reload claim from `ARCHITECTURE.md` is
  unverified.
- **F-2026-034** — `selfdef-store` has no concurrent-insert
  or crash-recovery test.
- **F-2026-035** — `selfdef-nats` has no real-broker
  round-trip test. JetStream durability promises are
  unverified.
- **F-2026-036** — `selfdef-collector-tetragon` has no
  isolation test; every translation goes through daemon
  tests only.

These six are the "implement" findings under the SDD-debt
parent. This SDD frames the contract; the implementation PR
that lands the missing tests cites this SDD.

## Goals

1. Define what "integration-tested" means in this codebase
   for the seams the audit flagged: module ↔ daemon
   (eventstream JSONL), daemon ↔ Prometheus
   (/metrics), correlator hot-reload, store concurrent
   writes, NATS round-trip, collector isolation.
2. Establish a small set of test categories with explicit
   contracts an author of a new test must satisfy.
3. Provide patterns the implementation PR will use for the
   six missing tests.
4. Avoid re-litigating per-test design decisions in every
   future PR — the SDD is the appeal authority.

## Non-goals

- A general-purpose test-harness rewrite. The existing
  `cargo test` + per-crate integration test files are the
  baseline; this SDD describes patterns over them, not a
  new framework.
- A coverage target. Coverage % is not a contract. The
  contract is about *what* is tested, not *how much*.
- A property-testing or fuzzing strategy. Useful but
  separate scope.
- Performance / load tests. Useful but separate scope.

## Glossary

- **Unit test** — `#[cfg(test)] mod tests` in the same crate
  as the code under test. Exercises one function / type in
  isolation.
- **Integration test** — `crates/<name>/tests/*.rs`. Runs
  against the crate's public API as if from a downstream
  consumer.
- **Daemon integration test** — under
  `crates/selfdef-daemon/tests/`. Spins up multiple crates
  in-process and exercises an end-to-end flow.
- **Module integration test** — under
  `crates/selfdef-cli/tests/module_*.rs`. Spawns
  `bash` against an install module's `apply.sh` /
  `check.sh` / `uninstall.sh`.
- **Seam** — a place where data crosses a crate / module /
  process boundary. The audit flagged six seams as
  insufficiently tested.
- **Hermetic** — the test allocates its own tempdir, doesn't
  read or write paths outside that tempdir, and doesn't
  depend on host services beyond the binaries it explicitly
  shims.

## Current state

The codebase distinguishes three test surfaces today:

1. **In-source unit tests** (`#[cfg(test)] mod tests`) —
   the dominant style. Most crates have substantial unit
   coverage (selfdef-core has snapshot + property tests;
   selfdef-bus has lossy / multiple-subscriber tests; etc).
2. **Per-crate integration tests** (`tests/*.rs` per crate)
   — selfdef-cli (12 files), selfdef-daemon (8), selfdef-api
   (1), selfdef-correlator (1), selfdef-core (2). The other
   15 crates have zero.
3. **Replay corpora** (`tests/replay/<source>/*.jsonl`) —
   shared by daemon and per-collector tests. Discovery-style
   walking is used for sigma rule tests; ad-hoc loading for
   collector tests.

What's missing is **a written contract** for what each
surface is responsible for. The audit's findings make the
absence concrete:

- The module integration tests assume dry-run honesty without
  asserting it (F-2026-030).
- The API metrics integration test substring-matches the
  Prometheus exposition without asserting format strictness
  (F-2026-031).
- The capability gating tests cover `/status` but not
  `/metrics` (F-2026-032).
- The correlator integration test loads rules but never
  reloads them under live traffic (F-2026-033).
- The store has no integration tests at all (F-2026-034).
- The NATS bridge has unit tests for subject layout but no
  end-to-end test (F-2026-035).
- The Tetragon collector is exercised only via the daemon
  pipeline; no isolation test would catch a regression in
  its translation logic (F-2026-036).

## Design alternatives considered

### Alternative A — Write down a test categorisation; revise existing test files to match

Define test categories. Audit each existing test against
the categorisation. File mismatches as their own findings.

**Pros**
- Comprehensive.
- Forces a pass over every test.

**Cons**
- Massive scope. Six findings turn into dozens.
- Low marginal value over just shipping the missing tests.
- The categorisation itself isn't useful if no future test
  is written against it.

### Alternative B — Just write the seven missing tests

Skip the contract; write the tests F-2026-030..-036 ask for,
each in its respective crate.

**Pros**
- Smallest scope; fastest to ship.
- Concrete close on six findings.

**Cons**
- Doesn't address F-2026-082 (the SDD-debt parent). The next
  module/feature PR will produce the same pattern of
  "tests verified the unit, not the flow" because nothing
  has changed about how authors decide what to test.
- The seven tests get written ad-hoc, each in its own style,
  reinforcing the existing helper-duplication problem
  (F-2026-060).

### Alternative C — Contract + patterns + reference implementations (recommended)

- Define a small contract: four test categories, each with
  an explicit "what counts as enough" rule.
- Define three shared patterns the implementation PR will
  use: a dry-run-negative wrapper, a Prometheus exposition
  parser, a real-broker NATS test fixture.
- The implementation PR ships the seven missing tests using
  those patterns and updates the existing test files where
  they fall outside contract.

This addresses both the F-2026-082 parent and the seven
implementation findings. Larger scope than B but
proportionate to the audit's concern.

## Recommended design

**Alternative C.**

## Detailed design

### D-1 — Test categories

Four categories, each with an explicit contract:

**Category 1 — Translation tests.** Lives in the source
crate's `#[cfg(test)] mod tests` or in
`crates/<name>/tests/translation.rs`. Asserts the crate
correctly translates its input format (Tetragon JSON,
Suricata EVE, journald, auditd) into `selfdef_core::Event`.
Contract: every translation branch has at least one
positive test (input shape, expected Event field
projection) and at least one tolerance test (input shape
that's malformed in a documented way → no panic, logged
warning).

**Category 2 — Pipeline tests.** Lives in
`crates/selfdef-daemon/tests/`. Spins up a minimal
in-process pipeline of `bus + collector + correlator +
responder + store` and asserts a full flow (event in,
expected effect at the end). Contract: every "promise" the
daemon makes operator-side (a finding lands in store with
the right severity, NotifyAction is invoked, the API
returns the expected JSON) must be exercised by at least
one pipeline test that would fail if the promise regressed.

**Category 3 — Module-script tests.** Lives in
`crates/selfdef-cli/tests/module_*.rs`. Spawns `bash` on a
module's `install/*.sh` against a hermetic tempdir.
Contract: for each script, both the **dry-run-negative**
(SELFDEF_DRY_RUN=1 produces zero on-disk delta) and the
**live-positive** (SELFDEF_DRY_RUN=0 produces the
documented effect) paths are asserted.

**Category 4 — Seam tests.** Lives in
`crates/selfdef-daemon/tests/` (when the seam crosses a
process boundary that's still in-tree) or in a new
`crates/selfdef-daemon/tests/seam_*.rs` family. Asserts
two-side behaviour at a seam: the writer side produces what
the reader side parses, including the failure modes.
Contract: every seam the audit flagged
(`docs/review/40-integration-audit.md` Flows 1–6) has at
least one seam test.

The four categories overlap deliberately. A pipeline test
might also exercise translation; a seam test might use a
module-script test as one of its inputs. The contract is
about **at-least-one-of** coverage, not exclusive
categorisation.

### D-2 — Three shared patterns

#### D-2a — `dry_run_must_be_a_noop` wrapper

A helper in `crates/selfdef-cli/tests/common/mod.rs`
(creating that file in the process) that takes a module's
apply.sh path + a fixture builder, runs apply with
`SELFDEF_DRY_RUN=1`, snapshots the tempdir before and after,
and asserts byte-equality.

Closes F-2026-030. Used by every module-script test that
already exercises the live-positive path.

#### D-2b — Prometheus exposition parser

The `m12_api.rs` `/metrics` tests today substring-match.
Replace with a small parser fixture that:

- Verifies `Content-Type` matches
  `text/plain; version=0.0.4; charset=utf-8` (exact, not
  prefix).
- Parses the body into `(name, labels, value)` tuples.
- Asserts presence of expected metrics by name + label set.
- Asserts absence of duplicate `(name, labels)` keys
  (Prometheus invariant).

The parser is ~60 lines of rust + a small test-only crate
dep, or a hand-rolled parser if no suitable crate is
already in workspace. The implementation PR picks; the
SDD's contract is "format-strict, not substring".

Closes F-2026-031. Touches `m12_api.rs:469-482`.

#### D-2c — Real-broker NATS fixture

The audit's F-2026-035 needs a real `nats-server` binary.
Approach: a `crates/selfdef-nats/tests/integration.rs`
that:

- Skips with `#[ignore]` if `nats-server` is not on PATH
  (so CI without the binary stays green).
- When the binary is present, spawns it on a free port,
  waits for it to bind, runs the bridge against it,
  publishes one event from "host A" and asserts it arrives
  on "host B" (two `Bridge` instances pointed at the same
  broker, distinct host_tag values).
- Tears down the broker on test exit.

CI changes: install `nats-server` in the test job (one
`apt install` line). The skip-when-missing pattern means
contributors without it locally don't get blocked.

Closes F-2026-035.

### D-3 — Implementation PR breakdown

The implementation PR that lands these tests should NOT
land them in one diff; the audit's R-002 finding warns
against PRs too large to verify end-to-end. Suggested
sequence:

1. **PR Test-1**: `tests/common/mod.rs` + the
   `dry_run_must_be_a_noop` wrapper (D-2a). Adopts it in
   one module-test file as a reference. Closes F-2026-030
   for that one module; the others follow in their own
   small PRs.
2. **PR Test-2**: Prometheus exposition parser (D-2b).
   Touches only `m12_api.rs`. Closes F-2026-031,
   F-2026-032 (the same parser supports the read-cap
   gating test).
3. **PR Test-3**: real-broker NATS fixture (D-2c). New
   `selfdef-nats/tests/integration.rs`. Closes F-2026-035.
4. **PR Test-4**: SIGHUP-under-traffic correlator test.
   New `crates/selfdef-correlator/tests/hot_reload.rs`.
   Closes F-2026-033.
5. **PR Test-5**: store concurrent-insert + crash-recovery
   tests. New `crates/selfdef-store/tests/concurrent.rs`.
   Closes F-2026-034.
6. **PR Test-6**: Tetragon collector isolation tests. New
   `crates/selfdef-collector-tetragon/tests/translation.rs`.
   Closes F-2026-036. Aligns with SDD-001's collector
   work (they likely land together).

Each PR is small enough to verify against this SDD's
contract.

### D-4 — Linkage to SDD-001

SDD-001's D-4 specifies an AI-machine end-to-end test in
`crates/selfdef-daemon/tests/m_ai_machine.rs`. Under the
categorisation in D-1, that's a Category 2 (pipeline) test
plus a Category 4 (seam) test combined. The SDD-001
implementation PR satisfies F-2026-006 directly; the
contract here makes it explicit that future similar
modules (host-hardening-guard, etc.) must ship their own
pipeline + seam tests by default.

### D-5 — Where the contract lives

A new `docs/dev/test-contract.md` (under `docs/src/dev/` to
appear in mdbook) carries the four categories + the three
patterns as operator-authoring guidance. The SDD itself is
the design rationale; the doc is the runbook for
contributors writing new tests.

## Test plan (this is a meta-test plan)

The SDD's own contract:

1. `docs/dev/test-contract.md` exists and matches D-1 + D-2.
2. `crates/selfdef-cli/tests/common/mod.rs` exists with the
   `dry_run_must_be_a_noop` helper.
3. `crates/selfdef-api/tests/m12_api.rs` uses the
   exposition parser; the substring assertions for the
   `/metrics` body are gone.
4. `crates/selfdef-nats/tests/integration.rs` exists and is
   `#[ignore]`-gated on `nats-server` presence.
5. `crates/selfdef-correlator/tests/hot_reload.rs` exists.
6. `crates/selfdef-store/tests/concurrent.rs` exists.
7. `crates/selfdef-collector-tetragon/tests/translation.rs`
   exists.
8. Each of the six implementation PRs cites SDD-005 in its
   body.

## Rollout / migration

- No public API changes. New tests + one new helper module.
- CI may need `nats-server` installed in the test job. If
  not, the test stays `#[ignore]`-gated and runs locally.
- Existing tests are not deleted. Where they overlap a new
  pattern (substring-matching the metrics body), the new
  test supersedes; the substring assertion can be removed
  in the same PR.

## Risks

- **R-1 — the contract becomes a paperwork burden** for
  small fixes. Mitigated by making it a runbook for new
  tests, not a gate on existing ones. PRs that don't add
  tests don't trigger the contract.
- **R-2 — the real-broker NATS test makes CI flaky** if
  the broker takes too long to bind. Mitigated by the
  `#[ignore]`-by-default pattern + a generous wait-for-bind
  window with explicit timeout.
- **R-3 — the dry-run-negative wrapper false-positives**
  on file-system metadata changes (mtime, atime). Mitigated
  by snapshotting only file paths + sha256 of contents,
  not full stat.

## Open questions

- **Q-A** — Should the contract require both a pipeline
  test AND a seam test for every new module? Probably yes
  for modules that introduce a new event source; no for
  modules that don't (e.g. a future `host-baseline`
  module that's pure passive observation).
- **Q-B** — Does the test-contract doc go under
  `docs/src/dev/` (visible in mdbook to contributors) or
  under `docs/sdd/` (alongside the SDDs as design context)?
  Today: dev. Both is also fine.
- **Q-C** — How do we keep the contract from going stale?
  Suggestion: every Phase-N audit (yearly) re-asks "do
  these categories still match the codebase?" The current
  audit at `docs/review/` is Phase 1; future Phases re-run
  the seven explorers against an updated inventory and
  surface contract drift as findings.

## Appendix — interaction with other SDDs

- SDD-001 implementation PR carries the AI-machine
  pipeline + seam test (Category 2 + 4). This SDD makes
  that test pattern reusable for future modules.
- SDD-002 implementation PR adds `[daemon_requires]` and
  the validator. Both unit tests (Category 1) and an
  integration test (Category 3 — the apply.sh refusal on
  mismatch) per the SDD-002 D-3 / D-4 spec. Both align with
  this contract.
- SDD-003 implementation PR's profile-aware
  multi-instance check is a Category 1 (manifest
  deserialisation) + Category 3 (resolver refusal at apply
  time) shape. Aligns.
- SDD-004 is doc-only; no test contract implication
  beyond review-style verification.
