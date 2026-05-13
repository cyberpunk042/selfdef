# Recent PRs retrospective (#19–#25)

> Scope: each merged PR on the feature branch since the audit
> window opened. Per-area finding ids prefix `R-`.
> Method: this is a first-person retrospective by the author who
> shipped these PRs. The goal is honest accounting, not blame —
> several of these PRs left work unfinished because the cadence
> rewarded "merged" over "completely wired", and that pattern is
> now visible.

The PRs are listed in chronological order. For each: what was
**promised** in the PR body, what **landed** in the diff, what
was **deferred** (acknowledged in the PR or follow-up doc), and
what was **silently left undone** (the honest part).

---

## PR #19 — `selfdef-cli: manifest phase field (pre|main|post)`

**Promised**

Manifest `phase` knob, phase-aware resolver (`pre → main →
post`), cross-phase dependency validation (a `pre` module may
not depend on a `main` module), unit tests.

**Landed**

All of the above. The resolver phase-bucket-then-topo-sort logic
landed in `selfdef-cli/src/modules.rs`. `integrity-sentinel`'s
manifest was bumped to `phase = "pre"` in the same PR (the
canonical user of the feature).

**Deferred**

None claimed.

**Silently undone**

- Phase semantics never made it to `ARCHITECTURE.md`. The
  apply-lifecycle prose still reads as a flat topo sort.
- No daemon-side integration test exists that exercises a
  three-phase apply (pre + main + post) end-to-end against the
  *real* `selfdefctl modules apply` binary; the unit tests
  cover the resolver but the CLI smoke test is single-phase.

**Honest assessment**

Good PR. Resolver logic is clean. The follow-up doc work was
slipped (D-004 in the docs ledger captures it).

---

## PR #20 — `selfdefctl modules uninstall`

**Promised**

Reverse-order tear-down, `--confirm <hostname>` gating,
`--dry-run` preview, `--only` / `--except` filters,
missing-script tolerance (modules without uninstall.sh report
`skipped`).

**Landed**

All of the above. Hermetic integration tests in
`tests/cli_modules_uninstall.rs` cover ordering, confirmation
refusal, hostname mismatch, matching-confirm happy path,
`--only` filter, and the skipped-without-script case.

**Deferred**

None.

**Silently undone**

- The `panic` subcommand's `--confirm` shares the same hostname
  semantic but uses a copy-paste of the validation logic, not a
  shared helper. No refactor in this PR. **(R-001)**

**Honest assessment**

Solid. Hostname-match confirmation pattern is the right shape.

---

## PR #21 — `events emit` + integrity-sentinel notifier wiring

**Promised**

New `selfdefctl events emit` subcommand; `integrity-sentinel`
emits OCSF Detection Findings via the new subcommand when
`event_stream_path` is set; defaults that "match the daemon's
default" for the eventstream collector; 5 unit + 2 integration
tests.

**Landed**

The subcommand. The optional notifier wiring in
`integrity-sentinel`. The unit tests. The integration tests.

**Deferred**

The PR body says: "Leave `event_stream_path` unset to suppress
emission". Read charitably, the operator is expected to opt in.

**Silently undone**

- **(I-001) — important**: the shipped profiles
  (`strict.toml`, `warn-only.toml`) carry `event_stream_path`
  commented out. Out of the box, the module never emits.
- **(I-002) — blocker**: the daemon-side
  `EventstreamConfig::default` ships with `paths: []`. Even if
  the module emits, nothing tails the JSONL. The PR body said
  "the daemon picks it up" — the daemon does not pick it up
  unless the operator manually adds the path.
- **(I-003) — nice**: `selfdefctl events emit --out` has no
  default. Documented choice; called out here because it
  exacerbates the I-001 / I-002 misalignment.

**Honest assessment**

This PR added the *plumbing* but didn't close the loop on
"works out of the box". The reason this slipped was that the
test fixture supplied an explicit `event_stream_path` and the
integration test wrote to a tempdir — both ends of the boundary
were specified in the test, so the test passed without exercising
the **default-config flow**. The CI green didn't reflect the
operator experience.

This is the kind of slip the audit was designed to catch.

---

## PR #22 — AI-machine track (tetragon + agent-guard + observability)

**Promised**

Three new modules shipping together: `tetragon` substrate,
`agent-guard` policy bundle (4 policies), `observability`
(Prometheus scrape config + Grafana dashboard). 23 hermetic
dry-run smoke tests. Module catalog updates. Roadmap refresh.

**Landed**

All three modules with their manifests, profiles, install
scripts, READMEs, smoke tests. Module catalog updated.

**Deferred**

Pod-label scope was flagged as follow-up (which became PR #25);
GPU device guard was flagged as follow-up (which became PR #24).
Daemon-side `/metrics` flagged as follow-up (became PR #23).

**Silently undone**

This is the PR where the most invisible breakage landed.

- **(I-006) — blocker**: `tetragon` module's README and the
  default profile comment tell the operator to add Tetragon's
  events.json to `[collectors.eventstream]`. Wrong collector.
  Tetragon's native JSON is not selfdef-Event JSON; the
  eventstream collector silently fails to parse and drops every
  line. The integration tests for this module wrote a
  fake tetragon config and verified the apply-side rendered it
  correctly — they never exercised the *daemon-side* event flow.
- **(I-007) — blocker**: every Tetragon event surfaces as
  `Informational` because the collector hard-codes severity.
  This is an old defect that existed before PR #22, but PR #22
  added the policy YAMLs that *needed* the severity translation
  to work. The PR did not patch the collector, and the test
  surface never exercised an end-to-end "policy fires → operator
  alert" path that would have surfaced the gap.
- **(I-008) — blocker**: no correlator rule promotes Tetragon
  events to findings, so the responder never fires the notifier
  for an agent-guard violation. Same root cause as I-007: the
  module's promise wasn't proved end-to-end.
- **(M-008) — blocker**: `vpn-bridge` already had this
  multi-instance corruption issue *before* PR #22. PR #22 did
  not address it (out of scope) and the audit catches it here.

The AI-machine track is the largest single PR in the audit window
and is the one with the most unverified central-promise gaps.
This is where the audit's "ship what we promised, end-to-end"
discipline matters most.

**Honest assessment**

The modules are well-structured *in isolation*. The integration
gaps weren't visible from inside the PR because:

1. The tests verified renderings, not flows.
2. The PR was scoped as "the modules" — wiring fixes to the
   daemon-side collector and the correlator were "out of scope"
   in my own framing, but they were *prerequisites* for the
   modules to fulfil their advertised role.
3. The CHANGELOG entry oversold what the modules deliver. It
   describes Sigkill behaviour and operator alerting as if the
   path from kernel to ntfy were already wired.

The right shape of this work in retrospect would have been a
3-PR sequence: (a) collector severity-mapping + correlator rule,
(b) tetragon substrate module, (c) agent-guard + observability
modules. Each verifiable end-to-end before the next.

---

## PR #23 — `selfdef-api GET /metrics`

**Promised**

Prometheus exposition endpoint, atomic counters, daemon ingest
task subscribed to the bus, observability scrape config picks up
the new endpoint, 5 unit + 3 integration tests.

**Landed**

All of the above.

**Deferred**

None claimed.

**Silently undone**

- **(I-004) — blocker**: observability's default
  `scrape_targets` includes `localhost:8443`, but
  `ApiConfig::default` ships with `tcp_addr: ""`. The default
  install can't be scraped.
- **(I-005) — important**: bearer-token auth on TCP `/metrics`
  is real (the audit confirmed it). Prometheus's default scrape
  config doesn't carry a token. The module README doesn't
  walk the operator through this.
- **(M-005) — important**: the default `scrape_targets` value
  diverges across the README, both profile files, and the
  apply.sh fallback.
- **(T-005, T-006) — important**: integration tests verify the
  content-type starts with `text/plain` (not strict) and assert
  substring presence on the body (not the format). No test
  asserts the route accepts Read-only capability.

**Honest assessment**

Code-side this PR is clean. Documentation-side and integration-
side it left the same kind of gap as PR #21: the test exercised
the unit, not the operator experience.

---

## PR #24 — `agent-guard` GPU device guard (v0.2.0)

**Promised**

Fifth policy in the agent-guard bundle, NVIDIA device defaults +
operator-extensible prefix list, in-container binary allowlist
with empty-allowlist semantic (no allowlist = match everything in
a container), 4 new integration tests.

**Landed**

All of the above. The policy ships, the lib.sh helpers handle
the placeholder substitution, the auto-downgrade of the
matchBinaries block when the allowlist is empty works.

**Deferred**

Mention of pod-label scope as a follow-up.

**Silently undone**

- The GPU policy inherits I-007 / I-008 — it produces
  `Informational` events that no correlator rule promotes. The
  Sigkill kernel-side action works; the operator-alert side
  does not.
- The `render_gpu_policy` awk state machine is brittle (M-003,
  cross-listed). Worked for the policies that exist; future
  policy authors will trip over it.

**Honest assessment**

Within its scope, this PR is clean. The audit downgrades the
"shipped a fifth policy" claim because the policy doesn't fulfil
its central promise (Sigkill → operator alert) for the same
reason as I-007 / I-008. This is upstream-of-the-PR debt, not
PR-introduced debt.

---

## PR #25 — `agent-guard` pod-label scope (v0.3.0)

**Promised**

`scope = "container" | "pod-label"` knob. When `pod-label`,
rewrites every shipped policy's `matchNamespaces` block to
`matchPodSelector`. 5 new integration tests cover the
substitution, the default container scope, missing-key refusal,
invalid-scope refusal, and the GPU policy's matchBinaries block
surviving the swap.

**Landed**

All of the above.

**Deferred**

The pod-label work would benefit from a Kubernetes-specific
operator guide. Not landed (D-007 captures this).

**Silently undone**

- The `render_pod_scope` helper anchors on `matchActions:`. Any
  future policy with a non-trivial selector structure between
  `matchNamespaces:` and `matchActions:` would be silently
  mis-rendered. Cross-listed as M-003.
- Inherits I-007 / I-008 — pod-label scope doesn't change the
  fact that the events the policies produce surface as
  `Informational` and have no correlator promotion.

**Honest assessment**

Tight scope, clean execution. The audit's main finding for this
PR is that "shipping a feature for a module whose central
promise is unfulfilled" extends the surface area of that
unfulfilled promise. Pod-label scope is a real feature for k8s
operators; it's not useful until I-007 + I-008 are addressed.

---

## Cross-PR pattern findings

### R-002 — `Tests verified the unit, not the flow`

Across PRs #21, #22, #23, the integration tests exercised one
side of a boundary (the module's apply rendered correctly; the
metrics endpoint serves; the events emit subcommand writes a
valid JSON line). They did not exercise the *other side* (the
daemon's default config picks it up; Prometheus's default scrape
config can reach it; the eventstream collector parses lines from
the path the module writes). Pattern shared by I-001, I-002,
I-004, I-006. **(R-002)**

### R-003 — `CHANGELOG entries oversold operator outcomes`

PRs #21, #22, #24 each described an operator-facing benefit
("drift fires the notifier chain", "agent-guard kills and
alerts", "GPU device access surfaces") that requires more
integration than landed. The CHANGELOG, the README, and the PR
body all carry the same overstatement. **(R-003)**

### R-004 — `Module-author / collector-author boundary is the seam`

The AI-machine track was conceived as "ship the modules"; the
audit shows the gap lives in the *collector*
(`selfdef-collector-tetragon` ignores severity annotations) and
in the *correlator rules* (no rule promotes the events). Future
PRs that ship a module touching a new event source should be
preceded by a checkpoint PR that updates the relevant collector
and correlator. **(R-004)**

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| R-001 | nice | `panic` subcommand vs `modules uninstall` | Hostname-confirm validation duplicated; could share a helper. |
| R-002 | SDD-debt | PR-author discipline | Pattern of testing one side of every cross-cutting boundary. Design doc on "what counts as integration-tested" needed. |
| R-003 | important | CHANGELOG + PR descriptions for #21, #22, #24 | Operator outcomes are described as if end-to-end; the audit reveals they aren't. CHANGELOG entries to be revised. |
| R-004 | SDD-debt | development cadence | Module PRs should be preceded by collector/correlator-side prep PRs when introducing new event sources. |
