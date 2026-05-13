# Charter — selfdef architecture & PM sweep, Phase 1

> Status: Phase 1 (audit only). No code changes are part of this
> document set. Specifically: no fixes, no refactors, no new
> features, no test rewrites. The deliverable is a complete picture
> of where the codebase stands today, where it drifts from its
> stated intent, and where work landed half-finished.

## Why this exists

selfdef has moved fast: 25 PRs landed on the long-running feature
branch in a tight window, several of them adding entire module
families (`tetragon`, `agent-guard`, `observability`), a new
Prometheus surface on the daemon, and cross-cutting wiring through
the eventstream collector. Each PR was scoped to a single
deliverable, merged, then the next started. That cadence is good
for keeping diffs reviewable, but it leaves predictable risks:

- **Integration drift.** A PR that promised "the daemon will scrape
  this metrics endpoint" might have shipped the endpoint without
  flipping the default scrape target in the consumer module.
- **Doc drift.** README sections, profile defaults, and the
  CHANGELOG entry for one PR don't all stay in sync with later PRs
  that change the same surface.
- **Half-finished promises.** A README claims a knob exists; the
  scripts honour it; the test suite never exercises it.
- **Orphan code.** A crate exists with a real public surface; the
  daemon never instantiates it. Or vice versa: a feature is wired
  in code but invisible to docs / the operator-facing CLI.

This audit asks the same question across every surface: *did the
thing we said we'd ship actually ship, end-to-end, including the
documentation and the test coverage?*

## Scope

In scope:

1. Every Rust crate under `crates/` — public surface, daemon
   wiring, test coverage, schema version drift, deprecated APIs.
2. Every module under `modules/` — manifest, install scripts,
   profiles, README, lifecycle integration with `selfdefctl`.
3. Every doc page under `docs/src/` plus the repo-root README,
   SECURITY, ARCHITECTURE, CHANGELOG.
4. Every test directory: per-crate unit tests, per-crate
   integration tests, replay corpora.
5. Every detection rule directory (`rules/sigma`, `rules/tetragon`,
   `rules/yara`).
6. The `xtask` build helper.
7. CI configuration (`.github/workflows/`, `deny.toml`,
   `supply-chain/`).
8. Recent PRs (#19 through #25 inclusive) — what each promised vs
   what landed.

Out of scope for *this* phase (deliberately):

- Implementing any fix.
- Rewriting any test.
- Proposing the future architecture beyond a one-line
  "what we'd want here" note per finding.
- Vendor-specific guidance (e.g. which Prometheus version, which
  Tetragon channel).

## Findings model

Each finding gets:

- A stable id: `F-2026-NNN`.
- A severity: **blocker** / **important** / **nice** / **SDD-debt**.
- A surface (which file or directory it relates to).
- A short description (what's wrong / missing / inconsistent).
- An evidence reference (file:line where applicable).
- A recommended next phase: investigate / design / implement / doc.

The ledger in `99-findings-ledger.md` is the single index. Every
audit doc cross-references findings by id rather than re-stating
them.

### Severity rubric

| Severity | Definition | Example |
| --- | --- | --- |
| **blocker** | Ship is silently broken or unsafe for the documented use case. | A module's default profile points at a path the install scripts never create. |
| **important** | The thing works but a documented promise is not honoured, or a real operator workflow doesn't survive a soft restart. | A `/metrics` endpoint serves on TCP but Prometheus's default scrape config in the bundled observability module targets the wrong port. |
| **nice** | Polish — something is clumsy, redundant, or under-documented but doesn't trip up real use. | A test asserts a literal string that could be relaxed; one of two profile docs contradicts the other on a minor knob. |
| **SDD-debt** | A design decision was made without a written design doc, and the consequences are now spread across several surfaces. | "Why is the host_tag a high-cardinality label everywhere except in `/metrics`?" |

A finding can drop in severity if the audit surfaces a reason it
turned out to be intentional. We don't promote nice → important
during this phase — that's a Phase-2 conversation.

### What this audit will NOT do

- Grade individual people's work; it grades the artifact.
- Propose a single sweeping refactor. Each finding stands alone.
- Demand 100% test coverage. The bar is "the things the docs
  promise are exercised by a test that would fail if they
  regressed".

## Process

1. **Inventory** (`10-inventory.md`) — the unembellished list of
   what's in the repo right now. No claims, just file counts.
2. **Per-area audits** (`20-` through `80-`) — each one reads its
   surface, cross-references the inventory, and emits findings.
3. **PR retrospective** (`70-recent-prs-audit.md`) — for PRs
   #19–#25, what was promised in the PR body vs what landed vs
   what was deferred. Critical and honest about gaps.
4. **Findings ledger** (`99-findings-ledger.md`) — the
   numbered index of every finding.

Each audit doc is self-contained and skimmable. No buried
conclusions: every doc ends with a "Findings raised in this
section" list.

## What happens after Phase 1

Out of scope here, but flagged so the audit is honest about its
own role: Phase 2 is a triage conversation where the user picks
which findings get a Phase-3 design doc (SDD). Phase 3 produces
the design docs. Phase 4 implements. Phase 5 verifies. The audit
docs are the entry point — they don't try to predict triage
priorities.
