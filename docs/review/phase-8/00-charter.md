# Phase 8 audit — charter (DEFERRAL)

> Status: **deferred** — audit explicitly not opened on this cycle.
> Owner: audit team (n/a until re-opened)
> Last updated: 2026-05-15
> Vintage prefix (when opened): `F-2033-NNN`

## TL;DR

Phase 8 would audit the post-Phase-7 cycle (PRs `#156`..`#171`,
16 merged PRs across selfdef + 1 in root-ghostproxy). Two structural
defects make a useful Phase 8 audit impossible right now:

1. **Authorship bias** — 16 of 16 selfdef PRs in this cycle were
   authored by the same agent who would run the audit. An audit by
   the author is not an audit; it's self-justification.
2. **Cycle composition** — 13 of the 16 PRs are documentation,
   skill specs, or decisions-log entries. Only 2 PRs touch
   substantive code (`#160` impl D-005 apply.sh length check;
   `#170` impl D-004 write(1) integration crate). The audit
   programme's seven explorers (recent-PRs / crate / module /
   integration / docs / tests / security) presuppose code-shaped
   surface area; six of those explorers would find effectively
   nothing on this cycle.

This document is **itself the audit output for Phase 8**: the audit
team examined the cycle, concluded a full run wasn't useful, and
documented why. Phase 8 re-opens when one of the trigger conditions
below fires.

## Why deferral rather than a thin compliance audit

Two alternatives were considered:

- **Full 7-explorer run**: ~1-2 days of audit work, almost certainly
  surfacing no real findings because the auditor is the author.
  Cost is real; signal is near-zero. Worse, a "clean Phase 8" would
  falsely strengthen the trajectory table — "Phase 8 had 0 findings"
  reads as quality assurance, but it's actually noise.
- **Thin compliance audit**: a single explorer (recent-PRs only)
  cataloguing each merge. Even this has the bias defect: the
  cataloguer would be reviewing their own PR bodies.

Both alternatives produce false-positive signal. The honest
output is: **don't run, document the constraint, define the
trigger**.

## The cycle Phase 8 would have audited

### Sub-cycle 1 — orient + resolve infrastructure (PRs #156-#163)

8 PRs landing the `/view` + `/questions` skill stack + the
`docs/decisions.md` audit log + supporting handoffs.

| PR | What | Code? |
|---|---|---|
| #156 | `/view` skill + end-of-Phase-7 handoff | docs/skill |
| #157 | `/view` augmentation (depth contract per section) | docs/skill |
| #158 | `/questions` skill + `docs/decisions.md` seed | docs/skill |
| #159 | D-001..D-007 — first decisions batch | docs |
| #160 | **impl D-005** — apply.sh refuses cleanly when instance id > 7 chars | **code + 2 new tests** |
| #161 | impl D-002 — SECURITY.md addendum on SSE 30s slow-client bound | docs |
| #162 | end-of-/questions-pipeline handoff | docs |
| #163 | `/questions solve-all` verb | docs/skill |

### Sub-cycle 2 — cleanup-cycle decisions + doc-drift fixes (PRs #164-#169)

6 PRs formalizing remaining SDD soft answers + correcting stale
documentation.

| PR | What | Code? |
|---|---|---|
| #164 | ARCHITECTURE.md channel catalog refresh — 11 channels shipped | docs |
| #165 | D-008..D-021 — second decisions batch (14 soft answers) | docs |
| #166 | SDD-004 known-gaps: 4 "Future SDD" items marked shipped | docs |
| #167 | D-017+D-020 — mdbook entry-points for test-contract + module-helpers | docs |
| #168 | D-022/D-023 — realization notes for D-003 and D-015 | docs |
| #169 | end-of-cleanup-cycle handoff | docs |

### Sub-cycle 3 — write(1) integration + dashboard requirements (PRs #170-#171)

2 PRs: one substantive code crate + one requirements-only SDD.

| PR | What | Code? |
|---|---|---|
| #170 | **impl D-004** — write(1) per-user session-attention channel + D-024 | **NEW CRATE + 20 tests + daemon wiring + config + STARTER_CONFIG** |
| #171 | SDD-009 requirements-only stub (no design choices) | docs |

### Cross-repo

- `cyberpunk042/root-ghostproxy` PR #1 — `/view` + `/questions` skill install + auto-compact OFF / auto-dream ON settings merge.
- `cyberpunk042/devops-solutions-information-hub` PR #1 — opened in error, **closed without merging**. Not part of the audit cycle.

### By the numbers

- **16 PRs merged** in selfdef (`#156`..`#171`); **1 PR merged** in root-ghostproxy; **1 PR closed without merging** in devops-info-hub.
- **2 PRs touch substantive Rust code** (#160, #170).
- **1 net-new crate** (`selfdef-integration-write`).
- **2 PRs add new tests** (#160 +2 tests; #170 +20 tests). Combined +22 tests.
- **24 D-NNN entries appended** to the audit log (D-001..D-024).
- **All 23 question-shaped open items across SDDs 001-008 now formally answered or explicitly deferred** in the audit log.
- **1 net-new SDD** (SDD-009 requirements stub).

## Bias analysis

| Authorship of cycle | All by the same agent (this session) |
| Authorship of Phase 8 audit (if opened) | Same agent |
| Effective inter-rater reliability | 1 rater; no triangulation possible |
| Cycle composition | 13 docs/skill · 2 code · 1 SDD stub |
| Code surface available to 6 of 7 explorers | Minimal — 2 PRs, both authored + reviewed by the same agent |
| Operator review | All 17 cycle merges (selfdef #156-#171 + root-ghostproxy #1) were operator-merged after CI green; merge approval is operator-side, not agent-side. **This is the only independent signal in the cycle.** |

The merge-side review by the operator is genuine signal, but it
operates at a different granularity than the audit programme's
explorers (which look for cross-PR patterns, drift, integration-
seam fit, security posture, test-contract adherence, etc.).
Phase 8 would need to add what merge-side review doesn't — and the
agent who wrote the cycle is the wrong agent to perform that
analysis.

## Trigger conditions for opening Phase 8 for real

Phase 8 (full or partial) should open when **any one** of these
fires:

1. **A non-author agent or human auditor** is available to run the
   seven explorers (or a subset of them) against the cycle.
2. **A substantial code-shaped cycle** accumulates after this
   session — say, 5+ PRs touching non-doc Rust code — at which
   point the code-focused explorers (crate / module / integration
   / tests / security) have real surface to chew on, even with
   author-overlap.
3. **A production-relevant defect** is reported against any of
   PRs #156-#171's output, at which point the audit becomes a
   targeted root-cause investigation rather than a programme-wide
   sweep.
4. **The dashboard design SDD lands** (the SDD-009 successor) and
   its impl cycle ships. That would be a natural Phase 8 boundary:
   the dashboard impl is substantial code with cross-crate seams +
   security surface + UI tests, exactly what the audit programme
   was built for.

## What Phase 9 (or whichever opens next) inherits

When Phase 8 (or the next-numbered phase) opens for real:

- **Findings prefix**: `F-2033-NNN` (reserved here so it's not
  re-allocated by something else).
- **Cycle to audit**: from PR `#156` (Phase 7 wrap merge) forward,
  through wherever the trigger fires. The 16 PRs cataloged above
  are the starting baseline.
- **Bias-mitigation requirement**: the audit team running Phase 8
  must include at least one rater who did **not** author any of
  PRs #156-#171. If that's impossible, the audit charter must
  explicitly declare the bias constraint and weight findings
  accordingly (e.g. apply a higher confidence-bar before
  closing in-place).

## Status

- Phase 7 trajectory remains the current published trajectory.
- Phase 8 vintage `F-2033-NNN` is **reserved but unallocated**.
- The cycle inventory above is the starting baseline; future audits
  can extend it forward without re-inventorying.
- No findings raised under Phase 8. The findings ledger
  (`99-findings-ledger.md`) is a placeholder documenting the
  deferral.

## Cross-references

- Phase 7 wrap: [`../phase-7/99-findings-ledger.md`](../phase-7/99-findings-ledger.md)
- Audit programme charter conventions: [`../00-charter.md`](../00-charter.md)
- Cycle inventory: PR list above; full git log via `git log --oneline --merges main` from `b22c2e0` forward.
- D-024 (per-user transport realization): [`../../decisions.md`](../../decisions.md)
- SDD-009 (dashboard requirements): [`../../sdd/009-dashboard.md`](../../sdd/009-dashboard.md)
