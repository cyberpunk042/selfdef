# Phase 4 — recent-PRs audit (post-Phase-3 closure)

Companion to Phase 3's [20-recent-prs-audit.md](../phase-3/20-recent-prs-audit.md)
and Phase 2's [20-recent-prs-audit.md](../phase-2/20-recent-prs-audit.md).
Same shape: walk the ~17 PRs shipped during Phase 3's closure cycle
(commit `f40bf05` through `8b44322`) and flag observations that didn't
get caught at PR-review time.

## Methodology

For each PR: read the diff, read the description, check the
tests, check the docs. Look for:

- **Coverage gaps** — features the PR added without
  corresponding tests.
- **Drift** — claims in the PR description that don't match
  the code that landed.
- **Documentation drift** — feature shipped, docs reference
  the old shape.
- **Inconsistencies** — error messages, exit codes, default
  paths that don't match siblings.
- **Cargo cult patterns** — a habit copied across PRs that
  one could argue isn't quite right.

Outcomes feed F-2029-NNN entries in the section below.

## PRs surveyed

| # | Topical commit | Title | Audit pass |
| --- | --- | --- | --- |
| 1 | 2381a31 | docs: Phase 3 recent-PRs explorer + ledger (raises F-2028-001..004) | review-clean |
| 2 | a794372 | docs: Phase 3 crate explorer (raises F-2028-005..014) | review-clean |
| 3 | 3f18b32 | fix(cli): token-reader symmetry (closes F-2028-004 + -005) | review-clean |
| 4 | fd077f8 | docs: Phase 3 module explorer (raises F-2028-015) | review-clean |
| 5 | abe91af | fix(vpn-bridge): migrate to SDD-006 v2 manifest helpers (closes F-2028-015) | review-clean |
| 6 | c318487 | docs: Phase 3 integration explorer (raises F-2028-016..019) | review-clean |
| 7 | 3c60b6f | fix(cli): SSE parser feeds raw bytes (closes F-2028-018 + -019) | review-clean |
| 8 | 9a49a3e | docs: Phase 3 docs explorer (raises F-2028-020..024) | review-clean |
| 9 | 97954dc | docs: STARTER_MODULES per-block mode hint + inventory time-anchor (closes F-2028-022 + -024) | review-clean |
| 10 | 5948829 | docs(cli): CLI doc-clarity cluster (closes F-2028-006 + -007 + -010) | review-clean |
| 11 | b467e27 | docs: Phase 3 tests explorer (raises F-2028-025; verifies F-2028-026..035) | review-clean |
| 12 | e99f369 | fix(cli): surface 503 typed reason on TCP follow (closes F-2028-016 + -017) | review-clean |
| 13 | 8147264 | docs: Phase 3 security explorer (raises F-2028-036..039) | review-clean |
| 14 | 90cbe6e | docs: SDD-007 per-token SSE subscriber quota (scopes F-2028-037 + -039) | review-clean |
| 15 | a1d6823 | sec(api): SDD-007 per-token SSE subscriber quota (closes F-2028-037 + F-2028-039) | observation: F-2029-001 |
| 16 | d88befe | polish: Phase 3 nice-cluster wrap-up (closes F-2028-001 + -012 + -013 + -025) | review-clean |
| 17 | 8b44322 | feat(api): SDD-007 D-4 operator-tunable SSE caps | review-clean |

## Observations (raw, pre-triage)

The findings below get ledger entries if triaged; this section
captures the audit's first-pass observations with enough
context to triage each one. Severity ratings are the auditor's
recommendation; final triage in the ledger.

### F-2029-001 — SDD-007 implementation PR claims D-4 shipped but defers it to follow-up PR

PR `a1d6823` (the SDD-007 implementation PR) commits a message
claiming "D-4 (config knobs) deferred to a thin follow-up; defaults
(8 per-token, 64 global) match the SDD." However, the companion
PR `8b44322` (shipped 13 minutes later in the same session) implements
D-4 fully. The implementation PR's status documentation in the
CHANGELOG at that point states "SDD-007 status: implemented (D-1, D-2,
D-3, D-5, D-6 shipped; D-4 deferred)". When PR `8b44322` lands, the
`docs/sdd/007-per-token-sse-subscriber-quota.md` file is updated
(the first commit that writes to it) with a full status section
claiming all five Ds are shipped.

**Observation**: This is accurate but potentially confusing at merge
time. PR `a1d6823`'s message correctly defers D-4; a reader at that
moment in the audit trail sees "D-4 pending follow-up". PR `8b44322`
lands immediately after and stamps the SDD as "fully implemented",
but a reader skimming PR `a1d6823`'s commit message might miss that
D-4 actually shipped 13 minutes later (in the same session).

**Ambiguity**: The timeline is: (1) design doc lands (90cbe6e), (2) D-1..D-3/D-5/D-6 implementation lands (a1d6823, accurate re: D-4 defer), (3) D-4 follow-up lands (8b44322, full implementation). This is correct and efficient — the defer-and-pair pattern is intentional for reducing PR size. No code drift, no feature gap. The SDD status doc is correctly updated.

**Recommendation**: **demoted** — this is clean execution of the defer-and-pair pattern. The commit message for `a1d6823` is accurate at its write time; the SDD status section is added in `8b44322` and is correct. No action needed; left in ledger for audit trail completeness since it touches auditor process expectations (was the defer real or cosmetic?).

## Closed without finding

The 16 PRs marked "review-clean" passed the audit without an
actionable observation. This is a high pass rate (94%) — even
higher than Phase 3's recent-PRs audit (73% clean after
demotion, 4 observations across 29 PRs) and Phase 2's (comparable
high rate on closure cycles). The 1 observation flagged is
**demoted** — not a defect, just a process clarification.

The high pass rate reflects:

1. **Phase 3's closure PRs were meticulously reviewed before
   merge.** The 39 findings from Phase 3 across all seven
   explorers were addressed in dedicated, tightly-scoped
   follow-up PRs (token-reader symmetry, vpn-bridge v2,
   SSE parser bytes, docs clarity, SDD-007 design +
   implementation + D-4 config). Each was tested before
   merge.

2. **Documentation-only PRs (2381a31, a794372, fd077f8,
   c318487, 9a49a3e, 97954dc, 5948829, b467e27, 8147264,
   90cbe6e) don't introduce observable shape.** They can't
   introduce code drift; the audit looked for phrasing gaps,
   factual accuracy, and doc-code alignment. All explorers
   correctly cross-checked their findings against the ledger.

3. **Feature PRs (3f18b32, 3c60b6f, e99f369, a1d6823, d88befe,
   8b44322) shipped with comprehensive tests.** The audit
   spot-checked test coverage, implementation patterns, and
   SDD alignment:
   - Token-reader symmetry (PR #86): mode check + whitespace
     trim both now match daemon-side; 2 new tests pass.
   - vpn-bridge v2 (PR #87): manifest recording + uninstall
     cleanup refactored to use helpers; 1 new round-trip test
     passes; multi-instance leak is fixed.
   - SSE parser bytes (PR #88): refactored to work on raw bytes,
     UTF-8 conversion at line boundaries; 2 new unit tests
     (multibyte split 2/2, 3-byte split 1/2) plus 13 existing
     tests still pass.
   - SSE 503 detail (PR #91): JSON body extraction + 1 new
     integration test for cap saturation.
   - SDD-007 impl (PR #92): SHA-256 fingerprint, dual-counter
     guard, 3 new integration tests (per-token cap, per-token
     isolation, HashMap cleanup) plus existing global-cap test.
   - Polish (PR #93): paths compile-time validation, timeout
     message naming, import-style cleanup, underflow asserts;
     275/275 tests pass.
   - D-4 config (PR #94): optional knobs plumbed through daemon
     config → ApiState → SubscriberGuard; 2 new integration
     tests (per-token override, global override); init template
     ships the knobs commented at defaults.

4. **The closure cycle had deliberate structure.** The explorer
   PRs raised findings; closure PRs addressed them with single
   responsibilities. No bundling, no scope creep. The SDD-007
   design-first-then-implement-then-config pattern is clean and
   reviewable.

The single observation flagged (F-2029-001, demoted) is not a
defect — it's a confirmation that the defer-and-pair pattern
worked: PR `a1d6823` correctly deferred D-4 in its message; PR
`8b44322` shipped it 13 minutes later and the SDD status was
updated. The timeline is accurate and the implementation is
complete.

Phase 4 is effectively wrapped with zero blockers, zero important,
and one demoted finding (which is really an audit-process note,
not a code drift).
