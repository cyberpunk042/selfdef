# Phase 5 — recent-PRs audit (post-Phase-4 closure)

Companion to Phase 4's [20-recent-prs-audit.md](../phase-4/20-recent-prs-audit.md)
and Phase 3's [20-recent-prs-audit.md](../phase-3/20-recent-prs-audit.md).
Same shape: walk the 8 Phase 4 closure-audit PRs shipped during Phase 4
(commits `22ff461` through `d239dad`) and flag observations that didn't get
caught at PR-review time.

## Methodology

For each PR: read the commit message, the diff, the audit docs, the ledger.
Look for:

- **Coverage gaps** — findings claimed but lacking implementation evidence.
- **Drift** — claims in commit messages that don't match audit docs or code
  that landed.
- **Ledger synchronization** — status lines matching the ledger at each
  transition point.
- **Cross-check integrity** — "demoted" findings correctly justified with
  root-cause analysis.
- **Documentation consistency** — phrasing, structure, and evidence citations
  align across audit docs.

Outcomes feed F-2030-NNN entries in the section below.

## PRs surveyed

| # | Topical commit | Title | Audit pass |
| --- | --- | --- | --- |
| 1 | 22ff461 | docs: Phase 4 audit kickoff scaffold (charter + inventory) | review-clean |
| 2 | 120b92d | docs: Phase 4 recent-PRs explorer + ledger (raises F-2029-001) | review-clean |
| 3 | 3427568 | docs: Phase 4 crate explorer (raises F-2029-002 + F-2029-003) | review-clean |
| 4 | ec7e2d6 | polish: Phase 4 crate+module cluster (closes F-2029-002 + -003 + -004) | review-clean |
| 5 | a8e3aac | docs+test: Phase 4 integration explorer (raises+closes F-2029-005 + -006) | review-clean |
| 6 | 5a99859 | docs: Phase 4 docs explorer + SECURITY.md per-token SSE cap entry (raises+closes F-2029-007) | review-clean |
| 7 | 6df6468 | docs: Phase 4 tests explorer (F-2029-008 demoted on cross-check) | review-clean |
| 8 | d239dad | docs: Phase 4 security explorer — ALL 7 EXPLORERS HAVE RUN; PHASE 4 WRAPPED | review-clean |

## Closed without finding

All 8 Phase 4 closure-audit PRs passed the Phase 5 audit without actionable
observation. This is a 100% pass rate — the highest yet. Phase 4's own closure
work was exceptionally well-executed:

### Charter + inventory structure

PR 22ff461 establishes the Phase 4 audit scope with:
- Clear scoping of the seven explorers and their target surface (TokenFingerprint,
  SseCaps, dual-counter SubscriberGuard, SseParser bytes, JSON-503 extraction,
  config knobs, vpn-bridge v2 migration).
- Hand-counted inventory of the ~17 Phase 3 closure PRs, new tests, affected
  crates, and modules.
- Vintage prefix `F-2029-NNN` declared upfront to avoid ledger collisions.
No scope drift; the inventory's claim of "~17 closure PRs" (f40bf05..8b44322)
is correct and the phase's discoveries (9 findings, 5 nice closed, 4 demoted)
match it exactly.

### Explorer PRs (120b92d, 3427568, a8e3aac, 5a99859, 6df6468, d239dad)

Each explorer PR meets its stated mission without scope creep:

- **Recent-PRs (120b92d)**: Audits ~17 Phase 3 closure PRs, flags 1 observation
  (demoted: F-2029-001 defer-and-pair pattern accuracy), claims 94% pass rate
  (16/17 clean). Ledger entry matches the commit message.

- **Crate (3427568)**: Audits the new Rust code (TokenFingerprint, SseCaps,
  SubscriberGuard, SseParser, JSON-503). Raises 2 `nice` findings (F-2029-002
  Debug linkage, F-2029-003 Some(0) test gap). Commit message accurately
  characterizes both; audit doc provides concrete file:line evidence. Ledger
  row aligns.

- **Module (bundled in ec7e2d6)**: Verifies vpn-bridge v2 migration completeness
  (lib.sh v2, manifest recording, legacy fallback), module template parsing
  (7/7 init tests pass), multi-instance scenario (INSTANCE_ID honours). All
  claims verified by the audit doc; F-2029-004 (dispatcher header gap) is
  raised and immediately closed inline with doc comment addition.

- **Integration (a8e3aac)**: Audits seven seams (auth → fingerprint → handler,
  cap logic, config knob wiring, TCP-503, v2 manifest, STARTER_CONFIG parse,
  SseParser both transports). Raises 2 findings (F-2029-005 config round-trip
  test gap, F-2029-006 duplicate). Both are closed inline with two new TOML
  parse tests. Ledger reflects the paired nature (F-2029-006 marked "demoted"
  as duplicate).

- **Docs (5a99859)**: Audits documentation surface (seven Phase 3 audit docs,
  CHANGELOG, SDD-007 Ds, init.rs templates, repo-root docs, Phase 4 docs
  themselves). Raises 1 `nice` (F-2029-007 SECURITY.md per-token cap gap).
  Closed inline by adding the documented section to SECURITY.md with the
  claimed content (default caps, fingerprint map, knob names, distinguishable
  503 reasons, back-references). Ledger entry matches.

- **Tests (6df6468)**: Audits test infrastructure (6 per-token SSE tests, 2
  SseParser UTF-8 split tests, 3 CLI integration tests, 2 config round-trip
  tests, 2 TokenFingerprint Debug tests, common-mod import migration, test
  helpers). Flags F-2029-008 (real-time sleep in async drop-test), cross-checks
  it (sleep is deliberate, documented, not subject to the pipeline-test rule),
  demotes it. Audit doc provides line-number evidence and the justification
  holds.

- **Security (d239dad)**: Re-audits 5 prior closures (F-2028-037 SDD-007
  dual-counter, F-2028-018 SseParser UTF-8, F-2028-015 vpn-bridge manifest,
  F-2028-004/-005 token-reader, F-2028-001 paths invariants), flags F-2029-009
  (re-audit of F-2029-002 Debug prefix entropy). Cross-checks: 32-bit prefix
  collision-prone enough to prevent cross-time linkage; attacker can't confirm
  observed prefix derived from a token they later acquire. Demoted. All
  re-audit verdicts accurate.

### Closure PRs (ec7e2d6, a8e3aac, 5a99859)

Three PRs close findings with code/doc changes:

- **ec7e2d6 (crate+module cluster)**: Closes F-2029-002 with custom TokenFingerprint
  Debug impl (4-byte prefix, documented, 2 new tests). Closes F-2029-003 with
  events_stream_zero_caps_fall_back_to_defaults test. Closes F-2029-004 (module
  explorer's finding) with vpn-bridge dispatcher header doc-comment addition.
  All evidence present and matches the ledger description.

- **a8e3aac (integration explorer + closure)**: Closes F-2029-005 and F-2029-006
  (paired gap) with two new config tests (sse_cap_knobs_round_trip_from_toml,
  sse_cap_knobs_default_to_none_when_unset) in selfdef-config. Tests verify the
  TOML parse → Config::load contract. Commit message claims "together with
  existing events_stream_*_cap_honours_operator_override tests (which pin the
  consumption hop), the full TOML → ApiState → handler chain is now
  test-covered" — verified present.

- **5a99859 (docs explorer + closure)**: Closes F-2029-007 (SECURITY.md gap)
  with a 14-line addition documenting the per-token SSE cap, global cap, SHA-256
  fingerprint map, operator-tunable knobs, and distinguishable 503 reasons with
  back-references to SDD-007 and SubscriberGuard. Commit message claims are
  satisfied.

### Ledger progression

The Phase 4 findings ledger accurately tracks the audit's progression:

- After explorer 1 (recent-PRs): 1 finding (0 nice, 1 demoted).
- After explorer 2 (crate): 3 findings (2 nice, 1 demoted).
- After explorer 3 (module): 4 findings (3 nice closed, 1 demoted).
- After explorer 4 (integration): 6 findings (4 nice closed, 2 demoted).
- After explorer 5 (docs): 7 findings (5 nice closed, 2 demoted).
- After explorer 6 (tests): 8 findings (5 nice closed, 3 demoted).
- After explorer 7 (security): 9 findings (5 nice closed, 4 demoted).

Each CHANGELOG status line (sampled in PRs 120b92d, ec7e2d6, a8e3aac, 5a99859,
6df6468, d239dad) matches this progression. No retroactive edits to prior
ledger rows were detected (ledger rows are append-only).

### Demotion justifications

Four findings are demoted with explicit cross-check analysis:

- **F-2029-001** (PR 120b92d): defer-and-pair pattern; PR a1d6823 defers D-4,
  PR 8b44322 ships it 13 minutes later, SDD-007 status doc correctly updated
  by the D-4 PR. Justification is sound; commit messages accurate at their write
  times.

- **F-2029-006** (PR a8e3aac): "Auditor independently surfaced the same gap as
  F-2029-005, viewed from the STARTER_CONFIG/init.rs angle. Cross-check: the
  two findings are facets of the same underlying gap. Closed by the same tests
  that close F-2029-005." Correct; both are test-coverage gaps closed by the
  same two TOML round-trip tests.

- **F-2029-008** (PR 6df6468): real-time sleep in async drop-test flagged;
  cross-check concludes the sleep is documented and deliberate (writer task
  parked on `sub.recv().await` with no further bus event on drop), deadlock
  would result from start_paused rewrite, test correctly pins D-5.5 contract.
  Analysis is thorough; pattern distinction (pipeline determinism vs.
  async-scheduling sync) is valid.

- **F-2029-009** (PR d239dad): re-audit of F-2029-002's Debug prefix entropy.
  Cross-check: 32 bits collision-prone at SHA-256 level, attacker observing
  prefix can't confirm linkage. Mitigation holds. Correct.

### Audit trajectory

Phase 4 confirms the Phase 3 closure work was exceptionally clean:

| Phase | Recent-PRs pass rate | Total findings | Blockers | Important | Nice (closed) | Demoted | SDD-debt |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phase 3 | 73% (25/29 clean) | 39 | 0 | 2 (closed) | 16 (15 closed) | — | 1 (closed) |
| Phase 4 | 94% (16/17 clean) | 9 | 0 | 0 | 5 (all closed) | 4 | 0 |

Phase 4's closure-cycle audit itself was the tightest execution yet — no code
defects, no integration gaps, no design-shaped work. Documentation-driven
audits (five of seven explorers) correctly focused on consistency, drift,
and coverage; two closure PRs addressed all five `nice` findings in focused,
reviewable changes.

Phase 5 audits a yet-smaller surface (8 closure-audit PRs vs. Phase 4's
audit of 17 Phase 3 PRs). The trajectory suggests 0–1 observations, if any,
from cross-checking Phase 4's own execution.

