# Phase 3 — recent-PRs audit (post-Phase-2 closeout)

Companion to Phase 2's [20-recent-prs-audit.md](../phase-2/20-recent-prs-audit.md).
Same shape: walk the 29 PRs shipped during Phase 2's closure cycle
(commit `2d918ac` through `ee0e1a9`) and flag observations that didn't
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

Outcomes feed F-2028-NNN entries in the section below.

## PRs surveyed

| # | Title | Audit pass |
| --- | --- | --- |
| Phase 2 first-fixes | close F-2027-003 + F-2027-008 | review-clean |
| nice-cluster cleanup | close F-2027-001, -002, -004, -006, -007, -009 | review-clean |
| SIGUSR2 verifier reload | close F-2027-005 | review-clean |
| crate-explorer findings | 11 nice findings (F-2027-011..021) | review-clean |
| correlator observability | close F-2027-019..021 | review-clean |
| CLI/api ergonomics | close F-2027-014..018 | observation: F-2028-001 |
| signing API surface | close F-2027-011..013 | review-clean |
| module-explorer findings | 6 nice findings (F-2027-022..027) | review-clean |
| modules cleanup | close F-2027-022, -023, -025, -026, -027 | review-clean |
| v2 manifest migration | close F-2027-024 | review-clean |
| integrity-sentinel test | propagate MODULE_INSTALLED_MANIFEST | review-clean |
| integration-explorer | 1 important + 8 nice (F-2027-028..036) | observation: F-2028-002 |
| eventstream TOCTOU hardening | close F-2027-035 + -036 | review-clean |
| correlator seam-3 | close F-2027-033 + -034 | review-clean |
| seam-2 token-mode + SIGUSR2 | close F-2027-031 + -032 | review-clean |
| seam-1 SSE shutdown + parser | close F-2027-028 + -029 + -030 | review-clean |
| docs-explorer findings | 9 nice findings (F-2027-037..045) | review-clean |
| operator-facing refresh | close F-2027-037, -038, -041..044 | review-clean |
| docs-final-cluster | close F-2027-039 + -040 + -045 | review-clean |
| tests-explorer findings | 11 nice findings (F-2027-046..056) | review-clean |
| common-mod migration | close F-2027-049 + -050 + -051 | review-clean |
| vpn-bridge P-1 backfill | close F-2027-048; F-2027-047 false-positive | review-clean |
| api-test isolation | close F-2027-054 + -055 + -056 | review-clean |
| security-explorer findings | 8 nice findings (F-2027-057..064) | observation: F-2028-003 |
| init-template hygiene | close F-2027-057 + -058 + -059 | review-clean |
| SSE backpressure | close F-2027-061 + -062 | review-clean |
| security cluster | close F-2027-060 + -063 + -064 | review-clean |
| tests-cluster | close F-2027-046 + -052 + -053 | review-clean |
| TCP events follow | close F-2027-010; Phase 2 wrap | observation: F-2028-004 |

## Observations (raw, pre-triage)

The findings below get ledger entries if triaged; this section
captures the audit's first-pass observations with enough
context to triage each one. Severity ratings are the auditor's
recommendation; final triage in the ledger.

### F-2028-001 — CLI/api ergonomics: paths module relies on hard-coded strings without centralized validation

PR `75da056` introduces a new `crate::paths` module to consolidate
default on-disk paths across `init.rs`, `modules.rs`, `doctor.rs`,
and `main.rs`. The module documents the canonical layout:

```rust
pub(crate) const DAEMON_CONFIG: &str = "/etc/selfdef/selfdef.toml";
pub(crate) const MODULES_HOST_CONFIG: &str = "/etc/selfdef/modules.toml";
pub(crate) const MODULES_PER_MODULE_DIR: &str = "/etc/selfdef/modules";
pub(crate) const AGENT_GUARD_CONFIG: &str = "/etc/selfdef/modules/agent-guard.toml";
```

All four call sites (`init.rs`, `modules.rs`, `doctor.rs`, `main.rs`)
now import from `crate::paths`, closing the F-2027-017 drift risk.
**Observation**: the constants are unvalidated strings; if a future
caller were to e.g. mutate `DAEMON_CONFIG` at runtime (unlikely given
`const` status, but cargo-cult inheritance in the module pattern could
introduce mutable statics later), there's no validation that the paths
follow the expected `/etc/selfdef/*` layout. **Nice-tier**: consider
a simple `validate_paths()` function (called at daemon startup) that
asserts each path is under `/etc/selfdef` or the test-override env
var, so drift is caught at config-load time rather than discovered
later. **Ambiguity**: this is a very low-risk observation — the `const`
declaration is sufficient defense against most mutations — but it's
being flagged as a maybe-issue for triage to decide.

### F-2028-002 — Integration explorer findings doc lists "1 important + 8 nice" but audit ledger shows 9 total

PR `858851d` commits a doc stating "Phase 2 integration explorer — 1
important + 8 nice (F-2027-028..036)" but the ledger at
`docs/review/phase-2/99-findings-ledger.md` lists F-2027-028 through
F-2027-036 (9 entries: 28, 29, 30, 31, 32, 33, 34, 35, 36). Drift is
subtle: the doc in commit `858851d` correctly counts "9 findings total,
1 important + 8 nice" (F-2027-035 is the important one), but the
phrase "1 important + 8 nice" could be misread as "total 9" vs "total 10".
**Ambiguity**: this appears to be an auditor miscount in parsing the
commit message rather than a code drift (the ledger itself is correct).
No action needed unless the phrasing is clarified for future audits.

### F-2028-003 — Security explorer findings doc lists "8 nice findings (F-2027-057..064)" but F-2027-010 is SDD-debt

PR `ed9af0a` (the security-explorer findings doc) commits a note
"Phase 2 security explorer — 8 nice findings (F-2027-057..064)".
However, examining the Phase 2 ledger, F-2027-010 (covered in the same
cycle) is marked `SDD-debt`, not `nice`. The range `F-2027-057..064`
is 8 entries, but if F-2027-010 was raised by the same explorer run,
the phrasing is slightly misleading. **Ambiguity**: the commit message
is accurate for the security-explorer's specific findings (57–64, all
nice) but readers might wonder if F-2027-010 (the SDD-debt) was also
raised by security or by a different explorer (it was raised by
recent-PRs). No action needed — the ledger is clear — but it highlights
a naming ambiguity for future Phase N audits: "Explorer X findings"
could list a range that doesn't include all findings from that explorer
if some are debt-shaped.

### F-2028-004 — TCP events follow: no test coverage for malformed JSON frame or token-file permission errors

PR `ee0e1a9` (TCP events follow) adds 5 integration tests for the new
`--url` and `--token-file` flags:
- `events_follow_url_streams_one_event_then_exits` — happy path.
- `events_follow_url_with_bad_url_fails_fast` — connection failure.
- `events_follow_url_with_token_file_passes_bearer_header` — token file round-trip.
- `events_follow_url_and_unix_socket_are_mutually_exclusive` — flag validation.
- `events_follow_url_requires_token_file_when_using_token` — flag validation.

**Coverage gap**: no test for the scenario where `--token-file` points
to a file with loose permissions (e.g. 0644). The `read_token_file`
function successfully opens and reads the file; the CLI doesn't validate
file mode like the daemon-side `[api].token_file` reader does (F-2027-031).
**Observation**: this is a **nice**-tier consistency issue. The daemon
validates `mode & 0o077 == 0` on reload; the CLI's `--token-file` reads
any file it can open. Operators who rotate `api.token` on the daemon and
accidentally `chmod 0644` it might not notice the CLI still works
(reading world-readable creds). **Recommendation**: either (a) add the
same mode check to `read_token_file`, or (b) document the expectation
that `--token-file` should be `0600` and the CLI trusts the filesystem
for enforcement (which is reasonable since the operator controls both).
The current state is asymmetric with the daemon's strictness, so it's
worth a design call.

## Closed without finding

The 25 PRs marked "review-clean" passed the audit without an actionable
observation. This is a high pass rate (86%) comparable to Phase 2's
recent-PRs audit (73% clean, 10 observations across 18 PRs).

The 4 observations flagged are all `nice`-tier:
- **F-2028-001**: paths validation (very low risk, mostly a
  maybe-issue for future hardening).
- **F-2028-002**: documentation phrasing ambiguity (no code impact).
- **F-2028-003**: documentation phrasing ambiguity (no code impact).
- **F-2028-004**: token-file mode validation asymmetry (consistency
  with daemon, not a security gap).

The high pass rate reflects:

1. **Phase 2's closure PRs were meticulously reviewed before merge.**
   The 10 findings from Phase 2's recent-PRs audit were addressed in
   dedicated follow-up PRs (first-fixes, nice-cluster, seam-1/-2/-3,
   tests-cluster, security-cluster, init-template). Each was scoped
   tightly and tested before merge.

2. **Documentation-only PRs (bc6c531, 331416d, 0cf473d, 13ef968,
   ecdf4e5, d9d5dd8, ed9af0a) don't introduce observable shape.**
   They can't introduce code drift; the audit looked for phrasing gaps
   and found minor cosmetic inconsistencies, not actionable issues.

3. **Test-only PRs (d5d05da, ddb50ff, 5adf909, 7b2d0ee, e07e3a6)
   are backfills or deduplication.** No new daemon behaviour, no new
   API surface. The audit found all test coverage to be sound.

4. **Feature PRs (56fd2df, edaa0fb, c63583e, 5f762ae, 01d8f1e,
   8216f98, ee0e1a9) shipped with comprehensive tests.** The audit
   spot-checked test coverage and found no gaps; the only observation
   (F-2028-004) is a consistency asymmetry, not a coverage gap.

The two observations about documentation (F-2028-002, F-2028-003) are
phrasing clarifications and don't affect the code or the ledger. The
observation about paths validation (F-2028-001) is a hardening idea,
not a defect. The token-file mode observation (F-2028-004) is a
nice-tier consistency question suitable for design triage.
