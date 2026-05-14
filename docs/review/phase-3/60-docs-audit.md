# Phase 3 — Docs audit

> Scope: the documentation surface introduced by the Phase 2 closure
> cycle (~28 PRs, commits `2d918ac` through `ee0e1a9`).
>
> Does **not** re-litigate Phase 2's docs audit (every `F-2027-037..045`
> that shipped during Phase 2 closeout). If a Phase 2 doc fix is
> broken, that's a new `F-2028-NNN` with a back-reference.

## Headlines

- **No blockers, no important findings.** Documentation surface
  introduced by Phase 2 closures is consistent and accurate.
- **5 nice findings** clustered around three themes:
  - **Phase 3 explorer docs' own status drift** — the charter and
    ledger carry stale "in progress" and explorer-count markers
    that weren't refreshed as explorers shipped.
  - **CHANGELOG.md phase-status lines drift** — successive entries
    show inconsistent "X findings" counts across adjacent PRs
    during the same explorer's closure cycle.
  - **init.rs doc-comment precision** — `STARTER_MODULES` header
    claims a specific behavior that differs slightly from what the
    code and comments actually recommend.
- Three explorers remain to ship.

## Per-area observations

### Area 1 — Seven Phase 2 audit docs themselves

Audits of `docs/review/phase-2/20-recent-prs-audit.md` through
`80-security-audit.md`. These docs are time-stamped snapshots
capturing findings as each explorer shipped; the ledger carries
live status. Per-doc drift check:

**20-recent-prs-audit.md** — "reviewed the 29 PRs shipped during
Phase 2's closure cycle"; ledger now shows 29 entries with all
findings closed or demoted. Doc internally consistent, no drift
to code.

**30-crate-audit.md** — "11 nice findings clustered around three
themes"; ledger shows 11 raised (5 open, 3 demoted, 3 closed).
Doc accurately reflects the audit posture at write time; no
forward-looking "phase status" lines to drift.

**40-module-audit.md** — "1 important finding (F-2028-015)";
ledger confirms. The audit correctly flagged the vpn-bridge
inventory claim drift. No drift in the doc itself.

**50-integration-audit.md** — "4 nice findings, 0 blockers, 0
important"; ledger shows F-2028-016..019 (4 entries). Doc is
accurate. No forward-looking status markers to drift.

All four Phase 2 audit docs (20, 30, 40, 50) are self-contained
snapshots with no forward-looking status lines. They are stable.

### Area 2 — CHANGELOG.md explorer status lines

Each closure PR in the CHANGELOG includes a "Phase 3 status after
this PR" line. Cross-check the findings counts:

1. **"recent-PRs audit" section (line 4):** "4 findings raised, 0
   blockers, 0 important, 2 nice, 2 demoted." ✔

2. **"crate explorer" section (line 115):** "14 findings raised
   across 2 explorers. 0 blockers, 0 important, 9 nice, 5 demoted,
   0 SDD-debt. Five explorers remain."
   - Claims "2 explorers" raised 14 findings total.
   - Cross-check: recent-PRs raised 4, crate raised 10 (F-2028-005
     through -014) = 14 total. ✔

3. **"module explorer" section (line 81):** "15 findings raised
   across 3 explorers: 0 blockers, 1 important (F-2028-015, open),
   9 nice (2 closed, 7 open), 5 demoted, 0 SDD-debt. Four explorers
   remain (integration, docs, tests, security)."
   - Claims "3 explorers" raised 15 findings total.
   - Cross-check: recent-PRs 4 + crate 10 + module 1 (F-2028-015)
     = 15 total. ✔
   - Claims "9 nice (2 closed, 7 open)"; ledger shows F-2028-001,
     -004, -005, -006, -007, -010, -012, -013 (8 open) +
     F-2028-004/-005 now closed in line 81 context = 6 open + 2
     closed = 8 nice total, not 9. (See finding F-2028-020 below.)

4. **"integration explorer" section (line 46):** "19 findings across
   4 explorers: 0 blockers, **1 important (now closed)**, 13 nice (2
   closed by PR #86, 11 open), 5 demoted, 0 SDD-debt. Three explorers
   remain (docs, tests, security)."
   - Claims "4 explorers" raised 19 findings total.
   - Cross-check: 15 prior + integration 4 (F-2028-016 through -019)
     = 19. ✔
   - But context is confusing: line says "1 important (now closed)"
     but line 81 says "1 important (F-2028-015, open)" — the -015
     finding was raised by the module explorer (line 81) as open;
     it was closed later by a follow-up PR. At the time of the
     integration PR section (line 46), the context should reflect
     the actual state *at that PR's merge time*. This is editorial
     inconsistency rather than drift, but the phrasing is
     confusing. (See finding F-2028-021 below.)

### Area 3 — init.rs STARTER_CONFIG + STARTER_MODULES doc-comments

Read lines 134-228 (STARTER_CONFIG) and 230-300 (STARTER_MODULES).
Cross-check claims:

**Line 140-144** states the template documents "every audit-shipped
opt-in security feature (rule signing, eventstream integrity, api
token, rbac probe) is OFF in this file." Cross-check against the
template:
- `[security].require_signed_rules = false` ✔
- `[api].enabled = false` ✔
- `[collectors.eventstream].integrity_check = false` ✔
- RBAC probe — no setting in the template; it's a CLI command
  (`selfdefctl rbac check`), not a config file knob. ✔ (accurate)

**Line 192-199** documents the `control_token_file` split:
"`control_token_file` gates the mutating control endpoints." The
comment says "Leave `control_token_file` unset to disable the control
plane entirely; set it to a separate 0600 file with its own rotated
token to expose control under a stricter audience." The code matches
the doc comment. ✔

**Lines 240-246** (`STARTER_MODULES` header) state: "F-2027-059:
every per-module `config = "..."` file below is a trust boundary —
the daemon evaluates its contents at apply time. Provision each file
as 0640 root:selfdef before uncommenting the matching block."

Cross-check against the template lines 256-287:
- Each module block includes a `config = "..."` line.
- The comment recommends `install -m 0640 -o root -g selfdef
  /usr/share/selfdef/modules/<slug>.toml.example
  /etc/selfdef/modules/<slug>.toml`
- **Drift**: the comment says "0640" (read for root+selfdef group)
  but does not match the full recommended install command at line
  245-246 which says `install -m 0640 -o root -g selfdef`. The
  literal install invocation is correct, but the comment doesn't
  *show* the file mode as part of the module block itself — it's
  only documented in the header. An operator copying the module
  block without reading the full header would miss the 0640
  requirement. (See finding F-2028-022 below.)

### Area 4 — `docs/dev/*.md` runbooks (none touched)

The Phase 2 closure cycle did not touch the six Phase 2 runbooks
(first-run, module-helpers, operator-health-check, rbac-posture,
signing, test-contract) — those were audited in Phase 2's docs
audit (D2-001 through -009). No new drift introduced during Phase
3's closure cycle.

### Area 5 — README.md + ARCHITECTURE.md + SECURITY.md

The three repo-root docs were not modified during the Phase 2 closure
cycle. Phase 2's docs audit (D2-005, D2-006, D2-007 for README;
D2-008 for ARCHITECTURE) identified pending drift, but those fixes
were intended for a follow-up "operator-facing refresh" PR that may
not have shipped. Quick verification:

- **README.md** (line 90): verb-tour section still lists only legacy
  verbs; `selfdefctl events follow --url`, `selfdefctl keys
  verify-dir`, and the expanded `selfdefctl rbac check --probe`
  subject list are not mentioned. (This is Phase 2 drift, not Phase 3
  drift, so not counted as a new finding.)

- **ARCHITECTURE.md** (line 12): SIGUSR2 diagram label still says
  `(api tokens)` only; post-Phase-2 the signal also reloads the
  verifier and re-verifies rules. (Phase 2 drift, not Phase 3.)

These are pre-existing Phase 2 findings, not new drift.

### Area 6 — Phase 3 charter and ledger self-drift

The Phase 3 charter and ledger are the most-recent documents and
carry status markers that can drift quickly.

**00-charter.md § Status** (lines 122-132) states "This PR opens Phase
3 with: the charter, a structured inventory, one explorer's first-pass
output (recent-PRs audit), and the Phase 3 ledger with the initial
findings. The remaining explorers will run in follow-up PRs. Phase 3
closes when every important / blocker has either a 'closed by <PR>'
back-reference or a tracked SDD."

This phrasing is accurate for the charter's own opening commit, but
the charter itself has not been re-updated as explorers shipped. At
the time of writing the docs-audit explorer (this doc), the charter
still reads "The remaining explorers will run in follow-up PRs" even
though four explorers have already shipped (recent-PRs, crate, module,
integration). (See finding F-2028-023 below.)

**99-findings-ledger.md § Status** (lines 50-62) states "19 findings
across 4 explorers" and "Three explorers remain: docs, tests,
security." This is accurate *at the time this ledger was last updated*
but may drift if new explorers ship without the ledger being refreshed.
The ledger is a living document, so periodic refresh is expected. No
finding here; the ledger's format is designed for incremental updates.

### Area 7 — Phase 3 explorer audit docs' own numbering

The Phase 3 explorer docs (20-recent-prs-audit through 50-integration-
audit) use per-area id prefixes (per Phase 2's shape) before rolling up
to the global ledger. But Phase 3 docs use the global ledger IDs
directly (F-2028-NNN) without intermediate per-explorer prefixes like
Phase 2 did (D2-, C2-, M2-, I2-, etc.).

**Cross-check consistency:**
- 20-recent-prs-audit.md (lines 60-92): lists F-2028-001, -002, -003, -004.
  No per-explorer prefix. ✔
- 30-crate-audit.md (lines 50-97): lists F-2028-005 through -014. No
  per-explorer prefix. ✔
- 40-module-audit.md: lists F-2028-015. No per-explorer prefix. ✔
- 50-integration-audit.md: lists F-2028-016 through -019. No per-explorer
  prefix. ✔

All Phase 3 explorer docs consistently use the global F-2028-NNN ledger
IDs directly, skipping the per-explorer prefix layer. This is a deliberate
choice (cleaner numbering) and is consistent across all four explorers.
No drift.

## Observations (findings)

### F-2028-020 — CHANGELOG.md nice-finding count off-by-one in module explorer line

**Surface:** `/home/user/selfdef/CHANGELOG.md:81` (the "module explorer"
closure's "Phase 3 status after this PR" line).

**Evidence:** The line states "9 nice (2 closed, 7 open)" but the ledger
count is 8 nice findings at the time that status line was written (the
line itself announces that F-2028-015 is now closed; the prior state had
9 nice + 1 important = 10 total "actionable" findings before F-2028-004
and -005 were closed by PR #86, leaving 8 nice + 1 important = 9
actionable). The count "9 nice (2 closed, 7 open)" is off: it should be
"8 nice (2 closed, 6 open)" or the context needs clarification. This
suggests the status line was copy-pasted from a template and not
updated for the actual counts at merge time.

**Severity:** nice. The triage table and ledger are correct; this is a
count-mismatch in a summary line that doesn't affect decision-making.
The error doesn't propagate to the ledger itself.

**Recommendation:** implement (one-line fix to CHANGELOG's module
explorer status line).

### F-2028-021 — CHANGELOG.md phase-status lines don't capture the sequential closure state

**Surface:** `/home/user/selfdef/CHANGELOG.md` — three "Phase 3 status
after this PR" lines (lines 46, 81, 115) that claim the state at PR
merge time but don't account for PRs that close prior findings after
an explorer ships.

**Evidence:** The integration-explorer PR's status line (line 46) says
"1 important (now closed)" referring to F-2028-015. But F-2028-015 was
raised by the *module* explorer (line 81) before the integration
explorer shipped (line 46 comes *before* line 81 in the Unreleased
section, so the integration PR is the most recent). At the time the
integration PR merged, F-2028-015 was already open (raised by the
prior module-explorer PR). The phrasing "(now closed)" is editorial
hindsight added when writing the integration PR, but the integration
PR itself didn't close F-2028-015 — a follow-up PR did. This creates
an ambiguous timeline.

A clearer structure: each status line should reflect the state *at
that PR's merge* (not "now" = reader's current time), and if a PR
closes findings from a prior explorer, it should reference them
explicitly ("closes F-2028-015 from module explorer").

**Severity:** nice. The CHANGELOG is read sequentially top-to-bottom;
a reader following the dates understands the temporal ordering. The
ambiguity is editorial.

**Recommendation:** implement (clarify the status-line phrasing to
separate "state at this PR's merge" from "state now as you read").

### F-2028-022 — STARTER_MODULES header documents mode but template doesn't surface it

**Surface:** `/home/user/selfdef/crates/selfdef-cli/src/init.rs` lines
240-246 vs. 256-287.

**Evidence:** The header (lines 240-246) documents the F-2027-059
trust-boundary requirement: "Provision each file as 0640 root:selfdef
before uncommenting the matching block" and shows the full `install -m
0640 -o root -g selfdef` invocation. But the template itself (lines
256-287) doesn't repeat the mode requirement at each module block. An
operator who copies a module block (e.g., lines 256-257) without
reading the full header would see:

```toml
# [modules.tetragon]
# config = "/etc/selfdef/modules/tetragon.toml"
```

and might create the file as 0644 (a `cp` or `touch` default) instead of
0640. The comment at lines 239-246 is clear, but embedded per-module
comments would reinforce the trust boundary without requiring header
context.

**Severity:** nice. Operators reading the header + first-run checklist
(which references the init docs) will see the requirement. But
robustness would add a one-line per-module reminder: `# (trust boundary;
must be 0640 root:selfdef)`.

**Recommendation:** implement (add a per-module reminder in the template).

### F-2028-023 — Phase 3 charter's status section is stale

**Surface:** `/home/user/selfdef/docs/review/phase-3/00-charter.md`
§ Status (lines 122-132).

**Evidence:** The section states "This PR opens Phase 3 with: … The
remaining explorers will run in follow-up PRs." But at the time of
writing this audit (which is the fifth explorer of seven), four
explorers have already shipped: recent-PRs, crate, module, integration.
The charter's status description is accurate for the charter's own
opening PR but hasn't been updated as explorers shipped.

The ledger (`99-findings-ledger.md`) carries the live count ("19 findings
across 4 explorers") but the charter still implies "one explorer has
shipped, six remain." This is low-risk because readers will consult the
ledger for truth, not the charter's status section. But consistency would
require the charter to be re-updated or to drop the per-explorer status
entirely and delegate to the ledger.

**Severity:** nice. The ledger is the source of truth; the charter's
status section is aspirational framing that drifted. Not actionable for
the current phase, but worth noting for Phase 4: decide whether charter
status sections should be kept live or delegated to the ledger entirely.

**Recommendation:** defer (policy decision for next cycle; no code impact).

### F-2028-024 — Phase 3 inventory claims v2 migration completeness but v1 modules exist

**Surface:** `/home/user/selfdef/docs/review/phase-3/10-inventory.md`
§ Module-side machinery (lines 119-125).

**Evidence:** The inventory states "All 8 modules completed SDD-006 v2
manifest-helpers migration (closure of F-2027-024)." But the module
explorer (40-module-audit.md lines 44-70) cross-checked via grep and
found 6 v2 + suricata (correctly exempt, no persistent files) +
vpn-bridge (v1, incorrect). The claim "all 8 modules" is imprecise.

The module-audit doc correctly qualifies this ("the phrasing 'all 8
modules' is imprecise"), and the closure PR fixed vpn-bridge. But the
inventory doc itself (line 120-125) was not updated post-closure to
reflect the corrected state. For readers discovering Phase 3 via the
inventory, the claim "all 8 modules" will mislead them until they
cross-check with the audit doc.

**Severity:** nice. The audit doc catches the drift, and the closure PR
fixes the code. But documentation consistency would update the inventory
post-closure to read "6 modules migrated to v2; suricata (exempt) and
vpn-bridge (F-2028-015, closed) remain."

**Recommendation:** implement (update the inventory after the vpn-bridge
closure PR ships, to reflect the corrected state).

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| F-2028-020 | nice | CHANGELOG.md nice-finding count off-by-one | CHANGELOG refresh |
| F-2028-021 | nice | CHANGELOG.md status-line timing ambiguity | CHANGELOG clarification |
| F-2028-022 | nice | STARTER_MODULES template lacks per-module mode reminder | init.rs docstring refresh |
| F-2028-023 | nice | Phase 3 charter status section drifted | defer (Phase 4 policy) |
| F-2028-024 | nice | Phase 3 inventory claims incorrect v2 migration state | inventory refresh post-vpn-bridge |

All five findings land as `nice` severity. Two natural closing-PR clusters:

1. **CHANGELOG clarification** (F-2028-020 + F-2028-021) — one PR
   refreshes the explorer status lines to clarify counts and timing.

2. **Documentation refresh** (F-2028-022 + F-2028-024) — one PR updates
   the init-template doc-comment and the inventory description to
   reflect Phase 2's closure state accurately.

F-2028-023 is a policy question for Phase 4: whether charter status
sections should be kept live or deprecated in favor of the ledger.
