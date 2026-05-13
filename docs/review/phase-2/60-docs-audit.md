# Phase 2 — Docs audit

> Scope (per the Phase 2 charter): six new `docs/dev/<feature>.md`
> runbooks, README.md, ARCHITECTURE.md, six SDDs (all
> `implemented`), plus the four already-shipped Phase 2 audit
> docs in `docs/review/phase-2/`. Per-area ids prefix `D2-` and
> roll up to the ledger as `F-2027-NNN`.
>
> What this audit doesn't re-litigate: Phase 1's docs audit
> (every `F-2026-NNN` docs finding closed during the previous
> cycle). If a Phase 1 fix is broken, that's a new
> `F-2027-NNN` with a back-reference.

## Headlines

- **No blockers and no important findings**. Doc surface is
  in good shape overall — the six new runbooks all exist,
  the README and ARCHITECTURE.md were both refreshed during
  Phase 2 closeout (PRs #52/#53), every SDD is `implemented`
  and has at least one passing test.
- **9 nice findings** clustered into three themes:
  - **Drift from Phase 2 closures** — three doc surfaces
    pre-date or skipped the closure of F-2027-005 / -007 /
    -024 / -028 / -029 / -032 and still describe the
    pre-fix behaviour.
  - **README missing post-Phase-1 verbs** — `selfdefctl
    events follow`, `selfdefctl init *`, `selfdefctl doctor`,
    `selfdefctl rbac check`, `selfdefctl keys verify-dir` are
    all reachable via `--help` but not all called out in the
    README's verb tour.
  - **Phase 2 audit docs' own status drift** — the charter
    + ledger had stale "in progress" / "three explorers
    remain" markers when in fact four explorers have run and
    35 of 36 findings are closed.
- 36 findings total across four explorers; this audit adds 9.

## Per-area observations

### Area 1 — `docs/dev/<feature>.md` runbooks

Inventory: `first-run.md`, `module-helpers.md`,
`operator-health-check.md`, `rbac-posture.md`, `signing.md`,
`test-contract.md`. All six are present. Per-runbook drift:

- `docs/dev/signing.md:102-114` walks the operator through
  the two hot-reload signals (SIGHUP for rules, SIGUSR2 for
  the verifier) but doesn't mention that SIGUSR2 also reloads
  the API token files (`[api].token_file` /
  `[api].control_token_file`). After PR #58 + #69 + #70, one
  SIGUSR2 fan-outs to tokens + verifier + rules and emits a
  single summary log line — operators reading just this doc
  won't know the signal is multi-purpose. **(D2-001)**

- `docs/dev/rbac-posture.md:35-36` and lines 90-91 still list
  the built-in probe set as `system:authenticated +
  system:unauthenticated`, but F-2027-007's closure (PR #57)
  expanded the set to four — also `system:masters` and
  `system:serviceaccount:default:default`. Doc claims the CLI
  probes two; the CLI now probes four. **(D2-002)**

- `docs/dev/test-contract.md` doesn't reference any Phase 2
  pattern or seam-test convention even though SDD-005 P-3
  (NATS) and the new SSE / SIGUSR2 / minisign-verify /
  eventstream-integrity seams all have integration tests
  that follow patterns worth documenting (e.g. the
  `MODULE_INSTALLED_MANIFEST` per-test override that landed
  in PR #65). Add a "Per-test isolation overrides" section
  pointing at the env-var pattern. **(D2-003)**

- Inconsistent section structure across runbooks: `first-run.md`
  has 11 sections (TL;DR / commands / examples / opt-ins /
  tests / etc), `signing.md` has 8, `rbac-posture.md` has 5
  (no "Environment variables" / "Exit codes" / "Tests"
  sections). Pick a canonical shape and apply uniformly.
  **(D2-004)**

### Area 2 — `README.md`

The README was rewritten in PR #52 (post-Phase-1) and has
roughly held shape since. Three drift items:

- `README.md` verb-tour section doesn't mention the post-PR-#52
  CLI surface adds: `selfdefctl init {config,modules,checklist}`
  (PR #51), `selfdefctl doctor` (PR #50), `selfdefctl events
  follow` (PR #54), `selfdefctl keys verify-dir` (PR #57),
  `selfdefctl api rotate-token` (already documented), and the
  expanded `selfdefctl rbac check --probe` subject list (PR
  #57). Operators discovering the CLI by reading the README
  will miss most of the Phase 2 cycle. **(D2-005)**

- `README.md` doesn't mention Phase 2 closure findings
  (F-2027-005 SIGUSR2 verifier reload, F-2027-035 eventstream
  TOCTOU/symlink hardening, F-2027-007 expanded RBAC probes,
  F-2027-014 `with_full_capability` feature-gating). The
  "Security opt-ins" section cites only `F-2026-` follow-ups
  from Phase 1. Operators evaluating maturity can't tell
  what's been iterated. **(D2-006)**

- `README.md:173` Quickstart's `cargo deb -p selfdef-daemon`
  builds only the daemon; the CLI is a separate target
  (`selfdef-cli`'s binary is `selfdefctl`). The README never
  tells operators they need to package the CLI separately or
  use a workspace-wide flag. **(D2-007)**

### Area 3 — `ARCHITECTURE.md`

Two drift items, both around the SIGUSR2 fan-out which
expanded across Phase 2:

- `ARCHITECTURE.md:12` labels SIGUSR2 in the topology diagram
  as `(api tokens)` only. Post-PR-#58 / #69 / #70 the signal
  also covers rule-signing verifier reload + rule re-verify.
  Operators tracing signal flow on the diagram will miss the
  verifier path. **(D2-008)**

- `ARCHITECTURE.md:199` describes the rotate-token flow as
  the canonical SIGUSR2 use case without mentioning the
  verifier or the summary log. The "SIGUSR2 reload summary"
  line is now the operator's single-glance answer to "did
  the rotation overall succeed?" but the doc still implies
  per-branch logs only. (Same fix as D2-008 — refresh in one
  pass.)

### Area 4 — SDDs (`docs/sdd/`)

Six SDDs, all `implemented`. The status tags are accurate as
of the post-Phase-1 closeout. One forward-looking observation:

- **No SDD cross-references the F-2027-NNN findings that
  iterated on its surface.** Examples:
  - SDD-003 (vpn-bridge multi-instance) drove F-2027-001 (UX
    polish) and F-2027-025 (safe_name defense). Neither is
    cited in the SDD.
  - SDD-004 (rule signing) drove F-2027-005 (verifier
    reload) and F-2027-006 (batch verify). Neither is cited.
  - SDD-006 (module-script lib v2) drove F-2027-024
    (per-module v2 migration). Cited in the helpers
    runbook but not in the SDD itself.

  The SDDs are stable design records; the F-2027-NNN entries
  are stable finding IDs. A "Follow-up findings" tail
  section linking the two would make the lineage discoverable
  from the SDD reader's vantage. **(D2-009)**

### Area 5 — Phase 2 audit docs

The four audit docs shipped during this cycle
(`00-charter.md`, `10-inventory.md`, `20-recent-prs-audit.md`,
`30-crate-audit.md`, `40-module-audit.md`, `50-integration-audit.md`)
are internally consistent and faithful to the code state at
the time each was written. Two minor status-drift items I
spotted while writing this audit:

- `docs/review/phase-2/00-charter.md` § "Status" still lists
  the charter as "in progress" with the per-explorer state
  reflecting only the recent-PRs audit. The ledger
  authoritatively tracks per-explorer progress; the charter
  should either drop the per-explorer status block entirely
  (point at the ledger) or be refreshed at every explorer
  closure. The latter is high-maintenance — picking the
  former is the lighter-touch fix. (No new finding; track
  inline as a docs-cluster nit.)

- `docs/review/phase-2/20-recent-prs-audit.md:56-175` and
  subsequent explorer audits embed "closed by …" status
  strings inline in the per-observation rows. This is **by
  design** (the audit docs are time-stamped snapshots and
  the closure status is part of the historical record), but
  the ledger has the live status. Keep both, just be explicit
  in the audit doc's preamble that the per-row closure notes
  are time-stamped and the ledger is the source of truth.
  (No new finding.)

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| D2-001 | nice | `signing.md` SIGUSR2 multi-purpose | signing runbook refresh |
| D2-002 | nice | `rbac-posture.md` subject list | rbac runbook refresh |
| D2-003 | nice | `test-contract.md` missing isolation-override pattern | test-contract refresh |
| D2-004 | nice | inconsistent runbook section structure | docs-cluster refresh |
| D2-005 | nice | README verb-tour missing post-#52 surface | README refresh |
| D2-006 | nice | README missing Phase 2 closure context | README refresh |
| D2-007 | nice | README quickstart misses CLI packaging | README refresh |
| D2-008 | nice | ARCHITECTURE.md SIGUSR2 fan-out | architecture refresh |
| D2-009 | nice | SDDs don't cross-ref F-2027-NNN follow-ups | SDDs refresh |

All 9 entries land in the Phase 2 findings ledger as
F-2027-037 through F-2027-045 with `nice` severity. Two
natural closing-PR clusters: **operator-facing refresh**
(D2-001 + D2-002 + D2-003 + D2-005 + D2-006 + D2-007 +
D2-008 — one PR that does the doc walk + brings every
operator-touch surface forward to today's code state) and
**SDD lineage** (D2-009 — one PR adding "Follow-up findings"
tails to the six SDDs). D2-004 (section-structure
uniformity) is the most invasive single fix and warrants its
own PR.
