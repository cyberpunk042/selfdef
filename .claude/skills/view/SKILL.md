---
name: view
description: Project command-center view. Detects project shape and renders a structured snapshot — trajectory, current position, open/closed items, unanswered questions, way forward. Use when the user types /view, asks "where are we?", "what's left?", "what's the status?", or otherwise asks for a high-level project read.
---

# /view — project command center

Render a **command-center view** of the current project: where it's been,
where it is, where it's going. Designed to orient a session quickly without
forcing the user to scroll through ledgers.

## When to invoke

- User typed `/view`.
- User asked an orientation question: "where are we?", "what's the status?",
  "what's left?", "what's open?", "what should I work on next?".
- Cold-start of a session where the user wants a lay-of-the-land before
  picking a thread.

## Detection: figure out what kind of project this is

Before rendering, run these checks **in parallel** to detect the project's
shape:

1. `ls docs/handoff/*.md 2>/dev/null | sort | tail -3` — recent handoff?
2. `ls docs/review/phase-*/99-findings-ledger.md 2>/dev/null` — audit ledgers?
3. `ls docs/sdd/*.md 2>/dev/null` — SDD design docs?
4. `ls ARCHITECTURE.md SECURITY.md README.md 2>/dev/null` — root signposts?
5. `git log --oneline -20 2>/dev/null` — recent commit cadence.
6. `git branch --show-current && git status --short 2>/dev/null` — current branch + WIP.

### Shape A — full audit-programme project (selfdef-shape)

Detection: **at least one** of `docs/review/phase-*/99-findings-ledger.md`
exists AND `docs/sdd/*.md` exists.

Read the most recent handoff first (`docs/handoff/<latest>.md`) if any —
it's the canonical entry-point and will tell you the rest. Then read the
latest phase ledger, the most-recently-updated SDD, and the root signposts
(ARCHITECTURE.md, SECURITY.md). Render the **rich view** (below).

### Shape B — design-doc project (SDDs without audit ledgers)

Detection: `docs/sdd/*.md` exists but no `docs/review/phase-*/` directory.

Read the SDD index + the most recent few SDDs. Render the **design view**:
SDD list with status, recent commits referencing each, open questions.

### Shape C — vanilla git project

Detection: none of the above match.

Render the **synthesis view**: branch state, last 20 commits grouped by
theme, open TODOs in code (`rg -i 'TODO|FIXME|XXX'` capped to ~30 hits),
test/CI signals if a workflow file exists.

---

## Rich view (Shape A) — layout

Render the following sections, in order. Use strong ASCII headings, not
meek single-line bullets. The user has explicitly asked for visually
substantial renders; small renders feel evasive.

### 1. Trajectory

A table of every audit phase shipped, drawn from
`docs/review/phase-*/99-findings-ledger.md` files (look for the cumulative
trajectory table inside the latest phase ledger — that table is canonical
and already aggregated). Render as a wide markdown table:

```
| Phase | Cycle audited           | Findings | Important | Closed | SDD-debt | Demoted |
| ...   | ...                     | ...      | ...       | ...    | ...      | ...     |
```

### 2. Current position

Pull from the latest phase ledger's `Status` section. Specifically:

- **Phase status** (open / wrapped / draft).
- **Phase findings counters** (raised / closed / open / demoted / SDD-debt).
- **Important finding(s)** from this phase — what they were and how they
  closed.
- **Branch state**: current branch name + `git status --short` summary.

### 3. Open items

What's not done. Walk these sources in order:

- **Phase ledger**: any row whose severity is not "(closed)".
- **SDD impl-status tables**: rows marked `deferred`, `open`, or `pending`.
- **SDD open questions**: `Q-X` rows whose status is not "(answered)".
- **Recent issues**: `gh issue list --state open` if `gh` available;
  otherwise use `mcp__github__list_issues` if the repo is in scope.

Render as a punch list with file:line pointers so the user can navigate.

### 4. Answered questions (recent)

Pull `Q-X` or open-question rows from the most recent SDDs that have been
**answered** (status: answered / closed / shipped). One line each with the
PR or SDD section that closed them.

### 5. Way forward

Read the latest handoff's "what to ask first" / "next threads" section if
present. Otherwise synthesize from:

- SDD-008 D-N status table — what's next.
- "Deferred" rows in any ledger or SDD.
- TODO/FIXME comments in code (capped, low-noise).

Render as 2-4 candidate threads the user could pick up, each with a 1-line
description and a pointer.

### 6. Signposts

A small reference list — where to find what:

```
- Audit programme:  docs/review/phase-N/...
- Design docs:      docs/sdd/...
- Handoff (latest): docs/handoff/<latest>.md
- Root context:     ARCHITECTURE.md, SECURITY.md, README.md
- Recent commits:   git log --oneline -20
```

---

## Design view (Shape B) — layout

1. **SDD index**: number / title / status / last-touched commit.
2. **Open questions across all SDDs**: Q-X identifiers + which SDD they're in.
3. **Recent design-relevant commits**: `git log --oneline -20 -- docs/sdd/`.
4. **Way forward**: synthesize from SDD content.

## Synthesis view (Shape C) — layout

1. **Branch + WIP**: current branch, modified files, ahead/behind upstream.
2. **Recent activity**: last 20 commits, themed if a pattern emerges
   (group by `git log --pretty='%s'` prefix).
3. **In-code TODOs**: `rg -i 'TODO|FIXME|XXX' -n` capped to ~30 lines.
4. **Test/CI signals**: `.github/workflows/*.yml` summary if present.
5. **Open issues / PRs**: via gh CLI or MCP if available.

---

## Style rules

- Render strong, large ASCII tables and headings — not single-line
  apologetic bullets. The user explicitly wants substantial visual output.
- File:line references (e.g. `docs/sdd/008-notifications-orchestration.md:142`)
  wherever a fact comes from a specific source — the user navigates by them.
- Do not invent status. If a section has no data, say so explicitly
  ("No open findings.") rather than padding with prose.
- Cap the whole render at roughly one screen of dense content. The point
  is orientation, not a re-read of the ledgers.
- Do not edit any files. `/view` is read-only.

## Failure modes to avoid

- **Don't ask clarifying questions before rendering.** The user typed
  `/view` to get a view; ask follow-ups (if needed) after.
- **Don't summarize the summary.** If the latest handoff exists, lean on
  it — quote pointers verbatim, don't re-paraphrase.
- **Don't omit the trajectory table** on Shape-A projects. The
  multi-phase comparison is the most-requested view.
- **Don't claim something is "done" or "closed" without a source.** Tag
  every claim with the file or commit it came from.
