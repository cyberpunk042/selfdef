---
name: view
description: Project command center — Progress, Position, Done, TODO, Questions (answered + unanswered with options & recommendations), Way forward. Each section is augmented with reasoning, tradeoffs, and concrete next steps. Use when the user types /view or asks orientation questions ("where are we?", "what's the status?", "what's left?", "how far have we come?", "what's the way forward?").
---

# /view — augmented project command center

Render seven sections, **each substantially augmented** with reasoning,
options, tradeoffs, and concrete next steps. The render is the deliverable —
the user is using it to decide what to do next. Thin renders fail the job.

```
1. PROGRESS     — trajectory + trend analysis + what the trend predicts
2. POSITION     — current state + what it enables + what to watch
3. DONE         — shipped items, grouped, with significance + what each unlocked
4. TODO         — remaining work with priority + effort + blockers + dependencies
5. QUESTIONS    — ★ ANSWERED (decision + rationale + when) ★
                  ★ UNANSWERED (details + options + tradeoffs + recommendation) ★
6. WAY FORWARD  — threads with concrete first step + effort + tradeoff vs others
7. SIGNPOSTS    — where to find what (always include)
```

The **Unanswered** subsection is the most-augmented part of the entire view.
Treat every unanswered question as a mini-RFC: state the question, explain why
it's open, list options with explicit tradeoffs, name a recommendation with
reasoning, and identify what unblocks the decision. **Never list an unanswered
question with just a one-line gloss.**

## When to invoke

- User typed `/view`.
- Orientation questions: "where are we?", "what's the status?", "what's left?",
  "how far have we come?", "what's the way forward?", "what's pending?",
  "what's done?", "what's next?".
- Cold-start of a session where the user wants the lay of the land.

## Project-shape detection

Run these checks **in parallel** at the start:

1. `ls docs/handoff/*.md 2>/dev/null | sort | tail -3` — recent handoffs
2. `ls docs/review/phase-*/99-findings-ledger.md 2>/dev/null` — audit ledgers
3. `ls docs/sdd/*.md docs/plan/*.md docs/rfc/*.md 2>/dev/null` — design docs
4. `ls ARCHITECTURE.md SECURITY.md README.md ROADMAP.md TODO.md CHANGELOG.md 2>/dev/null`
5. `git log --oneline -25` — recent commit cadence
6. `git branch --show-current && git status --short` — current branch + WIP
7. `rg -i 'TODO|FIXME|XXX' -n -g '!target' -g '!node_modules' | head -50` — in-code TODOs
8. Open GitHub issues if a `cyberpunk042/<repo>` is in MCP scope

Detect one of:

- **Shape A**: audit ledgers + SDDs both present (e.g. selfdef)
- **Shape B**: design docs only (SDDs / RFCs, no audit ledgers)
- **Shape C**: TODO.md / ROADMAP.md driven, no SDDs
- **Shape D**: vanilla git repo
- **Shape E**: not a git repo at all — synthesize from filesystem

The seven sections render for every shape. Only the **sources** vary.

---

## Section-by-section augmentation spec

### 1. PROGRESS

Wide trajectory table or timeline + a **trend annotation paragraph**.

Trend annotation must answer:
- Is the cadence accelerating, decelerating, or steady?
- What's the dominant work-type (features / fixes / audit / refactor)?
- What does the trajectory **predict** — convergence, expansion, plateau?

Source by shape:
- **A**: cumulative trajectory table from the latest phase ledger.
- **B**: SDD-by-SDD status table + last-touched.
- **C**: TODO sections grouped done/in-progress/not-started.
- **D**: `git log --pretty='%s'` themed by commit-prefix; bucket by month.
- **E**: filesystem tree + modification-date histogram.

### 2. POSITION

Concrete facts table + **two augmentations**:

1. **What this state enables** — what becomes possible now that wasn't before?
2. **What to watch** — what's fragile, what's drifting, what could regress?

Always include: branch, status-short, last commit subject/age, open-PR status,
the single most-important fact.

### 3. DONE

Grouped punch list of shipped items. **Each group gets a one-line significance
note**: why did this batch matter; what did it unlock for downstream work.

Render as either:
- A progress-bar block (`━━━━━━━━━━ 100% — N items`) for natural categories, OR
- A table with `Item | Source | Significance` columns

Sources by shape:
- **A**: rows marked `shipped`/`closed` in SDD impl-status tables; closed
  findings in the latest phase ledger.
- **B**: SDDs marked `shipped`/`approved`.
- **C**: TODO checkboxes already checked.
- **D/E**: recent merged PRs / commits.

### 4. TODO

Punch list with **four augmentation columns**:

| Item | Priority | Effort | Blocker | Pointer |

- **Priority**: `★ now` / `near` / `later` / `someday`
- **Effort**: `S` (≤1 PR) / `M` (≤3 PRs) / `L` (own SDD/cycle)
- **Blocker**: who/what gates it; `—` if nothing
- **Pointer**: file:line so the user can navigate

After the table, render a **dependency note** — which items unblock others.

Sources:
- Phase ledger rows not `(closed)`
- SDD rows marked `deferred`/`open`/`pending`
- TODO/ROADMAP unchecked items
- In-code `TODO`/`FIXME`/`XXX` (capped to ~15)
- Open GitHub issues if accessible

### 5. QUESTIONS — answered + unanswered

#### 5a. ANSWERED — decisions made

Table with **four columns**:

| Question | Decision | Rationale | When/where |

`Rationale` is **mandatory** — never just the decision. Explain *why* this
answer over alternatives. `When/where` cites the PR / SDD section / handoff
section that captured the decision.

Source: SDD Q-X rows marked `answered`/`closed`/`shipped`; decisions captured
in handoff docs; resolved issues with their resolution.

#### 5b. UNANSWERED — decisions pending  ★ HIGH-DEPTH ★

**Every unanswered question is a mini-RFC.** Render each as:

```
### Q-N: <Question stated as a question>

**Status**: <open / deferred / blocked / waiting on user>
**Why it's open**: <2-3 sentences — deferred because X / unclear because Y /
                   waiting on Z>
**What it gates**: <what's blocked downstream / what can't ship until this lands>
**Stakes**: <low / medium / high — and a sentence on why>

**Options**:

  A) <Option name — concrete approach>
     • What it looks like: <one line>
     • Pros: <upside>
     • Cons: <downside>
     • Effort: <S / M / L>
     • Risk: <low / medium / high>

  B) <Option name>
     ...

  (Render 2-4 options. If only one option exists, name that explicitly and
  explain why no alternatives — sometimes the design space is genuinely narrow.)

**Recommendation**: <Option X — one sentence on why this beats the others>
**What unblocks the decision**: <user input on X / a spike to measure Y /
                                 the prerequisite SDD landing / time>
```

Source-walk for each question:
- SDD `Q-X` rows not yet answered → read the SDD's "Open questions" section
  for the actual question text + author's framing.
- "Deferred" rows in SDD impl-status tables → read the surrounding context.
- "Way forward" / "TBD" / "Out of scope (deferred to future SDD)" markers.
- Items the latest handoff flagged as needing user input.

If a question's options aren't already enumerated in the SDD, **synthesize
them** from the surrounding context. State that the options are synthesized
rather than quoted, so the user can correct.

### 6. WAY FORWARD

2-5 candidate threads. **Each thread is augmented** with:

```
N. <Thread name>
   Concrete first step: <one specific command/file/action>
   Effort: <S / M / L>
   Prerequisites: <none / Q-X answered / Y shipped>
   Tradeoff vs other threads: <why pick this over thread N+1>
   My read: <recommended / optional / wait>
```

Pull from the latest handoff's "what to ask first" if present — that's
authoritative. Augment any thread the handoff mentions with the above shape.

### 7. SIGNPOSTS

Compact reference table. Always include:

```
Handoff (latest)      docs/handoff/<latest>.md
Audit programme       docs/review/phase-N/...        (if Shape A)
Design docs           docs/sdd/...                   (if A or B)
Root context          ARCHITECTURE.md · SECURITY.md · README.md · CHANGELOG.md
Recent commits        git log --oneline -20
Open PRs / issues     <github URL>
```

---

## Style rules

- **Generous ASCII**: wide tables, strong headings (`##`), monospace blocks
  for trees/lists, box-drawing for the title line. User has explicitly asked
  for visually substantial renders.
- **File:line pointers** for every fact (`docs/sdd/008.md:142`). User
  navigates by them.
- **Don't invent status.** Empty sections render `_(none — nothing to report)_`.
- **Mark synthesis explicitly.** If options/recommendations are *your* synthesis
  rather than quoted from a doc, say so: "(options synthesized; correct me if
  you'd frame them differently)".
- **Skip the explanation-of-what-you're-doing meta.** Render the view; the
  user will react.
- **No clarifying questions before rendering.** The user typed /view to get a
  view; follow-ups come after they see it.
- **Cap at ~2 screens of dense content.** The augmentation makes this longer
  than a thin render; that's intended.

## Read-only

`/view` never edits files. Pure read + synthesis + render.

## Failure modes to avoid

- Rendering Unanswered as a one-line bullet list. **Every unanswered question
  needs the mini-RFC treatment.**
- Listing decisions in the Answered table without the **Rationale** column.
- Rendering DONE as just counts; always include significance.
- Rendering TODO without priority / effort / blocker columns.
- Skipping the trend annotation under PROGRESS.
- Skipping "what it gates" on unanswered questions — that's the load-bearing
  field for deciding whether to answer it now or wait.
- Audit-programme framing leaking into non-audit projects. Detect the shape
  first; map sources to the same seven sections.
