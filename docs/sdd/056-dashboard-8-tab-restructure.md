# SDD-056 — Dashboard 8-tab restructure (MS011 Z-1 closure plan)

> Status: **implemented** — Stage-2 plan was authored as `scoping`;
> all 5 implementation steps of the migration sequence shipped in
> commits 91b8899 (step 2) + 81ebdca (step 3) + 4136965 (step 4) +
> a9bf06e (step 5 + L1 gate evolution from step 5). The 17-panel
> single-page-with-anchor-nav layout documented in SDD-054 is now
> selectable via the operator-toggleable "Show all" button +
> the 8-tab restructure ships per this SDD's spec. SDD-026 Z-1
> reaches implementation through SDD-056 — but SDD-026 as a whole
> stays at `review` because other Z-N vectors (Z-2 shell-out
> invocation, Z-3 apply+revert mutations, Z-13 SD-R87/R86
> enrichment) remain multi-commit follow-up arcs per SDD-055.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21 (status: scoping → implemented; 5 of 7
> closure boxes checked, with the remaining 2 documenting SDD-026
> Z-1 specifically — see § Roadmap to closure below).
> Implements milestone: MS011 Z-1
> Builds on: SDD-026 (Z-1 ratification source — "8 tabs: Models /
> Modules / Profiles / Hardware / Network / Logs / MCP / REPL"),
> SDD-054 (as-shipped 17-panel retrospective + open question D-1)

## Problem

SDD-026 Z-1 ratifies an 8-tab dashboard layout. Today's PWA ships
17 panels on a single page. SDD-054 documents the as-shipped
state. This SDD specifies the restructure.

The mapping from 17 panels → 8 tabs is not 1:1 — multiple panels
collapse under each tab. This SDD specifies that mapping
deterministically so the implementation work has a fixed target.

## Goals

1. Specify the 17-panel → 8-tab mapping
2. Specify the JS framework choice (or non-choice)
3. Specify the URL routing (deep-link to specific tab)
4. Specify the per-tab refresh strategy (active-tab-only vs
   background-refresh-all)
5. Specify the L1 gate evolution to enforce tab structure

## Non-goals

- This SDD does NOT implement the restructure — that's the
  Stage-3 arc that follows ratification
- It does NOT replace SDD-054 (as-shipped retrospective stays
  in the ledger as the intermediate state record)
- It does NOT cover the Cockpit physical UI (separate surface)

## Recommended design

### 8-tab specification

Per SDD-026 Z-1 verbatim. Each tab collapses one operator-relevance
cluster from SDD-054:

| Tab | Panels collapsed | Source clusters |
|---|---|---|
| **Models** | Inference backends + (future) per-model status | NEW + Z-2 layer-up |
| **Modules** | Modules + Audit chains | MS006 + MS009 |
| **Profiles** | Flex profile + (future) per-profile diff | Z-3 |
| **Hardware** | Hardware + GPU + CPU + RAID | MS010 + Z-4 + Z-5 + Z-9 |
| **Network** | Network + (future) per-component drill | Z-7 |
| **Logs** | Findings + Storage (log dir usage) | MS005 + Z-10 |
| **MCP** | (future) MCP tool catalog + invocation log | Z-11 |
| **REPL** | (future) pop-out Python REPL UI | Z-12 |

**Composite health stays as a permanent top-of-page strip**
(not a tab — it's the always-visible glance). Same for the four-
watchdog set badges (always-visible status row).

**Alerts** is a permanent top-of-page strip (operator must see
alerts regardless of which tab is active).

This produces the final layout:

```
┌─ HEADER: title + status + panel-nav (replaced by tab nav)
├─ ALWAYS-VISIBLE STRIP: composite health + 4 watchdog badges + alerts
└─ ACTIVE TAB CONTENT: 1 of 8 tabs (Models / Modules / Profiles /
                                     Hardware / Network / Logs /
                                     MCP / REPL)
```

### Framework choice

SDD-026 Z-1 specifies "askama+minijinja+HTMX; ZERO npm-tooling
chain". The PWA today is vanilla JS — same zero-npm constraint
satisfied. The restructure has 3 options:

**Option A — Pure vanilla JS (continue today's stack).** Tabs
implemented as `<section>` show/hide via class toggle. Active
tab tracked via URL hash. Pros: no new dependency. Cons:
hand-rolled router; no template engine. *Recommendation*: yes
for the restructure — keeps the zero-npm promise. The codebase
already proves vanilla JS scales to 17 panels; 8 tabs is a
simplification.

**Option B — askama (server-side template) + HTMX.** SDD-026's
original choice. Pros: type-safe templates, server-side renders,
HTMX for partial updates. Cons: significant rework — daemon would
need to serve rendered HTML instead of JSON; existing /v1/*
routes stay but new /tab/<name> routes get added. *Recommendation*:
defer; revisit if vanilla JS hits a complexity wall.

**Option C — Minijinja-only (no HTMX).** Server-renders the shell,
JS fetches /v1/* as today. *Recommendation*: defer; effectively
the same as Option A for client behavior with extra server-side
cost.

**Decision recommended**: Option A. Vanilla JS, hand-rolled tab
router via URL hash, no new dependency.

### URL routing

Tab state in URL hash: `#tab=models`, `#tab=modules`, etc.
Operator can deep-link / bookmark / share specific tab. On load,
parse hash; default to `composite` (today's full-page-scroll view
preserved as a fallback for operators who want everything visible
at once).

### Refresh strategy

Active tab only: each panel's `setInterval` runs only when its
tab is active. Inactive tabs pause their probes. Saves
nvidia-smi / df / ping / mdstat / etc. invocations across the
17-panel set when only 1 tab is visible.

Always-visible strip (health + watchdogs + alerts) refreshes
regardless.

### L1 gate evolution

`L1-dashboard-sections.sh` today asserts panel presence. New
checks:

- `<nav id="tab-nav">` with 8 `<a data-tab="...">` anchors
- `<section data-tab="<name>">` wrappers around each tab's
  collapsed panel set
- JS `function switchTab(name)` + URL-hash listener wired
- JS `pauseInactiveTab(name)` + `resumeActiveTab(name)`
- Per-tab refresh interval invocations gated by `activeTab`
  closure variable

### Migration sequence

1. **Single commit** — author this SDD (scope locked)
2. **Single commit** — add 8-tab HTML scaffold + CSS (panels
   still scroll-visible; tab UI inert)
3. **Multi-commit** — implement tab switching JS + URL hash router
4. **Single commit** — wire active-tab pause/resume in setIntervals
5. **Single commit** — flip default landing to first tab (Models);
   add operator-toggleable "show all (legacy)" mode
6. **Single commit** — promote SDD-026 Z-1 from `review` to
   `implemented` + promote SDD-056 from `scoping` to `implemented`
   + promote MS011 from `partial` to `done`

Total: 5 implementation commits across 1 multi-cycle session.

## Implementation status

**This SDD only — Stage-2 scope. No implementation yet.**

## Open questions

- **D-1**: Vanilla-JS hand-rolled tab router vs lightweight router
  library (e.g. ~10kB navigo)? **Recommendation**: vanilla JS —
  zero new dependency, the router is ~30 lines.

- **D-2**: Preserve scroll-all-panels mode as operator-toggleable
  fallback? **Recommendation**: yes — some operators want
  everything-on-one-screen for screen real estate reasons; the
  toggle is 1 line of CSS class on `<main>`.

- **D-3**: When a tab has zero panels today (MCP / REPL), should
  the tab still appear with a placeholder, or hide until panels
  ship? **Recommendation**: show placeholder — operators see the
  complete navigation surface; the placeholder reads "Coming —
  see SDD-056 § Migration sequence step <N>".

- **D-4**: Per-tab keyboard shortcut (e.g. `g m` → Modules,
  `g h` → Hardware)? **Recommendation**: defer to D-1
  (per-panel show/hide toggle) — keyboard shortcuts add JS
  complexity that doesn't pay back until the tab structure is
  validated by operator use.

## Roadmap to closure

Operator-readable closure conditions for SDD-056 → implemented:

- [x] 8-tab HTML scaffold shipped (commit 91b8899)
- [x] Tab-switching JS shipped + URL hash router (commit 81ebdca)
- [x] Active-tab pause/resume wired into setInterval (commit 4136965)
- [x] Default-landing flip + "show all" toggle shipped (commit a9bf06e)
- [x] L1-dashboard-sections.sh extended with tab checks (commits
      91b8899 + 81ebdca + a9bf06e — full drift detection layer)
- [ ] SDD-026 Z-1 promoted from review → implemented (deferred
      because SDD-026 covers all 13 Z-vectors, not just Z-1;
      promote when remaining Z-N arcs land per SDD-055)
- [ ] MS011 partial → done in INDEX.md (same deferral reason as
      above — MS011 has 4 substantive multi-commit Z-vector
      follow-up arcs per SDD-055)

5 of 7 boxes checked. SDD-056 promotes scoping → implemented
because all 5 implementation steps shipped. The remaining 2 boxes
document Z-1's role in the larger MS011 / SDD-026 closure — they
unblock when the other Z-N arcs land.

The dashboard ships TODAY in its full Z-1 form (the 8-tab
restructure works; operator can toggle between tabbed + all
modes). Z-1 as a Z-vector is **functionally complete**; the
ratification gates above are bureaucratic — they track
documentation-level promotion of the parent SDD-026 + the
parent MS011.
