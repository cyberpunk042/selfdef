# Handoff — end of /questions pipeline session

> **Read this first** if you are starting a new session on selfdef.
> Last updated: 2026-05-15 (post-Phase-7 / pipeline-validation session).
> Supersedes `docs/handoff/2026-05-15-end-of-phase-7.md` — that doc
> covered state through PR #155 (Phase 7 wrap). This doc covers what
> shipped after, PRs #156..#161.

## TL;DR — where things are

- **Phase 7 still wrapped** (no audit phase opened or closed this session;
  the close-of-Phase-7 state described in the prior handoff still holds).
- **New session work shipped**: the **`/view` + `/questions` skill
  pipeline** went end-to-end. Skill infra → decisions log → 2
  implementations of those decisions.
- **6 PRs merged** this session (#156-#161). See trajectory table below.
- **First-ever `docs/decisions.md`** — chronological audit log of D-NNN
  design decisions. D-001..D-007 landed.
- **2 D-NNN decisions implemented in code/docs**: D-005 (apply.sh refuses
  cleanly when instance id > 7 chars) and D-002 (SECURITY.md addendum on
  the SSE 30-second slow-client bound).
- **The deck is still empty.** Same as end-of-Phase-7: no open findings,
  no SDD-debt, no GH issues. The remaining D-NNN entries (D-001, D-003,
  D-004, D-006, D-007) are deferred or gated on prerequisites that
  don't exist yet.

## What to ask first in the next session

The natural threads are now heavier than the small-impl cadence of this
session. Four real options:

1. **Scope `write(1)` integration crate** — unlocks D-004 (wall users
   allowlist). Net-new channel module; probably wants its own SDD or
   serious design pass first.
2. **SDD-009 dashboard** — D-001 logged the comprehensive-scope
   requirement; design has been deliberately deferred to its own
   conversation. Operator has consistently said "separate chat."
3. **SDD-010 (or similar): TracingPolicy / sigma signing** — unlocks
   D-003. Working hypothesis is inline detached + bundled CA; final
   shape needs a design SDD.
4. **Phase 8 audit** — 6 PRs landed since Phase 7 wrapped; cycle is
   real. Caveat: most of those are infrastructure for the audit
   programme itself, so "auditing your own session's work" has bias.
5. **Switch repos** — `cyberpunk042/root-ghostproxy` and
   `cyberpunk042/devops-solutions-information-hub` are in MCP scope
   and have been untouched. `/view` is now globally installed so it
   works there too.
6. **Sit on it** — legitimate; the orient→decide→impl loop just ran
   clean. Coming back when something pulls is honest.

**The right first question** to ask the operator: "The /questions
pipeline drained. Next thread: write(1), SDD-009 dashboard, SDD-010
signing, Phase 8, switch repos, or sit on it?"

## How this session worked (cadence — unchanged from prior)

These rules carried unchanged across both the Phase-7 sessions and
this pipeline-validation session:

- **One PR per cycle**, ready-for-review by default.
- **Advance signal**: operator typing "good, its merged, you can
  continue" or a near-variant.
- **No commits without explicit ask** (the session's PRs were
  requested implicitly via the cadence — the operator confirmed by
  merging each).
- **No model identifier** in any pushed artifact. Chat replies only.
- **Visual reporting is generous** — ASCII tables, strong headings.
- **GitHub MCP scope restricted** to `cyberpunk042/{selfdef,
  root-ghostproxy, devops-solutions-information-hub}`.
- **`/questions solve` flow**: render mini-RFC → AskUserQuestion picker
  (always with "Other" override) → diff → ship/leave/cancel.
- **Auto-compact OFF, auto-dream ON, PreCompact snapshot, SessionStart
  inject** — context-management protocol active.

## Session trajectory — 6 PRs merged

| # | PR | Title | What it unlocked |
|---|---|---|---|
| 1 | #156 | `/view` skill + end-of-Phase-7 handoff | Orientation layer (PROGRESS, POSITION, DONE, TODO, QUESTIONS, WAY FORWARD, SIGNPOSTS) |
| 2 | #157 | `/view` augmentation spec | Depth contract per section; mini-RFC shape for UNANSWERED |
| 3 | #158 | `/questions` skill | Interactive resolution layer + `docs/decisions.md` seed |
| 4 | #159 | D-001..D-007 decisions batch | 7 SDD `Q-X` / `D-N` rows answered in place + audit log opened |
| 5 | #160 | impl D-005 — apply.sh instance-id length | First impl from a /questions decision. Includes SDD-003 typo fix (8 → 7 chars math). |
| 6 | #161 | impl D-002 — SECURITY.md SSE bound | Documents the 30s slow-client timeout as the leak-window bound |

**Pipeline net result**: orient → decide → implement loop validated
end-to-end. The /view + /questions skills are now the durable
infrastructure; future sessions can use them to surface and resolve
open design questions without rebuilding the pattern.

## Cumulative trajectory (still Phase 2..7)

```
┌───────┬────────────────────────────────────────┬──────────┬─────────┬────────┬──────────┬─────────┐
│ Phase │ Cycle audited                          │ Findings │ Import. │ Closed │ SDD-debt │ Demoted │
├───────┼────────────────────────────────────────┼──────────┼─────────┼────────┼──────────┼─────────┤
│   2   │ Phase 1 closure cycle                  │    64    │    3    │   60   │    1     │   —     │
│   3   │ Phase 2 closure cycle                  │    39    │    2    │   16   │    1     │   —     │
│   4   │ Phase 3 closure cycle                  │     9    │    0    │    5   │    0     │    0    │
│   5   │ Phase 4 closure cycle                  │     0    │    0    │    0   │    0     │    0    │
│   6   │ SDD-008 cycle (22 PRs / 9 crates)      │   16     │    3    │   14   │    2*    │    2    │
│   7   │ post-Phase-6 cycle (7 PRs / 4 crates)  │   6      │    1    │    6   │    0     │    0    │
└───────┴────────────────────────────────────────┴──────────┴─────────┴────────┴──────────┴─────────┘
```

Phase 8 will audit the post-Phase-7 cycle (PRs #156-#161 + anything
that lands before it opens). 6 PRs is enough to be a real cycle, but
most are infrastructure for the audit programme itself, so the audit
should explicitly call out which findings (if any) are about the
infrastructure vs. about the underlying code.

## D-NNN decisions — status snapshot

| ID | Question | Status | Where |
|---|---|---|---|
| D-001 | SDD-008 D-9 dashboard scope | requirements logged; design deferred to own SDD | `docs/sdd/008…md:46` + `docs/decisions.md` |
| D-002 | SDD-007 D-3 SSE terminate-on-revoke | answered (keep current); documented bound | `SECURITY.md:139` + `docs/decisions.md` |
| D-003 | SDD-004 Q-C TracingPolicy signing shape | working hypothesis (B); awaits design SDD | `docs/sdd/004…md:54` |
| D-004 | SDD-008 Q-F wall(1) per-user opt-in | answered (allowlist); gated on `write(1)` | `docs/sdd/008…md:462` |
| D-005 | SDD-003 Q-C WG interface name limit | **implemented** in apply.sh | `modules/vpn-bridge/install/profiles/relay-via-server.sh` |
| D-006 | SDD-001 Q-C KillPidAction wiring | keep deferred to own SDD | `docs/sdd/001…md:560` |
| D-007 | SDD-001 Q-D multi-host propagation test | keep deferred (SDD scope) | `docs/sdd/001…md:566` |

## Repo signposts — additions this session

| Topic | Path |
|---|---|
| **NEW** Decisions log | `docs/decisions.md` |
| **NEW** /view skill (project) | `.claude/skills/view/SKILL.md` |
| **NEW** /view skill (global) | `~/.claude/skills/view/SKILL.md` |
| **NEW** /questions skill (project) | `.claude/skills/questions/SKILL.md` |
| **NEW** /questions skill (global) | `~/.claude/skills/questions/SKILL.md` |
| **NEW** Global protocol memory | `~/.claude/CLAUDE.md` |
| **NEW** PreCompact/SessionStart scripts | `~/.claude/scripts/*.sh` |
| Prior handoff | `docs/handoff/2026-05-15-end-of-phase-7.md` |

All earlier signposts from the prior handoff are unchanged.

## Standing rules — unchanged

- Branches: `claude/<topic>`.
- Push: `git push -u origin <branch-name>`; retry 4× backoff on net errors.
- Never skip hooks; never force-push to main.
- Confirm before destructive ops.
- Never include any model identifier in pushed artifacts.

## Useful one-shot commands

```bash
# Orient
/view

# Resolve open questions interactively
/questions             # show the queue
/questions solve all   # walk through every open question

# Read the latest handoff (this file, currently)
cat docs/handoff/2026-05-15-end-of-questions-pipeline.md

# See the decisions log
cat docs/decisions.md

# Recent activity
git log --oneline -15

# Workspace health
cargo check --workspace
cargo test --test module_vpn_bridge_multi_instance
```

## End

This handoff captures the post-Phase-7 pipeline-validation session.
The prior handoff (`2026-05-15-end-of-phase-7.md`) remains in tree
for history — it correctly described the state at PR #155. This doc
describes the state at PR #161.
