# Handoff — end of Phase 7

> **Read this first** if you are starting a new session on selfdef.
> Last updated: 2026-05-15. Cumulative state at the close of the
> Phase 7 audit cycle. Designed as a cold-start signpost, not a
> re-read of the ledgers.

## TL;DR — where things are

- **SDD-008 (notifications-orchestration) is complete.** All D-1..D-8
  + D-5e + D-4 HTTP ack shipped. **11 channel integrations live**
  (ntfy, signal, smtp, twilio, slack, discord, wall, pagerduty, loki,
  opensearch, thehive). D-9 (dashboard) is the only deferred design
  point — separate SDD when scoped.
- **Phase 7 closure-cycle audit is wrapped.** 6 findings raised,
  **6 closed in-place, 0 open, 0 SDD-debt, 0 demoted** — the first
  all-in-place-closure phase in the audit programme's history.
- **No open SDD-debt.** Phase 6's two items (F-2031-009 D-5e
  subscription wiring, F-2031-013 daemon-pipeline tests) closed via
  PRs #140 + #141 inside the cycle Phase 7 audited.
- **The audit programme has caught 73 findings across Phases 2-7**,
  10 of them important; trajectory is converging.

## What to ask first in the next session

The deck is genuinely clean. The four candidate next threads are:

1. **SDD-009 dashboard (D-9 from SDD-008).** The deferred design
   point. User has indicated they will scope this in a separate
   design conversation. Pre-work: read SDD-008 D-9 / "Way forward"
   section + the operator-facing channels list in `SECURITY.md`.
2. **Phase 8 audit (the post-Phase-7 cycle).** Only worth starting
   once new code lands. Right now the cycle to audit is ~0 PRs.
3. **Operator-side polish.** No specific item is open — would be
   exploratory. Likely targets: starter-config ergonomics
   (`crates/selfdef-cli/src/init.rs`), `selfdefctl notify` UX,
   docs/dev guides for the 4 new Q-G adapters.
4. **A different SDD entirely.** Existing SDDs 1-7 cover AI/ML
   end-to-end, defaults, VPN/bridge, threat model, test contract,
   shared module-script lib, per-token SSE quota — each is its own
   thread if the user wants to revisit.

**The right first question** to ask the user: "Phase 7 wrapped clean
— which thread next: dashboard (SDD-009), operator polish, a
different SDD, or something new?"

## How this session worked (working cadence)

These rules carried across all of Phase 6 + Phase 7 + the SDD-008
implementation cycle. Re-applying them keeps the rhythm:

- **One PR per cycle.** Each closure or fix ships as its own PR;
  small enough to review in one sitting.
- **Ready-for-review by default**, not draft. Drafts only for an
  explicit reason or partial work.
- **Advance signal**: the user typing "good, its merged, you can
  continue" (or near-variant) means: move to the next item on the
  audit checklist / next planned PR.
- **No commits without explicit ask.** Same for pushes; same for
  destructive git operations.
- **No model identifiers in commits, PR titles/bodies, code
  comments, or any pushed artifact.** Chat replies only.
- **Visual reporting is generous.** ASCII tables, wide trajectory
  views, strong headings. The user has explicitly asked for
  substantial renders.
- **GitHub MCP scope is restricted** to `cyberpunk042/selfdef`,
  `cyberpunk042/root-ghostproxy`,
  `cyberpunk042/devops-solutions-information-hub`. Other repos are
  off-limits.

## Trajectory — Phases 2..7 at a glance

| Phase | Cycle audited                          | Findings | Important | Closed | SDD-debt | Demoted |
| ----- | -------------------------------------- | -------- | --------- | ------ | -------- | ------- |
|   2   | Phase 1 closure cycle                  |    64    |     3     |   60   |    1     |   —     |
|   3   | Phase 2 closure cycle                  |    39    |     2     |   16   |    1     |   —     |
|   4   | Phase 3 closure cycle                  |     9    |     0     |    5   |    0     |    0    |
|   5   | Phase 4 closure cycle                  |     0    |     0     |    0   |    0     |    0    |
|   6   | SDD-008 cycle (22 PRs / 9 crates)      |    16    |     3     |   14   |    2*    |    2    |
| **7** | post-Phase-6 cycle (7 PRs / 4 crates)  |   **6**  |   **1**   |  **6** |  **0**   |  **0**  |

\* Both Phase 6 SDD-debt items closed inside the Phase 7 audit window.

Phase 7's one important finding was **F-2032-005**: DispatcherAdapter
re-minted UUIDv7 ack_tokens on every `notify()` while the engine's
ON-CONFLICT-preserve clause kept the OLD token; re-submits shipped
URLs with T2 while the engine had T1 → click → 404. Closed by adding
`EscalationEngine::lookup_or_mint_token` and having the adapter call
it before constructing the Payload. Full detail:
`docs/review/phase-7/30-module-audit.md` and
`docs/review/phase-7/99-findings-ledger.md`.

## SDD-008 final state

```
D-1   Taxonomy: modules ≠ integrations               shipped (PR #110)
D-2a  selfdef-notifier-orchestrator trait crate      shipped (PR #111)
D-2b  selfdef-integration-ntfy                       shipped (PR #112)
D-2c  selfdef-integration-signal                     shipped (PR #113)
D-3   Per-channel subscription model (legacy chain)  shipped (PR #115 + #117)
D-4   selfdefctl notify {ack,forget,list}            shipped (PR #123)
D-4 H GET /notify/ack/:token + ack_token + ack_link  shipped (PR #142)
D-5a  EscalationEngine persistent layer              shipped (PR #118)
D-5b  PayloadDispatcher façade                       shipped (PR #119)
D-5c  Wake task + rung advancement                   shipped (PR #122)
D-5d  Daemon wiring                                  shipped (PR #124)
D-5e  Subscription filter on engine path             shipped (PR #140)
D-6a  Operating modes (enforce / audit)              shipped (PR #125)
D-6b  Named profiles (auto / aggressive / patient)   shipped (PR #126)
D-6c  Per-rung channel filtering + custom profiles   shipped (PR #129 + #130)
D-7   Panic floor (audit-mode bypass)                shipped (PR #127)
D-8   wall(1) session-attention                      shipped (PR #128)
D-9   Dashboard                                      DEFERRED — separate SDD

Q-C   slack channel                                  shipped (PR #120)
Q-D   twilio channel                                 shipped (PR #116)
Q-E   smtp channel                                   shipped (PR #114)
Q-G   pagerduty / loki / opensearch / thehive        shipped (PRs #143-#146)
      discord channel (no explicit Q)                shipped (PR #121)
```

11 channel integrations total. See
`docs/sdd/008-notifications-orchestration.md:23` for the live table.

## Repo signposts — where to find what

| Topic                                | Path                                                          |
| ------------------------------------ | ------------------------------------------------------------- |
| Latest phase ledger                  | `docs/review/phase-7/99-findings-ledger.md`                   |
| Phase 7 charter + 7 explorer reports | `docs/review/phase-7/00-charter.md`..`80-security-audit.md`   |
| All prior ledgers                    | `docs/review/phase-{2,3,4,5,6}/99-findings-ledger.md`         |
| SDD index                            | `docs/sdd/000-charter.md` + `001`..`008`                      |
| Active SDD (notifications)           | `docs/sdd/008-notifications-orchestration.md`                 |
| Root architecture                    | `ARCHITECTURE.md`                                             |
| Security model + addenda             | `SECURITY.md` (notification credentials + URL-leakage map)    |
| Starter config (operator-facing)     | `crates/selfdef-cli/src/init.rs::STARTER_CONFIG`              |
| Engine-path persistence              | `crates/selfdef-notifier-engine/src/lib.rs`                   |
| Dispatcher + wake task               | `crates/selfdef-notifier-engine/src/{dispatcher,wake_task}.rs`|
| HTTP ack handler                     | `crates/selfdef-api/src/handlers.rs::notify_ack`              |
| Adapter (Event → Payload bridge)     | `crates/selfdef-daemon/src/dispatcher_adapter.rs`             |
| Daemon wiring                        | `crates/selfdef-daemon/src/main.rs::build_notifier_path`      |
| Engine-path pipeline-test harness    | `crates/selfdef-daemon/tests/m_notify_engine.rs::EngineHarness` |
| Q-G adapter pattern reference        | `docs/dev/integrations.md`                                    |
| `/view` skill                        | `.claude/skills/view/SKILL.md`                                |

## Standing rules — must follow on next session

- **Branches**: develop on `claude/<topic>`; never push to `main` or
  another agent's branch without explicit user request.
- **Push protocol**: `git push -u origin <branch-name>`; retry up to
  4× with exponential backoff on network errors; create a draft (or
  ready-for-review per the cadence above) PR immediately after push
  if one doesn't already exist.
- **Pre-commit hooks**: never skip (`--no-verify` is forbidden).
- **Force push to main/master**: never; warn if asked.
- **Sensitive files**: never commit `.env`, credentials, large
  binaries. Stage by name, not `git add -A`.
- **Confirm before destructive ops**: `git reset --hard`,
  `git push --force`, branch deletion, large refactor sweeps. The
  default is to ask.

## Open SDD-debt — none

Phase 7 wrapped with **0 open SDD-debt items** and **0 open
findings**. Both Phase 6 carry-overs (F-2031-009 D-5e wiring,
F-2031-013 daemon-pipeline tests) closed inside the post-Phase-6
cycle (PRs #140 + #141).

## Unanswered questions

Inside SDD-008, every numbered open question (Q-A..Q-G) has been
either answered, addressed, or rolled into D-9 (dashboard). Q-G
specifically has shipped 4 pattern-instance adapters; the question
itself ("which alert-routing integrations matter?") is **answered
in practice** by the 4 shipped + 4 prior human-facing channels
covering the full alert-routing matrix.

The one **explicitly deferred design question** is D-9: the
dashboard. Pre-work pointers when the user opens that thread:

- `docs/sdd/008-notifications-orchestration.md` — D-9 section +
  any "Way forward" notes.
- `crates/selfdef-api/src/handlers.rs::notify_ack` — model for
  HTTP surface in the same authentication regime.
- `SECURITY.md` — URL-leakage map sets the constraints for any
  future dashboard URL surface.

## Useful one-shot commands

```bash
# Quick orientation
/view

# Read the latest ledger
cat docs/review/phase-7/99-findings-ledger.md

# See the SDD-008 impl table
sed -n '23,50p' docs/sdd/008-notifications-orchestration.md

# Recent activity
git log --oneline -30

# Workspace health
cargo check --workspace
cargo test --workspace --no-run    # compile-only, fast sanity
```

## End

This handoff is meant to be **stable** — until SDD-009 starts, or
until a new audit phase opens. When that happens, write
`docs/handoff/<yyyy-mm-dd>-<topic>.md` and link from it back here.
