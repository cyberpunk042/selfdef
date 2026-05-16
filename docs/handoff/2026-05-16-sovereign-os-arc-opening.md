# Handoff — sovereign-os arc opening (cold-start signpost for new session)

> **Read this first** if you are starting a new session on selfdef
> OR if you are about to bootstrap `cyberpunk042/sovereign-os`.
> Last updated: 2026-05-16 (arc-opening session — operator authorized
> new fourth-repo arc via `/goal` directive; this session prepared all
> knowledge transfer; operator-side action required next).
>
> Supersedes the prior handoff:
> - `2026-05-15-end-of-channels-cycle.md` — Stage 1 close (channel completion through #181)
> - `2026-05-16-end-of-stage2-anchor.md` — Stage 2 anchor (SDD-010 + D-025, PR #182)
>
> This handoff covers the **sovereign-os arc opening** + the operator-side action items needed before the next session can execute PR 1 in the new repo.

## TL;DR — where things are

- **Operator opened a substantially larger cross-repo arc** on 2026-05-16 via `/goal` directive: build a complete OS-image generation + customization pipeline for the SAIN-01 AI workstation, in a NEW fourth repo `cyberpunk042/sovereign-os`. SDD + TDD discipline. Multi-profile from day 1. SFIF lifecycle. IaC quality bar.
- **Architectural map updated to four repos**: sovereign-os BUILDS (new), selfdef RUNS, info-hub SYNTHESIZES, root-ghostproxy (dormant).
- **Plan-agent rendered a 10-PR foundation phase** (Scaffold → Foundation → start of Infrastructure) with 5 stage gates. Verbatim plan at info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md`.
- **Operator framing decisions all locked**: public visibility, AGPL-3.0-or-later (mirrors selfdef), research-first substrate (not pre-committed), schema-first profiles, Plan-agent yes.
- **Post-Plan operator refinements added**: SFIF discipline / IaC quality bar (tweakable + env-var-driven + restart-from-state + observable + operable) / "Debian as Ark" framing / Q-016 distro-base reconsideration added to substrate-survey scope.
- **Blocked at the precursor**: agent's GitHub MCP scope returned 403 on `create_repository` for `sovereign-os`. **Operator-side action required**: create repo manually + expand agent MCP scope. Requires a new session.
- **Stage 2 (selfdef-on-SAIN-01, SDD-010) reframed**: downstream of sovereign-os; design conversation revisited after sovereign-os produces deployable images.

## What to do FIRST in the next session

This handoff exists because the operator-side action requires a new session. The flow:

1. **Operator (THIS session, after this PR merges)**:
   - Create `cyberpunk042/sovereign-os` (public, AGPL-3.0-or-later, README auto-init, no preset .gitignore, no preset license)
   - Expand agent's GitHub MCP scope to include `cyberpunk042/sovereign-os`
   - Open a new session

2. **Next session (fresh agent, reads this handoff cold)**:
   - **Step 1**: Read this handoff in full. It's the cold-start substrate.
   - **Step 2**: Read SDD-011 at `docs/sdd/011-sovereign-os-arc-opening.md` (this PR's companion). It explains the cross-repo bridge.
   - **Step 3**: Read the Plan-agent output verbatim at info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md`. It's the authoritative scaffold for PRs 1-10.
   - **Step 4**: Read the operator-directive log verbatim at info-hub `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md`. It's the operator's exact words — SFIF, IaC bar, "Debian as Ark", Q-016 addition, handoff mandate.
   - **Step 5**: Verify `cyberpunk042/sovereign-os` exists + MCP scope includes it. Try a no-op `get_file_contents` against the new repo to confirm.
   - **Step 6**: When operator says "go" → open **sovereign-os PR 1** (charter stub + repo skeleton + seeded `decisions.md` with Q-001..Q-016).

## Sovereign-os PR 1 brief (the immediate first action when authorized)

Per the Plan-agent output:

**Title**: `chore: bootstrap sovereign-os repo skeleton and charter stub`

**Scope**: Pure structural seed. No build code. No scripts (beyond placeholders).

**Files to land**:

| File | Approx LOC | Content |
|---|---|---|
| `README.md` | ~150 | Repo purpose; relationship to selfdef + info-hub; status (foundation phase, no buildable artifact yet); pointer to info-hub `wiki/backlog/milestones/sain-01-sovereign-node.md` as architectural baseline |
| `docs/sdd/000-charter.md` | ~200 | Stub charter: mission, scope boundaries (BUILDS the OS; does not RUN on it; does not SYNTHESIZE knowledge), SDD+TDD commitment, SFIF discipline commitment, IaC quality bar, "Debian as Ark" framing, explicit non-goals |
| `docs/decisions.md` | ~120 | Seeded with operator-confirmed locked decisions + 16 open questions (Q-001..Q-016 — see Plan-agent output + the Q-016 addition for distro-base reconsideration) |
| `docs/sdd/INDEX.md` | ~30 | Empty numbered table reserving 000-010 slots |
| `docs/handoff/INDEX.md` | ~20 | Empty handoff anchor table |
| `docs/review/INDEX.md` | ~20 | Empty audit phase table |
| `.gitignore` | ~30 | Match selfdef's patterns (target/, .env, etc.) |
| `LICENSE` | ~30 | AGPL-3.0-or-later (mirror selfdef) |
| `CODEOWNERS` | ~10 | TBD — mirror selfdef's pattern |

**Critical**: PR 1 is NOT a build artifact. It's the repo scaffold + the charter that locks the SFIF + IaC + SDD+TDD commitments. Subsequent PRs (2-10) deliver Foundation (research SDDs, profile schema, whitelabel mechanism) + start of Infrastructure (TDD harness).

## The 10-PR foundation phase at a glance

Per Plan-agent macro-arc (full detail in the info-hub dump):

```
SCAFFOLD TIER (PRs 1-3)
  PR 1:  Repo skeleton + charter stub                       (~600 LOC)
  PR 2:  ARCHITECTURE.md + cross-repo refs                  (~900 LOC)
  PR 3:  mdbook + MCP config template                       (~500 LOC)
  ─── STAGE GATE 1 ───

FOUNDATION TIER (PRs 4-8) — parallel tracks possible
  PR 4:  SDD-003 substrate survey + Q-001 + Q-016           (~1300 LOC; research-heavy)
  PR 5:  SDD-004 profile schema                             (~1000 LOC)
  ─── STAGE GATE 2 (substrate decision) ───
  PR 6:  Profiles: sain-01 + old-workstation stubs          (~700 LOC)
  ─── STAGE GATE 3 (schema lock) ───
  PR 7:  SDD-006 Debian surface audit                       (~950 LOC)
  PR 8:  SDD-007 whitelabel mechanism                       (~900 LOC)
  ─── STAGE GATE 4 (whitelabel + legal) ───

INFRASTRUCTURE TIER (PRs 9-10) — start of
  PR 9:  SDD-008 test harness spec                          (~850 LOC)
  PR 10: Harness scaffold + first passing tests             (~1200 LOC)
  ─── STAGE GATE 5 (FOUNDATION COMPLETE) ───
  ↓
  Stage 2 (build scripts) authorized only after Gate 5
```

Each gate = explicit operator review + authorize-next-phase. The agent pauses at each gate; no PR opens past a gate without operator sign-off.

## Operator framing decisions (locked, 2026-05-16)

| Decision | Locked answer |
|---|---|
| Primary repo | New: `cyberpunk042/sovereign-os` |
| Substrate | Research-first (PR 4 surveys; operator picks at Gate 2) |
| Profile shape | Schema-first, multi-profile from day 1 |
| Plan tool use | Yes — Plan-agent macro-arc rendered + adopted |
| Visibility | Public |
| License | AGPL-3.0-or-later (mirror selfdef per verified LICENSE file) |
| Substrate excludes | None — all 8 candidates surveyed + Q-016 distro-base reconsideration added |

## Operator quality bar (verbatim, sacrosanct)

> "Do not rush anything and do not minimize anything nor should you compress or conflate or hallucinate anything"
> "We think before we act always. And we do things in order and we respect workflows and methodologies"
> "Everything being able to evolve, before and after"
> "I want things observable and operable and customizable, at all stages of lifecycle"
> "We do this clean and right and professional"
> "we always deliver IaC, high quality scripts and libs and configuration and easily tweakable and configurable and customisation and even via env vars when needed, or other pre-existing config or temporary file detected and restarting from there such as if there is has to be a local tracking of the progress of a build in multi-steps that can only ever re-happen locally"
> "we remember the SFIF, Skaffold, Fundation, Infrastructure, Features"
> "I think Debian is a bit like saying we have our Arc but we start from there, kind of thing ?"

These apply to every sovereign-os PR.

## SFIF tier mapping for sovereign-os arc

| SFIF tier | sovereign-os PRs | What lands |
|---|---|---|
| **Scaffold** | PRs 1-3 | Repo skeleton, charter, mdbook + MCP template |
| **Foundation** | PRs 4-8 | Substrate survey, profile schema, profile stubs, whitelabel audit + mechanism |
| **Infrastructure** | PRs 9-10 + Stage 2 | TDD harness scaffold; then actual build scripts |
| **Features** | Stage 2+ | Image generation, interactive build modes, lifecycle management tools, model catalog integration |

## Cross-repo state map (post-arc-opening)

| Repo | Status | Recent landings | Workflow |
|---|---|---|---|
| `cyberpunk042/selfdef` (THIS repo) | active; SDD-011 + handoff land in this PR | SDD-010 (Stage 2 stub, #182), 2026-05-16-end-of-stage2-anchor handoff (#183), SDD-011 (this PR), D-026 (this PR), this handoff (this PR) | SDDs + decisions log + audit phases + handoffs + mdbook |
| `cyberpunk042/devops-solutions-information-hub` | active; L0 verbatim provenance landing in info-hub PR #7 | SAIN-01 ingestion arc (PRs #2-#6 ~440 KB), sovereign-os arc-opening L0 (PR #7) | L0 raw → L4 lessons; `pipeline post` validation; mdbook |
| `cyberpunk042/sovereign-os` (NEW, pending) | **awaiting operator-side bootstrap** | none yet | will mirror selfdef rhythm (SDDs/decisions/audit/handoffs/mdbook) |
| `cyberpunk042/root-ghostproxy` | dormant | /view + /questions skill install (earlier this session arc) | n/a active |

## Open questions seeded for sovereign-os `docs/decisions.md` PR 1

Per Plan-agent output + the Q-016 addition:

1. **Q-001** — Final substrate selection (PR 4 → Gate 2)
2. **Q-002** — Profile inheritance model — single-parent vs composition
3. **Q-003** — Whitelabel brand identity — name, palette, logo
4. **Q-004** — Legal scope (public distribution vs internal)
5. **Q-005** — ZFS root layout details
6. **Q-006** — Secure-boot posture
7. **Q-007** — Kernel choice (stock vs custom AVX-512-tuned)
8. **Q-008** — Installer experience (debian-installer / Calamares / custom TUI / image-only)
9. **Q-009** — Hardware procurement timeline
10. **Q-010** — CI infrastructure (GHA runners vs self-hosted)
11. **Q-011** — Cross-repo commit-pin level
12. **Q-012** — Future-profile timeline (minimal / developer / headless)
13. **Q-013** — Observability binding details
14. **Q-014** — Decommission/wipe profile testing
15. **Q-015** — Reproducibility target
16. **Q-016** — Distro-base reconsideration (NEW — does staying on Debian 13 cost material potential? Working hypothesis: stay on Debian + customize)

## Selfdef-side open questions (SDD-011)

These don't go in sovereign-os; they live in selfdef and surface when the arc progresses:

- **SQ-A** — Once sovereign-os ships first deployable image, do we revisit SDD-010 Stage 2 design immediately or wait for hardware?
- **SQ-B** — Does selfdef adopt the SFIF discipline as a documented quality bar in its own SDDs?
- **SQ-C** — Cross-repo commit-pinning posture between selfdef ↔ sovereign-os
- **SQ-D** — Phase-9 audit trigger: does sovereign-os Foundation-Complete satisfy one of Phase 8's deferral trigger conditions?

## Standing rules (carried unchanged across the entire session arc)

- **Never commit unless asked. Never push unless asked. Never destructive ops unless asked.**
- **Never skip hooks** (`--no-verify`); never force-push to main; never include model identifier in commits or pushed artifacts.
- Operator quality bar: "do not minimize, do not reduze, do not conflate, do not hack, do not take shortcuts" — sacrosanct.
- No silent corrections to L0 verbatim; corrections happen at L1+ synthesis with explicit flagging.
- Advance signal: operator typing "good its merged you can continue" or near-variant; without it, the agent waits.
- **NEW** — GitHub MCP scope is being expanded by operator-side action to include `cyberpunk042/sovereign-os`. Until that's confirmed in the next session, agent cannot interact with the new repo.

## Repo signposts for the next session

| Topic | Path |
|---|---|
| **This handoff** | `docs/handoff/2026-05-16-sovereign-os-arc-opening.md` (selfdef) |
| Selfdef-side SDD-011 (cross-repo bridge) | `docs/sdd/011-sovereign-os-arc-opening.md` (selfdef) |
| Selfdef-side D-026 (sovereign-os decision) | `docs/decisions.md` D-026 entry (selfdef) |
| Selfdef-side SDD-010 (Stage 2 stub, downstream of sovereign-os) | `docs/sdd/010-selfdef-on-sain01.md` (selfdef) |
| **Plan-agent macro-arc output (authoritative)** | `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md` (info-hub) |
| **Operator-directive log (verbatim)** | `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md` (info-hub) |
| SAIN-01 architectural baseline | `wiki/backlog/milestones/sain-01-sovereign-node.md` (info-hub) |
| SAIN-01 epics (11) | `wiki/backlog/epics/milestone-sain01/e100..e110-*.md` (info-hub) |
| L1 source-synthesis (BitNet / DFlash / Zen 5 / SAIN-01 spec) | `wiki/sources/src-*.md` (info-hub) |
| L2 concepts (Trinity / 1-bit / spec-dec / VFIO / ZFS / dual-CCD) | `wiki/domains/{ai-models,ai-agents,devops}/concept-*.md` (info-hub) |
| L3 comparisons (4 head-to-heads) | `wiki/comparisons/cmp-*.md` (info-hub) |
| Prior selfdef handoff (Stage 2 anchor) | `docs/handoff/2026-05-16-end-of-stage2-anchor.md` (selfdef) |
| Prior selfdef handoff (channels cycle close) | `docs/handoff/2026-05-15-end-of-channels-cycle.md` (selfdef) |

## Cross-references

- **Verbatim operator directives**: info-hub `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md`
- **Verbatim Plan-agent output**: info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md`
- **Selfdef-side bridge**: `docs/sdd/011-sovereign-os-arc-opening.md` (this PR)
- **Selfdef-side decision log**: `docs/decisions.md` D-026 (this PR)
- **Prior arc handoff**: `docs/handoff/2026-05-16-end-of-stage2-anchor.md` (superseded by this handoff for the cold-start substrate)

## What this session arc produced (end-of-session summary)

```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   SESSION ARC — FINAL STATE                                          ║
║                                                                      ║
║   STAGE 1 (selfdef channel completion):                              ║
║     ✅ PRs #170-#181  — 12 PRs                                       ║
║                                                                      ║
║   STAGE 1.5 (info-hub SAIN-01 ingestion):                            ║
║     ✅ info-hub PRs #2-#6  — 5 PRs (~440 KB structured docs)         ║
║                                                                      ║
║   STAGE 2 ANCHOR (selfdef SDD-010 + D-025):                          ║
║     ✅ PR #182 — SDD-010 requirements-only stub                      ║
║                                                                      ║
║   STAGE 2 HANDOFF (selfdef end-of-stage2-anchor):                    ║
║     ✅ PR #183                                                       ║
║                                                                      ║
║   STAGE 3 — sovereign-os arc opening (this PR + paired info-hub):    ║
║     🟢 selfdef this PR — SDD-011 + D-026 + supersession handoff      ║
║     🟢 info-hub PR #7   — L0 verbatim (directive + Plan-agent)       ║
║                                                                      ║
║   OPERATOR-SIDE ACTION PENDING:                                      ║
║     ⏳ Create cyberpunk042/sovereign-os (public, AGPL)               ║
║     ⏳ Expand agent MCP scope                                        ║
║     ⏳ Open new session → next agent reads THIS handoff → PR 1       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

The arc has a clean handoff line. The next session resumes cold from this handoff and the four cross-referenced documents (SDD-011, D-026, info-hub directive log, info-hub Plan-agent dump). No knowledge is lost.
