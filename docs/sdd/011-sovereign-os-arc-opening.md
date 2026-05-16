# SDD-011 — sovereign-os arc opening: cross-repo bridge from Stage 2 to the new fourth-repo concern

> Status: **scoping — arc-bridge document, operator-gated next steps**
> Owner: TBD (next session opens against the new `cyberpunk042/sovereign-os` repo)
> Last updated: 2026-05-16
> Closes findings: none yet — net-new cross-repo arc
> Supersedes/expands: builds on SDD-010 (Stage 2 — selfdef-on-SAIN-01) by adding an upstream architectural concern (the OS-build pipeline itself)
> Derived from: operator `/goal` directive 2026-05-16 + Plan-agent macro-arc output + post-Plan refinements (SFIF / IaC / Debian-as-Ark)

## Implementation status

**Arc opened, repo bootstrap pending operator-side action.**

The operator authorized a new fourth repo (`cyberpunk042/sovereign-os`) via the 2026-05-16 `/goal` directive. The repo doesn't exist yet — agent's GitHub MCP scope is restricted to three existing repos; `create_repository` returned `403 Resource not accessible by integration`. **Operator-side action required** to bootstrap (create the repo + expand the agent's MCP scope), and this requires a new session.

This SDD is the **selfdef-side bridge** that captures what's about to happen on the other side of that operator-side action. It does NOT replace SDD-010 (which scoped Stage 2 selfdef-on-SAIN-01 integration); it documents the broader architectural picture in which Stage 2 now sits:

```
                  upstream                              downstream
              ┌─────────────────┐                  ┌─────────────────┐
              │  sovereign-os   │  produces ──────▶│   SAIN-01 host  │
              │  (new repo,     │                  │   (the running  │
              │   build pipeline)│                  │   workstation)  │
              └────────┬────────┘                  └────────┬────────┘
                       │                                    │
                       │ architectural baseline             │ daemon target
                       ▼                                    ▼
              ┌─────────────────┐                  ┌─────────────────┐
              │   info-hub      │                  │    selfdef      │
              │  (knowledge:    │  references ────▶│  (this repo:    │
              │   11 epics +    │                  │   security      │
              │   L1-L3 + plan) │                  │   daemon + Stage│
              │                 │                  │   2 = SDD-010)  │
              └─────────────────┘                  └─────────────────┘
```

selfdef's Stage 2 work (SDD-010) is **downstream** of sovereign-os: selfdef RUNS on the OS that sovereign-os PRODUCES. The integration design conversation (Q-A..Q-H in SDD-010) becomes more concrete once sovereign-os produces deployable images. Until then, Stage 2 remains deferred per its existing requirements-only framing.

## Operator Directive

> "continue till we reach the point we have the whole series of scripts to generate and configure and build a custom image / custom OS and all the costomization that is possible and even needed. to the point pre, during and post. all in Spec Driven Development and Test Driven Development."

> "we always deliver IaC, high quality scripts and libs and configuration and easily tweakable and configurable and customisation and even via env vars when needed, or other pre-existing config or temporary file detected and restarting from there such as if there is has to be a local tracking of the progress of a build in multi-steps that can only ever re-happen locally."

> "I think Debian is a bit like saying we have our Arc but we start from there, kind of thing ?"

> "we remember the SFIF, Skaffold, Fundation, Infrastructure, Features."

> "Dont even ask me question, just get to it."

The full verbatim is preserved at info-hub `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md`. Cross-reference required for any agent picking up this arc.

## Problem

After the SAIN-01 ingestion arc closed (info-hub PRs #2-#6) and the Stage 2 anchor landed (selfdef PR #182, SDD-010), the operator opened a substantially larger arc: build the actual OS image that the SAIN-01 milestone describes. This is **architecturally upstream of selfdef** and would represent scope creep if it lived in either selfdef (which is a security daemon, not an OS builder) or info-hub (which is knowledge synthesis, not impl).

The natural home is a new fourth repo. Per the operator's framing answers:

1. New repo `cyberpunk042/sovereign-os`
2. Substrate research-first (not pre-committed to live-build)
3. Profile schema-first, multi-profile from day 1
4. Plan agent renders the macro-arc; operator reviews before execution

The Plan agent returned a 10-PR foundation phase (raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md). Operator answered the three pre-PR-1 questions: Public visibility, AGPL-3.0-or-later license (matching selfdef), and substrate survey covers all candidates plus a NEW Q-016 (distro-base reconsideration — would switching away from Debian 13 unlock material new potential?).

Then the operator added refinements:
- **SFIF discipline applies to the arc itself**: PRs 1-3 Scaffold; PRs 4-8 Foundation; PRs 9-10 begin Infrastructure
- **IaC quality bar**: every PR delivers tweakable + configurable + env-var-driven + restart-from-state scripts
- **"Debian as Ark"**: Debian 13 is the starting boat, not the destination; alternatives surveyed honestly
- **Handoff mandate**: this session prepares ALL knowledge transfer before the operator-side repo-creation session

This SDD captures the bridge.

## Required Coverage — what this SDD anchors

### 1. Cross-repo state map (post-arc-opening)

Four repos in the ecosystem:

| Repo | Responsibility | Workflow conventions |
|---|---|---|
| `cyberpunk042/devops-solutions-information-hub` | **Knowledge synthesis** — L0 raw → L4 lessons; SAIN-01 milestone + 11 epics; cross-cutting concept pages | wiki/ tree; `pipeline post` validation; `/questions` skill; manifest.json; mdbook |
| `cyberpunk042/selfdef` | **Security daemon + audit framework** — 12 notification channels; agent-guard Tetragon module; persistent escalation engine | docs/sdd/; docs/decisions.md; docs/review/phase-N/; docs/handoff/; mdbook; cargo workspace |
| `cyberpunk042/sovereign-os` (NEW, pending bootstrap) | **OS-build pipeline** — image generation, customization, lifecycle management; SFIF discipline; SDD + TDD throughout | docs/sdd/; docs/decisions.md; docs/review/; docs/handoff/; mdbook; scripts/; profiles/; whitelabel/; schemas/; tests/ |
| `cyberpunk042/root-ghostproxy` | (dormant — received /view + /questions skill install earlier this session arc) | n/a active |

### 2. SFIF mapping

The operator's SFIF lifecycle pattern (verbatim: "Scaffold, Foundation, Infrastructure, Features") applies to the sovereign-os arc itself:

- **Scaffold (PRs 1-3)** — repo genesis: charter stub, ARCHITECTURE.md, mdbook + MCP template. No build code. Pure structural seed.
- **Foundation (PRs 4-8)** — research + spec: substrate survey, profile schema, profile stubs, whitelabel surface audit + mechanism. Decisions land here.
- **Infrastructure (PRs 9-10 + Stage 2 onwards)** — TDD harness scaffold + first scripts. Build pipeline starts to execute.
- **Features (post-foundation)** — actual image generation, interactive build modes, lifecycle management tools, model catalog integration.

The 10-PR foundation phase (Plan agent's output) covers Scaffold + Foundation + start of Infrastructure. The Features tier is Stage 2-N of the arc, all gated.

### 3. IaC quality bar (verbatim operator commitment)

Every PR in sovereign-os MUST deliver:

- **IaC discipline** — every operational pattern as reproducible tooling. No manual infrastructure. Declarative where possible.
- **High quality scripts and libs and configuration** — selfdef's existing quality bar applies (clippy-clean, fmt-clean, sealed dependencies, drift-guard tests where applicable).
- **Easily tweakable + configurable + customisable** — via env vars; via pre-existing config detection; via temporary-file detection for build-state.
- **Local progress tracking for multi-step builds** — a build that crashes at step 7 of 12 MUST be resumable from step 7. State lives locally (no centralized service). Detected via on-disk artifacts (e.g., `.sovereign-os-build/state.json` or equivalent).
- **Observable** — every stage logs structured + queryable state; every long-running operation exposes progress.
- **Operable** — operator can intervene mid-flight (pause, inspect, resume, rewind).

### 4. "Debian as Ark" framing

The operator framed Debian 13 as the **starting boat, not the destination**. The substrate survey (PR 4 of sovereign-os) must include Q-016 — distro-base reconsideration — but the working hypothesis remains: stay on Debian 13 + customize heavily. Alternatives (Fedora / openSUSE / Arch / Nix) evaluated honestly; trade-offs documented either way; the loss of staying on Debian is documented if any.

### 5. Stage Gate placement (operator review checkpoints)

Per the Plan-agent output:

| Gate | After | What operator reviews |
|---|---|---|
| Gate 1 | sovereign-os PR 3 | Structural foundation matches selfdef rhythm |
| Gate 2 | sovereign-os PR 4 | Substrate decision (Q-001 + Q-016 resolved) |
| Gate 3 | sovereign-os PR 6 | Profile schema lock-in |
| Gate 4 | sovereign-os PR 8 | Whitelabel mechanism + legal posture |
| Gate 5 | sovereign-os PR 10 | Foundation-complete; authorizes Stage 2 (first build scripts) |

Each gate is an explicit ExitPlanMode-style checkpoint.

## Goals

1. **Selfdef-side capture of the arc bridge** — this SDD exists so that selfdef's own audit programme + decisions log + SDD index reference the new sovereign-os concern as a peer architectural artifact, not as something hidden.
2. **Cold-start substrate for the next session** — a fresh agent reading selfdef's `docs/sdd/INDEX` (if it had one) or `docs/handoff/<latest>.md` sees the sovereign-os arc immediately + knows where to find the Plan.
3. **SDD-010 (Stage 2) gets context** — selfdef's Stage 2 design conversation makes more sense once sovereign-os is producing deployable images; this SDD records that dependency.
4. **No premature design commits** — like SDD-010, this is a scope-contract artifact. Implementation work happens in the new repo, not here.

## Non-goals (this SDD)

- Does NOT pick the sovereign-os substrate (sovereign-os PR 4 surfaces; operator decides at Gate 2)
- Does NOT pick the brand identity for whitelabel (deferrable past sovereign-os PR 8)
- Does NOT authorize ANY selfdef-side code change for Stage 2 integration (still gated on SDD-010's three triggers)
- Does NOT duplicate the Plan-agent output (preserved verbatim in info-hub `raw/dumps/`)
- Does NOT redefine the SAIN-01 milestone or its 11 epics (info-hub authoritative)
- Does NOT replace SDD-010 (Stage 2 stays a separate concern downstream of sovereign-os)

## Open questions

These remain open at the selfdef level (not duplicated from sovereign-os's own Q-001..Q-016):

- **SQ-A** — Once sovereign-os ships its first deployable image, do we revisit SDD-010 Stage 2 design immediately, or wait for hardware?
- **SQ-B** — Does selfdef adopt the SFIF discipline as a documented quality bar in its own SDDs (alongside existing SDD/decision/audit pattern)?
- **SQ-C** — Cross-repo commit-pinning: how does selfdef reference specific sovereign-os releases (symbolic / hard-pinned / hybrid per Plan-agent's trade-off table)?
- **SQ-D** — Phase-9 audit trigger: does sovereign-os reaching Foundation-Complete (Gate 5) satisfy one of Phase 8's deferral trigger conditions for selfdef's own audit programme?

These are selfdef-side concerns the agent surfaces here so they don't fall off the radar.

## Way forward

1. **Operator-side action (new session required)**:
   - Create `cyberpunk042/sovereign-os` (public, AGPL-3.0-or-later, README auto-init, no preset .gitignore, no preset license)
   - Expand agent's GitHub MCP scope to include the new repo
   - Open new agent session
   - Agent reads `docs/handoff/2026-05-16-sovereign-os-arc-opening.md` (this PR's companion)
   - Operator says "go" → agent opens sovereign-os PR 1
2. **First sovereign-os PR (PR 1)**: charter stub, repo skeleton, seeded decisions log with Q-001..Q-016. ~600 LOC.
3. **Foundation phase (PRs 2-10)** per Plan-agent output: Scaffold → Foundation → start of Infrastructure. Five stage gates throughout.
4. **Foundation-Complete (sovereign-os Gate 5)** → Stage 2 (first actual build scripts in sovereign-os) authorized; SDD-010 selfdef-side integration revisits triggered.

## Cross-references

- `docs/sdd/010-selfdef-on-sain01.md` — the Stage 2 stub this SDD bridges to.
- `docs/decisions.md` D-025 (existing) — the Stage 2 trigger entry.
- `docs/decisions.md` D-026 (this PR) — the sovereign-os arc-opening decision.
- `docs/handoff/2026-05-16-sovereign-os-arc-opening.md` (this PR) — cold-start signpost for the next session.
- info-hub `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md` — verbatim operator directives.
- info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md` — Plan-agent macro-arc output.
- info-hub `wiki/backlog/milestones/sain-01-sovereign-node.md` — SAIN-01 milestone (architectural baseline that sovereign-os implements).
- info-hub `raw/notes/2026-04-09-user-directive-raw-idea-flow-patterns-standards.md` — original SFIF directive.
- Future `cyberpunk042/sovereign-os/docs/sdd/000-charter.md` — the new repo's own charter (sovereign-os PR 1).
