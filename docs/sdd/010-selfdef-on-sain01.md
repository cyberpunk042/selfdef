# SDD-010 — selfdef on SAIN-01 host: deployment integration (requirements + scope)

> Status: **scoping — requirements only, design deferred**
> Owner: TBD (separate design conversation once SAIN-01 hardware is procured and the info-hub milestone advances)
> Last updated: 2026-05-16
> Closes findings: none yet — net-new cross-repo integration
> Derived from: `cyberpunk042/devops-solutions-information-hub` PRs #2-#6 (the SAIN-01 ingestion arc) + `docs/decisions.md` D-025 (this PR's Stage-2 trigger).

## Implementation status

**Requirements captured. Design and implementation deliberately deferred to
a separate design conversation, gated on**:

1. The SAIN-01 hardware procurement progressing (operator-side decision; CPU + Blackwell + ProArt + RTX 3090 + dual NVMe + 256 GB DDR5 + dual NIC).
2. The operator's Oracle Core model selection (Ling-2.6-flash vs Nemotron-3-Nano-Omni vs both — see info-hub milestone E110).
3. Operator authorization to commit selfdef impl effort to the integration (no impl effort spent before the integration design lands).

This SDD intentionally does **not** pick implementation choices. It captures
the integration's scope-of-required-coverage so that the eventual design
conversation starts from a stable requirements baseline. Mirrors the
SDD-009 (dashboard) pattern: requirements stub now; design SDD later;
implementation downstream.

When the design conversation lands:
- A successor SDD or major revision of this one captures the selected
  design points (D-1, D-2, ... matching SDDs 001-008's shape).
- The Q-A..Q-N open questions resolve via `/questions solve` +
  `docs/decisions.md` (same audit flow used elsewhere).
- Until then, this doc reads as a **scope contract**, not an
  implementation plan.

## Problem

selfdef ships today as a Debian-package daemon. The 2026-05 ingestion arc
in `cyberpunk042/devops-solutions-information-hub` (the operator's
second-brain wiki) captured the design for **SAIN-01** — a bare-metal
AMD Zen 5 + dual-NVIDIA workstation with a custom-tuned Debian 13 host,
ZFS-stratified storage, VFIO-isolated dual GPUs, kernel-level Tetragon
eBPF perimeter, and the SRP Trinity software architecture (Pulse /
Weaver / Auditor).

The SAIN-01 milestone (`wiki/backlog/milestones/sain-01-sovereign-node.md`
in the info-hub) lands the host. **selfdef is intended to run on that
host** — but several integration points need design before the daemon
can deploy cleanly:

1. **Tetragon policy coexistence.** SAIN-01's Auditor module uses Tetragon
   eBPF `TracingPolicy` for kernel-level perimeter enforcement
   (`sovereign-kernel-fence`). selfdef's `agent-guard` module also writes
   Tetragon TracingPolicies. Two independent policy authors writing into
   the same kernel eBPF substrate need coordination — without it, kills
   could be duplicated, missed, or worse, the policies could contradict.

2. **State-fabric placement.** SAIN-01's Weaver module writes the
   four context files (`IDENTITY.md`, `SOUL.md`, `AGENTS.md`,
   `CLAUDE.md`) to `tank/context` with `sync=always` for atomic
   inter-agent state handoffs. selfdef's persistent escalation engine
   (`escalations.sqlite`, SDD-008 D-5a/b/c) currently defaults to
   `/var/lib/selfdef/`. On SAIN-01, the natural placement is on
   `tank/context` so escalations participate in the same atomic-write
   contract — but this requires deliberate config + verification.

3. **Notifier channel coexistence.** SAIN-01's Auditor uses
   `guardian-core` (a Python daemon) to surface kernel-killed events to
   userspace. selfdef's notifier ships 12 channels including `wall(1)`
   + `write(1)` — both subprocess-invoked from selfdef's daemon. The
   Auditor's Tetragon allowlist needs to accommodate
   `/usr/bin/wall` + `/usr/bin/write` (selfdef's notifier subprocess
   invocations) without producing false-positive kills.

4. **Package + systemd unit adjustments.** selfdef's standard
   `.deb` installs a systemd unit + drops config into
   `/etc/selfdef/`. On SAIN-01, paths may need adjustment (model
   weights on `tank/models`, state on `tank/context`, audit logs
   shared with `guardian-core`'s `tank/context/security_audit.log`).
   The unit file also wants `Requires=tetragon.service` +
   `BindsTo=tetragon.service` so Tetragon outages don't leave selfdef
   running with its perimeter half-broken.

5. **Resident model awareness.** selfdef's notifier escalation profiles
   currently target generic message templates; on SAIN-01, the Oracle
   Core model (Ling-2.6-flash or Nemotron-3-Nano-Omni per info-hub
   E110) becomes the *receiver* of selfdef's own escalations if
   operator wires it that way (e.g., selfdef notifies via Slack →
   Oracle Core synthesizes a triage suggestion → operator reviews).
   This is *optional* selfdef-side awareness; the basic notifier
   chain works without it.

Without an integration design, the daemon can run on SAIN-01 in a
naive sense — but the architectural coherence of the Sovereign Node is
compromised: Tetragon policies fight each other; state-fabric isn't
shared; the notifier and the Auditor independently fire on the same
event.

D-025 (this PR's decisions-log entry) captures the operator's
direction:

> *"when we are ready we will transpose into the selfdef and the new
> Development and Epics and Modules and Tasks needed to get there and
> all the Spec files and requirements and clear vision."*

This SDD formalizes the scope so the eventual design conversation
starts from it.

## Required coverage — what the integration must surface

Per D-025, the integration provides comprehensive selfdef-on-SAIN-01
deployment design. Five required-coverage areas:

### 1. Tetragon policy coexistence

- Single Tetragon daemon on the host.
- Both `agent-guard` policies (selfdef-side) and `sovereign-kernel-fence`
  (SAIN-01-side) load and coexist without contradiction.
- A merged policy or a clearly-scoped authority model.
- Allowlist accommodates: `wall`, `write` (selfdef's notifier
  subprocesses), `python3`, `nvidia-smi`, `vllm`, `podman` (SAIN-01
  baseline), plus whatever selfdef's other modules need.
- Operator-visible audit trail for which policy fired which kill.

### 2. State-fabric integration

- selfdef's `[notifier.escalations_path]` defaults to a path on
  `tank/context` (e.g., `/mnt/vault/context/selfdef-escalations.sqlite`).
- Atomic-write semantics inherited from `tank/context`'s `sync=always`.
- ZFS snapshot strategy includes the selfdef escalation state.
- No conflicts with the four Trinity state files (IDENTITY/SOUL/AGENTS/CLAUDE).

### 3. Notifier channel coexistence

- selfdef's notifier-chain `wall` + `write` channels function inside
  the Tetragon-allowlisted subprocess set.
- Optional: integration with `guardian-core`'s audit log
  (`tank/context/security_audit.log`) so selfdef events appear in the
  same operator-readable log as kernel kills.
- 10 non-TTY channels (ntfy, signal, slack, etc.) work unchanged —
  they don't intersect the Tetragon allowlist.

### 4. Package + systemd adjustments

- `selfdef.service` systemd unit gains `After=tetragon.service` +
  `Requires=tetragon.service` (refuse to start without the Auditor's
  substrate up).
- Paths in default config adjust for SAIN-01: model weights on
  `tank/models`, state on `tank/context`, eventstream on
  `tank/agents`.
- Deb package optionally ships a "SAIN-01 preset" config snippet
  operators can `dpkg-reconfigure selfdef` onto, OR the operator-
  side `selfdefctl init config --target=sain01` produces a
  SAIN-01-adapted starter config.

### 5. Resident model awareness (optional)

- Operator-configurable knob to point selfdef at the Oracle Core
  model for synthesis tasks (e.g., post-event triage suggestions).
- Routes via vLLM's OpenAI-compatible API at the resident model's
  endpoint.
- Falls back to no-Oracle-synthesis if the Oracle Core is in
  sleep state (per SAIN-01 [[load-balancing profile]] selection).

## Goals

1. **Selfdef runs cleanly on SAIN-01** — the daemon + its 12 notifier
   channels + the agent-guard module + the persistent escalation
   engine all operate without architectural conflict with the
   Sovereign Node's Trinity.
2. **Tetragon-authoritative single daemon** — one Tetragon process,
   one policy authoring path, no duplication.
3. **State-fabric coherence** — selfdef's escalation state participates
   in `tank/context`'s `sync=always` atomic-write contract.
4. **Operator-driven configuration** — SAIN-01-specific paths +
   knobs are configurable, not hardcoded; selfdef stays
   deployable on non-SAIN-01 hosts unchanged.
5. **Composable** — existing selfdef deployments (non-SAIN-01) keep
   working; SAIN-01-specific code is opt-in.

## Non-goals (this SDD)

This SDD intentionally does **not** decide:

- **Tetragon policy merge mechanism** — open question (see Q-A).
- **State-fabric placement default vs override** — open question (see Q-B).
- **Notifier-Auditor audit-log sharing** — open question (see Q-C).
- **selfdef-side Oracle Core integration shape** — open question (see Q-D).
- **selfdef SDDs that may need cross-references** — open question (see Q-E).
- **Stage-2 epics inside selfdef's own backlog** — open question (see Q-F).
- **Hardware-procurement timeline** — operator-side.

Picking these prematurely would foreclose options the operator may
want to keep open. The design chat selects; this scoping doc only
defines the surface.

## Glossary

- **SAIN-01** — Sovereign AI Node, the bare-metal workstation
  specified in the info-hub milestone `wiki/backlog/milestones/sain-01-sovereign-node.md`.
- **Trinity (Pulse / Weaver / Auditor)** — the SRP-decoupled software
  architecture of SAIN-01 (info-hub `wiki/domains/ai-agents/concept-srp-trinity-pulse-weaver-auditor.md`).
- **Stage 2** — the cross-repo transposition phase, where info-hub's
  SAIN-01 design materializes as new selfdef artifacts (this SDD is
  Stage-2 PR #1).
- **info-hub** — `cyberpunk042/devops-solutions-information-hub`,
  the operator's second-brain wiki that holds the SAIN-01 master
  spec.

## Open questions (for the separate design chat)

These are deliberately enumerated rather than answered. Each is a
distinct design decision the eventual integration SDD will need to
resolve.

- **Q-A — Tetragon policy authoring authority.** Does selfdef's
  `agent-guard` module's TracingPolicy merge into SAIN-01's
  `sovereign-kernel-fence`, or do they coexist as separate policies
  on the same daemon? Merge avoids duplication but couples selfdef's
  policy evolution to SAIN-01's release cycle. Coexist preserves
  selfdef's independence but risks contradictions.
- **Q-B — State-fabric placement default.** Is `tank/context` the
  default for `[notifier.escalations_path]` on SAIN-01 deployments
  (auto-detected via systemd unit or config probe), or operator-
  opted-in via `selfdefctl init config --target=sain01`? Auto-detect
  is friendlier; opt-in is more explicit.
- **Q-C — Audit-log sharing.** Does selfdef's notifier append to
  `tank/context/security_audit.log` (shared with `guardian-core`),
  or maintain its own audit log? Sharing simplifies operator review;
  separate logs preserve forensic boundaries.
- **Q-D — selfdef-side Oracle Core integration.** Does selfdef call
  the resident Oracle Core model (Ling or Nemotron) for synthesis
  tasks (e.g., post-event triage suggestions)? Or does selfdef stay
  Oracle-Core-unaware, with the Weaver pulling selfdef state via
  external integration? selfdef-aware is tighter but adds coupling.
- **Q-E — Cross-SDD references.** Which existing selfdef SDDs (008
  notifications, 004 security, 001 ai-machine) need cross-references
  added when this SDD's design lands? Audit-pass scope.
- **Q-F — selfdef backlog format.** Stage 2 expands selfdef's surface
  significantly. Does selfdef adopt an Epic/Milestone backlog
  (mirroring info-hub) for this work, or stick to SDD + decisions-log
  + audit-phase ledgers (selfdef's existing pattern)? Adopt-Epic
  format is consistent with info-hub but creates a new artifact type
  in selfdef.
- **Q-G — Selfdef deployment outside SAIN-01.** All Stage-2 changes
  must compose cleanly with non-SAIN-01 deployments (Debian server,
  developer workstation, CI). What's the default path that does
  NOT activate SAIN-01-specific behavior?
- **Q-H — Stage-2 epic count + ordering.** How many epics does
  Stage 2 decompose into on the selfdef side? The info-hub
  milestone has 11; selfdef's side may be smaller (no hardware
  ownership) or larger (cross-cutting integration). Operator scopes
  during the design chat.

## Way forward

1. **Trigger** for the design chat: operator initiates a separate
   conversation. Triggers include:
   - SAIN-01 hardware procurement progresses to assembly.
   - Operator selects an Oracle Core resident model (info-hub E110).
   - Operator wants to commit selfdef impl effort to the integration.
2. **Output** of the design chat: a successor SDD (or major revision
   of this one) that resolves Q-A..Q-H as D-1..D-N design points,
   matching the shape SDDs 001-008 have today. Each design point
   appears in `docs/decisions.md` via the standard `/questions
   solve` flow.
3. **Implementation cycle** follows the design SDD, gated on
   operator approval per the established cadence (one PR per
   cycle, ready-for-review default).
4. **Phase-N audit** — if a substantial code-shaped cycle accumulates
   from Stage-2 impl, that satisfies one of Phase 8's deferral
   trigger conditions (per `docs/review/phase-8/00-charter.md`),
   and Phase 8 (or successor) could open.

## Cross-references

- `docs/decisions.md` D-025 — Stage 2 transposition trigger (the
  decision this SDD elaborates).
- info-hub `wiki/backlog/milestones/sain-01-sovereign-node.md` —
  the SAIN-01 master spec (the architectural baseline this SDD
  integrates against).
- info-hub `wiki/sources/src-sain-01-sovereign-node-spec.md` — L1
  synthesis with the hallucination map.
- info-hub `wiki/domains/ai-agents/concept-srp-trinity-pulse-weaver-auditor.md`
  — the Trinity concept (the architectural axiom Stage 2 must
  preserve).
- info-hub `wiki/comparisons/cmp-wall-vs-write-vs-tetragon-for-perimeter.md`
  — the cross-cutting comparison that links selfdef's notifier
  channels with SAIN-01's Auditor.
- `docs/sdd/008-notifications-orchestration.md` — the notifier
  orchestration SDD that ships the 12 channels selfdef brings to
  the integration.
- `docs/sdd/004-security-threat-model.md` — the threat model
  (SECURITY.md addendum lands when Q-A resolves).
- `docs/sdd/009-dashboard.md` — sibling requirements-only stub
  (Stage 2 follows the same scoping pattern as SDD-009).
- `docs/handoff/2026-05-15-end-of-channels-cycle.md` — the prior
  selfdef-side handoff that ended on "all 12 channels shipped";
  Stage 2 is the natural next chapter when operator-gated.
