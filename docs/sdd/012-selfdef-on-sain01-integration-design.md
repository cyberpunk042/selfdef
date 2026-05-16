# SDD-012 — selfdef-on-SAIN-01 integration design (closes SDD-010 Q-A..Q-H)

> Status: **review** — design proposals concrete; locks at next Phase audit / operator gate
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-16
> Closes findings: SDD-010 Q-A..Q-H (proposes concrete resolution for each)
> Derived from: SDD-010 (scoping stub); SDD-011 (cross-repo bridge); info-hub SAIN-01 milestone + 11 epics; sovereign-os foundation phase complete (charter through SDD-011 + build pipeline + hooks + Trinity inference stack); operator-verbatim goal directive

## Implementation status

**SDD-010 was a scoping stub** ("requirements only, design deferred";
gated on hardware procurement + Oracle Core model selection + operator
authorization). Two of three triggers have fired:

- ✅ **info-hub SAIN-01 milestone landed** (PRs #2-#6, 11 epics, ~440KB).
- ✅ **sovereign-os foundation complete on main**: charter + boundary contract + substrate survey + profile schema + initial profiles + Debian surface audit + whitelabel mechanism + TDD harness + inference backend stack SDD-011 + 9-step build pipeline + 19 hook scripts + sovereign-osctl + 55 passing Layer 1+2 tests. **A deployable image is forthcoming once operator picks substrate at Gate 2** (mkosi-on-Debian-13 recommended).
- ⏳ **Hardware procurement** still operator-side; this design lands the integration so impl can begin the moment hardware + image are ready.

Per the operator's recent goal directive (verbatim): *"You can work with this goal on selfdef too when you need."* — this SDD takes that authorization.

This SDD **proposes concrete resolutions** for SDD-010's eight open
questions. Each resolution is justified by the now-existing sovereign-os
artifacts (which weren't in scope when SDD-010 was written).

## Resolution of SDD-010 open questions

### Q-A — Tetragon policy authoring authority

**Proposal**: **coexist as separate policies, single authoring authority per origin.**

Each Tetragon `TracingPolicy` declares its `metadata.name` uniquely.
- sovereign-os ships `sovereign-kernel-fence.yaml` (4-binary sys_execve allowlist + SIGKILL)
- selfdef's `agent-guard` ships `agent-guard-*.yaml` (existing module's policies)
- Both load into the same Tetragon daemon; the daemon merges allowlists permissively (a syscall is allowed if ANY policy allows it; SIGKILL if any policy denies it AND no policy allows).

**Why coexist rather than merge**:
- Merging couples selfdef's release cycle to sovereign-os.
- Each policy file is operator-readable and audit-trail-distinct.
- Tetragon already handles N policies natively.

**Boundary contract**: the sovereign-os policy ONLY governs container-runtime syscalls (`podman`, `vllm`, `nvidia-smi`, `python3`); selfdef's `agent-guard` governs Docker/Podman/containerd container-internal syscalls scoped via pod-label match. Non-overlapping.

**Audit trail**: each kill event's `policy_name` field identifies origin. The sovereign-os `guardian-core` Python daemon and selfdef's notifier both subscribe to the Tetragon event stream and filter by `policy_name` — neither processes the other's kills.

Mechanism: a new `selfdefctl perimeter check-overlap` command (Stage-2+ on selfdef side) verifies no policy allowlist contradicts another.

### Q-B — State-fabric placement default

**Proposal**: **operator-opted-in via `selfdefctl init config --target=sain01`** (NOT auto-detected).

Auto-detection (e.g. test for ZFS dataset `tank/context`) is friendly
but failure-prone: a non-SAIN-01 system with a coincidentally-named ZFS
dataset would silently re-route selfdef state. Opt-in via the existing
`selfdefctl init` flag chain keeps the boundary explicit.

When `--target=sain01` is passed:
- `[notifier.escalations_path] = "/mnt/vault/context/selfdef-escalations.sqlite"`
- Other selfdef state paths follow the same pattern (under `/mnt/vault/context/` per the SAIN-01 storage stratification).

selfdef ZFS snapshot/replication strategy is reserved for a future Stage-2 PR; the path placement is sufficient for the integration milestone.

### Q-C — Audit-log sharing

**Proposal**: **selfdef writes to its own audit log AND, when `--target=sain01` is set, appends a summary line per event to `/mnt/vault/context/security_audit.log`**.

The shared `security_audit.log` is THE operator's chronological event timeline. selfdef's full audit (richer per-event detail) stays in its own log; the summary line in the shared log says "see selfdef-events.jsonl line N at YYYY-MM-DDTHH:MM:SS for full detail".

Trade-off accepted:
- Forensic boundaries preserved (each daemon owns its log).
- Operator gets ONE shared timeline for cross-component review.
- No log-injection risk (only summary lines + path reference).

Implementation: selfdef notifier gains a "shared-audit-summary" output channel (similar to `wall` / `write` channels per selfdef's notifier-channel system), enabled by `--target=sain01`.

### Q-D — selfdef-side Oracle Core integration

**Proposal**: **selfdef stays Oracle-Core-unaware in v1; opt-in `oracle-triage` notifier channel post-procurement**.

Rationale: selfdef's escalation model is "detect → notify operator". Adding "Oracle Core synthesis" before notification couples selfdef to a specific inference backend (Q-017 outcome) and adds latency. Operator-driven post-event Oracle-Core triage is the better pattern (operator clicks a button in the dashboard; the dashboard calls the Oracle Core; selfdef stays decoupled).

When operator wants tighter integration, an opt-in notifier channel:
- `selfdefctl init oracle-triage --endpoint http://127.0.0.1:8080` (the sovereign-os router)
- selfdef notifier emits the event payload to the router; router dispatches to Oracle Core (DFlash on code/math content; Logic Engine for parse-heavy events).

This keeps the boundary clean: selfdef owns event detection; sovereign-os owns inference dispatch.

### Q-E — Cross-SDD references

**Proposal**: **the following selfdef SDDs gain cross-references when this design lands**:
- SDD-001 (ai-machine-end-to-end) — § "Tetragon coexistence" pointer to this SDD
- SDD-004 (security-threat-model) — § "Cross-policy authority" pointer
- SDD-008 (notifications-orchestration) — § "shared-audit-summary channel" + "oracle-triage channel" stubs (NOT impl in this SDD; Stage-2 PRs land them)

Each cross-reference is one line; no body changes to those SDDs in this PR.

### Q-F — selfdef backlog format

**Proposal**: **stick to selfdef's existing SDD + decisions-log + audit-phase ledger pattern**. Do not adopt info-hub's epic/milestone format on selfdef.

Rationale:
- selfdef's pattern is operator-fluent (12 SDDs already + audit phases + decisions log).
- The Stage-2 impl work is well-scoped into 4-6 PRs, not a multi-epic project.
- Adopting info-hub's format on selfdef would create a new artifact type to maintain without proportional value.

Stage-2 selfdef impl tracks via existing pattern: new SDDs (013+) per substantive concern, decisions-log entries per resolved question.

### Q-G — selfdef deployment outside SAIN-01

**Proposal**: **all SAIN-01-specific behavior is gated behind `[deployment.target]` config field** (default: `generic`).

```toml
[deployment]
target = "generic"  # or "sain01"
```

When `target = "generic"` (default):
- Default state paths (`/var/lib/selfdef/`)
- No shared-audit-summary channel
- No oracle-triage channel
- Tetragon agent-guard module behaves as today
- All existing non-SAIN-01 deployments work identically

When `target = "sain01"`:
- Paths shift to `/mnt/vault/context/`
- shared-audit-summary channel auto-enabled
- oracle-triage channel offered (operator opts in via additional config)
- `selfdefctl perimeter check-overlap` available

The dispatch is a single config branch; no code-paths fork.

### Q-H — Stage-2 epic count + ordering

**Proposal**: **4 SDDs / PRs**, in this order:

| Order | SDD | Scope |
|---|---|---|
| 1 | SDD-013 | `[deployment.target]` config + path resolution + non-SAIN-01 regression-prevention tests |
| 2 | SDD-014 | shared-audit-summary notifier channel (per Q-C); cross-references in SDD-008 |
| 3 | SDD-015 | Tetragon perimeter coexistence runtime (per Q-A); `selfdefctl perimeter check-overlap`; cross-references in SDD-001 + SDD-004 |
| 4 | SDD-016 | oracle-triage notifier channel (per Q-D, opt-in); router-endpoint configuration |

Each PR independently ships; no PR depends on a subsequent one's content. Total Stage-2 selfdef work: 4 PRs, estimated 2-3 weeks operator time (mostly testing on real SAIN-01 hardware once procured).

## Goals

1. **No surprise overlaps** — selfdef and sovereign-os perimeters coexist with explicit boundaries (Q-A).
2. **Non-SAIN-01 unchanged** — every existing selfdef deployment works identically (Q-G).
3. **Operator-opt-in for integration** — auto-detection rejected (Q-B); explicit `--target=sain01` + per-channel opt-in (Q-D).
4. **Forensic-boundary preserved** — selfdef owns its audit log; sovereign-os shared timeline is summary-only (Q-C).
5. **Format consistency** — selfdef stays in its SDD/decisions/audit-phase pattern (Q-F).
6. **Ordered, small Stage-2 PRs** — 4 PRs land independently (Q-H).

## Non-goals (this SDD)

- Does NOT implement any of the 4 Stage-2 SDDs above. This is the design layer; impl lands in subsequent PRs.
- Does NOT change selfdef's notifier 12-channel set (which stays as today); the 2 new channels are additive.
- Does NOT modify selfdef's existing `agent-guard` Tetragon policy. SDD-015 will add the `check-overlap` tooling but not change agent-guard semantics.
- Does NOT pin a specific Oracle Core model (operator decides via info-hub E110 + Q-017 inference-backend stack on sovereign-os).

## Open sub-questions

None at the design layer. Each Stage-2 SDD will surface its own implementation-specific sub-questions.

Operator-visible question that COULD land here but doesn't, by design:

- **Brand identity for selfdef-on-SAIN-01 UX** (e.g., should the shared-audit-summary line use sovereign-os's branding or selfdef's?) — deferred; current decision: selfdef-branded summary lines in the shared log (forensic clarity).

## Way forward

1. **This SDD merges** → operator confirms or asks for revisions on the 8 proposals.
2. **Q-A..Q-H closure** → D-N entries in `docs/decisions.md`.
3. **SDD-013 opens** → `[deployment.target]` config plumbing + tests. PR scope: 1-2 days operator time.
4. **SDD-014..016 in order** → each PR small and independently testable.
5. **Hardware procurement converges** → Stage-2 impl PRs land alongside SAIN-01 assembly.
6. **First selfdef-on-SAIN-01 boot** → operator validation; Phase 9 (or successor) audit triggered per Phase 8's deferral conditions.

## Cross-references

- SDD-010 (scoping stub this SDD closes): `docs/sdd/010-selfdef-on-sain01.md`
- SDD-011 (cross-repo bridge; sovereign-os arc opening): `docs/sdd/011-sovereign-os-arc-opening.md`
- SDD-001 (ai-machine-end-to-end; gains cross-reference per Q-E)
- SDD-004 (security-threat-model; gains cross-reference per Q-E)
- SDD-008 (notifications-orchestration; gains cross-reference per Q-E)
- sovereign-os `docs/sdd/011-inference-backend-stack.md` (Q-D's router endpoint reference)
- sovereign-os `scripts/hooks/post-install/tetragon-policy-load.sh` (sovereign-kernel-fence.yaml; Q-A's coexisting policy)
- sovereign-os `scripts/sovereign-osctl` (`inference` subcommand; Q-D's router target)
- info-hub `wiki/backlog/milestones/sain-01-sovereign-node.md` (SAIN-01 milestone; the host this integrates against)
- info-hub E110 (model catalog; Oracle Core selection; informs Q-D's optional channel)
