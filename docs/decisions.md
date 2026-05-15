# Decisions log

Chronological audit trail of design-question resolutions. Each `D-NNN`
entry corresponds to an answered question from one of the SDDs (or a
similar source doc — handoff, audit ledger, RFC). Entries are
append-only — never edit a past entry; if a decision is revisited,
append a new entry that references the prior one.

Driven by the `/questions` skill — when the operator answers an open
question, the SDD's `Q-X` row is annotated **in place** with
`**answered (D-NNN, YYYY-MM-DD)**` and a new entry is appended here.
The two artifacts together form the audit trail: the SDD stays the
canonical source of truth; this log gives the chronological view.

## Format (per entry)

```markdown
## D-NNN — YYYY-MM-DD — <one-line summary>

**Decision**: <what was decided — operator-verbatim if free-text>
**Question**: <full question, copied from source doc>
**Source**: `docs/sdd/<n>-<title>.md`:<line> (Q-X row)
**Rationale**: <why this option beats the alternatives — synthesis +
                any operator commentary>
**Affected items**: <files / future SDDs / impl crates touched>
**Reversibility**: fully-reversible | partial | locked
**Linked**: PR #<n>
```

`Reversibility` legend:

- **fully-reversible** — the decision can be revisited at any time with
  no migration cost. Most design choices land here.
- **partial** — revisiting requires some refactor / migration but no
  data loss or compat break.
- **locked** — revisiting requires a breaking change (data migration,
  protocol break, deprecation cycle).

## Cross-references

- `/questions` skill: `.claude/skills/questions/SKILL.md`
- `/view` orientation: `.claude/skills/view/SKILL.md`
- SDD index: `docs/sdd/000-charter.md` + `001`..`008`
- Audit programme ledgers: `docs/review/phase-*/99-findings-ledger.md`

---

## Entries

## D-001 — 2026-05-15 — Dashboard scope: comprehensive operator visibility (design deferred)

**Decision**: The dashboard's scope is **comprehensive operator visibility into selfdef's full surface — all modules, integrations, configurations, status, events, messages, and operations**. Detailed design (auth model, hosting, UI technology, ack flow, bulk operations, etc.) is explicitly deferred to a separate SDD / design conversation. This entry captures the requirement; the SDD-009 (or equivalent) dashboard design comes later.
**Question**: How should the SDD-008 D-9 dashboard be scoped?
**Source**: `docs/sdd/008-notifications-orchestration.md`:46 (D-9 row in impl-status table)
**Rationale**: Operator directive — the dashboard's role is full project visibility, not a minimal ack-list slice. Implementation choices (read-only HTML vs. full auth dashboard vs. TUI vs. SIEM-via-Loki) are design decisions that belong inside the future dashboard SDD, not in this requirements decision. Locking the scope up front prevents the design conversation from narrowing prematurely.
**Affected items**: Future SDD-009 (or equivalent) dashboard design conversation; eventual impl crates and config
**Reversibility**: fully-reversible — requirements can be expanded or refined when the design SDD is scoped
**Linked**: PR (this PR)

## D-002 — 2026-05-15 — SSE terminate-on-revoke: keep current behavior + document the bound

**Decision**: Keep current behavior. The F-2027-062 slow-client timeout (~30s default) is the documented upper bound on the leak window between a token rotation and the closure of any still-open SSE connections bearing the revoked credential. No new code; ensure the bound is explicit in SECURITY.md if it isn't already.
**Question**: Does selfdef need terminate-on-revoke for SSE subscribers?
**Source**: `docs/sdd/007-per-token-sse-subscriber-quota.md`:27 (D-3 row)
**Rationale**: Attack profile is narrow (insider-revoke + currently-open connection); slow-client timeout caps the window; no operator has surfaced demand. Adding `drained_at` per fingerprint (Option A in the mini-RFC) is the cleaner upgrade path if demand surfaces later — but until then, code complexity isn't justified.
**Affected items**: `SECURITY.md` (addendum to document the bound if not already explicit)
**Reversibility**: fully-reversible — Option A (drained_at per fingerprint) is the documented upgrade path
**Linked**: PR (this PR)

## D-003 — 2026-05-15 — TracingPolicy/sigma signing: inline detached + bundled CA (working hypothesis)

**Decision**: Working hypothesis for the future F-2026-024 follow-up SDD: **inline detached signatures + bundled CA**. Each policy YAML carries a `.sig` companion; the daemon verifies on load against a bundled trust root. Matches selfdef's filesystem-native distribution model; works offline; no OCI registry dependency. Detailed shape (key rotation policy, CA format, signature algorithm, sigma+TracingPolicy unification) is scoped when the F-2026-024 SDD lands.
**Question**: What shape should the shared TracingPolicy/sigma signing machinery take?
**Source**: `docs/sdd/004-security-threat-model.md`:54 (Q-C resolution row)
**Rationale**: Cosign/OCI (Option A) is more standard but adds OCI registry + toolchain dependencies selfdef doesn't currently need. Manifest-hash anchored (Option C) doesn't cleanly support operator-authored policies. Defer-further (Option D) leaves an explicit gap in SECURITY.md. Inline detached (Option B) is the lightest-weight match for filesystem-native distribution.
**Affected items**: Future F-2026-024 signing SDD; sigma-rule signing path; TracingPolicy loader; SECURITY.md (eventual update once SDD lands)
**Reversibility**: fully-reversible — working hypothesis only; final shape decided in the future SDD
**Linked**: PR (this PR)

## D-004 — 2026-05-15 — wall(1) per-user opt-in: explicit allowlist, ship paired with write(1)

**Decision**: Per-user opt-in for wall(1) lands as `[notifier.wall].users = [...]` — an explicit operator-managed allowlist in config. Only listed TTYs receive escalation broadcasts. Ship paired with the `write(1)` session-attention transport so the design touch on wall amortizes across both transports.
**Question**: Should wall(1) gain per-user opt-in lists?
**Source**: `docs/sdd/008-notifications-orchestration.md`:462 (Q-F row)
**Rationale**: Explicit allowlist matches the URL-leakage mitigation already documented in SECURITY.md. Group-based via /etc/group (Option B) adds nsswitch complexity and externalizes "SOC" semantics without a clear gain. Document-only (Option C) leaves multi-tenant hosts bleeding URLs — incompatible with the project's "no bugs" posture.
**Affected items**: `crates/selfdef-integration-wall` (config schema + TTY filtering); `crates/selfdef-config` (config parsing); SECURITY.md (URL-leakage map update once shipped); future write(1) integration crate
**Reversibility**: fully-reversible
**Linked**: PR (this PR — requirements only; implementation PR pairs with write(1))

## D-005 — 2026-05-15 — WG interface name limit: refuse cleanly in apply.sh

**Decision**: `apply.sh` validates the instance id length up-front and refuses cleanly with an explicit operator-facing error when the id exceeds 8 characters (the bound that keeps `selfdef-${INST}` within Linux's 15-character interface-name limit). Document the bound in README. No silent truncation; no name munging.
**Question**: How should the WG interface name handle the 15-char Linux limit?
**Source**: `docs/sdd/003-vpn-bridge-multi-instance.md`:600 (Q-C row)
**Rationale**: Operator-facing failure modes should be explicit. Silent truncation or hash-suffix munging (Option B) makes debugging harder and breaks the mapping between instance id and interface name. Document-only without enforcement (Option C) leaves a known foot-gun and contradicts selfdef's quality posture.
**Affected items**: `selfdef-instance/apply.sh` (length check at instance resolution); README addendum
**Reversibility**: fully-reversible
**Linked**: PR (this PR — requirements logged; implementation PR pending)

## D-006 — 2026-05-15 — KillPidAction wiring to agent-guard findings: keep deferred

**Decision**: Keep deferred. KillPidAction wiring belongs to its own SDD covering responder cgroup-reaping if and when operator demand surfaces. SDD-001 stays out of scope for this hook.
**Question**: Wire `KillPidAction` to agent-guard findings?
**Source**: `docs/sdd/001-ai-machine-end-to-end.md`:560 (Q-C row)
**Rationale**: Matches SDD-001 author intent. The kernel already killed the process via Tetragon; KillPidAction is for the correlator-promotes-then-reaps profile, which is a different SDD's concern. Wiring it inside SDD-001 would creep scope into responder semantics.
**Affected items**: Future "responder cgroup-reap" SDD if demand surfaces
**Reversibility**: fully-reversible
**Linked**: PR (this PR)

## D-007 — 2026-05-15 — Multi-host propagation in D-4 integration test: keep deferred

**Decision**: Keep deferred. SDD-001 explicitly stays single-host; the D-4 integration test stays single-host accordingly. A multi-host propagation test (with NATS broker fixture) belongs to whichever SDD covers multi-host scope.
**Question**: Does the D-4 integration test need a real NATS broker for multi-host propagation?
**Source**: `docs/sdd/001-ai-machine-end-to-end.md`:566 (Q-D row)
**Rationale**: SDD scope discipline. SDD-001 is explicitly single-host; cross-host concerns belong in a different SDD. Adding NATS fixture inside SDD-001 widens scope and adds test-infra cost without addressing a stated operator need.
**Affected items**: Future multi-host SDD if scoped
**Reversibility**: fully-reversible
**Linked**: PR (this PR)
