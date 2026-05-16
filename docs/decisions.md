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
- SDD index: `docs/sdd/000-charter.md` + `001`..`011`
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

## D-008 — 2026-05-15 — agent_guard_observed.yml Post-mode rule: don't ship for v1

**Decision**: Do not ship the `agent_guard_observed.yml` Post-mode rule alongside the v1 agent-guard module. Revisit after operator feedback in production.
**Question**: Do we ship the `agent_guard_observed.yml` Post-mode rule alongside?
**Source**: `docs/sdd/001-ai-machine-end-to-end.md`:549 (Q-A row)
**Rationale**: Every audit-mode policy fire would create an `Informational` finding, which clutters the store. Conservative default until operator demand surfaces; cheap to add later.
**Affected items**: `modules/agent-guard/` (policy YAMLs); future operator-feedback cycle
**Reversibility**: fully-reversible
**Linked**: PR (this PR)

## D-009 — 2026-05-15 — sigma rule level: literal `high`

**Decision**: Sigma rules for agent-guard findings use a literal `level: high`, not a per-policy mapping from the YAML's `selfdef.io/severity` annotation. D-1b leaves room for per-policy mapping once upstream Tetragon exposes annotations in events.
**Question**: Should the sigma rule's `level` be a literal `high`, or should it map per-policy from the YAML's `selfdef.io/severity` annotation?
**Source**: `docs/sdd/001-ai-machine-end-to-end.md`:554 (Q-B row)
**Rationale**: Annotations aren't in the Tetragon event today; literal works without upstream changes. Per-policy mapping is the cleaner end-state once annotations land.
**Affected items**: agent-guard sigma rule generator
**Reversibility**: fully-reversible
**Linked**: PR (this PR)

## D-010 — 2026-05-15 — Drop-in support in selfdef-config: no for v1

**Decision**: No drop-in directory in `selfdef-config` for v1. The configuration snippet goes in `/etc/selfdef/selfdef.toml`. A drop-in directory matching systemd's pattern would be a separate SDD if it gains traction.
**Question**: Drop-in support in `selfdef-config`?
**Source**: `docs/sdd/002-defaults-that-work.md`:520 (Q-A row)
**Rationale**: Conservative posture — the single-file config is simpler to reason about, and `--write-snippets` mode can produce non-clobbering files via a future drop-in directory if operators ask.
**Affected items**: `selfdef-config` crate; future drop-in SDD if scoped
**Reversibility**: fully-reversible

## D-011 — 2026-05-15 — [daemon_requires] removal: not for v1

**Decision**: `[daemon_requires]` does not support negative dependencies (`enabled = false` preventing other defaults) in v1.
**Question**: Does `[daemon_requires]` need to support removal?
**Source**: `docs/sdd/002-defaults-that-work.md`:526 (Q-B row)
**Rationale**: Scope discipline — v1 covers the positive case; negative dependencies are a separate concern that hasn't surfaced as needed.
**Affected items**: `selfdef-config` `[daemon_requires]` schema
**Reversibility**: fully-reversible

## D-012 — 2026-05-15 — selfdefctl modules apply --auto-fix: out of scope

**Decision**: `selfdefctl modules apply --auto-fix` (rewriting `selfdef.toml` directly to resolve detected gaps) is out of scope for v1.
**Question**: Should `selfdefctl modules apply --auto-fix` rewrite `selfdef.toml` directly?
**Source**: `docs/sdd/002-defaults-that-work.md`:529 (Q-C row)
**Rationale**: Requires a comment-preserving TOML editor. Substantial tooling cost; the validator already surfaces the gap; operator can fix manually with the suggested diff.
**Affected items**: `selfdefctl modules apply` (no behavior change in v1)
**Reversibility**: fully-reversible

## D-013 — 2026-05-15 — Validator runs on selfdefctl modules check: yes (default)

**Decision**: The daemon-config validator runs on every `selfdefctl modules check` invocation (default yes). `check` is read-only and surfacing daemon-config drift before apply is strictly better than waiting until apply-time.
**Question**: Should the validator run on every `selfdefctl modules check` too?
**Source**: `docs/sdd/002-defaults-that-work.md`:532 (Q-D row)
**Rationale**: Read-only command, so surfacing extra issues is pure information gain; operators benefit from seeing drift before they reach apply.
**Affected items**: `selfdefctl modules check`
**Reversibility**: fully-reversible

## D-014 — 2026-05-15 — Per-profile metadata table: out of scope for SDD-003

**Decision**: Per-profile metadata table does not gain extra fields (e.g. per-profile `phase` overrides, per-profile `requires`) in SDD-003. The schema in D-1 is already extensible; add fields when a concrete operator need surfaces.
**Question**: Should the per-profile metadata table support more fields than `instanced`?
**Source**: `docs/sdd/003-vpn-bridge-multi-instance.md`:592 (Q-A row)
**Rationale**: Adding speculative fields adds maintenance cost without addressing a stated need; the schema is forward-compatible by design.
**Affected items**: SDD-003 D-1 schema (no change)
**Reversibility**: fully-reversible

## D-015 — 2026-05-15 — Resolver error message includes suggested fix: yes

**Decision**: The vpn-bridge profile resolver's error message includes the suggested fix ("declare `instanced=true` in `profiles.details.<profile>`") when an operator hits the singleton-profile guard with a non-empty instance suffix.
**Question**: Should the resolver error message include the suggested fix?
**Source**: `docs/sdd/003-vpn-bridge-multi-instance.md`:596 (Q-B row)
**Rationale**: Operator-ergonomics improvement at zero design cost. Tracked as an implementation-PR follow-up if the resolver's current message doesn't already include it.
**Affected items**: `selfdef-cli` profile resolver error path
**Reversibility**: fully-reversible

## D-016 — 2026-05-15 — Pipeline + seam test requirement: yes for event-source modules

**Decision**: The test contract requires both a pipeline test AND a seam test for modules that introduce a new event source. Purely passive modules (e.g. a future `host-baseline` observation module) are exempt.
**Question**: Should the contract require both a pipeline test AND a seam test for every new module?
**Source**: `docs/sdd/005-test-contract.md`:453 (Q-A row)
**Rationale**: Pipeline + seam tests are load-bearing for modules that introduce events into the bus. Pure observers don't need them; over-applying would create test-debt for low-risk additions.
**Affected items**: SDD-005 test-contract spec; future module-introduction PRs
**Reversibility**: fully-reversible

## D-017 — 2026-05-15 — Test-contract doc location: docs/src/dev/

**Decision**: The test-contract doc lives under `docs/src/dev/` (mdbook-visible to contributors). Cross-publishing under `docs/sdd/` is acceptable but not required.
**Question**: Where does the test-contract doc go?
**Source**: `docs/sdd/005-test-contract.md`:458 (Q-B row)
**Rationale**: Contributors discover test-contract guidance through dev docs; placing it there matches the audience.
**Affected items**: `docs/src/dev/` (test-contract publication)
**Reversibility**: fully-reversible

## D-018 — 2026-05-15 — Keep test contract from going stale: per-Phase audit re-validation

**Decision**: Every Phase-N audit re-asks "do these test-contract categories still match the codebase?" Contract drift surfaces as audit findings, just like any other drift signal.
**Question**: How do we keep the test contract from going stale?
**Source**: `docs/sdd/005-test-contract.md`:462 (Q-C row)
**Rationale**: Leverages the existing closure-cycle audit cadence — no new process needed. The seven explorers already inventory the codebase; contract-drift is a natural finding category.
**Affected items**: Future Phase-N audit charters (test-contract drift check)
**Reversibility**: fully-reversible

## D-019 — 2026-05-15 — Shared lib location: packaging/lib/

**Decision**: The shared module-script library lives at `packaging/lib/` (alongside other deb-distributed assets). No top-level `share/selfdef-lib/` directory.
**Question**: Where does the shared module-script lib live?
**Source**: `docs/sdd/006-shared-module-script-lib.md`:521 (Q-A row)
**Rationale**: `packaging/lib/` matches what the daemon ships today; reusing it avoids a new top-level path unless a cross-package concern emerges.
**Affected items**: `packaging/lib/` (SDD-006 implementation)
**Reversibility**: fully-reversible

## D-020 — 2026-05-15 — module-helpers.md location: docs/src/dev/

**Decision**: `module-helpers.md` lives under `docs/src/dev/` (visible to contributors writing modules), with a back-reference from SDD-006.
**Question**: Where does `module-helpers.md` go?
**Source**: `docs/sdd/006-shared-module-script-lib.md`:526 (Q-B row)
**Rationale**: Audience-matched placement — contributors writing modules read dev docs, not SDDs.
**Affected items**: `docs/src/dev/module-helpers.md`; SDD-006 cross-reference
**Reversibility**: fully-reversible

## D-021 — 2026-05-15 — v2 shared lib for YAML editing: out of scope for v1

**Decision**: v2 of the shared lib for YAML editing (whether via `yq` as a module `requires` or an in-house bash/python editor) is out of scope for v1. Tracked for future scoping when YAML-editing modules need it.
**Question**: Future v2 of the shared lib for YAML editing: `yq` as `requires`, or in-house editor?
**Source**: `docs/sdd/006-shared-module-script-lib.md`:530 (Q-C row)
**Rationale**: Premature commitment without a YAML-editing module that needs the helper; deferring keeps v1 scope tight.
**Affected items**: Future v2 SDD for YAML-editing helpers
**Reversibility**: fully-reversible

## D-022 — 2026-05-15 — Realization note: D-003 already shipped via the minisign path

**Decision**: D-003's working hypothesis (TracingPolicy/sigma signing as "inline detached signatures + bundled CA") is **already realized in shipped code** via the minisign-based signing path that landed before D-003 was logged. The "future F-2026-024 follow-up SDD" framing in D-003 is therefore obsolete: the F-2026-024 follow-up shipped as opt-in features. No further SDD work needed unless the operator wants to revisit the signing format (e.g. cosign/OCI instead of minisign).
**Question**: Is D-003 still pending, or has it been realized?
**Source**: `docs/decisions.md` D-003 entry (supersedes); `docs/sdd/004-security-threat-model.md`:321-340 (post-#166 status: "shipped"); `SECURITY.md`:244 (TracingPolicy signing runbook).
**Rationale**: When D-003 was logged in PR #159, the framing assumed signing was net-new design work. Investigation in PR #166 (SDD-004 known-gaps refresh) surfaced that minisign-based rule signing + TracingPolicy signing already shipped as F-2026-024 follow-up — the working hypothesis is concretely realized via `.minisig` sibling files + `[security].signing_public_key_file`. D-003's "inline detached + bundled CA" is structurally what minisign provides (`.minisig` = inline detached, the configured public-key file = the trust anchor).
**Affected items**: `docs/decisions.md` (this entry supersedes D-003's "pending working hypothesis" framing); operator-facing reality unchanged.
**Reversibility**: fully-reversible — if operators later prefer cosign/OCI over minisign, that's a new design conversation; both paths can coexist via the `.minisig` opt-in mechanism.
**Linked**: PR (this PR); supersedes D-003 (`docs/decisions.md`).

## D-023 — 2026-05-15 — Realization note: D-015 already shipped via F-2027-001

**Decision**: D-015 (vpn-bridge profile-resolver error message includes the suggested fix `[profiles.details.<profile>] instanced = true`) is **already realized in shipped code**. The error path at `crates/selfdef-cli/src/modules.rs:547-553` embeds the exact copy-pasteable TOML stanza in its `anyhow::bail!` message, per the F-2027-001 audit finding closure ("embed the exact copy-pasteable TOML stanza in the diagnostic so operators don't have to compose it from prose").
**Question**: Is D-015's "include the suggested fix" requirement met by current code?
**Source**: `docs/decisions.md` D-015 entry; `crates/selfdef-cli/src/modules.rs`:540-553 (the error path with the embedded stanza); F-2027-001 audit finding closure.
**Rationale**: D-015 logged the design intent on 2026-05-15 in PR #165. Investigation during a follow-up sweep found that the implementation already ships per F-2027-001 — the resolver bails with the full TOML stanza, not just prose. The decision is therefore retrospectively documenting existing behaviour, not gating new work.
**Affected items**: `docs/decisions.md` (this entry supersedes D-015's "implementation-PR follow-up" framing); operator-facing reality unchanged.
**Reversibility**: fully-reversible — if the message ever drops the stanza in a refactor, this entry is the audit-trail evidence that it shouldn't.
**Linked**: PR (this PR); supersedes D-015 (`docs/decisions.md`).

## D-024 — 2026-05-15 — D-004 realization: per-user transport ships as the `write` channel (not `wall.users`)

**Decision**: D-004 prescribed "per-user opt-in for wall(1) lands as `[notifier.wall].users = [...]`." On implementation, that mechanism doesn't cleanly map to `wall(1)` semantics — `wall(1)` natively broadcasts to every logged-in TTY and has no per-user filter. Forcing a `wall.users` allowlist would have required either (a) shelling out to `write(1)` under the hood for the filtered case (duplicating logic the write crate now owns), or (b) reimplementing per-user TTY enumeration inside the wall crate (substantial). Instead, **per-user opt-in is realized as a separate first-class channel**: `selfdef-integration-write` (new crate) targeting `write(1)` per user. `wall` keeps its broadcast-all-TTYs semantics; operators wanting per-user opt-in configure the `write` channel.
**Question**: How is D-004's per-user opt-in mechanism actually shipped?
**Source**: `docs/decisions.md` D-004 entry (supersedes the "wall.users allowlist" mechanism wording).
**Rationale**: Faithful to D-004's **intent** (operators get per-user opt-in for session-attention) while respecting Unix `wall(1)` semantics. Cleaner separation of concerns — each channel has one transport (`wall` = `wall(1)` broadcast; `write` = `write(1)` per-user). Removes the need to duplicate per-user logic across both crates. Documented in `WallConfig`'s rustdoc: "`wall.users` intentionally does not exist; the per-user transport is its own channel."
**Affected items**: New crate `crates/selfdef-integration-write/`; `selfdef-config::NotifierConfig::write` field + `WriteConfig` struct; `selfdef-daemon` channel wiring (both legacy chain + engine path); `selfdef-cli::init` STARTER_CONFIG block for `[notifier.write]`.
**Reversibility**: fully-reversible — if operator demand surfaces for a literal `wall.users` field, the wall crate could grow per-user mode (delegating to write(1) under the hood). The shipped split keeps the future option open.
**Linked**: PR (this PR); supersedes D-004 (`docs/decisions.md`).

## D-025 — 2026-05-16 — Stage 2 transposition trigger: info-hub SAIN-01 milestone landed

**Decision**: The cross-repo Stage-2 transposition (selfdef → SAIN-01 integration) is now formally triggered. The info-hub side (`cyberpunk042/devops-solutions-information-hub`) has landed the full L0→Backlog ingestion of the SAIN-01 Sovereign Node spec — L0 verbatim provenance (PR #2), L1 source-synthesis × 4 pages (PR #3), L2 concept pages × 6 (PR #4), L3 comparisons × 4 (PR #5), milestone + 11 epics (PR #6), ~440 KB structured docs across 30 files. The architectural baseline is locked. This PR opens Stage 2 on the selfdef side as **SDD-010 requirements-only stub** (mirrors the SDD-009 dashboard pattern). Detailed design (Q-A..Q-H from SDD-010) is deferred to a separate design conversation, gated on hardware procurement + Oracle Core model selection + operator authorization.
**Question**: When + how does selfdef respond to the info-hub's SAIN-01 milestone now that it has landed?
**Source**: info-hub `wiki/backlog/milestones/sain-01-sovereign-node.md` (the master spec); operator verbatim from the 2026-05-16 session ("when we are ready we will transpose into the selfdef and the new Development and Epics and Modules and Tasks needed to get there and all the Spec files and requirements and clear vision").
**Rationale**: The info-hub side is structurally complete; selfdef now needs its own scope artifact for the cross-repo integration. Requirements-only is the right shape for this PR because: (a) hardware isn't procured yet (operator-side action); (b) the Oracle Core resident-model selection is operator-gated (Ling vs Nemotron vs both — info-hub E110's first Done When); (c) committing impl effort before the integration design lands would be the kind of premature scope-creep the operator's quality bar explicitly rejects. SDD-010 captures the five required-coverage areas (Tetragon policy coexistence, state-fabric integration, notifier-channel coexistence, package + systemd adjustments, optional Oracle Core awareness) and the eight open questions (Q-A..Q-H) for the design conversation.
**Affected items**: `docs/sdd/010-selfdef-on-sain01.md` (new SDD, requirements-only stub); future Stage-2 design SDD (or major revision of SDD-010); future selfdef-side Stage-2 PRs.
**Reversibility**: fully-reversible — requirements can be expanded, narrowed, or re-scoped when the design SDD lands. The stub commits to scope, not implementation.
**Linked**: PR (this PR); related to info-hub PRs #2-#6 (the SAIN-01 ingestion arc).

## D-026 — 2026-05-16 — Sovereign-os arc opening + Plan adoption + SFIF/IaC quality bar + Q-016 distro-base reconsideration

**Decision**: The operator opened a substantially larger cross-repo arc via the 2026-05-16 `/goal` directive — building a complete OS-image generation + customization pipeline for the SAIN-01 AI workstation. After two rounds of framing-question answers and the Plan agent's macro-arc output, the following multi-part decision lands:

1. **New repo**: `cyberpunk042/sovereign-os` (operator creates manually; agent's GitHub MCP scope must be expanded operator-side; requires a new session)
2. **Visibility**: Public
3. **License**: AGPL-3.0-or-later (mirrors selfdef per verified `cyberpunk042/selfdef/LICENSE`)
4. **Plan adoption**: 10-PR foundation phase per Plan-agent output (preserved verbatim in info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md`)
5. **Substrate**: research-first (not committed; PR 4 surveys all 8 candidates plus distro-base reconsideration)
6. **Profile shape**: schema-first, multi-profile from day 1 (default SAIN-01; alternate old-workstation)
7. **SFIF discipline applies**: PRs 1-3 Scaffold; PRs 4-8 Foundation; PRs 9-10 begin Infrastructure; Stage 2+ Features
8. **IaC quality bar**: tweakable + configurable + env-var-driven + restart-from-state + observable + operable (verbatim operator commitment)
9. **"Debian as Ark" framing**: Debian 13 = starting boat, not destination; Q-016 distro-base reconsideration in substrate survey scope
10. **Stage 2 (selfdef-on-SAIN-01, SDD-010) reframed**: downstream of sovereign-os; design conversation makes more sense once sovereign-os produces deployable images

**Question**: How does selfdef respond to the operator's 2026-05-16 /goal directive opening the OS-build pipeline arc?
**Source**: operator `/goal` directive (verbatim in info-hub `raw/notes/2026-05-16-user-directive-sovereign-os-arc-opening.md`); Plan-agent output (verbatim in info-hub `raw/dumps/2026-05-16-sovereign-os-macro-arc-plan.md`); SDD-011 (this PR's companion).
**Rationale**: The new arc is architecturally upstream of selfdef and would represent scope creep if hosted in either selfdef or info-hub. New repo respects the cleanest separation principle: sovereign-os BUILDS the OS; selfdef RUNS on it; info-hub SYNTHESIZES knowledge. Plan-agent adoption + research-first substrate + schema-first profiles + SFIF + IaC bar all flow from the operator's "do not rush, do not minimize, think before we act" quality bar. The handoff mandate ("Dont even ask me question, just get to it") authorizes this PR's multi-document landing without further question-asking; subsequent execution gated on operator-side repo-creation + MCP-scope-expansion.
**Affected items**: `docs/sdd/011-sovereign-os-arc-opening.md` (this PR); `docs/handoff/2026-05-16-sovereign-os-arc-opening.md` (this PR — supersedes 2026-05-16-end-of-stage2-anchor.md); future `cyberpunk042/sovereign-os` repo (pending operator-side bootstrap); SDD-010 Stage 2 reframed as downstream.
**Reversibility**: fully-reversible at the architectural-decision level (new-repo direction can be revisited; alternative paths documented in handoff); locked at the Plan-adoption level only insofar as the 10-PR foundation phase is what the agent will execute when authorized.
**Linked**: PR (this PR); paired with info-hub PR landing the L0 verbatim provenance.

## D-027 — 2026-05-16 — Hardware-aware modules + tune surface (SDD-018; SD-R14..R19)

**Decision**: Lock the operator-stable contracts shipped across SD-R14..R19 into doctrine via SDD-018. Five surfaces become forever-supported (with deprecation cycles for any future renames):

1. `[requires_hardware]` block in module.toml (SD-R14): 5 predicates (avx512_vnni, avx512_bf16, memory_gib_min, gpu_count_min, sain01_verdict_min) AND-ed, gate runs at apply time, skipped modules log clear stderr.
2. `selfdefctl modules check-hardware` (SD-R15): read-only dry-run; human + `--json` outputs.
3. `selfdefctl hardware thermals` (SD-R17): per-sensor reads from /sys/class/hwmon + nvidia-smi; operator-stable source label format (`<hwmon-name>/<label-or-tempN>` and `nvidia-gpu-<index>`).
4. `selfdefctl hardware tune` (SD-R19): host-tuned compile flags in 4 formats (sh / env-file / make / json); `SELFDEF_HARDWARE_*` env-var names operator-stable; `-mprefer-vector-width=512` gated on avx512f.
5. `selfdefctl doctor hardware.thermals` row (SD-R18): target-aware severity (Warn only on sain01 + no sensors).

**Question**: After 6 in-arc rounds (SD-R14..R19) + 3 cross-repo mirrors (sovereign-os R170, R172, R173), what doctrine commitments do we lock so future evolutions stay backward-compatible?
**Source**: SD-R14..R19 commits on `claude/sain01-integration-arc` (PR #190); sovereign-os R170, R172, R173 commits on main; SDD-018 (this commit).
**Rationale**: Operators are now writing/expecting these surfaces. Future renames break tooling silently; locking the names + semantics in a single SDD makes deprecation explicit (and reviewable). Cross-repo mirrors documented in one place keeps the bridge alignment legible.
**Affected items**: `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` (this commit); 6 in-arc selfdef commits; 3 sovereign-os commits; future selfdef rounds that touch the surface MUST cite this SDD.
**Reversibility**: contracts are reversible but expensive — any rename requires a Stage-2+ deprecation cycle (parallel old+new names for ≥1 release).
**Linked**: PR #190; sovereign-os main.
