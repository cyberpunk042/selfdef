# context.md — selfdef journey state + positioning + what's ahead

> **Read me first after every compaction.** This file is the operator-requested re-orientation surface for selfdef (2026-05-19). Mirrored from sovereign-os/context.md per the two-ultimate-solutions doctrine — both repos share the operator framing, each from its own POV.
>
> Authoritative full picture: see `cyberpunk042/sovereign-os/context.md` (same operator-state-of-the-art, this file is the selfdef-anchored view).

## The two ultimate solutions (operator framing, verbatim 2026-05-19)

> "Continue Endlessly to toward the two ultimate solutions and their perfectioning and high UX/Developer Experience."

This repo is **Solution 2 — `selfdef`** — the IPS daemon. Boundary enforcement + Guardian + operator surface. **Independent** (boots without sovereign-os per MS043 R10217-R10225 offline-survivability) AND **combining** (publishes 9 MS007 mirror crates for sovereign-os cockpit consumption).

`cyberpunk042/sovereign-os` is **Solution 1** — the runtime/cockpit. `cyberpunk042/devops-solutions-information-hub` is the **third piece** = read-only second-brain.

## Where we are right now (selfdef, 2026-05-19 snapshot)

### Catalog phase — COMPLETE

| metric | target | actual | status |
|---|---|---|---|
| Milestones | n/a | 45 (MS001-MS045) | ✓ |
| R-rows | 10,000+ (combined with sovereign-os) | ~11,200 (selfdef alone) | ✓ |
| Latest milestone | MS045 | UX coherence test harness validating MS043 240 R-rows | ✓ |

### Backward-sweep phase — COMPLETE

- MS010 file-level canon-update annotation applied (commit `6a2f6ef`) per 6 redefinitions in sovereign-os M061.

### Implementation status

| artifact | status | reference |
|---|---|---|
| 12-channel notify set (write/wall/ntfy/signal/discord/slack/smtp/thehive + shared-audit-summary + integration-orchestrator + notifier-engine + notifier-orchestrator) | ✓ shipped | `CHANGELOG.md` channel inventory |
| `selfdefctl notify resend <event_id>` escalation triage | ✓ shipped | `CHANGELOG.md` PR #173 |
| `selfdef-integration-write` per-user TTY channel | ✓ shipped | `CHANGELOG.md` PR #170 |
| 8/8 SATURATED mirror crates (auth-tier / bashrc-install / history-sink / dashboard-manifest / surface-manifest / ux-checklist / audit-manifest / doc-manifest) | ✓ shipped | `crates/selfdef-{auth-tier,...}/Cargo.toml` |
| selfdef-rules-mirror (MS043 D-12 networking source, 1 of 9 mirror crates) | ✓ shipped (7 passing tests) | `crates/selfdef-rules-mirror/` (commit a0b35e6) |
| selfdef-grants-mirror (MS043 D-13 fs/network/capability grants source, 2 of 9) | ✓ shipped (8 passing tests) | `crates/selfdef-grants-mirror/` |
| selfdef-capability-mirror (MS043 D-14 capability_word tokens source, 3 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-capability-mirror/` |
| selfdef-sandbox-mirror (MS043 D-15 MS036 tier A/B/C/D allocations source, 4 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-sandbox-mirror/` |
| selfdef-audit-mirror (MS043 D-16/D-19 MS009 chain status + M049 13-field span + MS026 OCSF source, 5 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-audit-mirror/` |
| selfdef-quarantine-mirror (MS043 D-17 MS042 declaration-vs-observed mismatch source, 6 of 9) | ✓ shipped (11 passing tests) | `crates/selfdef-quarantine-mirror/` |
| selfdef-trust-score-mirror (MS043 D-18 per-tool trust score history source, 7 of 9) | ✓ shipped (12 passing tests) | `crates/selfdef-trust-score-mirror/` |
| selfdef-cli-mirror (MS043 50+ subcommand schema introspection, 8 of 9; doctrine "Fullstack at the edges" verbatim) | ✓ shipped (13 passing tests) | `crates/selfdef-cli-mirror/` |
| selfdef-tui-mirror (MS043 4-panel layout schema introspection, 9 of 9; doctrine "A dashboard should not show vanity graphs" verbatim) | ✓ shipped (14 passing tests) | `crates/selfdef-tui-mirror/` |
| selfdef-profile-authority-gate (MS040 six-profile authority matrix per dump 17468-17500 + R09361-R09600; doctrine "Authority follows evidence" verbatim per R09362 dump 17501) | ✓ shipped (27 passing tests) | `crates/selfdef-profile-authority-gate/` |
| selfdef-autonomous-gates (MS040 autonomous profile predeclared envelope per F04711-F04720; /etc/selfdef/profiles/autonomous-gates.toml schema + glob matcher + MS003 envelope signing) | ✓ shipped (18 passing tests) | `crates/selfdef-autonomous-gates/` |
| selfdef-commit-authority (MS041 8 commit types + 5 mandatory fields + high-risk triple gate per dump 17389-17421; doctrine "A commit is any durable change" verbatim R09601) | ✓ shipped (22 passing tests) | `crates/selfdef-commit-authority/` |
| selfdef-network-boundary (MS038 5-profile egress enforcement per E0382-E0386 dump 3594-3620; policy_bits 8-bit encoding + FQDN/CIDR allowlist + TTL ceiling) | ✓ shipped (22 passing tests) | `crates/selfdef-network-boundary/` |
| selfdef-filesystem-boundary (MS037 3-dir exchange + 6-step import pipeline + 5-field patch + 6-check predicates per E0371-E0376 dump 3550-3593; doctrines verbatim per E0371 + E0373) | ✓ shipped (21 passing tests) | `crates/selfdef-filesystem-boundary/` |
| selfdef-actor-registry (MS041 actor catalog per F04918 + R09654-R09759; /etc/selfdef/actors/registry.json schema + fingerprint canonicalisation + revocation lifecycle) | ✓ shipped (20 passing tests) | `crates/selfdef-actor-registry/` |
| selfdef-policy-decision (MS033 10-field decision object per F03863-F03872 dump 16220; 4-outcome state machine; doctrines "Every action becomes observable and governed" + "Trace is emitted when the action is decided, not after" verbatim) | ✓ shipped (23 passing tests) | `crates/selfdef-policy-decision/` |
| selfdef-communication-boundary (MS034 8-message-type schema per E0343-E0349 dump 3450-3488; 4 transports + ToolPlan/PatchProposal/etc; doctrines "Never let the VM directly mutate host truth" + "The VM proposes. Host commits." verbatim) | ✓ shipped (18 passing tests) | `crates/selfdef-communication-boundary/` |
| selfdef-trace-span (MS033/M049 13-field span emitter per F03882 dump 16221; doctrines "Trace is emitted when the action is decided, not after" + "Every action MUST emit a trace event object" verbatim) | ✓ shipped (16 passing tests) | `crates/selfdef-trace-span/` |
| selfdef-capability-word (MS035 64-bit capability_word bit-field per E0352 dump 3496-3504; 8-byte layout: allowed-tools/fs-scope/network-scope/runtime/memory/output-type/trust-level/flags) | ✓ shipped (20 passing tests) | `crates/selfdef-capability-word/` |
| selfdef-state-snapshot (unified IPS state envelope composing 6 sub-crates per MS041 R09757 + canonical-path /var/lib/selfdef/state-snapshot.json) | ✓ shipped (11 passing tests) | `crates/selfdef-state-snapshot/` |
| selfdef-sandbox-dispatcher (MS036 tier selection engine — companion engine to selfdef-sandbox-mirror; full decision matrix across side-effect × network × trust × risk) | ✓ shipped (15 passing tests) | `crates/selfdef-sandbox-dispatcher/` |
| selfdef-quarantine-engine (MS042 4-disposition decision engine — companion engine to selfdef-quarantine-mirror; severity + recidivism + SecretAccess escalator + whitelist override) | ✓ shipped (15 passing tests) | `crates/selfdef-quarantine-engine/` |
| selfdef-evidence-ledger (MS040 R09408-R09410 gate-evidence 100-day retention + trace_id/actor index) | ✓ shipped (11 passing tests) | `crates/selfdef-evidence-ledger/` |
| selfdef-functional-modules (MS006 14-functional-module catalog) | ✓ shipped (11 passing tests) | `crates/selfdef-functional-modules/` |
| selfdef-grant-issuer (companion engine to selfdef-grants-mirror) | ✓ shipped (11 passing tests) | `crates/selfdef-grant-issuer/` |
| selfdef-policy-bus (MS033 6-subsystem dispatch fabric: Observability/EventBus/Correlator/AuditLog/NotifyChain/OperatorQueue) | ✓ shipped (10 passing tests) | `crates/selfdef-policy-bus/` |
| selfdef-trust-score-engine (companion engine to selfdef-trust-score-mirror; 9-reason canonical deltas + 0..1000 clamp) | ✓ shipped (18 passing tests) | `crates/selfdef-trust-score-engine/` |
| selfdef-boundary-summary (R08591 5-boundary SATURATED composite: MS034/MS035/MS036/MS037/MS038) | ✓ shipped (13 passing tests) | `crates/selfdef-boundary-summary/` |
| selfdef-doctrinal-preservation (10-doctrine verbatim registry composite per "you cannot invent crap") | ✓ shipped (9 passing tests) | `crates/selfdef-doctrinal-preservation/` |
| selfdef-doctrine-coverage (post-boot 3-composite integrity report — modules + boundaries + doctrines) | ✓ shipped (9 passing tests) | `crates/selfdef-doctrine-coverage/` |
| **selfdef Rust workspace: 30 crates total** | ✓ MILESTONE | `crates/selfdef-*` |
| **9 of 9 mirror crates COMPLETE** — 100 passing tests total across MS007 typed-mirror trio | ✓ MILESTONE | `crates/selfdef-*-mirror/` |
| selfdef-web minimal-web bundle (R10166-R10173 + R10212 + R10220 — localhost:7575, 4-panel layout, SSE 2s refresh, read-only default + operator-key-gated mutations, sovereignty-clean static bundle) | ✓ shipped (13 passing tests + ux-harness L1 minimal-web check active) | `crates/selfdef-web/` |
| MS024 eBPF + nftables | catalog ✓ / impl partial (eBPF programs in `bpf/`) | `crates/selfdef-collector-ebpf/` |
| MS026 OCSF observability | catalog ✓ / impl ongoing | `crates/selfdef-collector-*/` |
| Multi-environment Discord/Slack/Signal/Telegram/SMTP/TheHive integrations | ✓ shipped | `crates/selfdef-integration-*/` |
| Guardian Daemon `/usr/local/bin/guardian-core` Python impl (MS044) | ✓ shipped + 17 integration tests passing | `scripts/guardian/guardian-core` + `tests/integration/test_guardian_core.py` |
| MS045 UX coherence test harness `/usr/bin/selfdef-ux-harness` impl | ✓ shipped (Python 3 binary + systemd service + timer, 10/10 checks passing in --json) | `scripts/ux-harness/selfdef-ux-harness` + `config/systemd/selfdef-ux-harness.{service,timer}` |
| 9 D-12..D-18 mirror crates (selfdef-rules / -grants / -capability / -sandbox / -audit / -quarantine / -trust-score / -cli / -tui) | catalog ✓ (MS043 R10182-R10193) / impl pending | `backlog/milestones/MS043-*` |

## What's ahead (selfdef forward queue)

Per "little piece by little piece" — next tractable selfdef deliverables:

1. **MS044 Guardian Daemon** Python impl at `/usr/local/bin/guardian-core`
   - 3-step response protocol: SIGKILL via `podman kill` → atomic ZFS audit log append → console bell
   - systemd unit at `/etc/systemd/system/guardian-core.service` (After=Requires=tetragon.service / Type=simple / Restart=always)
   - Tetragon eBPF UNIX socket listener at `/var/run/tetragon/tetragon.events`
2. **MS045 UX coherence test harness** binary at `/usr/bin/selfdef-ux-harness`
   - L1 schema/lint validators for CLI subcommand list + TUI panels + minimal-web panels + mirror crate list
   - CLI startup p95 <50ms benchmark across 1000 runs
   - TUI keyboard replayer via PTY (j/k/h/l/Enter/q/?/P/F)
   - Web contrast checker (WCAG 2.1 AA 4.5:1 via pa11y)
   - Web keyboard replayer (Tab/arrow/Enter/Esc via Playwright)
3. **9 MS007 mirror crates** for sovereign-os D-12..D-18 cockpit dashboards:
   - `crates/selfdef-rules-mirror/` (Ring 0-4 nftables rules)
   - `crates/selfdef-grants-mirror/` (filesystem grants)
   - ~~`crates/selfdef-capability-mirror/`~~ ✓ shipped 2026-05-19 (capability_word tokens, 11 passing tests)
   - ~~`crates/selfdef-sandbox-mirror/`~~ ✓ shipped 2026-05-19 (MS036 tier A/B/C/D allocations, 11 passing tests)
   - ~~`crates/selfdef-audit-mirror/`~~ ✓ shipped 2026-05-19 (MS009 chain status + M049 13-field span + MS026 OCSF, 11 passing tests)
   - ~~`crates/selfdef-quarantine-mirror/`~~ ✓ shipped 2026-05-19 (MS042 declaration-vs-observed mismatch, 11 passing tests)
   - ~~`crates/selfdef-trust-score-mirror/`~~ ✓ shipped 2026-05-19 (per-tool trust history + band classifier, 12 passing tests)
   - ~~`crates/selfdef-cli-mirror/`~~ ✓ shipped 2026-05-19 (50+ subcommand schema + doctrine preservation, 13 passing tests)
   - ~~`crates/selfdef-tui-mirror/`~~ ✓ shipped 2026-05-19 (4-panel canonical layout + doctrine preservation, 14 passing tests)
   - **9 of 9 mirror crates SHIPPED 2026-05-19** — MS043 typed-mirror trio complete (100 passing tests)
4. ~~**selfdef CLI subcommand completion**~~ ✓ shipped 2026-05-19 — bash + fish + zsh per MS043 R10134 at `completions/{bash,fish,zsh}/`

## What NOT to do — operator standing rules (mirror)

Same rules as sovereign-os/context.md. Verbatim:

1. **"you cannot invent crap"** — every selfdef R-row traces to source.
2. **"do not minimize the work in selfdef"** — full 240-R-row pattern per milestone.
3. **"Respect the projects"** — IPS features stay HERE; sovereign-os features stay THERE.
4. **"Knowledge is the second-brain / information-hub"** — info-hub READ-ONLY.
5. **"layered ON TOP OF prior direction — never discarded"** — additive only.
6. **"NO random trash please"** — sovereignty-clean. No invention.
7. **"you cannot re-invent what UX mean"** — match existing CLI/TUI patterns.
8. **"DISABLE_AUTOCOMPACT=1 sacrosanct"** — never substitute.
9. **"never include model identifier in commit messages / PR bodies / pushed artifacts"** — chat replies only.
10. **"the AI does NOT decide when it's complete"** — operator-controlled.

## Hook integration — ACTUALLY WIRED 2026-05-19

This file is referenced by **live, working hooks** (verified post-edit):

- `~/.claude/session-start-context.sh` detects both `/home/user/sovereign-os/context.md` and `/home/user/selfdef/context.md` and emits a `systemMessage` JSON pointing the model at both files. Wired into `SessionStart` hook in `~/.claude/settings.json`.
- `~/.claude/post-compact-reorient.sh` uses the same detection logic on `PostCompact` events.
- Canonical templates in `~/.claude/env-bootstrap/templates/` — `apply.sh` reinstalls if drift detected. Template-vs-live drift zero post-wire.

Smoke-tested via `bash ~/.claude/session-start-context.sh` — emits valid JSON pointing to both repos' context.md.

After compaction:
1. Read this file
2. Read `cyberpunk042/sovereign-os/context.md` for full ecosystem picture
3. Pick next item from "What's ahead" forward queue
4. Execute one tractable deliverable
5. Update this file before ending turn

## Recent commits (most recent first)

### Session 2026-05-19 (post-compaction) — 15 fresh Rust crates added (IPS axis)

- `b27795d` — `selfdef-trust-floor`: 6-side-effect trust gate (floor + grace → Allow/Ask/Deny)
- `ea27742` — `selfdef-bus-subscriber-registry`: 9-subscriber bus catalog with assert-ready gate
- `fab4856` — `selfdef-audit-digest`: sliding-window per outcome/side-effect/profile/risk
- `976c315` — `selfdef-rule-pack-version`: 8-pack semver+signature manifest with pinned floors
- `64090f5` — `selfdef-anomaly-hint`: 6-class non-blocking deviation envelope
- `ac51521` — `selfdef-replay-ring`: bounded FIFO ring buffer for in-memory event rewind
- `8e50305` — `selfdef-audit-redaction`: 6-redactor sanitizer for outbound audit text
- `dc80f8c` — `selfdef-incident-classifier`: 5-level Info/Notice/Warn/Critical/Emergency taxonomy
- `6045134` — `selfdef-substrate-self-test`: 7-canary boot-time fixture harness
- `70c810a` — `selfdef-grant-revocation-log`: append-only with 5 reasons
- `8257d32` — `selfdef-retention-policy`: 8-kind retention rule set
- `d7cc07b` — `selfdef-doctrine-citation`: per-decision doctrine tag set
- `3b8e184` — `selfdef-collector-arming-state`: 6-state per-collector arming machine
- `f05ce99` — `selfdef-collector-quarantine-ledger`: append-only ledger with 5 reasons
- `694c505` — `selfdef-collector-budget-guard`: per-collector EPS budget verdict
- `d6e8881` — `selfdef-collector-source-taxonomy`: 7-collector typed catalog

### Earlier milestones

- `cdc9064` — MS045 UX coherence test harness milestone (240 R-rows)
- `0b5a648` — MS044 Guardian Daemon catalog milestone (240 R-rows)
- `6a2f6ef` — Patch Pass A MS010 canon-update annotation
- `eb04ed9` — MS043 IPS operator surface — CLI + TUI + dashboard-mirror exports
- `470b375` — MS042 Tool authority — declaration-vs-observed discipline (catalog close)
- `a96661d` — MS041 Commit authority — durable-change discipline
- `2835824` — MS040 Authority and profiles — six-profile authority matrix
- `d686ccc` — MS039 Authority levels (L0..L6) + trust rings (Ring 0..4) — IPS-side projection

Earlier history: see `git log --oneline backlog/milestones/` and `CHANGELOG.md`.

Selfdef workspace at 166 crates total (was 83 pre-session, +83 fresh this session).
Full workspace test suite: 2834 passing tests. Newest:
`selfdef-decision-router` (composite 4-outcome gate),
`selfdef-action-replay-counter` (sliding-window repeat counter),
`selfdef-substrate-readiness` (8-check daemon bring-up gate).
Earlier:
`selfdef-evidence-redaction-policy` (per-channel × redactor),
`selfdef-policy-decision-batcher` (MAX_BATCH=128 + FNV-1a hash). Newest batch:
`selfdef-grant-receipt`, `selfdef-audit-summary-digest`,
`selfdef-bus-priority-policy`, `selfdef-host-fingerprint-attestation`.
Earlier:
`selfdef-decision-budget` (per-profile × action daily/weekly/monthly caps). Newer:
`selfdef-context-sensitivity-policy` (Public/Internal/Confidential × ProviderClass flow),
`selfdef-grant-renewal-policy` (min-remaining + max-delta renewal bounds),
`selfdef-decision-throttle` (per-subject token-bucket). Newer:
`selfdef-grant-revocation-cascade`, `selfdef-egress-fingerprint`,
`selfdef-mode-pre-flight`, `selfdef-event-bus-stats`. Even-newer:
`selfdef-policy-decision-replay` (Identical/Drift/Refused comparator),
`selfdef-evidence-chain-link` (FNV-1a chain hash for evidence ledger),
`selfdef-actor-rotation` (operator MS003 key rotation chain),
`selfdef-policy-bundle-pack` (atomic named bundle registry). Newer additions:
`selfdef-network-rule-pack` (outbound allow/deny, closed-default),
`selfdef-decision-cache` (TTL Outcome cache),
`selfdef-audit-rotation-policy` (7-class segment rotation),
`selfdef-actor-attestation-chain` (operator→agent→service signed chain),
`selfdef-promotion-throttle` (sliding-window promotion cap).
Earlier IPS-authority
additions: `selfdef-sandbox-tier-policy` (5 tiers, one-step promotion gates),
`selfdef-snapshot-policy` (7-trigger ZFS retention), `selfdef-rate-limit-policy`
(6 profiles × rps/rpm/rph), `selfdef-mode-cooldown-policy` (per-mode dwell),
`selfdef-grant-promotion-policy` (TTL extend / scope widen gates). Latest additions include
`selfdef-grant-coverage-summary` (per-actor × kind rollup),
`selfdef-trust-promotion-feed` (auto-suggest promotions/demotions),
`selfdef-decision-explainer` (operator rationale chain),
`selfdef-policy-conflict-detector` (3-class policy stream scanner),
`selfdef-grant-overlap-detector` (per-kind scope overlap detection).

### Boundary correction batch (2026-05-19 post-/goal-reissue)

After operator critique ("things in Sovereign-OS you should have done in
Selfdef and used in Sovereign-OS"), the following IPS-authority crates
were shipped to selfdef as the source-of-truth that the (already-shipped)
sovereign-os runtime crates mirror:

- `selfdef-execution-mode-policy` — 7-mode capability-tuple authority
- `selfdef-mode-transition-authority` — Forbidden/DirectShift/Snapshot/Routine gate matrix
- `selfdef-tool-capability-policy` — (tool × mode × profile) admission
- `selfdef-toggle-audit-authority` — 5-scope MS003-signed audit
- `selfdef-replay-source-authority` — Replay-mode entry gate
- `selfdef-policy-bundle-signature` — operator-signed substrate manifest
- `selfdef-routing-decision-authority` — (ProviderClass × Profile × Mode) gate
- `selfdef-eval-gate-policy` — (SideEffectClass → required eval + staleness)
- `selfdef-high-risk-triple-gate` — MS041 snapshot + eval + oracle-or-human
- `selfdef-quarantine-cause-taxonomy` — 8 causes with severity floor + clear policy
- `selfdef-trace-id-issuer` — deterministic trace_id minting with collision detection
- `selfdef-trust-score-history` — append-only per-subject score audit
- `selfdef-action-class-taxonomy` — 10-class IPS-authoritative action classification
- `selfdef-config-mutation-authority` — config-namespace × min-profile gate
Final-leg crates beyond the rolled-up batch:
`selfdef-grant-application-queue`, `selfdef-network-egress-decision`,
`selfdef-process-spawn-registry`, `selfdef-pattern-match-engine`,
`selfdef-secret-detection` (4-class outbound payload scanner),
`selfdef-evidence-search` (tag+subject+time-range filter),
`selfdef-correlation-window` (sliding-window per-subject burst tracker).
Additional crates beyond the first batch:
`selfdef-subject-cohort` (5-tier trust cohorts with monotonic promotion),
`selfdef-evidence-tag` (6-tag evidence ledger taxonomy),
`selfdef-deny-recurrence` (per-(subject, action) deny counter),
`selfdef-grant-template-pack` (8 operator-curated grant templates),
`selfdef-policy-budget-ledger` (per-subject token+cost cap evaluator),
`selfdef-substrate-fingerprint` (boot-time FNV-1a tamper-detection snapshot),
`selfdef-trust-promotion-event` (operator-initiated cohort change log),
`selfdef-host-watcher-channel` (fsnotify-equivalent registry),
`selfdef-dispatch-fanout-budget` (per-subscriber bus rate verdict),
`selfdef-host-mutation-emitter` (HostMutationEvent builder).

Every crate ships with canonical empty builders, full validate() + serde
roundtrip + edge-case tests (7..14 passing tests per crate).

## Reference table — operator quotes that shape the work

Same as sovereign-os/context.md. Single source of truth for the operator's standing direction lives at the sovereign-os file; this file mirrors the table by reference.

---

**Last updated**: 2026-05-19 (commit `8482efe` + this file)
**Authoritative full picture**: `cyberpunk042/sovereign-os/context.md`
**Next AI session**: read this file → read sovereign-os/context.md → pick next item from selfdef forward queue → execute → update this file.

## Latest cycle (post-resume 2026-05-19)

Added 8 IPS-authority crates this cycle:
- `selfdef-emergency-stop-policy` (kill switch with rescue-class gate
  + release-authority binding)
- `selfdef-quorum-approval-policy` (N-of-M distinct-operator approval
  with veto-vacates-pool semantics)
- `selfdef-clipboard-egress-policy` (ContextSensitivity × ClipboardTarget
  × Profile decision matrix, TopSecret never to clipboard)
- `selfdef-time-window-policy` (per-op weekday + hour-of-day windows
  with wrap-past-midnight support)
- `selfdef-prompt-injection-classifier` (6-signal pattern classifier:
  override/extraction/role-hijack/exfiltration/jailbreak/obfuscation;
  bucketed Clean/Suspicious/Likely/Confirmed)
- `selfdef-blast-radius-classifier` (5-level radius: LocalEphemeral /
  LocalPersistent / CrossSession / CrossMachine / Public, bumped by
  irreversibility + public/fleet visibility)
- `selfdef-secret-redaction-policy` (7 secret classes with stable
  FNV-1a placeholder tokens for cross-occurrence correlation)
- `selfdef-token-lifetime-policy` (4 token classes with
  max_lifetime + idle_timeout, FutureIssued clock-skew detection)

All include canonical builders, full validate() + serde roundtrip +
edge-case tests (13..17 tests each). Workspace count: 174 crates.

### Second wave (same day, +5 more IPS-authority crates)

- `selfdef-blast-radius-classifier` (5-level radius from
  TargetScope×Reversibility×Visibility, with note trail explaining
  each bump)
- `selfdef-policy-conflict-resolver` (Deny>Ask>Sandbox>Allow
  multi-policy merge with priority tie-break and winning_source
  recorded for audit)
- `selfdef-substrate-attestation-chain` (FNV-1a chained
  AttestationEntry; tamper at any index reports first BrokenChain
  with expected/actual hashes)
- `selfdef-execution-budget-policy` (triple cap wall_seconds/tokens/
  dollars_micro with per-axis deny reporting)
- `selfdef-fs-watch-policy` (glob-based allow/deny/never-watch
  with deny-overrides; canonical protects ~/.ssh ~/.gnupg ~/.aws
  /etc/shadow)
- `selfdef-credential-vault-policy` (Local/Cloud/Master/Recovery
  classes, sliding-window per-hour quota, op-class allow-list,
  operator-approval flag)

Total crates this resume cycle: 14. Workspace count now 179.

### Third wave (same day, +6 more IPS-authority crates)

- `selfdef-dns-egress-policy` (wildcard subdomain support, deny-
  overrides, never_resolve always wins; canonical blocks
  transfer.sh / pastebin.com / file.io)
- `selfdef-process-launch-policy` (AllowRule/DenyRule with argv-prefix
  matching; NeverLaunch hard set)
- `selfdef-tool-output-truncation-policy` (HeadOnly/HeadTail/
  MiddleEllipsis per ToolClass, UTF-8 boundary preserving; canonical
  Llm 128KiB MiddleEllipsis)
- `selfdef-evidence-retention-policy` (per-class days_to_keep +
  never_delete override; canonical keeps CanaryTrip+Operator forever)
- `selfdef-tool-version-pinning` (Semver or Sha256 pin per tool,
  AdmitDecision reports which axis mismatched)
- `selfdef-canary-tripwire-policy` (state-hash tripwire with
  Info/Warn/Critical severity; case-insensitive hex compare)

Total this resume: 20 selfdef IPS-authority crates. Workspace 185.

### Fourth wave (same day, +5 more IPS-authority crates)

- `selfdef-llm-output-trust-tier` (4-tier Verified/Corroborated/
  Unverified/Contradicted classifier from
  (ProviderTier × GroundTruth × consensus_count))
- `selfdef-trace-sampling-policy` (per-class ppm with FNV-1a trace
  hashing; DecisionDenial + CanaryTrip force-kept)
- `selfdef-decision-reason-codes` (20 canonical ReasonCode variants
  with stable kebab-keys + default operator messages)
- `selfdef-replay-divergence-detector` (typed DivergenceCause:
  DecisionChanged / OutputDiffered / ToolMissing / TimingExceeded /
  Extra / Shorter; first-divergence-wins)
- `selfdef-sandbox-network-isolation` (5 tiers × 5 destination
  classes; tier-vs-class inequality gate)

Total this resume: 25 selfdef IPS-authority crates. Workspace 190.

### Fifth wave (same day, +3 more IPS-authority crates)

- `selfdef-pii-detection-policy` (Email/Phone/SsnUs/CreditCard/IpV4
  pattern detector with Luhn check for cards)
- `selfdef-prompt-context-quota` (5-class System/Operator/Persistent/
  Tool/Untrusted sub-cap + global cap with per-class actual report)
- `selfdef-recovery-snapshot-authority` (Hourly/Daily/Weekly classes
  with min_kept per class; select_for_recovery at-or-before)

Total this resume: 28 selfdef IPS-authority crates. Workspace 193.

### Sixth wave (same day, +2 more IPS-authority crates)

- `selfdef-sandbox-fs-isolation` (5 SandboxTier × 5 PathClass ×
  3 FsOp; Tier0 None, Tier1 JailDir RO, Tier2 Workspace RW,
  Tier3 UserHome RW no-Host-write, Tier4 Host RW)
- `selfdef-audit-log-rotation-policy` (Size/Age/Lines threshold
  rotate-reason; canonical 64MiB/24h/1M-lines)

Total this resume: 30 selfdef IPS-authority crates. Workspace 195.

### Seventh wave (same day, +3 more IPS-authority crates)

- `selfdef-context-window-watermark` (4-zone Cool/Warm/Hot/Critical
  with action recommendation Continue/SoftWarn/Compact/EmergencyCompact)
- `selfdef-tool-invocation-rate-limit` (per-tool token bucket;
  max_per_minute + burst_size; lazy refill)
- `selfdef-prompt-output-similarity` (FIFO digest ring; trip
  CollisionDetected when ≥ threshold copies in window)

Total this resume: 33 selfdef IPS-authority crates. Workspace 198.

### Eighth wave (same day, +3 more IPS-authority crates)

- `selfdef-circuit-breaker-policy` (3-state per-subject breaker
  Closed/Open/HalfOpen with sliding-window failure threshold +
  timeout-driven HalfOpen trial)
- `selfdef-feedback-loop-detector` (Edge ring; CycleDetected on
  repeated edge, FeedbackDetected on output-equals-prior-input)
- `selfdef-anomaly-baseline` (sliding mean+stddev; z-score
  classifies Normal/Suspect/Anomalous against per-tier thresholds)

Total this resume: 36 selfdef IPS-authority crates. Workspace 201.

### Ninth wave (same day, +3 more IPS-authority crates)

- `selfdef-decision-replay-binding` (decision_id → replay_slot_id
  registry with reverse lookup decisions_for_slot)
- `selfdef-llm-temperature-policy` (per-ExecutionMode temp range
  with NaN-rejection; Replay 0..0 greedy, Execute 0..0.3)
- `selfdef-execution-mode-history` (bounded chronological log of
  transitions; transitions_to/from filters; current_mode helper)

Total this resume: 39 selfdef IPS-authority crates. Workspace 204.

### Tenth wave (same day, +2 more IPS-authority crates)

- `selfdef-prompt-input-classification` (6 InputSource →
  3 TrustClass map for the prompt-context-quota sub-cap router)
- `selfdef-tool-output-trust-veil` (typed wrap of tool output;
  unveil_with_tier(expected) rejects mismatched promotion)

Total this resume: 41 selfdef IPS-authority crates. Workspace 206.

### Eleventh wave (same day, +2 more IPS-authority crates)

- `selfdef-tool-output-language-policy` (5-shape sanity check per
  registered tool; Json/Yaml/Sexpr/Markdown/PlainText)
- `selfdef-rule-pack-precedence` (4-source pack precedence
  Vendor<Substrate<Operator<Emergency with deterministic id tie-break)

Total this resume: 43 selfdef IPS-authority crates. Workspace 208.

### Twelfth wave (same day, +7 more IPS-authority crates)

- `selfdef-mcp-tool-validation` (descriptor shape + name pattern +
  param count cap + uniqueness gate)
- `selfdef-llm-stream-cutoff-policy` (MaxTokens/StopSequence/
  RepetitionTrip/WallTimeExceeded streaming cutoffs)
- `selfdef-source-attribution-policy` (ArtifactClass × {Required/
  Optional/Forbidden} citation gate)
- `selfdef-substrate-self-test-cadence` (5 CheckClass cadence with
  must_run_before_first_use mandatory boot checks)
- `selfdef-action-confirmation-tier` (BlastRadius → required
  gesture None/SingleClick/TypedConfirm/TypedName)
- `selfdef-action-side-effect-classifier` (5-class Pure/Idempotent/
  Mutating/Destructive/External from Verb × external × repeatable)
- `selfdef-retry-policy` (per FailureClass exponential backoff
  with deterministic jitter; Permanent never retries)

Total this resume: 50 selfdef IPS-authority crates. Workspace 215.

### Thirteenth wave (same day, +4 more IPS-authority crates)

- `selfdef-grant-batch-policy` (multi-grant cap + BlastRadius
  ceiling + duplicate-id rejection)
- `selfdef-task-priority-policy` (pinned > class-priority >
  earliest-deadline > insertion-order ordering)
- `selfdef-decision-watchdog` (3 DecisionClass wall-time budgets
  with register/tick/complete)
- `selfdef-resource-fingerprint-policy` (FNV-1a hex pin per
  resource id; verify returns Ok/Drift{expected,observed}/Unknown)

Total this resume: 54 selfdef IPS-authority crates. Workspace 219.

### Fourteenth wave (same day, +3 more IPS-authority crates)

- `selfdef-fact-recall-cache-policy` (5 FactClass with per-class
  ttl_seconds + may_serve_stale; decide returns Hit/Stale/Miss)
- `selfdef-output-channel-allowlist` (4 Sensitivity × 7 OutputChannel
  matrix; TopSecret only to AuditLog)
- `selfdef-bundle-load-policy` (Vendor must sign, Operator unsigned
  only Local, Untrusted needs signature + operator approval)

Total this resume: 57 selfdef IPS-authority crates. Workspace 222.

### Fifteenth wave (same day, +3 more IPS-authority crates)

- `selfdef-substrate-cold-boot-policy` (6 ordered BootStep with
  required-vs-optional; first_failure/next_step/all_passed queries)
- `selfdef-prompt-allowlist-policy` (registered PromptTemplate(id,
  version, params); admit returns Allow/Unknown/MissingParams/
  UnexpectedParams)
- `selfdef-bundle-replay-window` (recorded vs current bundle-version
  window; canonical 30d; identity_only constructor)

Total this resume: 60 selfdef IPS-authority crates. Workspace 225.

### Sixteenth wave (same day, +3 more IPS-authority crates)

- `selfdef-tool-stream-watchdog` (per-stream silence + total timeouts
  with verdict Ok/Silence/TotalElapsed)
- `selfdef-input-canonicalization` (BomStripped/ZeroWidthDropped/
  LineEndingNormalized/WhitespaceCollapsed/Trimmed transforms list)
- `selfdef-decision-batch-size-policy` (3 DecisionClass batch_size
  + max_wait_ms; should_flush gate; Interactive 4/50ms, Bulk 128/5s)

Total this resume: 63 selfdef IPS-authority crates. Workspace 228.

### Seventeenth wave (same day, +4 more IPS-authority crates)

- `selfdef-substrate-network-clock-policy` (NTP drift gate Ok/Warn/
  Reject/NoAuthority; canonical 5s/60s)
- `selfdef-task-deadline-extension-policy` (per-class extension cap
  count + total-seconds; Maintenance disallows extension)
- `selfdef-decision-fingerprint-policy` (FNV-1a u64 hex of
  canonicalized decision input tuple)
- `selfdef-tool-cancellation-policy` (3 CancelMode × 4 ExecPhase;
  SafeOnly cancellable only in Prepare)

Total this resume: 67 selfdef IPS-authority crates. Workspace 232.

### Eighteenth wave (same day, +2 more IPS-authority crates)

- `selfdef-prompt-output-watermark` (ZWSP/ZWNJ embeds 8-bit FNV-1a
  mark in first 8 chars; verify recovers it)
- `selfdef-policy-cooldown-window` (4 PolicyClass per-key cooldown
  with try_fire/seconds_to_next)

Total this resume: 69 selfdef IPS-authority crates. Workspace 234.

### Nineteenth wave (same day, +2 more IPS-authority crates)

- `selfdef-substrate-replay-validator` (engine_version / rule_bundle_
  digest / tool_versions diff; Identical/Compatible/Incompatible)
- `selfdef-policy-explanation-formatter` (Explanation{headline<=80,
  detail_lines<=120, fix_suggestions} from policy_id + reason_code)

Total this resume: 71 selfdef IPS-authority crates. Workspace 236.

### Twentieth wave (same day, +2 more IPS-authority crates)

- `selfdef-decision-redo-budget` (per-session Same/Adjacent/Cross
  redo caps; Allow{remaining} / Denied)
- `selfdef-substrate-allocator-policy` (4 ResourceClass per_alloc_max
  + total_max with admit/release; cumulative tracking)

Total this resume: 73 selfdef IPS-authority crates. Workspace 238.

### Twenty-first wave (same day, +2 more IPS-authority crates)

- `selfdef-action-witness-policy` (per-BlastRadius N-distinct-
  witness requirement; submit_witness dedup; Pending/Allow)
- `selfdef-decision-delay-policy` (per-BlastRadius mandatory delay_ms
  between confirm and dispatch; monotonic by radius)

Total this resume: 75 selfdef IPS-authority crates. Workspace 240.

### Twenty-second wave (same day, +2 more IPS-authority crates)

- `selfdef-policy-state-snapshot` (FNV-1a-digested envelope around
  policy_blob with tamper-detect verify_digest)
- `selfdef-policy-feature-flag` (per-policy Mode Enabled/DryRun/
  Disabled + rationale + bounded history)

Total this resume: 77 selfdef IPS-authority crates. Workspace 242.

### Twenty-third wave (same day, +2 more IPS-authority crates)

- `selfdef-emergency-pause-policy` (soft-hold lever: paused denies
  NewTask/Resume, allows Checkpoint/ReadOnly)
- `selfdef-decision-trace-export-policy` (4 Sensitivity × 4
  ExportClass matrix gating trace export destinations)

Total this resume: 79 selfdef IPS-authority crates. Workspace 244.

### Twenty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-namespace-policy` (hierarchical namespace tree with
  parent_id walk + child-overrides-parent + sealed/mutable flag)

Total this resume: 80 selfdef IPS-authority crates. Workspace 245.

### Twenty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-cpu-quota` (per-Profile cpu_seconds budget in
  sliding window with admit/age-out)

Total this resume: 81 selfdef IPS-authority crates. Workspace 246.

### Twenty-sixth wave (same day, +3 more IPS-authority crates)

- `selfdef-substrate-gpu-quota` (per-Profile GPU slot-count +
  max_vram_mb_per_job; acquire returns slot_id, release frees)
- `selfdef-substrate-disk-quota` (per-Profile rolling-window
  write-bytes budget + max_file_bytes cap; account/rotate pair)
- `selfdef-llm-token-throttle` (per-Profile 1-minute rolling
  token-per-minute throttle with retry_after_ms hint)
- `selfdef-substrate-network-egress-quota` (per-Profile 5-minute
  rolling egress byte budget + max_request_bytes cap; account/rotate
  pair — volumetric lane, distinct from network-egress-decision)

Total this resume: 85 selfdef IPS-authority crates. Workspace 250.

### Twenty-seventh wave (same day, +3 more IPS-authority crates)

- `selfdef-substrate-fd-quota` (per-Profile max_open_fds;
  open(label)→Granted{handle_id}/Exhausted, close(id) frees)
- `selfdef-substrate-thread-quota` (per-Profile max_threads;
  spawn(label)→Granted{thread_id}/Exhausted, finish(id) frees —
  completes substrate quota family cpu/gpu/disk/network-egress/fd/
  thread)
- `selfdef-tool-output-byte-quota` (per-Profile warn_bytes/
  hard_bytes; admit_chunk returns Accept/Truncate{kept}/Reject
  around the warn ramp)

Total this resume: 88 selfdef IPS-authority crates. Workspace 253.

### Twenty-eighth wave (same day, +3 more IPS-authority crates)

- `selfdef-llm-response-size-cap` (per-Profile (max_completion_tokens,
  max_response_chars, max_attached_blobs); plan(req) → Granted /
  Capped{adjusted} / Unconfigured)
- `selfdef-prompt-language-allowlist` (per-Profile BCP-47 tag set
  with primary-subtag fallback + "*" wildcard; symmetric to
  tool-output-language-policy)
- `selfdef-tool-call-latency-budget` (per-Profile (soft_ms, hard_ms)
  start/poll/finish ledger; poll → OnTime/SoftExpired/HardExpired)

Total this resume: 91 selfdef IPS-authority crates. Workspace 256.

### Twenty-ninth wave (same day, +2 more IPS-authority crates)

- `selfdef-substrate-cpu-affinity` (per-Profile BTreeSet<core_id>
  permitted; classify returns Allowed/Denied{allowed}/Unconfigured;
  canonical 16-core split with no overlap among non-Private)
- `selfdef-actor-trust-floor` (per-Profile floor 0..=1000 on
  trust-score-engine scores; classify returns Allowed/BelowFloor
  {floor}/Unconfigured; Production 900 / Experimental 100)

Total this resume: 93 selfdef IPS-authority crates. Workspace 258.

### Thirtieth wave (same day, +2 more IPS-authority crates)

- `selfdef-prompt-attachment-mime-policy` (per-Profile MIME glob
  allowlist: exact, subtype 'image/*', full '*'; canonical
  Experimental=*, Production exact image/png+jpeg+pdf)
- `selfdef-grant-spend-ledger` (per-grant issue/spend/revoke
  ledger; spend → Accepted{remaining}/Exhausted{remaining}/Revoked
  /UnknownGrant; distinct from policy-budget-ledger)

Total this resume: 95 selfdef IPS-authority crates. Workspace 260.

### Thirty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-revert-window` (record_change opens revert_ms
  window; revert returns Accepted{prior_blob}/Stale/Unknown;
  rotate drops expired)

Total this resume: 96 selfdef IPS-authority crates. Workspace 261.

### Thirty-second wave (same day, +2 more IPS-authority crates)

- `selfdef-llm-thinking-budget` (per-Profile max_thinking_tokens;
  plan returns Granted/Capped{adjusted}/Unconfigured; canonical
  Experimental 32k, Production/Careful 4k)
- `selfdef-session-lifetime-policy` (per-Profile (max_age_ms,
  max_idle_ms); classify returns Active/IdleExpired/AgeExpired/
  Unconfigured; AgeExpired takes precedence)

Total this resume: 98 selfdef IPS-authority crates. Workspace 263.

### Thirty-third wave (same day, +2 more IPS-authority crates)

- `selfdef-mcp-tool-trust-tier` (Sandbox<SemiTrusted<Trusted<
  Hardened tier; per-Profile floor; classify Allowed/BelowTier
  {needed,got}/UnknownTool/Unconfigured; Production=Hardened,
  Experimental=Sandbox)
- `selfdef-action-step-budget` (per-Profile max_steps; start/step/
  finish ledger; step Accepted{remaining}/Exhausted{cap}/Unknown
  Action/Unconfigured; sequential-depth lane distinct from fanout)

Total this resume: 100 selfdef IPS-authority crates. Workspace 265.

### Thirty-fourth wave (same day, +2 more IPS-authority crates)

- `selfdef-event-bus-backpressure` (per-event-kind (high_water,
  cap, pending); enqueue → Accepted/HighWater/Saturated/UnknownKind;
  dequeue saturates at 0)
- `selfdef-grant-issuance-cooldown` (per-template cooldown_ms;
  record_issued + classify Ready/Cooldown{ready_at_ms}; per-
  template independent; rotate drops expired)

Total this resume: 102 selfdef IPS-authority crates. Workspace 267.

### Thirty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-conflict-detector` (per-payload_hash window
  ledger; check returns Consistent/Divergent{outcomes}/Stale;
  rotate trims; distinct from replay-divergence-detector)

Total this resume: 103 selfdef IPS-authority crates. Workspace 268.

### Thirty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-tool-arg-redaction-policy` (BTreeSet of patterns: exact,
  *suffix, prefix*, full *; case-insensitive; redact_args replaces
  matched values with [REDACTED:<len>]; canonical password/secret/
  api_key/auth/bearer/credential/private_key/*_token/*_secret/
  *_key/aws_*/gcp_*/azure_*)

Total this resume: 104 selfdef IPS-authority crates. Workspace 269.

### Thirty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-namespace-quota` (per-namespace cap on installed
  policy count; plan_install returns Accepted{remaining}/
  CapReached{cap}/UnknownNamespace; pairs with namespace-policy)

Total this resume: 105 selfdef IPS-authority crates. Workspace 270.

### Thirty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-llm-context-shrink-policy` (per-message DropAction plan;
  System+Pinned+last keep_recent_n always Keep; drop scratch then
  tool then Summarize assistant/user; pure descriptor)

Total this resume: 106 selfdef IPS-authority crates. Workspace 271.

### Thirty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-collector-staleness-policy` (per-source freshness budget;
  set_budget/record/classify; verdicts Fresh{age}/Stale{age,
  budget}/Unknown/Unconfigured; record is monotonic)

Total this resume: 107 selfdef IPS-authority crates. Workspace 272.

### Fortieth wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-suspension-policy` (per-actor moratorium with
  auto-thaw; suspend/unsuspend/classify Active/Suspended{reason,
  unsuspend_at}/Unknown; rotate(now) evicts expired)

Total this resume: 108 selfdef IPS-authority crates. Workspace 273.

### Forty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-prompt-system-pinning` (pinned system-message ledger;
  pin(id, body, priority) replace-by-id; unpin; classify; ordered
  by priority desc + pin_seq asc; max_pinned cap; pairs with
  llm-context-shrink-policy — pinned ids are never dropped or
  summarized)

Total this resume: 109 selfdef IPS-authority crates. Workspace 274.

### Forty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-action-precondition-checker` (declarative action gates;
  Precondition enum HasGrant/NotSuspended/WithinHours{from,to}/
  EnvFlagPresent/MinTrustScore/DepActionCompleted; ctx snapshot
  pure-evaluate; reports all missing; within-hours wraps midnight)

Total this resume: 110 selfdef IPS-authority crates. Workspace 275.

### Forty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-blast-radius-cap` (per-Profile cap on
  BlastRadius from blast-radius-classifier; classify returns
  Allowed/OverCap{cap, observed}/Unconfigured; canonical
  Experimental=Public, Production=CrossSession, Private/
  Careful=LocalPersistent)

Total this resume: 111 selfdef IPS-authority crates. Workspace 276.

### Forty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-prompt-input-dedup` (sliding-window prompt-fingerprint
  dedup; observe(hash,ts) monotonic; check returns Fresh /
  Duplicate{age_ms, original_ts_ms}; rotate evicts)

Total this resume: 112 selfdef IPS-authority crates. Workspace 277.

### Forty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-action-idempotency-key` (at-least-once retry-safe
  ledger; submit Fresh/Replay{first_seen_ts, recorded_outcome};
  complete attaches outcome for future replays; rotate evicts)

Total this resume: 113 selfdef IPS-authority crates. Workspace 278.

### Forty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-mcp-tool-arg-constraint` (per-tool per-arg constraints
  RequiredPresent/ForbidEmpty/StrLenAtMost/StrEnum/IntRange;
  check returns Ok/Violations{items}/UnknownTool; multiple
  violations reported in a single pass; pairs with mcp-tool-
  validation)

Total this resume: 114 selfdef IPS-authority crates. Workspace 279.

### Forty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-pre-commit-hook` (Hook{id, priority, on_block,
  seq}; fire_order by priority desc then FIFO; veto_capable subset;
  orchestrator owns invocation; veto-capable hooks can block the
  commit)

Total this resume: 115 selfdef IPS-authority crates. Workspace 280.

### Forty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-feature-gate` (Requirement Avx2/Avx512/Neon/
  NvidiaGpu/RamAtLeastGB/CoresAtLeast over a Snapshot mirror of
  selfdef-hardware; classify Enabled/Disabled{missing}/Unknown
  Feature; lets optimized paths opt in honestly per substrate)

Total this resume: 116 selfdef IPS-authority crates. Workspace 281.

### Forty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-grant-template-allowlist` (per-Profile BTreeSet of
  template ids + '*' wildcard; classify Allowed/Denied
  {allowed_count}/Unconfigured; canonical Experimental=*,
  Autonomous adds outbound-http-write+spawn-child, Production
  capped at outbound-http-readonly)

Total this resume: 117 selfdef IPS-authority crates. Workspace 282.

### Fiftieth wave (same day, +1 more IPS-authority crate)

- `selfdef-rate-window-aggregator` (per-key events-per-window
  counter; record(key, ts) monotonic; count(key, now) filters
  in-window; rotate evicts globally; distinct from rate-limit-
  policy — this is the count-only lane)

Total this resume: 118 selfdef IPS-authority crates. Workspace 283.
