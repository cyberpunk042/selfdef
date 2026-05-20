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

### Fifty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-collector-coalescing` (per-source-per-fingerprint
  Observation{first_ts/last_ts/count}; observe Started/Merged;
  drain(now) emits + clears past-window entries; nested BTreeMap
  for JSON friendliness)

Total this resume: 119 selfdef IPS-authority crates. Workspace 284.

### Fifty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-diff-classifier` (DiffSummary→Classification
  {effects, worst}; risk order NewAllow>LoosensCap>RemovesDeny>
  SchemaBump>RemovesAllow>TightensCap=NewDeny>Neutral; adding
  deny/tightening cap classified as safer/lower-risk)

Total this resume: 120 selfdef IPS-authority crates. Workspace 285.

### Fifty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-config-personalization-bounds` (per-(Profile, knob)
  Bound enum IntRange/EnumOf/BoolEither/StrLenAtMost; Value enum
  Int/Str/Bool; check Ok/OutOfBound{bound,observed}/UnknownKnob/
  UnknownProfile; type-mismatch counts as OutOfBound)

Total this resume: 121 selfdef IPS-authority crates. Workspace 286.

### Fifty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-bus-deadletter-policy` (EventTrack{attempts,
  dead_lettered}; record_attempt → Delivered (clears) / Retry
  {attempts} / DeadLetter{attempts} / AlreadyDead; revive
  resets; dead_letter_ids reports current DLQ set)

Total this resume: 122 selfdef IPS-authority crates. Workspace 287.

### Fifty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-prewarm-policy` (PrewarmStep{kind, budget_ms,
  optional}; canonical schedules per Profile: Private minimal,
  Production strict, Experimental lenient with embedding refresh;
  bootstrapper executes in order respecting budget + optional flag)

Total this resume: 123 selfdef IPS-authority crates. Workspace 288.

### Fifty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-llm-prompt-cache-policy` ((Profile, PromptKind) →
  Cache{ttl}/NoCache{reason: PolicyDeny/SecretLeakRisk/
  Unconfigured}; contains_secret forces NoCache{SecretLeakRisk};
  canonical Production caches System+ToolOutput+Pinned, never
  UserTurn; Experimental caches Scratch too)

Total this resume: 124 selfdef IPS-authority crates. Workspace 289.

### Fifty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-sunset-policy` (SunsetEntry{sunset_at_ms,
  warn_window_ms}; classify Active/Warning{remaining_ms}/Expired/
  Unknown; rotate(now) emits + removes the expired set for the
  audit log)

Total this resume: 125 selfdef IPS-authority crates. Workspace 290.

### Fifty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-network-egress-domain-allowlist` (per-Profile FQDN
  allowlist with exact / *.suffix wildcards / full *; case-
  insensitive; *.example.com matches nested NOT bare; canonical
  Production api.anthropic.com + *.huggingface.co; Experimental=*;
  Private/Careful=empty-set deny-all)

Total this resume: 126 selfdef IPS-authority crates. Workspace 291.

### Fifty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-mcp-handshake-version` (Triple{maj,min,pat} parsed from
  X.Y.Z; classify Compatible (in allowlist OR in [min,max]) /
  TooOld{min} / TooNew{max} / Unparseable; explicit allowlist
  overrides the range)

Total this resume: 127 selfdef IPS-authority crates. Workspace 292.

### Sixtieth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-shadow-mode` (Mode{Off/Shadow/Enforce} per
  policy_id; classify_apply returns Allow / Block / ShadowBlock
  (recorder logs but caller proceeds) / Unconfigured; safe-rollout
  lane for new/modified policies)

Total this resume: 128 selfdef IPS-authority crates. Workspace 293.

### Sixty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-rollout-stage` (Stage{Disabled/Canary{ppm}/Beta
  {ppm}/Stable}; deterministic actor_hash % 1_000_000 < ppm gives
  InScope; pairs with policy-shadow-mode for gradual enforcement)

Total this resume: 129 selfdef IPS-authority crates. Workspace 294.

### Sixty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-quarantine-release-policy` ((min_reviewers, min_age_ms,
  require_operator); classify Releasable / NeedsMoreReviewers
  {have, need} / TooFresh{age, need_min_age} / NeedsOperator;
  order reviewers→age→operator)

Total this resume: 130 selfdef IPS-authority crates. Workspace 295.

### Sixty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-scrutiny-amplifier` (Tier Normal<Elevated<High
  <Critical based on per-actor failures within window_ms; record
  monotonic; ok=true doesn't count; rotate evicts stale;
  downstream policies decide what to gate)

Total this resume: 131 selfdef IPS-authority crates. Workspace 296.

### Sixty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-event-emitter-rate-cap` (per-emitter events-per-min cap
  in 60s sliding window; record Accepted{remaining}/Throttled{cap,
  retry_after_ms}/UnknownEmitter; distinct from bus-priority-
  policy and rate-limit-policy)

Total this resume: 132 selfdef IPS-authority crates. Workspace 297.

### Sixty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-grace-period` (install(policy_id, ts, grace_ms);
  classify InGrace{installed_at, grace_ms, remaining_ms}/InEffect/
  Unknown; ramp window for strict policies)

Total this resume: 133 selfdef IPS-authority crates. Workspace 298.

### Sixty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-heartbeat-policy` (per-component liveness;
  register(component_id, deadline_ms)/beat(monotonic)/check
  Live{age}/Stale{age, deadline}/Unknown; stale_set(now);
  re-register preserves last_beat)

Total this resume: 134 selfdef IPS-authority crates. Workspace 299.

### Sixty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-block-attempt-counter` (per-(actor, action_kind) Stats
  {attempts, blocked, last_attempt_ts, last_block_reason};
  blocked_total per actor across kinds; dashboard-surfacing lane)

Total this resume: 135 selfdef IPS-authority crates. Workspace 300.

### Sixty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-metric-histogram` (operator-chosen strictly-increasing
  bucket upper bounds + +Inf overflow; observe(value) lands in
  lowest bucket whose upper ≥ value; quantile(q_x100) Prometheus-
  style; mean() from sum/total)

Total this resume: 136 selfdef IPS-authority crates. Workspace 301.

### Sixty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-collector-jitter-policy` (deterministic FNV-1a jitter
  in [-max/2, +max/2] from collector_id % max_jitter_ms; same id
  always lands in same slot, distinct collectors spread; prevents
  thundering-herd synchronisation)

Total this resume: 137 selfdef IPS-authority crates. Workspace 302.

### Seventieth wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-introduction-policy` (first-touch handshake gate;
  record_introduction(actor, ts, attested_fingerprint); classify
  Allowed (recorded) / NeedsIntroduction; revoke for operator-
  triggered reset; re-record overwrites prior)

Total this resume: 138 selfdef IPS-authority crates. Workspace 303.

### Seventy-first wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-version-pin` (per-actor Pin{bundle_id, version};
  pin/unpin/resolve Pinned/Unpinned; staged-rollout lane keeping
  pinned actors on prior bundle while the rest migrate)

Total this resume: 139 selfdef IPS-authority crates. Workspace 304.

### Seventy-second wave (same day, +1 more IPS-authority crate)

- `selfdef-action-trace-budget` (Counter{max_spans, used}; start/
  admit/finish; admit returns Accepted{used}/Exhausted{cap}/
  UnknownAction; absolute-cap lane distinct from probabilistic
  trace-sampling-policy)

Total this resume: 140 selfdef IPS-authority crates. Workspace 305.

### Seventy-third wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-attribute-pack` (per-actor key→value store;
  set/get/delete; match_all(actor, predicates) returns Matched/
  Mismatched{missing, wrong:Vec<{key,expected,actual}>}/UnknownActor;
  exact-string matching)

Total this resume: 141 selfdef IPS-authority crates. Workspace 306.

### Seventy-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-explain-pack` (ExplainPack{outcome,
  rules_fired, rules_skipped:Vec<(rule_id, skip_reason)>, ts};
  record/fetch/rotate(now, retention); pure store paired with
  policy-explanation-formatter for rendering)

Total this resume: 142 selfdef IPS-authority crates. Workspace 307.

### Seventy-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-storage-quota` (per-Profile ProfileCaps
  {soft_bytes, hard_bytes}; classify Healthy/OverSoft{soft, used}/
  OverHard{hard, used}/Unconfigured; canonical Experimental 64/
  128GiB, Production 8/16GiB; persistent-footprint lane distinct
  from substrate-disk-quota write-budget)

Total this resume: 143 selfdef IPS-authority crates. Workspace 308.

### Seventy-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-action-result-cache` (Entry{result, stored_at, ttl_ms};
  put/get/rotate; get returns Hit{result, age}/Stale{age, ttl}/
  Miss; deterministic-result lane distinct from action-idempotency-
  key replay-dedup)

Total this resume: 144 selfdef IPS-authority crates. Workspace 309.

### Seventy-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-namespace-precedence` (priority resolver per namespace;
  resolve(&[candidates]) highest priority wins, tiebreaker = lex
  asc; rule-priority lane paired with policy-namespace-policy
  hierarchical tree)

Total this resume: 145 selfdef IPS-authority crates. Workspace 310.

### Seventy-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-exclusive-lock-policy` (Lease{lease_id, owner,
  acquired_at, max_hold_ms}; acquire returns Acquired/Self
  Reacquired (refresh)/HeldByOther; expired others auto-takeover;
  release returns Released/WrongLease/UnknownLease)

Total this resume: 146 selfdef IPS-authority crates. Workspace 311.

### Seventy-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-version-event` (actor → policy_id → last_version;
  observe returns FirstSeen / UnchangedVersion / NewVersion{old,
  new}; NewVersion fires exactly once per (actor, policy, version);
  chrome surfaces 'policy updated' banner)

Total this resume: 147 selfdef IPS-authority crates. Workspace 312.

### Eightieth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-bundle-staging` (Candidate{version, content_hash,
  staged_at}; stage/promote (returns prev-active) /reject/
  list_staged/active_version; promotion lane for new bundles)

Total this resume: 148 selfdef IPS-authority crates. Workspace 313.

### Eighty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-mcp-tool-namespace-scope` (per-tool allowed-namespace
  BTreeSet + '*' wildcard; classify Allowed/Denied{allowed}/
  UnknownTool; revoke auto-prunes; distinct from tool-trust-tier
  — this is the caller-scope lane)

Total this resume: 149 selfdef IPS-authority crates. Workspace 314.

### Eighty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-group-membership` (forward group→actors + reverse
  actor→groups indices; add/remove/members_of/groups_of/is_member;
  both indices kept in lockstep; empty entries auto-prune)

Total this resume: 150 selfdef IPS-authority crates. Workspace 315.

### Eighty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-eval-bench-recorder` (EvalSample{scenario, would_outcome,
  actual_outcome, ts}; report aggregates AgreementReport{total,
  agreed, disagreed_pct_x100, disagreement_samples capped at 16};
  pure recorder, no enforcement)

Total this resume: 151 selfdef IPS-authority crates. Workspace 316.

### Eighty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-handoff-policy` (Handoff{granted_at, expires_at,
  revoked}; grant(from, to, scope, window) / revoke / classify
  Active{expires_at}/Expired/Revoked/Unknown; revoked records
  kept for audit)

Total this resume: 152 selfdef IPS-authority crates. Workspace 317.

### Eighty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-delta-feed` (Event{seq, policy_id, kind: Staged/
  Promoted/Rejected/Reverted/Sunsetted, version_after, ts};
  push assigns monotonic seq; since(cursor) returns (events,
  new_cursor); rotate drops past-retention)

Total this resume: 153 selfdef IPS-authority crates. Workspace 318.

### Eighty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-emitter-policy` (decision_kind → BTreeSet
  <Sink: Audit/Trace/Operator/Mirror/External>; set/add_sink/
  remove_sink/emitted_to; remove auto-prunes empty entries)

Total this resume: 154 selfdef IPS-authority crates. Workspace 319.

### Eighty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-burst-detector` (per (subject, kind) Vec<ts>; classify
  count-in-window vs (elevated_threshold, burst_threshold) →
  Calm/Elevated{count}/Burst{count, threshold}; rotate drops
  out-of-window)

Total this resume: 155 selfdef IPS-authority crates. Workspace 320.

### Eighty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-shape-checker` (PolicyShapeChecker{required_
  fields, max_field_len}; check returns Ok/Issues{missing_fields,
  oversized_fields}; pure structural validator, no semantic
  reasoning)

Total this resume: 156 selfdef IPS-authority crates. Workspace 321.

### Eighty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-retry-backoff-policy` (delay_for_attempt(n, base_ms,
  max_ms, seed) → base*2^(n-1) capped at max + FNV-1a-derived
  jitter from seed+n; deterministic per seed; pure math)

Total this resume: 157 selfdef IPS-authority crates. Workspace 322.

### Ninetieth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-tmpdir-policy` (ProfileCaps{max_bytes,
  max_age_ms}; classify Healthy/OverSize/OverAge/OverBoth/
  Unconfigured; canonical Experimental 4GiB/7d, Production
  512MiB/1d, Private 16MiB/1d)

Total this resume: 158 selfdef IPS-authority crates. Workspace 323.

### Ninety-first wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-graceful-drain` (begin_drain(now, ms) sets
  deadline; observe(in_flight, now) → NotDraining/DrainContinue
  {in_flight, remaining_ms}/DrainReadyToSwap{reason:Idle|TimedOut,
  leftover_count}; coordinated bundle-swap lane)

Total this resume: 159 selfdef IPS-authority crates. Workspace 324.

### Ninety-second wave (same day, +1 more IPS-authority crate)

- `selfdef-event-outbox-policy` (Event{seq, payload, ts};
  append monotonic seq; pending() / confirm(up_to_seq) prunes;
  durable transactional-outbox pattern for at-least-once
  delivery)

Total this resume: 160 selfdef IPS-authority crates. Workspace 325.

### Ninety-third wave (same day, +1 more IPS-authority crate)

- `selfdef-llm-stop-sequence-policy` (per-Profile Vec<String>
  stop sequences; should_stop returns earliest-position match
  with longest-at-position tiebreak; canonical seed: <|im_end|>
  / <|endoftext|> / triple-newline)

Total this resume: 161 selfdef IPS-authority crates. Workspace 326.

### Ninety-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-text-redactor` (literal-pattern redactor; longest-
  needle-first; replaces each occurrence with [REDACTED:<char_
  count>]; returns (redacted, count))

Total this resume: 162 selfdef IPS-authority crates. Workspace 327.

### Ninety-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-action-lifecycle` (Phases Requested→Approved→Executing
  →(Completed|Failed|Cancelled); per-phase ts recorded; bad-
  transition rejected; Cancel from any pre-terminal phase)

Total this resume: 163 selfdef IPS-authority crates. Workspace 328.

### Ninety-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-cgroup-binding` (Profile → cgroup name;
  classify Bound{cgroup_name}/Unconfigured; canonical
  selfdef/<profile-name>; substrate uses returned name to
  spawn into the right cgroup)

Total this resume: 164 selfdef IPS-authority crates. Workspace 329.

### Ninety-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-tenant-quota-pool` (Pool{capacity, in_use}; set_pool
  preserves in_use; request → Granted{remaining}/Exhausted/Unknown
  Tenant; release saturates; per-tenant pool lane distinct from
  per-grant ledger)

Total this resume: 165 selfdef IPS-authority crates. Workspace 330.

### Ninety-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-mutation-record` (Record{mutation_id, policy_id,
  proposed_by, witnessed_by[], applied_by, ts}; record/fetch/
  for_policy; immutable once written)

Total this resume: 166 selfdef IPS-authority crates. Workspace 331.

### Ninety-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-stall-detector` (per-subject last_ts; observe monotonic;
  check(now, stall_ms) returns Active{age}/Stalled{age, threshold}/
  Unknown; stalled_subjects(now, threshold) lists currently-stalled)

Total this resume: 167 selfdef IPS-authority crates. Workspace 332.

### One-hundredth wave (same day, +1 more IPS-authority crate)

- `selfdef-resource-reservation` (per-resource Pool{capacity, held};
  reserve(resource, units, ts) returns id or Insufficient err;
  commit marks committed (held stays); abandon releases held;
  expire(now, max_age_ms) drops stale uncommitted only;
  set_capacity preserves existing held)

Total this resume: 168 selfdef IPS-authority crates. Workspace 333.

### Hundred-and-first wave (same day, +1 more IPS-authority crate)

- `selfdef-action-deadline-tracker` (register(action, deadline_ms);
  check(now, warn_ms) returns OnTime/Expiring/Expired/Unknown;
  extend forward-only — BackwardExtend err if new<existing;
  complete drops tracking; expired(now) lists overdue)

Total this resume: 169 selfdef IPS-authority crates. Workspace 334.

### Hundred-and-second wave (same day, +1 more IPS-authority crate)

- `selfdef-substrate-syscall-allowlist` (per substrate
  SubstrateAllowlist{allowed:BTreeSet, allow_count, deny_count};
  decide pure returns Allowed/Denied{reason}/Unknown;
  observe_decision increments telemetry counters; register
  idempotent; allow/disallow manage the set)

Total this resume: 170 selfdef IPS-authority crates. Workspace 335.

### Hundred-and-third wave (same day, +1 more IPS-authority crate)

- `selfdef-path-allowlist-policy` (per-substrate SubstratePaths{
  grants:Vec<PrefixGrant{prefix, Mode{Read/WriteOnly/ReadWrite}}>};
  decide(path, mode) returns Allowed/DeniedMode{prefix, granted}/
  DeniedNoMatch/Unknown; first matching prefix wins; grant() upserts;
  RW satisfies all)

Total this resume: 171 selfdef IPS-authority crates. Workspace 336.

### Hundred-and-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-llm-model-fallback-policy` (Chain{models:Vec,
  health:BTreeMap<id,ModelHealth{fail_streak, cooldown_until,
  total_success/failure}>}; pick returns first non-cooldown model —
  Picked{model,rank}/AllInCooldown{next_available}/NoModels;
  record_failure places in cooldown; record_success clears)

Total this resume: 172 selfdef IPS-authority crates. Workspace 337.

### Hundred-and-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-recurring-task-scheduler` (RecurringTask{interval_ms,
  next_due_ms, enabled, runs}; due_at(now) returns enabled-and-due
  task ids ordered by next_due then id; mark_run advances next_due
  past now in interval steps — drift-resistant: skips missed ticks)

Total this resume: 173 selfdef IPS-authority crates. Workspace 338.

### Hundred-and-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-concurrent-action-limiter` (ActorState{limit, in_flight,
  admitted_total, rejected_total}; admit returns Admitted/Rejected{
  in_flight,limit}/Duplicate; release decrements (idempotent on
  unknown/already-released); actors independent; un-configured uses
  default_limit)

Total this resume: 174 selfdef IPS-authority crates. Workspace 339.

### Hundred-and-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-change-window` (Window{name, [open_ms, close_ms),
  scope:Vec<policy_id>, Severity{Soft/Hard}}; decide returns Permit/
  SoftBlock{window}/HardBlock{window} — Hard beats Soft; empty
  scope = global; range half-open: open inclusive, close exclusive;
  active_for lists all currently-applicable)

Total this resume: 175 selfdef IPS-authority crates. Workspace 340.

### Hundred-and-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-credential-rotation-policy` (Credential{created_ms,
  max_age_ms, grace_ms, rotations}; check(now) returns Fresh{
  remaining}/DueForRotation{overdue, grace_remaining}/Expired{
  overdue}/Unknown — three lifecycle phases; rotate resets
  created_ms; needs_attention lists due-or-expired)

Total this resume: 176 selfdef IPS-authority crates. Workspace 341.

### Hundred-and-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-bus-envelope-stamping` (Envelope{emitter, seq, topic,
  ts_ms, payload_hash} via FNV-1a 64; stamp emits monotonic
  per-emitter seq independent of other emitters; verify detects
  payload tampering by recomputing hash; recover_emitter_state
  advances next-seq past observed but rejects backward recovery)

Total this resume: 177 selfdef IPS-authority crates. Workspace 342.

### Hundred-and-tenth wave (same day, +1 more IPS-authority crate)

- `selfdef-slo-budget-tracker` (Slo{target_bp 1..=10000, successes,
  failures}; Budget{total, allowed_failures = total × (1-target),
  actual_failures, remaining, burn_ratio_bp, exhausted}; targets
  in basis points (9990 = 99.9%); exhausts when actual >= allowed)

Total this resume: 178 selfdef IPS-authority crates. Workspace 343.

### Hundred-and-eleventh wave (same day, +1 more IPS-authority crate)

- `selfdef-ingest-admission-gate` (Inbound{origin, kind, size_bytes};
  decide runs origin_allowlist → kind_denylist → size check in
  order, returns Admitted or first Rejected{reason:
  OriginNotAllowed/KindDenied/OverSize}; observe records counters)

Total this resume: 179 selfdef IPS-authority crates. Workspace 344.

### Hundred-and-twelfth wave (same day, +1 more IPS-authority crate)

- `selfdef-denial-appeal-window` (Denial{denied_at_ms, actor,
  appeal:Option<Appeal>}; window_ms gates submit_appeal; one appeal
  per denial; resolve_appeal Resolution{Granted/Sustained}; state
  returns NotFound/Pending{window_close}/WindowClosed/AppealPending/
  Granted/Sustained)

Total this resume: 180 selfdef IPS-authority crates. Workspace 345.

### Hundred-and-thirteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-action-dependency-graph` (nodes/parents/children
  adjacency; add_edge refuses self-loops + cycle-introducing edges
  (WouldCycle err, graph unchanged); topological_order via Kahn
  with alphabetical tie-break; remove_node cleans adjacency)

Total this resume: 181 selfdef IPS-authority crates. Workspace 346.

### Hundred-and-fourteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-role-binding` (Role{id, permissions:BTreeSet};
  define_role replaces; grant_to_role/revoke_from_role mutate
  existing role (cascades to all bound actors); bind/unbind manage
  actor↔role; effective_permissions returns union; has_permission
  O(log n × roles); roles_of lists)

Total this resume: 182 selfdef IPS-authority crates. Workspace 347.

### Hundred-and-fifteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-metric-quantile-sketch` (power-of-2 buckets: bucket i
  covers (2^(i-1), 2^i]; record(v) classifies zero/bucket/overflow;
  quantile(q) returns bucket upper bound at q-th observation —
  overshoot ≤ factor 2; suitable for latency P50/P99 viz)

Total this resume: 183 selfdef IPS-authority crates. Workspace 348.

### Hundred-and-sixteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-network-cidr-allowlist` (parse_ipv4 + parse_cidr
  canonicalize to Cidr{network, prefix_len}; add/remove canonical
  entries; decide returns Allowed{matched}/Denied first-match wins;
  strict input 0..=255 octets, prefix 0..=32; /0 matches all)

Total this resume: 184 selfdef IPS-authority crates. Workspace 349.

### Hundred-and-seventeenth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-traffic-ramp` (per-policy ramp_bp 0..=10000;
  decide deterministic via FNV-1a-64(policy:actor) mod 10000 <
  ramp_bp; properties: deterministic per actor, monotonic under
  ramp increase, distribution matches bp on large samples,
  different policies independent)

Total this resume: 185 selfdef IPS-authority crates. Workspace 350.

### Hundred-and-eighteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-cas-store` (Versioned{value, version};
  put_cas requires expected_version match — Wrote{new_version}
  or Conflict{observed, expected}; new keys need expected=0;
  force() bumps without CAS; delete then re-put starts fresh)

Total this resume: 186 selfdef IPS-authority crates. Workspace 351.

### Hundred-and-nineteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-token-bucket-rate-limit` (Bucket{capacity, refill_per_sec,
  tokens, last_refill_ms, remainder_ms, granted_total, throttled_total};
  integer math with remainder_ms for sub-second precision;
  try_acquire refills then attempts consumption, returns Granted/
  Throttled{available, requested}/Unknown; cap holds during long
  elapses; zero refill never recovers)

Total this resume: 187 selfdef IPS-authority crates. Workspace 352.

### Hundred-and-twentieth wave (same day, +1 more IPS-authority crate)

- `selfdef-evidence-merkle-chain` (Link{seq, payload_hash,
  prev_chain_hash, chain_hash, ts_ms} where chain_hash = FNV-1a-64
  over (seq:ts:payload_hash:prev_chain_hash); append chains
  automatically; verify_continuity detects SelfHashMismatch /
  ContinuityBreak / SeqBreak)

Total this resume: 188 selfdef IPS-authority crates. Workspace 353.

### Hundred-and-twenty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-load-shed-policy` (Priority{Bulk<Low<Normal<High<Critical};
  Thresholds default 5000/6500/8000/9000/10000 bp; decide returns
  Admit/Shed when load_ratio_bp >= threshold; observe records
  per-priority admitted/shed counters; custom thresholds allowed)

Total this resume: 189 selfdef IPS-authority crates. Workspace 354.

### Hundred-and-twenty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-state-checkpoint-store` (Checkpoint{id, ts_ms, label,
  payload_hash:FNV-1a-64, bytes}; add assigns monotonic id;
  latest by ts then id; restore by id; prune enforces max_count +
  max_age_ms but never below min_keep — safe-restore floor)

Total this resume: 190 selfdef IPS-authority crates. Workspace 355.

### Hundred-and-twenty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-operator-approval-queue` (Item{id, summary, submitted,
  deadline, Priority{Low<Normal<High<Urgent}, Status{Pending/
  Approved/Rejected/Expired}}; submit/approve/reject; mark_expired_at
  advances overdue; pending() ordered by priority desc then submit
  asc; double-resolve rejected)

Total this resume: 191 selfdef IPS-authority crates. Workspace 356.

### Hundred-and-twenty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-clock-skew-tolerance` (max_ahead_ms/max_behind_ms bound
  acceptance window; accept(event_ts, now) returns InWindow{skew}/
  TooFarFuture{skew, max_ahead}/TooFarPast{skew, max_behind};
  observe tracks rolling max +/- skew and accepted/rejected
  counters; signed i64 skew = event_ts - now)

Total this resume: 192 selfdef IPS-authority crates. Workspace 357.

### Hundred-and-twenty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-liveness-challenge` (Challenge{nonce, actor,
  issued_at_ms, expires_at_ms, consumed}; issue assigns monotonic
  nonce + ttl; verify returns Verified/Expired/AlreadyUsed/Unknown/
  WrongActor{expected_actor}; verified nonces consumed (replay
  detected); prune drops consumed entries older than
  history_retention_ms)

Total this resume: 193 selfdef IPS-authority crates. Workspace 358.

### Hundred-and-twenty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-leader-election` (Group{leader, epoch, lease_expires_ms};
  try_acquire returns Acquired{epoch++}/SelfRenew{epoch}/HeldByOther{
  leader, until}; epoch bumps only on takeover; heartbeat renews
  for current non-expired leader; step_down voluntary; current(now)
  reflects live lease only)

Total this resume: 194 selfdef IPS-authority crates. Workspace 359.

### Hundred-and-twenty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-task-preemption-policy` (Priority{Background<Low<Normal<
  High<Critical} with ranks; decide returns Preempt/Keep{reason}
  gated by min_priority_gap and anti-thrash min_run_ms window
  from current.started_at; both must pass)

Total this resume: 195 selfdef IPS-authority crates. Workspace 360.

### Hundred-and-twenty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-advisory-feed` (Advisory{id, severity, summary,
  published_at_ms, dismissed, dismissed_at_ms, dismissed_by};
  publish, dismiss idempotent (preserves first dismissal),
  active()/by_severity(min) filter undismissed newest-first,
  prune drops dismissed past max_age_ms)

Total this resume: 196 selfdef IPS-authority crates. Workspace 361.

### Hundred-and-twenty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-llm-cost-tracker` (Rates+Usage per model →
  TierTotals{input/output/cache_read/cache_write micros}; integer
  precision in micro-units; set_rates configures; record returns
  delta + accumulates; grand_total_micros sums across models;
  reset_totals keeps rates)

Total this resume: 197 selfdef IPS-authority crates. Workspace 362.

### Hundred-and-thirtieth wave (same day, +1 more IPS-authority crate)

- `selfdef-session-resume-policy` (soft_resume_window_ms /
  reauth_window_ms; decide(disconnected_at, now, cause) returns
  ResumeFreely / RequireReauth / RequireNewSession;
  OperatorLogout always RequireNewSession regardless of windows)

Total this resume: 198 selfdef IPS-authority crates. Workspace 363.

### Hundred-and-thirty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-delivery-ack-tracker` (MessageEntry{Status{Pending/
  Delivered/DeadLetter}, retries_left, retry_count, last_nack_reason};
  enqueue/ack/nack; nack decrements retries until 0 then transitions
  DeadLettered on next nack; pending_count helper)

Total this resume: 199 selfdef IPS-authority crates. Workspace 364.

### Hundred-and-thirty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-causation-chain` (Decision{id, summary, ts_ms,
  caused_by:BTreeSet}; record validates causes exist; add_cause
  refuses cycles (WouldCycle if cause already downstream);
  ancestors/descendants walk with depth bound; branch-and-merge
  supported (true DAG))

Total this resume: 200 selfdef IPS-authority crates. Workspace 365.

### Hundred-and-thirty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-tenant-shard-router` (route(tenant) = shards[FNV-1a-64(
  tenant) % N]; pinned tenants override hash; set_shards updates
  shard list — invalid pins unpinned and counted; distribution
  test confirms even spread across shards)

Total this resume: 201 selfdef IPS-authority crates. Workspace 366.

### Hundred-and-thirty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-alert-escalation-policy` (Stage{Notify→Page→Wake→
  Resolved}; per-alert last_stage_ts drives elapsed; tick(now)
  advances stages past waits.notify_to_page_ms / page_to_wake_ms
  and returns changed (id, new_stage) pairs; Wake terminal; ack
  → Resolved)

Total this resume: 202 selfdef IPS-authority crates. Workspace 367.

### Hundred-and-thirty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-incident-record` (Stage{Open→Triaged→Mitigated→Resolved→
  PostmortemPending} strict forward transitions; reopen Resolved/
  PostmortemPending → Triaged (clears resolved_at); file_postmortem
  only in PostmortemPending; stage_log preserves history; ttr_ms
  reports time-to-resolve)

Total this resume: 203 selfdef IPS-authority crates. Workspace 368.

### Hundred-and-thirty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-fair-share-scheduler` (TenantState{weight≥1,
  cumulative_service, picks}; pick_next minimizes cumulative*1000/
  weight (alpha tie-break); charge adds units*1000/weight; higher-
  weight tenants win more picks per epoch; reset_service zeros
  cumulative across all)

Total this resume: 204 selfdef IPS-authority crates. Workspace 369.

### Hundred-and-thirty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-kill-switch-registry` (Switch{id, description, tripped,
  trip_reason, tripped_at_ms, tripped_by, dual_control, trip_count};
  register Armed; trip needs reason+actor; rearm with dual_control
  requires actor ≠ tripper (two-person rule); is_operational gates
  dependent code; tripped_ids lists current)

Total this resume: 205 selfdef IPS-authority crates. Workspace 370.

### Hundred-and-thirty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-action-denylist` (global denies map action→reason; per-
  actor denies isolated; decide(action, actor) returns Allow/Deny{
  reason, scope:Global|Actor}; global precedence over actor-
  specific; allow_global / allow_for_actor remove entries)

Total this resume: 206 selfdef IPS-authority crates. Workspace 371.

### Hundred-and-thirty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-data-exfil-detector` (Pattern{id, name, needle,
  severity, total_hits}; scan counts substring matches and returns
  Hits sorted Critical→Info then alpha; observe = scan + record
  counts + bytes_scanned; worst_hit filters by min severity)

Total this resume: 207 selfdef IPS-authority crates. Workspace 372.

### Hundred-and-fortieth wave (same day, +1 more IPS-authority crate)

- `selfdef-blue-green-deploy` (Slot{Blue/Green} active/standby;
  stage writes to inactive (StageToActive err otherwise);
  mark_warm flips readiness; swap flips active iff inactive has
  version + warm; rollback = another swap; new stage resets warm)

Total this resume: 208 selfdef IPS-authority crates. Workspace 373.

### Hundred-and-forty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-service-health-probe` (Health{Healthy/Degraded/Down};
  record updates consec counters and transitions: Healthy→
  Degraded on first fail; Degraded→Down after fail_to_down consec;
  Down→Degraded on first pass; Degraded→Healthy after
  pass_to_healthy consec; hysteresis prevents thrash)

Total this resume: 209 selfdef IPS-authority crates. Workspace 374.

### Hundred-and-forty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-action-outcome-ledger` (Outcome{Success/SoftFailure/
  HardFailure/Skipped/Cancelled}; ClassCounters + total +
  success_rate_bp; record appends to bounded ring (drops oldest +
  counts) and bumps per-class counters (preserved across drops);
  recent_newest_first)

Total this resume: 210 selfdef IPS-authority crates. Workspace 375.

### Hundred-and-forty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-actor-label-policy` (per-actor BTreeMap<key,value>;
  set_user_label refuses RESERVED_PREFIX "selfdef." (ReservedKey
  err); set_system_label accepts any key; remove_user_label vs
  remove_system_label parallels; empty value allowed for tag-only
  labels)

Total this resume: 211 selfdef IPS-authority crates. Workspace 376.

### Hundred-and-forty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-periodic-report-emitter` (Report{cadence_ms,
  last_emitted_ms, emissions, active}; should_emit checks active
  AND elapsed since last_emitted >= cadence; mark_emitted snaps
  last_emitted=now (skew-resistant); set_active pauses; due_at
  lists eligible)

Total this resume: 212 selfdef IPS-authority crates. Workspace 377.

### Hundred-and-forty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-lru-cache` (Entry{value, tick}; get touches recency
  (next_tick++); peek does not; put evicts lowest-tick on capacity
  overflow + counts evictions; update of existing key touches
  without evicting; hits/misses telemetry)

Total this resume: 213 selfdef IPS-authority crates. Workspace 378.

### Hundred-and-forty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-topic-pubsub-router` (per-subscriber pattern set;
  exact match or '*'-suffix prefix match; match_topic returns
  subscriber ids matching topic sorted; subscribe/unsubscribe/
  drop_subscriber idempotent)

Total this resume: 214 selfdef IPS-authority crates. Workspace 379.

### Hundred-and-forty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-trace-baggage` (per-trace key/value baggage bounded by
  max_entries + max_total_bytes; set rejects OverCount (new key
  past cap) / OverSize (proposed total > max); replace doesn't
  grow count; remove auto-tidies empty traces)

Total this resume: 215 selfdef IPS-authority crates. Workspace 380.

### Hundred-and-forty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-dry-run` (Mode{Enforce/DryRun} per policy
  (default DryRun); observe records would-allow vs would-deny +
  reason counts; top_reasons top-K by count; deny requires non-
  empty reason)

Total this resume: 216 selfdef IPS-authority crates. Workspace 381.

### Hundred-and-forty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-usage-receipt` (Receipt{id, actor, resource, ts_ms,
  input_bytes, output_bytes, tokens, duration_ms}; record bumps
  per-actor + per-resource Totals aggregates; totals_by_actor/
  totals_by_resource queries)

Total this resume: 217 selfdef IPS-authority crates. Workspace 382.

### Hundred-and-fiftieth wave (same day, +1 more IPS-authority crate)

- `selfdef-schema-migrator` (Step{from, to=from+1, label,
  reversible}; consecutive registration enforced; plan(from, to)
  returns forward labels OR backward with "rollback:" prefix;
  non-reversible blocks backward; missing step → Missing(version))

Total this resume: 218 selfdef IPS-authority crates. Workspace 383.

### Hundred-and-fifty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-periodic-quota-budget` (ActorBudget{cap_per_period,
  consumed, current_period_start_ms}; charge auto-rolls forward
  whole periods (snap not catch-up); returns Accepted/Exceeded{
  available, requested}; remaining reports headroom)

Total this resume: 219 selfdef IPS-authority crates. Workspace 384.

### Hundred-and-fifty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-prompt-size-cap` (ActorCaps{warn_bytes, hard_bytes};
  evaluate returns Allow/Warn{headroom_bytes}/Reject{over_bytes}/
  Unknown; set_caps requires warn < hard)

Total this resume: 220 selfdef IPS-authority crates. Workspace 385.

### Hundred-and-fifty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-geo-region-policy` (ActorRegions{Mode{AllowList/
  DenyList}, regions:BTreeSet}; decide honors actor config or
  falls back to default_mode + default_regions; AllowList in→Allow
  out→Deny; DenyList in→Deny out→Allow)

Total this resume: 221 selfdef IPS-authority crates. Workspace 386.

### Hundred-and-fifty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-text-anonymizer` (Pattern{id, needle, placeholder, hits};
  anonymize pure (returns rewritten + hits_per_pattern); observe
  records hits in state; substring matching only; total_hits sums)

Total this resume: 222 selfdef IPS-authority crates. Workspace 387.

### Hundred-and-fifty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-sliding-window-counter` (bucket_ms × bucket_count =
  window_ms; record adds to most-recent bucket; rotate drops
  oldest when time advances; long-idle clears entire window;
  total sums after rotation)

Total this resume: 223 selfdef IPS-authority crates. Workspace 388.

### Hundred-and-fifty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-subscription-registry` (Subscription{id, subscriber,
  topic, created_at, expires_at}; subscribe with ttl; renew
  extends; prune drops expired; active_count + by_topic filter
  by current time)

Total this resume: 224 selfdef IPS-authority crates. Workspace 389.

### Hundred-and-fifty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-fallback-chain` (Provider{id, healthy, failures};
  append ordered; pick returns first healthy; mark_unhealthy/
  mark_healthy flip; failures bumped per unhealthy mark)

Total this resume: 225 selfdef IPS-authority crates. Workspace 390.

### Hundred-and-fifty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-correlation-id-issuer` (Node{id, parent, created_at_ms};
  issue(parent) validates parent exists; lineage walks root→id;
  IDs monotonic u64)

Total this resume: 226 selfdef IPS-authority crates. Workspace 391.

### Hundred-and-fifty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-capability-token-store` (Token{id, holder, scopes:
  BTreeSet, expires_at_ms, revoked}; check returns Ok/Expired/
  Revoked/Unknown/MissingScope; revoke marks token)

Total this resume: 227 selfdef IPS-authority crates. Workspace 392.

### Hundred-and-sixtieth wave (same day, +1 more IPS-authority crate)

- `selfdef-bloom-filter` (two FNV-1a-64 hashes with different seeds;
  insert sets 2 bits; contains AND-checks; load_bp approximates
  load factor; clear zeros; no false negatives)

Total this resume: 228 selfdef IPS-authority crates. Workspace 393.

### Hundred-and-sixty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-counter-by-key` (inc/inc_by accumulate; top_k by count
  desc with alpha tie-break; grand_total sums; clear resets)

Total this resume: 229 selfdef IPS-authority crates. Workspace 394.

### Hundred-and-sixty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-spec-validator` (Spec{name, required:BTreeSet,
  forbidden:BTreeSet}; check(name, present) returns Issue list of
  MissingRequired or ForbiddenPresent per field)

Total this resume: 230 selfdef IPS-authority crates. Workspace 395.

### Hundred-and-sixty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-content-hash-cache` (Entry{hash:FNV-1a-64, first_seen,
  last_seen, seen_count}; observe returns New{hash}/Existing{hash,
  seen_count} + bumps last_seen; prune drops stale by last_seen)

Total this resume: 231 selfdef IPS-authority crates. Workspace 396.

### Hundred-and-sixty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-secret-binding-store` (per-actor name→ref_path bindings;
  no raw secrets stored — ref_path points to vault; bind/unbind/
  resolve/names_of; rebind replaces)

Total this resume: 232 selfdef IPS-authority crates. Workspace 397.

### Hundred-and-sixty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-graceful-shutdown` (Stage{Running→StopAccepting→
  Draining→Terminated}; begin → next; tick(now) auto-advances past
  per-stage timeouts; force_drain/force_terminate manual)

Total this resume: 233 selfdef IPS-authority crates. Workspace 398.

### Hundred-and-sixty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-leaky-bucket-shaper` (capacity + drain_per_sec; offer
  drains first then accepts if fits; rejects with overflow units;
  remainder_ms preserves sub-second precision)

Total this resume: 234 selfdef IPS-authority crates. Workspace 399.

### Hundred-and-sixty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-test-harness` (Case{id, input, expected_outcome,
  observed_outcome}; record_observed sets observation; summary
  returns Summary{total, passed, failed, unrun, mismatches})

Total this resume: 235 selfdef IPS-authority crates. Workspace 400.

### Hundred-and-sixty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-tiered-retention-policy` (Tier{Hot/Warm/Cold/Expired};
  classify(age_ms) by hot/warm/cold thresholds; bounds require
  hot ≤ warm ≤ cold)

Total this resume: 236 selfdef IPS-authority crates. Workspace 401.

### Hundred-and-sixty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-keyed-rate-limit` (per-key token buckets; auto-create
  with default cap/refill; set_override / forget manage; keys
  independent)

Total this resume: 237 selfdef IPS-authority crates. Workspace 402.

### Hundred-and-seventieth wave (same day, +1 more IPS-authority crate)

- `selfdef-data-freshness-tracker` (Freshness{Fresh/Stale/Expired/
  Unknown}; check(now) bands by age vs fresh_ms/stale_ms;
  update/forget)

Total this resume: 238 selfdef IPS-authority crates. Workspace 403.

### Hundred-and-seventy-first wave (same day, +1 more IPS-authority crate)

- `selfdef-sync-barrier` (N-party barrier; status{Waiting/Tripped/
  TimedOut}; arrive returns status; trip when arrived==expected;
  late arrivals after deadline → TimedOut)

Total this resume: 239 selfdef IPS-authority crates. Workspace 404.

### Hundred-and-seventy-second wave (same day, +1 more IPS-authority crate)

- `selfdef-handler-registry` (Handler{id, priority, enabled} per
  kind, sorted by priority desc; resolve returns first-enabled;
  set_enabled toggles; unregister auto-tidies empty kind)

Total this resume: 240 selfdef IPS-authority crates. Workspace 405.

### Hundred-and-seventy-third wave (same day, +1 more IPS-authority crate)

- `selfdef-decision-memo-table` (keyed by policy_version +
  input_hash; store/lookup with hit/miss counters;
  invalidate_version drops entries for a version)

Total this resume: 241 selfdef IPS-authority crates. Workspace 406.

### Hundred-and-seventy-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-exponential-backoff` (base_ms × (multiplier_bp/10000)^
  attempt capped at max_ms; deterministic jitter via FNV-1a-64
  per (attempt, seed))

Total this resume: 242 selfdef IPS-authority crates. Workspace 407.

### Hundred-and-seventy-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-vote-tally` (weighted approve/reject/abstain; cast
  replaces prior; decisive-early via worst-case + best-case
  approve_bp bounds vs threshold; otherwise Pending)

Total this resume: 243 selfdef IPS-authority crates. Workspace 408.

### Hundred-and-seventy-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-consistent-hash-ring` (FNV-1a-64 vnode hashing with
  decimal-encoded indices; assign returns first node clockwise;
  assign_replicas yields N distinct nodes; removal reassigns only
  removed-node keys)

Total this resume: 244 selfdef IPS-authority crates. Workspace 409.

### Hundred-and-seventy-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-hysteresis-band` (State{Low/High} with two thresholds;
  Low→High when sample>=upper; High→Low when sample<=lower;
  in-band samples leave state unchanged; transitions counter)

Total this resume: 245 selfdef IPS-authority crates. Workspace 410.

### Hundred-and-seventy-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-monotonic-counter` (advance-only u64; observe rejects
  regression+equality; observe_eq idempotent on equality; bump
  returns last+1 with overflow check; regressions counted)

Total this resume: 246 selfdef IPS-authority crates. Workspace 411.


### Hundred-and-seventy-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-exponential-moving-average` (alpha_bp 1..=10000; first
  sample seeds; subsequent samples blend ema=(alpha*sample+
  (10000-alpha)*ema)/10000; state carried as i128 scaled 10000)

Total this resume: 247 selfdef IPS-authority crates. Workspace 412.

### Hundred-and-eightieth wave (same day, +1 more IPS-authority crate)

- `selfdef-bounded-priority-queue` (Item{id, priority, seq}; push
  at capacity evicts lowest-priority (older-seq tie-break) if
  incoming>min, else drops incoming; pop returns highest priority
  (earlier-seq tie-break for FIFO))

Total this resume: 248 selfdef IPS-authority crates. Workspace 413.

### Hundred-and-eighty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-weighted-round-robin` (smooth WRR per Nginx: increment
  every lane's current_weight by configured weight; pick lane
  with max current_weight, ties by earliest registration;
  decrement winner by total_weight)

Total this resume: 249 selfdef IPS-authority crates. Workspace 414.

### Hundred-and-eighty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-interval-set` (sorted disjoint closed [lo,hi] intervals;
  insert merges overlap+adjacent (hi+1==lo); contains uses
  binary search; cover() sums widths as u128; bridging insert
  collapses multiple intervals)

Total this resume: 250 selfdef IPS-authority crates. Workspace 415.

### Hundred-and-eighty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-reservoir-sampler` (Algorithm-R sample of K from N;
  first k items fill reservoir, subsequent items replace random
  slot with probability k/i; deterministic xorshift64* PRNG)

Total this resume: 251 selfdef IPS-authority crates. Workspace 416.

### Hundred-and-eighty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-seat-pool` (fixed capacity reservation pool; acquire
  errors AtCapacity / DuplicateHolder; release frees by id;
  expire sweeps holders whose acquired_ms is older than
  now-ttl_ms; used/available counts)

Total this resume: 252 selfdef IPS-authority crates. Workspace 417.

### Hundred-and-eighty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-tag-set` (sorted unique non-empty string tags;
  add (returns inserted bool), remove, contains, intersection,
  union, difference, is_subset_of, is_disjoint_from; pure data)

Total this resume: 253 selfdef IPS-authority crates. Workspace 418.

### Hundred-and-eighty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-glob-matcher` (shell-style glob: * (no /), ? (no /),
  [abc]/[^abc] classes, \x escape; iterative backtracking on *;
  unterminated classes rejected at construction)

Total this resume: 254 selfdef IPS-authority crates. Workspace 419.

### Hundred-and-eighty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-rolling-checksum` (Adler-32; push: a=(a+byte) mod
  65521, b=(b+a) mod 65521, digest=b<<16|a; roll(out,in,L)
  O(1) update: a'=(a-out+in), b'=(b-L*out+a'-1); matches
  known Adler-32("Wikipedia"))

Total this resume: 255 selfdef IPS-authority crates. Workspace 420.

### Hundred-and-eighty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-prefix-trie` (Node{tag, BTreeMap<char,Node>}; insert
  rejects duplicates; lookup walks char-by-char returning the
  deepest tag along the path (longest-prefix); lookup_exact
  requires terminal; empty prefix tags the root)

Total this resume: 256 selfdef IPS-authority crates. Workspace 421.

### Hundred-and-eighty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-countdown-latch` (open-once latch on N arrivals;
  arrive(by, now) decrements remaining; first hit of 0 sets
  opened_at_ms + flips to Open permanently; post-Open arrivals
  counted as excess)

Total this resume: 257 selfdef IPS-authority crates. Workspace 422.

### Hundred-and-ninetieth wave (same day, +1 more IPS-authority crate)

- `selfdef-two-phase-commit` (Phase{Init/Preparing/Prepared/
  Committed/Aborting/Aborted}; register adds participants in
  Init; vote(id, Yes/No) recomputes phase; decide finalizes
  Prepared→Committed or Aborting→Aborted; vote-revision allowed
  pre-decide)

Total this resume: 258 selfdef IPS-authority crates. Workspace 423.

### Hundred-and-ninety-first wave (same day, +1 more IPS-authority crate)

- `selfdef-cidr-matcher` (IPv4 dotted-quad → u32 parse;
  parse_cidr "A.B.C.D/p" masks host bits; matches(ip) tests
  (ip&mask)==(network&mask); prefix 0 matches all, 32 matches
  exact)

Total this resume: 259 selfdef IPS-authority crates. Workspace 424.

### Hundred-and-ninety-second wave (same day, +1 more IPS-authority crate)

- `selfdef-key-set-diff` (Diff{added, removed, common} disjoint
  partitions of prev ∪ next; compute uses BTreeSet ops;
  is_change_free true iff added/removed empty; state stores
  last computed diff + computes counter)

Total this resume: 260 selfdef IPS-authority crates. Workspace 425.

### Hundred-and-ninety-third wave (same day, +1 more IPS-authority crate)

- `selfdef-id-generator` (ULID-like 128-bit: top 48 = ms ts,
  bottom 80 = per-tick sequence resetting each new ms;
  Crockford base32 → 26-char string; clock regression +
  sequence overflow rejected; pure deterministic)

Total this resume: 261 selfdef IPS-authority crates. Workspace 426.

### Hundred-and-ninety-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-fault-injector` (per-tag rate_bp 0..=10000;
  decide(tag, attempt_id) FNV-1a-64-hashes (tag, attempt_id,
  seed) mod 10000 and returns Inject iff < rate_bp; injects/
  skips counters; pure deterministic)

Total this resume: 262 selfdef IPS-authority crates. Workspace 427.

### Hundred-and-ninety-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-burn-rate-alert` (fast+slow windows of total/bad;
  burn_tenths = observed_bad_bp*10 / slo_bad_rate_bp;
  Severity{None/Slow/Fast/Both} compares each window burn to
  its factor; Google-SRE multi-window pattern)

Total this resume: 263 selfdef IPS-authority crates. Workspace 428.

### Hundred-and-ninety-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-delay-queue` (Entry{id, fire_at_ms, payload};
  schedule binary-inserts to keep sorted; cancel by id;
  poll(now) drains entries with fire_at<=now; next_fire
  returns earliest; duplicate ids rejected)

Total this resume: 264 selfdef IPS-authority crates. Workspace 429.

### Hundred-and-ninety-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-ttl-table` (key→value with per-entry expires_at_ms;
  insert sets now+ttl; get lazy-expires entries with
  expires_at<=now; touch refreshes; sweep eagerly removes;
  inserts/hits/misses/expired counters)

Total this resume: 265 selfdef IPS-authority crates. Workspace 430.

### Hundred-and-ninety-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-tier-ladder` (ordered tier names; promote/demote ±1
  with AtBoundary at endpoints; each transition appended to
  bounded history (oldest evicted at cap); non-empty reason
  required)

Total this resume: 266 selfdef IPS-authority crates. Workspace 431.

### Hundred-and-ninety-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-topo-sort` (add_node + add_edge over string-keyed
  DAG; sort() Kahn's algorithm with BTreeSet ties for
  deterministic ordering; CycleDetected when fewer nodes
  emitted; self-edges + unknown endpoints rejected)

Total this resume: 267 selfdef IPS-authority crates. Workspace 432.

### Two-hundredth wave (same day, +1 more IPS-authority crate)

- `selfdef-rule-list-applier` (Rule{id, Effect{Allow/Deny},
  Match::Exact|Prefix(value), matches}; evaluate walks rules in
  insertion order, first match wins; no-match returns
  default_effect with defaults_applied counter)

Total this resume: 268 selfdef IPS-authority crates. Workspace 433.

### Two-hundred-and-first wave (same day, +1 more IPS-authority crate)

- `selfdef-inflight-set` (InflightEntry{issued_ms, deadline_ms};
  issue tracks (rejects dup/empty/zero ttl); ack removes;
  sweep_timeouts removes past-deadline entries returning ids;
  issued/acked/timed_out counters)

Total this resume: 269 selfdef IPS-authority crates. Workspace 434.

### Two-hundred-and-second wave (same day, +1 more IPS-authority crate)

- `selfdef-permit-semaphore` (counting permit pool; try_acquire
  succeeds when n<=available, tracks high_water; rejected on
  Exhausted; release saturating-decrements held; pure data,
  no async)

Total this resume: 270 selfdef IPS-authority crates. Workspace 435.

### Two-hundred-and-third wave (same day, +1 more IPS-authority crate)

- `selfdef-ring-buffer` (fixed-capacity u64 ring; push appends
  until full, then overwrites oldest with head advance;
  samples() chronological; mean/min/max/last aggregates;
  pushes counter)

Total this resume: 271 selfdef IPS-authority crates. Workspace 436.

### Two-hundred-and-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-readiness-gate` (Component{required, ready};
  aggregate(): Unready if any required unready or no required;
  Degraded if all required ready + some optional unready;
  Healthy if all ready)

Total this resume: 272 selfdef IPS-authority crates. Workspace 437.

### Two-hundred-and-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-line-diff` (Op{Keep/Add/Del}; LCS-based diff using
  O(N*M) DP table + backtrack; turns a → b with deterministic
  ordered ops; identical inputs all-Keep)

Total this resume: 273 selfdef IPS-authority crates. Workspace 438.

### Two-hundred-and-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-stream-cursor` (advance_high_water monotonic + per-
  consumer commit (rollback rejected); reset allows any
  direction; lag = high_water - committed saturating)

Total this resume: 274 selfdef IPS-authority crates. Workspace 439.

### Two-hundred-and-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-flag-set` (named 64-bit flag set; register assigns
  lowest free bit (idempotent), Full at 64; set/clear/contains
  by name; union/intersect/subtract combine masks; active_names
  bit-order)

Total this resume: 275 selfdef IPS-authority crates. Workspace 440.

### Two-hundred-and-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-event-log` (append-only with monotonic seq;
  capacity-bounded dropping oldest; since(cursor) returns
  entries with seq>cursor; earliest_seq/latest_seq accessors)

Total this resume: 276 selfdef IPS-authority crates. Workspace 441.

### Two-hundred-and-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-span-tree` (Span{id, parent, name, start_ms, end_ms};
  insert rejects dup/unknown-parent/bad-times; root() asserts
  single root else MultipleRoots; children/descendants
  traversal; total_duration_ms)

Total this resume: 277 selfdef IPS-authority crates. Workspace 442.

### Two-hundred-and-tenth wave (same day, +1 more IPS-authority crate)

- `selfdef-saturation-meter` (utilization_bp = held*10000/cap;
  classify() Low/Medium/High/Saturated by strictly-increasing
  thresholds; may exceed 10000 → Saturated)

Total this resume: 278 selfdef IPS-authority crates. Workspace 443.

### Two-hundred-and-eleventh wave (same day, +1 more IPS-authority crate)

- `selfdef-semver` (Version{u32 major, minor, patch}; parse
  "M.N.P" tuple-ordered; is_compatible_with(other) iff same
  major and (other.minor>self.minor or (==minor &&
  other.patch>=self.patch)))

Total this resume: 279 selfdef IPS-authority crates. Workspace 444.

### Two-hundred-and-twelfth wave (same day, +1 more IPS-authority crate)

- `selfdef-kv-store` (Entry{value: Option<String>, generation};
  set increments per-key gen; cas requires matching expected
  gen else GenerationMismatch; delete tombstones with gen bump;
  live_count counts non-tombstoned)

Total this resume: 280 selfdef IPS-authority crates. Workspace 445.

### Two-hundred-and-thirteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-token-estimator` (estimate(text, divisor) = ceil(
  char_count/divisor) — Unicode chars not bytes; accumulate
  bumps total + observations; is_over_budget(limit) compares
  to total; reset clears)

Total this resume: 281 selfdef IPS-authority crates. Workspace 446.

### Two-hundred-and-fourteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-state-machine` (named-states FSM with (from, event)
  →to table; add_transition rejects dups; fire emits
  UndefinedTransition on miss (state unchanged); bounded
  history of {from, event, to, ts})

Total this resume: 282 selfdef IPS-authority crates. Workspace 447.

### Two-hundred-and-fifteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-layered-config` (ordered layers low→high; push_layer
  appends top; set(layer, k, v) writes; lookup walks high→low
  returning (value, source); pop_layer drops top; dup layer
  names rejected)

Total this resume: 283 selfdef IPS-authority crates. Workspace 448.

### Two-hundred-and-sixteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-log-histogram` (64 buckets indexed by floor(log2(
  value+1)); observe bumps; quantile(p_bp) walks buckets to
  cumulative >= target returning bucket lower bound)

Total this resume: 284 selfdef IPS-authority crates. Workspace 449.

### Two-hundred-and-seventeenth wave (same day, +1 more IPS-authority crate)

- `selfdef-named-lock` (Hold{owner, expires_at_ms}; acquire
  grants if free / expired / same owner; release requires
  matching owner; held(now) returns owner if valid; expire
  sweeps stale)

Total this resume: 285 selfdef IPS-authority crates. Workspace 450.

### Two-hundred-and-eighteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-patch-set` (Op{Set/Remove/Test}; apply pre-validates
  Test ops against current state, aborts all-or-none on
  mismatch; otherwise applies Set/Remove in order; empty
  keys/values rejected)

Total this resume: 286 selfdef IPS-authority crates. Workspace 451.

### Two-hundred-and-nineteenth wave (same day, +1 more IPS-authority crate)

- `selfdef-url-parts` (parse scheme://host[:port]/path[?query]
  → UrlParts; validates scheme+host non-empty, port 1..=65535;
  to_string reassembles; raw fields (no encoding))

Total this resume: 287 selfdef IPS-authority crates. Workspace 452.

### Two-hundred-and-twentieth wave (same day, +1 more IPS-authority crate)

- `selfdef-gc-sweeper` (Item{ts_ms, size}; sweep(now) phases:
  1) age — remove items with ts_ms < now-max_age_ms;
  2) size — evict oldest until total<=size_cap_bytes; returns
  removed ids; max_age=0 or cap=0 disable respective phase)

Total this resume: 288 selfdef IPS-authority crates. Workspace 453.

### Two-hundred-and-twenty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-string-fingerprint` (FNV-1a-64 → 16-hex-char stable
  fingerprint; short(s, len) returns leading len chars
  (1..=16); matches known FNV-1a values; pure deterministic)

Total this resume: 289 selfdef IPS-authority crates. Workspace 454.

### Two-hundred-and-twenty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-monotonic-clock` (Strict::Yes rejects equal,
  Strict::No allows; regressions counted with state
  unchanged; since_last saturating; pure data)

Total this resume: 290 selfdef IPS-authority crates. Workspace 455.

### Two-hundred-and-twenty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-vector-clock` (per-node counter map; tick increments;
  merge takes per-node max; compare returns Some(Equal/Less/
  Greater) or None when concurrent)

Total this resume: 291 selfdef IPS-authority crates. Workspace 456.

### Two-hundred-and-twenty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-frequency-map` (bounded key→count; observe
  increments or inserts; eviction picks lowest-count
  (lexicographic tie) on overflow; top_n returns count desc
  + key asc)

Total this resume: 292 selfdef IPS-authority crates. Workspace 457.

### Two-hundred-and-twenty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-invariant-set` (Invariant{holds, violations,
  last_ts}; register inits holds=true; report updates state +
  bumps violations on holds=false (historical, not reset);
  failing/all_holding accessors)

Total this resume: 293 selfdef IPS-authority crates. Workspace 458.

### Two-hundred-and-twenty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-case-convert` (tokenize splits by separators and
  capital→lower transitions, lowercases all; to_snake/kebab/
  camel/pascal regenerate; ASCII; non-ASCII passes through)

Total this resume: 294 selfdef IPS-authority crates. Workspace 459.

### Two-hundred-and-twenty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-step-curve` (Step{x, y} strictly increasing x;
  lookup(x) returns y of rightmost step.x<=x via binary
  search; default_y when x<first step or empty)

Total this resume: 295 selfdef IPS-authority crates. Workspace 460.

### Two-hundred-and-twenty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-cancel-set` (CancelRecord{ts_ms, reason}; cancel
  records flag; AlreadyCancelled rejects re-cancel (one-way);
  is_cancelled/reason/ids accessors)

Total this resume: 296 selfdef IPS-authority crates. Workspace 461.

### Two-hundred-and-twenty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-route-table` (exact + longest-prefix routing;
  add_exact/add_prefix register handlers; resolve checks
  exact first then longest matching prefix; returns
  Resolution{handler_id, kind, matched_len})

Total this resume: 297 selfdef IPS-authority crates. Workspace 462.

### Two-hundred-and-thirtieth wave (same day, +1 more IPS-authority crate)

- `selfdef-dependency-resolver` (add(id, deps); resolve(target)
  collects reachable ancestors and runs Kahn; Missing on
  unknown dep; Cycle when fewer nodes emitted; deps may
  forward-reference (checked at resolve))

Total this resume: 298 selfdef IPS-authority crates. Workspace 463.

### Two-hundred-and-thirty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-retry-budget` (per-key KeyState{used, window_start_ms};
  try_consume resets when window elapsed, bumps used iff
  used<budget else Exhausted; exhausted lists in-window
  saturated keys)

Total this resume: 299 selfdef IPS-authority crates. Workspace 464.

### Two-hundred-and-thirty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-three-way-merge` (base/ours/theirs map merge; for
  each key in union: unchanged→base; one-side change→that side;
  same change both→that value; diverging→Conflict; returns
  Outcome::Merged(map) or Outcome::Conflict(keys))

Total this resume: 300 selfdef IPS-authority crates. Workspace 465.

### Two-hundred-and-thirty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-ranking-table` (id→score; set inserts/overwrites;
  top_n sorts score desc + id asc; rank_of returns 1-based
  position or None; supports negative scores)

Total this resume: 301 selfdef IPS-authority crates. Workspace 466.

### Two-hundred-and-thirty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-prefix-sum` (push appends and updates cumulative
  i128 sum; sum_range(lo, hi) returns cum[hi]-cum[lo] in O(1);
  total exposes full sum; bad range rejected)

Total this resume: 302 selfdef IPS-authority crates. Workspace 467.

### Two-hundred-and-thirty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-peak-detector` (Sample{ts_ms, value}; observe
  appends + prunes samples older than now-window_ms;
  current_peak returns max over in-window samples; supports
  negative values)

Total this resume: 303 selfdef IPS-authority crates. Workspace 468.

### Two-hundred-and-thirty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-linear-interp` (Point{x, y} strictly increasing x;
  lookup interpolates between adjacent segments via i128;
  Extrapolation::Clamp returns endpoint y; Extend continues
  boundary slope)

Total this resume: 304 selfdef IPS-authority crates. Workspace 469.

### Two-hundred-and-thirty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-quota-table` (Quota{limit, period_ms, used,
  last_reset_ms}; consume advances period if elapsed then
  admits iff used+amount<=limit; Exceeded bumps denials;
  remaining accounts for period advance)

Total this resume: 305 selfdef IPS-authority crates. Workspace 470.

### Two-hundred-and-thirty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-named-counter` (multi-named u64 counters; inc/dec
  saturating; get returns 0 if absent; reset_all zeroes
  values (keeps keys); snapshot returns frozen copy; total
  sums u128)

Total this resume: 306 selfdef IPS-authority crates. Workspace 471.

### Two-hundred-and-thirty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-bounded-fifo` (Policy{DropOldest/Reject}; push at
  capacity evicts head (Evicted) or errors Full; pop/peek_head
  head-side ops; drops counts both eviction + rejection)

Total this resume: 307 selfdef IPS-authority crates. Workspace 472.

### Two-hundred-and-fortieth wave (same day, +1 more IPS-authority crate)

- `selfdef-bp-math` (apply(value, bp)=value*bp/10000 via i128;
  ratio_bp(numer, denom)=numer*10000/denom saturating to
  u32::MAX, rejects zero denom; clamp_bp limits to 10000)

Total this resume: 308 selfdef IPS-authority crates. Workspace 473.

### Two-hundred-and-forty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-union-find` (string-keyed disjoint-set; Entry{
  parent, rank, size}; find returns root with path
  compression; union joins by rank (ties bump rank);
  component_size returns set size)

Total this resume: 309 selfdef IPS-authority crates. Workspace 474.

### Two-hundred-and-forty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-approval-flow` (Stage{name, required, got};
  Phase{Pending/Approved/Rejected(reason)}; approve advances
  when got==required; final stage flips Approved; reject
  one-way; duplicate/non-required approvers rejected)

Total this resume: 310 selfdef IPS-authority crates. Workspace 475.

### Two-hundred-and-forty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-min-max-tracker` (online tracker over i64 stream;
  observe updates count + sum (i128) + min + max in O(1);
  mean = sum/count (None if empty); reset clears; supports
  negative values)

Total this resume: 311 selfdef IPS-authority crates. Workspace 476.

### Two-hundred-and-forty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-text-canonical` (Options{lowercase, trim, collapse_
  whitespace, strip_non_printable}; canonicalize applies steps
  in fixed order: strip→lowercase→collapse→trim; deterministic)

Total this resume: 312 selfdef IPS-authority crates. Workspace 477.

### Two-hundred-and-forty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-seen-set` (bounded TTL seen-id set; first_time
  records and returns true on first obs within TTL, false on
  duplicate within TTL; capacity evicts oldest; sweep removes
  expired)

Total this resume: 313 selfdef IPS-authority crates. Workspace 478.

### Two-hundred-and-forty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-csv-line` (single-line CSV split with quote+quote
  escape; configurable separator + quote char (supports TSV
  via '\t'); unbalanced quote rejected)

Total this resume: 314 selfdef IPS-authority crates. Workspace 479.

### Two-hundred-and-forty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-edit-distance` (Levenshtein distance via two-row
  DP O(|a|*|b|) time, O(min(|a|,|b|)) space; char-based for
  Unicode safety; similarity_bp scales to 0..=10000)

Total this resume: 315 selfdef IPS-authority crates. Workspace 480.

### Two-hundred-and-forty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-rect-overlap` (Rect{x, y, w, h} w,h>=1; intersect
  returns Option<Rect> (None on disjoint or edge-only);
  bounding_box; contains_point/contains_rect; area as i128)

Total this resume: 316 selfdef IPS-authority crates. Workspace 481.

### Two-hundred-and-forty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-weighted-mean` (observe(value, weight) accumulates
  Σ(v*w) (i128) + Σw (u128); mean = weighted_sum/total_weight
  (None if Σw=0); reset clears; zero weight rejected)

Total this resume: 317 selfdef IPS-authority crates. Workspace 482.

### Two-hundred-and-fiftieth wave (same day, +1 more IPS-authority crate)

- `selfdef-fixed-interval` (poll(now) returns count of
  period_ms elapsed since last_tick_ms; advances last_tick
  by n*period (drift bounded < 1 period); reset(now)
  restarts at now)

Total this resume: 318 selfdef IPS-authority crates. Workspace 483.

### Two-hundred-and-fifty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-linear-regression` (incremental n + Σx + Σy + Σxy +
  Σx² as i128; slope_micro=(n*Σxy-Σx*Σy)*1e6/(n*Σx²-Σx²);
  intercept_micro derived; Degenerate when denom=0)

Total this resume: 319 selfdef IPS-authority crates. Workspace 484.

### Two-hundred-and-fifty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-canary-ramp` (strictly-increasing (ts_ms,
  percent_bp 0..=10000) points; current_percent picks latest
  applicable; admit(now, key) FNV-1a-64 hash mod 10000;
  deterministic same-input decisions)

Total this resume: 320 selfdef IPS-authority crates. Workspace 485.

### Two-hundred-and-fifty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-clock-skew` (observe(local_ms, remote_ms) records
  skew=remote-local; tracks Σskew + count + min + max;
  mean=Σ/count (None if empty); range=max-min)

Total this resume: 321 selfdef IPS-authority crates. Workspace 486.

### Two-hundred-and-fifty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-request-coalescer` (enter(key) returns Leader for
  first caller (registers inflight), Follower for subsequent
  (bumps count); complete clears entry and returns follower
  count; per-key single-flight)

Total this resume: 322 selfdef IPS-authority crates. Workspace 487.

### Two-hundred-and-fifty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-listener-set` (topic→listener-id BTreeSet;
  subscribe idempotent; unsubscribe drops (and removes empty
  topic); listeners_for sorted; topics_for filters)

Total this resume: 323 selfdef IPS-authority crates. Workspace 488.

### Two-hundred-and-fifty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-policy-cache-key` (key(policy_version, input) →
  "<version>:<16-hex>" using FNV-1a-64 of input bytes;
  deterministic; same inputs → same key; diverges on either
  version or input change)

Total this resume: 324 selfdef IPS-authority crates. Workspace 489.

### Two-hundred-and-fifty-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-topic-stats` (TopicStat{total, window_count,
  window_start_ms}; record accumulates with auto-reset of
  window if elapsed>=window_ms; rate_per_sec returns
  window_count*1000/elapsed)

Total this resume: 325 selfdef IPS-authority crates. Workspace 490.

### Two-hundred-and-fifty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-threshold-set` (Threshold{name, value} sorted by
  value asc; add via binary-insert (rejects duplicate name or
  value); classify returns latest band with threshold<=value;
  below first → default_band)

Total this resume: 326 selfdef IPS-authority crates. Workspace 491.

### Two-hundred-and-fifty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-duplicate-detect` (DupEntry{text, shingles k-char
  BTreeSet}; observe records; is_near_dup(text, threshold_bp)
  returns first id with Jaccard >= threshold; uses k-char
  shingles for near-match)

Total this resume: 327 selfdef IPS-authority crates. Workspace 492.

### Two-hundred-and-sixtieth wave (same day, +1 more IPS-authority crate)

- `selfdef-path-normalize` (normalize splits on /, drops
  empty/"."; pops on ".."; absolute paths reject EscapesRoot;
  relative keeps ".."; preserves absolute-ness; "/"→"/",
  ""→".")

Total this resume: 328 selfdef IPS-authority crates. Workspace 493.

### Two-hundred-and-sixty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-decay-counter` (DecayCounter{decay_per_sec, last_ts_ms,
  stored}; observe(n, now) decays stored by
  decay_per_sec*(now-last)/1000 then adds n + advances last_ts_ms;
  value(now) read-only; reset clears; saturates at zero)

Total this resume: 329 selfdef IPS-authority crates. Workspace 494.

### Two-hundred-and-sixty-second wave (same day, +1 more IPS-authority crate)

- `selfdef-count-min-sketch` (depth*width u64 cell grid;
  add(key,n) hashes key into d distinct columns FNV-1a-64 +
  per-row seed and adds n to each; estimate returns min across
  rows — Count-Min upper bound; reset zeros)

Total this resume: 330 selfdef IPS-authority crates. Workspace 495.

### Two-hundred-and-sixty-third wave (same day, +1 more IPS-authority crate)

- `selfdef-fence-token` (FenceIssuer.issue() strictly-increasing
  u64 from 1; FenceAcceptor.accept(t) advances last_accepted if
  t >= last; strictly-older tokens rejected Stale, equal tokens
  idempotent; issuer overflow → Exhausted)

Total this resume: 331 selfdef IPS-authority crates. Workspace 496.

### Two-hundred-and-sixty-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-sequence-gap-detector` (observe(seq) tracks
  expected_next; seq > expected_next records half-open
  Gap[expected_next, seq) and advances; seq < expected_next
  bumps out_of_order; close_gap(seq) splits matching gap;
  missing() sums uncovered)

Total this resume: 332 selfdef IPS-authority crates. Workspace 497.

### Two-hundred-and-sixty-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-counting-bloom` (m 8-bit counters with k hash
  positions per key FNV-1a-64 + per-hash decimal seed; add
  increments each of k saturating 255; remove decrements
  skipping saturated; contains true iff all positions non-zero)

Total this resume: 333 selfdef IPS-authority crates. Workspace 498.

### Two-hundred-and-sixty-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-epoch-marker` (advance() bumps epoch+1 and resets
  seq=0; tag() returns (epoch, seq) and increments seq within
  current epoch; Tag is Ord lexicographically; both counters
  checked-add → Exhausted on overflow)

Total this resume: 334 selfdef IPS-authority crates. Workspace 499.

### Two-hundred-and-sixty-seventh wave — selfdef workspace crosses 500

- `selfdef-nonce-store` (observe(nonce, now_ms) returns Accept if
  unknown and inserts with expiry now+ttl, or Replay if seen and
  not yet expired; tick(now_ms) drops expired; HMAC/signature
  replay defense in the IPS admission path)

Total this resume: 335 selfdef IPS-authority crates. Workspace 500.

### Two-hundred-and-sixty-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-tombstone-set` (mark(id, now) records tombstone with
  expiry now+grace_ttl_ms; is_tombstoned(id, now) true iff
  non-expired; re-mark extends expiry; compact(now) prunes;
  prevents distributed delete→insert resurrection races)

Total this resume: 336 selfdef IPS-authority crates. Workspace 501.

### Two-hundred-and-sixty-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-stale-set` (per-key state Pending(since) /
  Refreshing(since); flag→Pending, start_refresh→Refreshing,
  confirm clears, fail reverts to Pending; double-flag
  idempotent preserves original since; pending_count for
  refresh scheduler queue depth)

Total this resume: 337 selfdef IPS-authority crates. Workspace 502.

### Two-hundred-and-seventieth wave (same day, +1 more IPS-authority crate)

- `selfdef-fixed-window-counter` (window of width window_ms
  aligned to window multiples; observe(n, now) realigns to
  containing bucket resetting if new, then adds n; count(now)
  also realigns; hard boundaries — edge bursts can briefly
  exceed nominal rate)

Total this resume: 338 selfdef IPS-authority crates. Workspace 503.

### Two-hundred-and-seventy-first wave (same day, +1 more IPS-authority crate)

- `selfdef-warmup-ramp` (cap(now) = floor + (target - floor) *
  elapsed / warmup_ms, clamped to [floor, target]; elapsed =
  now - start_ms saturating; ramped(now) true at full target;
  mitigates thundering-herd on restart)

Total this resume: 339 selfdef IPS-authority crates. Workspace 504.

### Two-hundred-and-seventy-second wave (same day, +1 more IPS-authority crate)

- `selfdef-prefetch-queue` (hint(key) enqueues; duplicate key
  moves existing entry to back most-recent wins; pop returns
  oldest; capacity-bounded with LRU eviction front-evict when
  full; VecDeque-backed)

Total this resume: 340 selfdef IPS-authority crates. Workspace 505.

### Two-hundred-and-seventy-third wave (same day, +1 more IPS-authority crate)

- `selfdef-priority-aging` (Job{id, base_priority,
  enqueued_at_ms}; effective(now) = base + (now-enqueued)/
  age_step; next(now) pops highest effective (ties → lower
  id); prevents starvation while preferring high priority)

Total this resume: 341 selfdef IPS-authority crates. Workspace 506.

### Two-hundred-and-seventy-fourth wave (same day, +1 more IPS-authority crate)

- `selfdef-deficit-round-robin` (Flow{id, quantum, deficit,
  queue VecDeque<u64>}; enqueue appends packet size; service()
  rotates, adds quantum to deficit, serves head iff size <=
  deficit; empty flows reset deficit per DRR semantics; two-sweep
  loop yields None iff all idle)

Total this resume: 342 selfdef IPS-authority crates. Workspace 507.

### Two-hundred-and-seventy-fifth wave (same day, +1 more IPS-authority crate)

- `selfdef-threshold-sig-store` (collects opaque (signer_id,
  shard) pairs per digest; submit idempotent per (digest, signer);
  ShardConflict if same signer submits different bytes; met
  true at >= m distinct signers; shards returns deterministic
  signer-id-ordered list for external combiner)

Total this resume: 343 selfdef IPS-authority crates. Workspace 508.

### Two-hundred-and-seventy-sixth wave (same day, +1 more IPS-authority crate)

- `selfdef-delta-pack` (diff(old, new) walks two BTreeMap
  <String,String> in lockstep and emits Vec<Op> in key-ascending
  order: Add for new-only keys, Remove for old-only, Update for
  both-with-differing-values, Equal silenced; apply(map, ops)
  replays idempotently)

Total this resume: 344 selfdef IPS-authority crates. Workspace 509.

### Two-hundred-and-seventy-seventh wave (same day, +1 more IPS-authority crate)

- `selfdef-recursion-guard` (enter(frame_id) pushes; leave pops;
  DepthExceeded if push would exceed max_depth, CycleDetected
  if id already on stack — both without mutating state;
  Underflow on leave-when-empty; suitable for nested IPS rule
  evaluation)

Total this resume: 345 selfdef IPS-authority crates. Workspace 510.

### Two-hundred-and-seventy-eighth wave (same day, +1 more IPS-authority crate)

- `selfdef-jump-hash` (Google Jump Consistent Hash via
  Lamping & Veach LCG step + jump; stateless O(ln n);
  bucket(key, num_buckets) in [0, num_buckets); growth moves
  ~1/n keys per bucket; +/-50% distribution balance verified)

Total this resume: 346 selfdef IPS-authority crates. Workspace 511.

### Two-hundred-and-seventy-ninth wave (same day, +1 more IPS-authority crate)

- `selfdef-rendezvous-hash` (HRW: for each (key, node) compute
  h = FNV-1a-64(key + ':' + node); node with highest h wins;
  top_k returns k highest-weighted nodes in desc order for
  replica set; removing a node redistributes its keys to
  next-highest of EACH key — no hot spot)

Total this resume: 347 selfdef IPS-authority crates. Workspace 512.

### Two-hundred-and-eightieth wave (same day, +1 more IPS-authority crate)

- `selfdef-denylist-store` (Entry{reason, added_at_ms,
  expires_at_ms}; add(key, reason, now, ttl_ms) inserts
  (ttl=0 permanent); denied(key, now) true iff entry exists
  AND non-expired; reason returns audit string even for
  expired; compact prunes)

Total this resume: 348 selfdef IPS-authority crates. Workspace 513.

### Two-hundred-and-eighty-first wave (same day, +1 more IPS-authority crate)

- `selfdef-allowlist-store` (Entry{reason, granted_by,
  granted_at_ms, expires_at_ms}; grant(key, reason, granted_by,
  now, ttl_ms) inserts (ttl=0 permanent); allowed(key, now)
  true iff non-expired; revoke removes; counterpart to
  selfdef-denylist-store)

Total this resume: 349 selfdef IPS-authority crates. Workspace 514.
