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

Selfdef workspace now at 55 crates (was 33 pre-session, +22 in this session).
Additional crates beyond the first batch:
`selfdef-subject-cohort` (5-tier trust cohorts with monotonic promotion),
`selfdef-evidence-tag` (6-tag evidence ledger taxonomy),
`selfdef-deny-recurrence` (per-(subject, action) deny counter),
`selfdef-grant-template-pack` (8 operator-curated grant templates),
`selfdef-policy-budget-ledger` (per-subject token+cost cap evaluator),
`selfdef-substrate-fingerprint` (boot-time FNV-1a tamper-detection snapshot).

Every crate ships with canonical empty builders, full validate() + serde
roundtrip + edge-case tests (10..14 passing tests per crate).

## Reference table — operator quotes that shape the work

Same as sovereign-os/context.md. Single source of truth for the operator's standing direction lives at the sovereign-os file; this file mirrors the table by reference.

---

**Last updated**: 2026-05-19 (commit `cdc9064` + this file)
**Authoritative full picture**: `cyberpunk042/sovereign-os/context.md`
**Next AI session**: read this file → read sovereign-os/context.md → pick next item from selfdef forward queue → execute → update this file.
