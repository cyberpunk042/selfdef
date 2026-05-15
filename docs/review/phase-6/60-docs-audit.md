# Phase 6 — docs audit

Audits the documentation surface added by SDD-008:

- `docs/sdd/008-notifications-orchestration.md` (440 LOC)
- `ARCHITECTURE.md` integrations-layer section (+66 LOC)
- `docs/dev/integrations.md` contributor template (291 LOC,
  new)
- `SECURITY.md` notification-credentials + TTY-broadcast rows
  (+3 LOC, in-band)
- `crates/selfdef-cli/src/init.rs` STARTER_CONFIG inline
  comments (+194 LOC of `#` doc lines)

Closes F-2031-001 (PR-label collision → SDD-008 appendix)
and raises + closes F-2031-011 and F-2031-012 (SDD-008
implementation-status + open-question staleness; init.rs
subscription-filter operator-discovery gap).

## Methodology

For each doc, audit on three axes:

1. **Internal consistency** — claims within the doc don't
   contradict each other; the doc's section-to-section
   narrative holds.
2. **Doc-vs-code reality** — the doc describes the shipped
   shape, not the as-charter shape.
3. **Operator discoverability** — an operator reading the
   doc finds out about gotchas (Phase 6 findings,
   stopgap warnings) without needing to read the audit
   ledger.

Cross-check: do the docs reference each other consistently
(SDD-008 → ARCHITECTURE.md → integrations.md →
init.rs)?

## Findings

### F-2031-001 (nice, closed-in-place)

**Surface**: `docs/sdd/008-notifications-orchestration.md`.

Raised by the recent-PRs explorer:

- PR #114's title labeled the SMTP integration crate
  `feat(sdd-008): D-7 Q-E …` even though SDD-008's actual
  D-7 is the panic floor (which shipped under PR #127 with
  the correct label).
- Anyone navigating the cycle's commit graph by D-N label
  hits a collision on `D-7`.

**Closed in this PR**: SDD-008 gains a "PR labels — appendix"
section that disambiguates exhaustively:

- `D-7 Q-E` PR #114 → D-2 pattern (channel-adapter carve)
  serving open question Q-E; the `D-7` label is a slip.
- `D-7` PR #127 → the true panic-floor implementation.
- Twilio / Slack / Discord (PRs #116 / #120 / #121) → D-2
  pattern serving Q-D / Q-C / no-Q; no D-N number minted.
- D-8 wall(1) (PR #128) → simultaneously D-8 AND a D-2
  pattern instance, with D-8 dominating.

Plus an "Implementation status" table now records the
canonical D → PR mapping at the top of the SDD.

### F-2031-011 (nice, closed-in-place)

**Surface**: `docs/sdd/008-notifications-orchestration.md`,
"Implementation status" and "Open questions" sections.

The "Implementation status" section read:

> Charter only. No implementation has shipped.

Stale — all 8 design points D-1..D-8 shipped during the
cycle. Similarly, every "Open question" working assumption
was decided during implementation, but the doc kept the
assumptions as live questions. Two assumptions were
**revised** by reality (not just confirmed):

- **Q-C**: charter assumed ntfy + signal + one email channel
  would land in v1 with Slack/Twilio/Discord deferred. **Reality**:
  all seven channels (including wall) landed in the SDD-008
  cycle. The "follow-up SDD" plan was abandoned because the
  integration crate template made each new channel routine.
- **Q-G**: charter assumed the operator-facing namespace
  would move from `[notifier]` → `[notifications]`. **Reality**:
  the existing `[notifier]` namespace was kept and extended
  to avoid breaking operators on upgrade. Rejected as
  needless churn.

Q-F (session-attention multi-user) was **revised** too —
v1 wall(1) broadcasts to every logged-in TTY rather than the
"per-user opt-in" originally assumed. Per-user opt-in
remains a future refinement, tracked in the
`selfdef-integration-wall` crate's module rustdoc.

**Closed in this PR**:

- "Implementation status" rewritten with a per-D status
  table naming each shipping PR and a section noting the
  four channel crates that shipped under Q-letter open
  questions rather than numbered Ds.
- "Open questions" annotated `→ confirmed` /
  `→ revised on implementation` per Q-letter, with the
  shipped behaviour described in 1-3 sentences each.
- "Naming" section's "audit programme picks up Phase 6 once
  material code lands" updated to point to the
  now-in-progress Phase 6 findings ledger.

### F-2031-012 (nice, closed-in-place)

**Surface**: `crates/selfdef-cli/src/init.rs` STARTER_CONFIG,
the `[notifier.subscriptions]` block comment.

The STARTER_CONFIG documents per-channel subscription filters
in detail but never mentions the F-2031-009 gap: those
filters silently do **not** apply on the engine path
(`escalations_path` set). An operator following the starter
config faithfully would set `escalations_path` to enable
escalation AND configure `[notifier.subscriptions.discord]
severity_floor = "critical"` to gate noisy discord — only to
find every event firing to discord regardless.

The integration explorer (PR #135) shipped the **daemon-side**
stopgap warning. This finding addresses the **starter-config
side**: the operator should learn about the gap when they
write the config, not only when they tail the daemon log.

**Closed in this PR**: STARTER_CONFIG's
`[notifier.subscriptions]` block now ends with:

```text
# IMPORTANT (Phase 6 F-2031-009): in v1 these filters apply ONLY on
# the legacy chain path (escalations_path unset). When the engine
# path is enabled (escalations_path set above), every channel sees
# every event regardless of [notifier.subscriptions.<ch>]. The
# daemon warns at startup when both knobs are set together so the
# misconfiguration is visible. Subscription-aware dispatching ships
# under the SDD-008 D-5e follow-up PR.
```

Also: the D-6c past-tense "Operator-defined profiles + per-
rung channel filtering land in follow-up Ds (D-6c)." was
fixed to present-tense ("ship under D-6c — see
[notifier.profiles.*] below") since D-6c has shipped.

## Audit notes — no new finding

### `ARCHITECTURE.md` "Integrations layer" section

Internal-consistency clean. Codifies the modules ≠
integrations boundary that SDD-008 D-1 set: integrations are
pure adapters (no host topology mutation, no installs);
modules are host-level (file-permissions, sshd, sudo). The
section cross-references the integration crates that exist
today by slug. Spot-checked against `crates/selfdef-
integration-*/` — every named crate exists.

### `docs/dev/integrations.md` contributor template

Walks a hypothetical new channel implementation
(`selfdef-integration-foo`) end-to-end: `Cargo.toml` shape,
`Channel` trait impl, `Notifier` trait impl, `from_config`
contract, secret-elision Debug pattern, test seams (with the
wiremock pattern documented). Cross-checked against the four
HTTP channels (twilio / slack / discord / smtp) — the template
matches the shipped shape.

One minor observation: the template's secret-elision section
predates F-2031-005's ntfy fix. The template does say "if
your channel carries secrets, write a custom Debug" — accurate
guidance, but doesn't call out that *every* HTTP channel
carries secrets (token / webhook). Not a finding; the
template's intent is right, and the four-channel cross-check
shows operators follow the guidance.

### `SECURITY.md` additions

Two new in-band rows landed during the SDD-008 cycle:

- **Notification credentials**: enumerates per-channel
  secret-file paths (ntfy tokens, signal-cli auth, SMTP
  `password_file`, Twilio `auth_token_file`, Slack +
  Discord `webhook_url_file`), notes the `0600` recommendation
  and daemon file-ownership requirement.
- **TTY broadcast**: documents the wall(1) channel's
  default `severity_floor = "high"` defense-in-depth and the
  `tty`-group / root permission requirement.

Both rows accurate. SDD-008 D-7 panic floor + D-6a audit
mode + per-channel subscription filter are **not** SECURITY
items per se (they're operational tuning rather than
security boundary) and correctly aren't in SECURITY.md.

### `STARTER_CONFIG` (init.rs) coverage

Every operator-facing SDD-008 knob is documented inline with:

- A `# SDD-008 D-N` reference.
- One-paragraph explanation of when to set it.
- A commented-out example.
- Severity / range constraints.

The seven channel sub-sections each carry a `# SDD-008` /
`# SDD-008 Q-N` reference. The four dispatcher knobs
(`escalations_path`, `mode`, `profile`, `panic_floor`) and
the two multi-key sub-maps (`[notifier.profiles.*]`,
`[notifier.subscriptions.*]`) all carry inline docs.

After this PR's F-2031-012 fix, the subscription block warns
about the engine-path bypass. Coverage is now complete vis-
à-vis the 13 SDD-008 surface elements catalogued in the Phase
6 inventory.

## Cross-doc consistency

Spot-checked the references between docs:

| From → To | Reference shape | Resolves? |
| --- | --- | --- |
| SDD-008 → ARCHITECTURE.md integrations | "See ARCHITECTURE.md §integrations layer" | yes |
| SDD-008 → integrations.md | "See `docs/dev/integrations.md`" | yes |
| ARCHITECTURE.md → SDD-008 | "(SDD-008 D-1)" inline | yes |
| integrations.md → orchestrator trait | crate-relative rustdoc link | yes |
| init.rs → SDD-008 | `# SDD-008 D-N:` inline | yes |
| init.rs → Phase 6 ledger | new F-2031-009 reference (this PR) | yes |
| SECURITY.md → SDD-008 | per-row `(per SDD-008 D-N)` inline | yes |
| Phase 6 module audit → SDD-008 D-5e | "feat(sdd-008): D-5e PR" | yes (anchor in this PR's Implementation status table) |

All cross-references resolve. The new F-2031-001
appendix in SDD-008 makes the doc the authoritative
cross-reference for cycle-era commit-message labels.

## Status

- F-2031-001 closed (PR-label appendix added to SDD-008).
- F-2031-011 closed (SDD-008 implementation-status table +
  open-question revision annotations).
- F-2031-012 closed (init.rs subscription-filter
  operator-discovery comment + D-6c past-tense fix).
- ARCHITECTURE.md, integrations.md, SECURITY.md audit clean.

## Hand-off

- **Tests explorer (next)**: audit the 159 new tests for
  SDD-005 pipeline-determinism compliance.
- **Security explorer**: pick up F-2031-003 (0BSD allow-list
  re-audit) plus credential-handling for all 7 channels and
  wall(1) TTY-broadcast.
