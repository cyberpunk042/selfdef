# Phase 6 — recent-PRs audit (post-SDD-008 closure)

Companion to Phase 5's [20-recent-prs-audit.md](../phase-5/20-recent-prs-audit.md)
and Phase 4's [20-recent-prs-audit.md](../phase-4/20-recent-prs-audit.md). Same
shape: walk the 22 SDD-008 PRs shipped during the cycle
(`#109`..`#130`, commits `f85ba78`..`28fc63b`) and flag
observations that didn't get caught at PR-review time.

## Methodology

For each PR: read the commit message, the diff, the SDD-008
status it claims to land, and the resulting tree state.
Look for:

- **Scope drift** — claims in commit/PR messages that don't
  match the diff.
- **Design-point mislabel** — commit-message D-N references
  not matching SDD-008's actual D-N definitions.
- **Coverage gaps** — surface area shipped without test
  coverage proportionate to its weight in the cycle.
- **Hot-fix pattern** — in-cycle fix-up commits whose root
  cause hints at a missing pre-commit guarantee.
- **Cross-PR consistency** — patterns established in PR N
  honoured in PR N+1 (avoid one-off shapes).
- **Documentation drift** — SDD-008 text vs. shipped APIs.

Outcomes feed `F-2031-NNN` entries in the section below.

## PRs surveyed

| # | Topical commit | Title (SDD-008 point) | Audit pass |
| --- | --- | --- | --- |
| 1 | `f85ba78` | docs(sdd-008): charter — notifications orchestration + integrations taxonomy | review-clean |
| 2 | `f5b4286` | docs(sdd-008): D-1 — codify modules-vs-integrations taxonomy | review-clean |
| 3 | `1327cb3` | feat(sdd-008): D-2a — scaffold selfdef-notifier-orchestrator trait crate | review-clean |
| 4 | `4a5d63c` | feat(sdd-008): D-2b — carve NtfyNotifier into selfdef-integration-ntfy | **F-2031-002** |
| 5 | `9ba344b` | feat(sdd-008): D-2c — carve SignalCliNotifier into selfdef-integration-signal | **F-2031-002** |
| 6 | `436c063` | feat(sdd-008): D-7 Q-E — selfdef-integration-smtp first email channel | **F-2031-001** |
| 6b | `3ab3b21` | chore(deny): allow 0BSD for lettre's quoted_printable transitive (in-cycle fix-up under #114) | **F-2031-003** (referral to security) |
| 7 | `123079d` | feat(sdd-008): wire SmtpNotifier into the daemon's notifier chain | review-clean |
| 8 | `172fa02` | feat(sdd-008): Twilio SMS integration crate + daemon wiring (Q-D) | review-clean |
| 9 | `6af6374` | feat(sdd-008): D-3 — per-channel subscription model (severity_floor + event_kinds) | review-clean |
| 10 | `4790a2b` | feat(sdd-008): D-5a — selfdef-notifier-engine persistent escalation layer | review-clean |
| 11 | `5794d7f` | feat(sdd-008): D-5b — PayloadDispatcher facade (engine + channel set glue) | review-clean |
| 12 | `93b988e` | feat(sdd-008): Slack integration crate + daemon wiring (Q-C) | review-clean |
| 13 | `a465661` | feat(sdd-008): Discord integration crate + daemon wiring | review-clean |
| 14 | `c2ad9a1` | feat(sdd-008): D-5c — wake task + rung advancement | review-clean |
| 15 | `af45dcc` | feat(sdd-008): D-4 — selfdefctl notify {ack,forget,list} | review-clean |
| 16 | `85bca96` | feat(sdd-008): D-5d — wire engine + dispatcher + wake task into daemon | review-clean |
| 17 | `26e5f6a` | feat(sdd-008): D-6a — dispatcher operating modes (enforce / audit) | review-clean |
| 18 | `868c334` | feat(sdd-008): D-6b — named escalation profiles (auto / aggressive / patient) | review-clean |
| 19 | `63016bd` | feat(sdd-008): D-7 — panic floor (audit-mode bypass for critical events) | **F-2031-001** (cross-link) |
| 19b | `3b80a85` | chore(fmt): collapse panic_floor parsing chain (rustfmt CI fix) (in-cycle fix-up under #127) | **F-2031-004** (demoted) |
| 20 | `e47b9d9` | feat(sdd-008): D-8 — wall(1) session-attention channel | review-clean |
| 21 | `86b4887` | feat(sdd-008): D-6c — per-rung channel filtering + custom profiles | review-clean |
| 22 | `28fc63b` | feat(sdd-008): TOML schema for D-6c custom profiles | review-clean |

## Observations

The SDD-008 cycle is, by surface area and PR count, the
largest single closure cycle in the audit programme's history
(22 PRs vs. Phase 3's ~17, Phase 4's 8, Phase 5's 8). Despite
the scale, **the cycle holds together remarkably well**:

- All 22 PRs ship behind a single SDD (SDD-008) with the
  charter landed first (`#109`).
- Each PR has a `feat(sdd-008): D-N — <title>` shape; the
  D-N references hew to SDD-008's design-point numbering with
  one exception (see F-2031-001).
- D-1..D-8 all merged; D-9 (dashboard) deferred to a separate
  design conversation per the SDD; D-4's HTTP
  `/notify/ack/<token>` complement explicitly left as
  follow-up.
- No retroactive commit-rewrites; the linear progression of
  merges shows the cycle was shipped in order.
- Two in-cycle fix-up commits (`3ab3b21`, `3b80a85`); both
  are direct CI-driven corrections with traceable root cause.

But the auditor flags 4 nice-level observations:

### F-2031-001 (nice): D-7 label collision in PR #114

PR #114 (`436c063`) — the SMTP integration crate's first
landing — is titled `feat(sdd-008): D-7 Q-E —
selfdef-integration-smtp first email channel`. SDD-008's
**D-7 is the panic floor**, which actually shipped in PR
#127 (`63016bd`) under the correct `feat(sdd-008): D-7 —
panic floor` title. The SMTP integration is an instance of
the D-2 pattern (channel-adapter carve, like the ntfy and
signal crates that shipped under D-2b and D-2c) coupled to
the Q-E open question (email channel adoption).

**Concrete impact**: low — both PRs are merged, the SDD-008
design points are documented correctly in `docs/sdd/008-*`,
and a reader of the commit graph can disambiguate via the
diff. But anyone using commit-message D-N labels to navigate
the cycle (e.g. a future explorer doing PR-by-PR
forensics on this audit programme) will hit a collision.

**Recommendation**: nice-level. Either:

- Annotate SDD-008 with a "Pre-history" / "PR labels"
  appendix noting the `#114` label collision and what each
  occurrence actually meant, **or**
- Leave the commit graph as-is and document the collision
  in the Phase 6 recent-PRs audit (this doc) as the
  authoritative cross-reference.

This audit takes the second option implicitly; if SDD-008 is
ever published externally, the appendix option becomes
preferable.

### F-2031-002 (nice): test-coverage thinness in PR #112 (ntfy) and PR #113 (signal)

The seven channel integration crates landed in roughly
chronological order: ntfy (`#112`, 4 tests) → signal
(`#113`, 3 tests) → smtp (`#114`, 7 tests) → twilio (`#116`,
12 tests) → slack (`#120`, 12 tests) → discord (`#121`, 13
tests) → wall (`#128`, 16 tests). **The first two crates are
notably thinner than the rest**.

Inspection (`crates/selfdef-integration-ntfy/src/lib.rs` and
`crates/selfdef-integration-signal/src/lib.rs`):

- **Ntfy** has 4 tests: tag-derivation (`ntfy_tags_default_to_*`),
  legacy `Notifier::notify` empty-URL guard,
  orchestrator `Channel::send` empty-URL guard,
  name-equivalence. **It has no test exercising the
  `post()` HTTP path** — the wiremock pattern that the
  subsequent crates (twilio, slack, discord) adopted is not
  back-applied.
- **Signal** has 3 tests: legacy empty-account guard,
  orchestrator empty-recipient guard, name-equivalence. **It
  has no test exercising the `signal-cli` subprocess
  invocation**.

The pattern matured during the cycle; later integration
crates land with mock-server tests that pin the on-the-wire
payload shape. The two early crates didn't get back-filled.

**Concrete impact**: low — both crates have config-validation
tests pinning the no-config-no-fire contract, and the failure
modes of their actual `post()` / subprocess paths are
non-stateful (a network error or subprocess-exec error maps
to a `ChannelError::Transport` / `NotifierError::Transport`
with no side-effect leakage). But coverage parity across the
seven channels would improve regression safety.

**Recommendation**: nice-level. The Phase 6 crate explorer
+ tests explorer will pick this up.

### F-2031-003 (nice → defer to security explorer): `0BSD` added to `deny.toml`

PR #114's in-cycle fix-up `3ab3b21` adds `0BSD` to
`deny.toml`'s `licenses.allow` list to permit the
`quoted_printable` 0.5.2 crate (a transitive dependency via
`lettre`). The commit message and `deny.toml` comment
justify the addition.

The recent-PRs auditor's role here is to **flag the
supply-chain decision for re-audit by the security
explorer**, not to second-guess the verdict. The 0BSD
license is OSI-recognized and effectively MIT-equivalent
(public-domain-grant + no-warranty); the audit-programme
question is whether the allow-list addition was tracked,
documented, and not silently widening the supply-chain
surface.

**Concrete impact**: deferred. The security explorer should
verify:

- `quoted_printable` crate is actually transitive via
  `lettre` (not a primary dep).
- No other 0BSD crates entered the tree by virtue of the
  allow-list expansion.
- The `deny.toml` justification comment is sufficient for
  future-operator review.

### F-2031-004 (demoted): rustfmt CI mismatch on PR #127

PR #127's in-cycle fix-up `3b80a85` (`chore(fmt): collapse
panic_floor parsing chain (rustfmt CI fix)`) is a cosmetic
correction where local `cargo fmt` produced output that
CI's rustfmt 1.88.0 disagreed with — specifically the
collapse of an `Option`-method chain on the panic-floor
parsing path.

Cross-check: this is **a known rustfmt 1.88.0 behaviour
nuance**, not a missing pre-commit hook. Locally, the
toolchain may have been pinned to a slightly different patch
release where the chain-collapse heuristic differs. CI
correctly caught the mismatch; the fix-up is exactly the
right shape (collapse to match CI's expectation, no other
code change). The cycle's fix-up commits include a clean
`chore(fmt)` shape with the CI-fix reason in the subject.

**Demotion rationale**: the audit programme already requires
all CI gates green before merge, and the fix-up commit landed
on the same branch before merge of `#127`. The "missing
pre-commit guarantee" framing is unjustified — rustfmt minor
version drift between dev environment and CI is a
process-level concern that would require the dev environment
to lockstep against the CI image, which is more cost than
value for the single observed incident.

If a second such fix-up occurs in a future cycle, the
recommendation flips to nice-level.

## Trajectory comparison

| Cycle | PRs audited | Recent-PRs findings | Pass rate | SDD-debt? |
| --- | --- | --- | --- | --- |
| Phase 2 | many | many | — | none flagged |
| Phase 3 | 29 | 4 nice | 86% (25/29 clean) | none |
| Phase 4 | 17 | 1 demoted | 94% (16/17 clean) | none |
| Phase 5 | 8 | 0 | 100% | none |
| **Phase 6** | **22** | **3 nice + 1 demoted** | **86% (19/22 clean)** | **none from recent-PRs** |

The 86% pass rate matches Phase 3's. Phase 5's 100% was
the audit of a documentation-heavy cycle (low-risk surface);
Phase 6 audits a 22-PR feature cycle and surfaces a
recent-PRs finding rate proportionate to the surface area.

None of the 4 observations rise to important or blocker.
**No SDD-debt findings from the recent-PRs explorer** —
SDD-008 itself is sound; the observations are
PR-execution-level (mislabel, test-coverage parity,
supply-chain re-audit hand-off, toolchain version drift),
not design-level.

## Hand-off to subsequent explorers

- **Crate explorer**: pick up F-2031-002 (ntfy + signal test
  thinness); audit the 9 new crates' shapes, error
  taxonomies, secret-elision Debug impls.
- **Security explorer**: pick up F-2031-003 (0BSD re-audit);
  evaluate credential-handling paths for all 7 channels and
  wall(1) TTY-broadcast surface.
- **Docs explorer**: pick up F-2031-001 (D-7 label collision)
  if SDD-008 should grow a "PR labels" appendix.
- **Tests explorer**: pick up F-2031-002 from the test-seam
  angle (no `post()` / subprocess-exec coverage).
