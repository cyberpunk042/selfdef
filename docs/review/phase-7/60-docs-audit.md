# Phase 7 — docs audit

Audits the post-Phase-6 documentation surface: SDD-008's
Implementation-status table + PR-labels appendix, STARTER_CONFIG's
5 new blocks (`ack_link_base` + 4 Q-G channels), SECURITY.md's
notification-credentials row. Closes **F-2032-003** (Q-G
commit-label pedantry) in-place by extending SDD-008's
PR-labels appendix.

## Methodology

For each doc surface added by the post-Phase-6 cycle, audit
on three axes:

1. **Internal consistency** — claims within the doc don't
   contradict each other.
2. **Doc-vs-code reality** — every "shipped" claim is true;
   every PR-reference resolves; every config-key shape matches
   the actual schema.
3. **Operator discoverability** — F-2032-003-class label
   pedantry: do `Q-G`-prefixed commits show up in the audit
   trail clearly enough that a Phase-N+1 explorer can find
   them when grepping the merge log?

## Findings

### F-2032-003 (nice, closed-in-place)

**Surface**:
`docs/sdd/008-notifications-orchestration.md` — the "PR
labels — appendix" section (introduced by Phase 6's
F-2031-001 closure).

**Pre-fix appendix scope**: covered only the original SDD-008
cycle commits (PRs #109..#130 / D-1..D-8). The four
post-Phase-6 Q-G adapter commits (PRs #143-#146) use a
`feat(sdd-008): Q-G — <service> integration` title that
shares the visual shape of `D-N` design-point prefixes,
but `Q-G` is an **open-question identifier** in this SDD,
not a design point. A reader skimming the commit graph
for D-N labels won't find the Q-G commits and may need
to consult the appendix to map their actual design point.

The post-Phase-6 cycle also shipped D-4-HTTP-ack (PR #142)
and D-5e (PR #140), both legitimate D-N references but
they post-date the appendix's original coverage window.

**Closed in this PR**: SDD-008's PR-labels appendix grows
a "**Post-Phase-6 cycle commits (Phase 7 audit window)**"
section that:

- Names PR #140 (D-5e) explicitly, with cross-reference
  to F-2031-009 closure.
- Names PR #141 (`test(sdd-005): daemon-level pipeline
  tests`) and notes it's under SDD-005's D-3 pattern, not
  SDD-008 directly — useful because a future Phase 8 explorer
  walking the merge graph by SDD prefix won't expect that
  cross-SDD reference.
- Names PR #142 (D-4 HTTP ack) and clarifies its
  relationship to the original CLI half (PR #123).
- Names PRs #143-#146 (Q-G adapters) and codifies the
  **commit-label shorthand** going forward:
  - `D-N` prefix → touches design point D-N.
  - `Q-X` prefix → pattern instance serving open question
    Q-X.
  - No prefix → pure D-2 pattern instance.

This shorthand makes the next round of label-pedantry
findings systematically catchable rather than ad-hoc.

## Other doc-surface observations (no findings)

### Implementation-status table update

The table claims every D-N and Q-G row is "shipped". After
the post-Phase-6 cycle, all four Q-G rows shipped and D-9
remains explicitly deferred. The pre-Phase-7 version had
placeholder PR references like "post-Phase-6 PR" / "post-D-4
PR" / "this PR"; this PR fills in the actual PR numbers
(#140, #142, #143, #144, #145, #146).

The table's preamble — "All design points D-1..D-8 shipped
during the Phase-6 cycle" — was technically narrowing the
scope of "all". This PR clarifies:

> All design points D-1..D-8 + D-5e + D-4 HTTP ack shipped;
> the original D-1..D-8 cycle ran as PRs #109..#130 under
> Phase 6; D-5e + D-4 HTTP-ack + the four Q-G adapter
> pattern-instances shipped post-Phase-6 as PRs #140..#146.

No finding — straight doc accuracy fix.

### STARTER_CONFIG (init.rs) coverage

Spot-checked the 5 new commented blocks added during the
post-Phase-6 cycle:

| Block | PR | Covers |
| --- | --- | --- |
| `[notifier].ack_link_base` | #142 | D-4 HTTP ack URL base |
| `[notifier.pagerduty]` | #143 | routing_key_file + endpoint + source |
| `[notifier.loki]` | #144 | endpoint + tenant_id + auth_token_file + source |
| `[notifier.opensearch]` | #145 | endpoint + index + auth_kind + username + auth_token_file + source |
| `[notifier.thehive]` | #146 | endpoint + api_key_file + source + alert_type |

Each block:

- Carries inline operator instructions (where to find the
  PD routing key, the Grafana Cloud stack id pattern, the
  OpenSearch auth-mode choice, the TheHive API-key
  generation steps).
- References `# SDD-008 Q-G` in the section comment.
- Shows a commented-out example matching the `from_config`
  contract exactly.

**Clean.** The OpenSearch block's `auth_kind` comment lists
the three options (`"none" | "basic" | "apikey"`) and
warns that unknown strings are rejected — matching the
Phase 7 crate-audit observation about explicit auth-mode
choice.

### SECURITY.md notification-credentials row

Spot-checked the post-Phase-6 additions to the credentials
row. After the four Q-G adapter PRs, the row enumerates:

- ntfy tokens (M4 + SDD-008 D-2b)
- signal-cli auth (D-2c)
- SMTP `password_file` (D-7 Q-E)
- Twilio `auth_token_file` (Q-D)
- Slack `webhook_url_file` (Q-C)
- Discord `webhook_url_file` (no Q-letter)
- PagerDuty `routing_key_file` (Q-G)
- Loki `auth_token_file` (Q-G)
- OpenSearch `auth_token_file` — flagged as "Basic password
  OR API key depending on `auth_kind`" (Q-G)
- TheHive `api_key_file` (Q-G)

10 credential paths in one row. Operator-readable but the
row is getting long. **No finding** — the structured
table format makes it scannable, and the per-channel
recommendation ("mode `0600`, daemon-owner-only") is
already factored out.

### No new SDDs

The post-Phase-6 cycle didn't ship any new SDD documents.
The 4 Q-G adapters are pattern instances under
`docs/dev/integrations.md`; D-4 HTTP ack + D-5e are
extensions of existing SDD-008 design points.

D-9 dashboard remains deferred (separate design
conversation), so no SDD-009 doc exists either.

## Cross-doc consistency

| Reference | Resolves? |
| --- | --- |
| SDD-008 Impl-status PR refs (#140..#146) | yes |
| SDD-008 PR-labels appendix → F-2031-001 + F-2032-003 ledger entries | yes |
| init.rs STARTER_CONFIG → Q-G adapter from_config contracts | yes |
| SECURITY.md notification-credentials → 10 channel auth secrets | yes |
| Phase 7 module audit → SDD-008 D-4 row | yes |
| Phase 7 integration audit → engine `unchecked_transaction` precedent in `record_ack_by_token` | yes |
| `docs/dev/integrations.md` → 4 Q-G crates pattern-instance check | yes (Phase 7 crate audit verified) |

All cross-references resolve. The PR-labels appendix is
now the authoritative cross-reference for both the
Phase 6 SDD-008 cycle AND the Phase 7 post-Phase-6 cycle.

## Status

- F-2032-003 closed in-place — SDD-008's PR-labels
  appendix extended with a "Post-Phase-6 cycle commits"
  section covering PRs #140-#146.
- SDD-008's Implementation-status table normalized: actual
  PR numbers in every row (no more "post-Phase-6 PR" /
  "this PR" placeholders).
- STARTER_CONFIG + SECURITY.md spot-checks pass.

## Hand-off

- **Tests explorer**: schema-migration test coverage (2
  new tests from F-2032-001 closure) + `EngineHarness`
  pattern review.
- **Security explorer**: F-2032-002 token-IS-auth re-audit.
  Note that the PR-labels appendix now disambiguates the
  Q-G commits cleanly, which makes future
  third-party-log-leak audit trails easier.
