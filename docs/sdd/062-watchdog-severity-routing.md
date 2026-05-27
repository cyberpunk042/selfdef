# SDD-062 — Route watchdog severities through the notifier engine

Status: accepted (rule shipped experimental)
Depends on: SDD-001 (collector→correlator→responder→notifier chain),
SDD-061 (shared watchdog scan helpers)

## Implementation status

- **D-1** — single tag-prefix Sigma rule that promotes any `selfdef-*`
  watchdog journald emission carrying `"severity":"alert"` to a Detection
  Finding. SHIPPED (`rules/sigma/execution/selfdef_watchdog_alert.yml`).
- **D-2** — companion `.tests.yaml` fixture run by the
  `selfdef-correlator` `every_rule_with_tests_passes` harness. SHIPPED.
- **D-3** — warn / ok tiers are NOT paged (local-triage signal, mirroring
  the agent-guard audit-mode precedent). DECIDED. **Revised by D-5**: the
  warn tier is now *routed to a non-paging finding* (it was originally
  dropped entirely); the no-page property is unchanged. The `ok` tier and
  the `-detail` lines remain unrouted.
- **D-4** — the rule is tag-prefix, not tag-enumerated, so it covers the
  WHOLE `selfdef-*` watchdog set, not just the SDD-061 module-lib scanners.
  Rule-test coverage now spans both axes: the module-lib detection-watchdogs
  (exec/injection/writable surfaces + the SDD-063 `module_lib_missing`
  fail-loud) AND the integrity/baseline watchdogs (suid-sgid, file-caps,
  rhosts, securetty, nsswitch, sysctl-hardening, …), proving an alert from
  either axis reaches the Detection Finding → `selfdef_findings_by_rule_total`
  → `SelfdefWatchdogAlertFinding` pager path, while warn/ok from either axis
  does not. 99 rule-test cases. SHIPPED. Functional-severity behavior of the
  watchdogs themselves is locked by the per-module `packaging/test/L2-*-watchdog.bats`
  suites (1154 L2 cases across 105 suites) — see `L2-watchdog-dedup-guard.bats`,
  which fails if a module-lib watchdog ships without an L2 suite.
- **D-5** — the `warn` tier is routed to a **non-paging** Detection Finding
  (operator direction 2026-05-27, revising D-3's original drop-it stance). A
  sibling tag-prefix rule `selfdef_watchdog_warn.yml` (`level: informational`,
  title `selfdef watchdog warn-tier finding`) matches `selfdef-*` +
  `"severity":"warn"`. At Informational it sits below the notifier panic
  floor (Medium default) so the notifier path never pages it, and it carries
  NO Prometheus alert, so the metrics path never pages it either — but it
  IS dashboard-visible via `selfdef_findings_by_rule_total{rule="selfdef
  watchdog warn-tier finding"}` (new stat panel id 10, blue/never-red) for
  trend triage. The warn rule is mutually exclusive with the alert rule (a
  body is either `"severity":"warn"` or `"severity":"alert"`). 7 rule-test
  cases (warn→finding incl. an integrity-axis case; alert/ok/non-selfdef/
  non-journald/-detail → 0). Rule-tests now 106 across 22 rules. SHIPPED
  (`rules/sigma/execution/selfdef_watchdog_warn.yml`).

## Why now

The ~40 detection-watchdog modules added across the recent
module-ecosystem batches each emit a structured finding via
`logger -t selfdef-<tag>` whose JSON body carries
`"severity":"ok|warn|alert"`. They do **not** set the syslog `PRIORITY`,
so the journald collector
(`crates/selfdef-collector-journald/src/lib.rs`) maps every one of them to
`SeverityId::Informational` and classifies them generically
(`class_uid 0`). No Sigma rule matched the `selfdef-*` identifiers, so an
`alert`-tier watchdog finding — a planted `execute()`, a writable-rooted
LOLBin, an injection-pattern hit — reached journald but never became a
Detection Finding and never fired the responder's notifier chain.

This is the "route the 40 new watchdogs' severities through the
notifier-engine" slice of the operator-chosen *wire modules into stack*
direction.

## Goals

1. An `alert`-tier emission from ANY current-or-future `selfdef-*`
   watchdog becomes a high-severity Detection Finding, with no per-module
   wiring — one rule, exactly as SDD-061 made the scan idioms one library
   helper.
2. The `-detail` companion lines (plain `ADDED …` / `REMOVED …` text, no
   JSON) and the `warn`/`ok` tiers do not page.
3. Test-first, auto-discovered by the existing rule-test harness.

## Non-goals

- NOT changing how the watchdogs emit (no `logger -p` retrofit across 40
  modules; matching the JSON body is the lighter, backward-compatible
  hook).
- NOT a per-module rule. The whole point is one tag-prefix rule.
- NOT routing the `warn` tier to the pager (see D-3).

## Design

### D-1 — one tag-prefix rule, body-matched on severity

`rules/sigma/execution/selfdef_watchdog_alert.yml` selects on three ANDed
criteria:

```yaml
detection:
  watchdog_alert:
    source: journald
    raw.SYSLOG_IDENTIFIER|startswith: "selfdef-"
    message|contains: '"severity":"alert"'
  condition: watchdog_alert
level: high
```

- `source: journald` — only journald-collected events (the collector tags
  its events `journald`).
- `raw.SYSLOG_IDENTIFIER|startswith: "selfdef-"` — any selfdef module
  identifier; the raw journald object is preserved under `raw` by the
  collector's `with_raw(raw)`.
- `message|contains: '"severity":"alert"'` — the collector copies the
  journald `MESSAGE` (the watchdog's JSON body) onto the event message via
  `with_message`. Matching the verbatim `"severity":"alert"` token is what
  discriminates the alert tier from `warn`/`ok` and from the `-detail`
  plain-text lines (which carry no such token).

`level: high` is the rule's contribution — it is independent of the
event's collector-assigned `SeverityId::Informational`, which is exactly
how the chain is meant to promote: the rule, not the raw syslog priority,
sets finding severity.

### D-2 — test-first

`selfdef_watchdog_alert.tests.yaml` is run by
`crates/selfdef-correlator/tests/rule_tests.rs`
(`every_rule_with_tests_passes`), which auto-discovers any rule with a
sibling `.tests.yaml`. Cases:

| case | expected_findings | proves |
|---|---|---|
| alert from a `selfdef-*` tag over journald | 1 | the routing fires |
| warn from a `selfdef-*` tag | 0 | severity tier discriminates |
| ok from a `selfdef-*` tag | 0 | severity tier discriminates |
| `-detail` plain-text line from a `selfdef-*` tag | 0 | body match, not tag-only |
| alert body but non-`selfdef-` identifier | 0 | prefix scopes it |
| alert from a `selfdef-*` tag but source != journald | 0 | source scopes it |

### D-3 — warn/ok are local-triage, not paged (warn routing revised by D-5)

Mirrors the agent-guard precedent (`hardening/agent_guard_violation.yml`):
audit-mode / non-meaningful signal stays out of the pager. Only the `alert`
tier (planted exec / writable LOLBin / injection pattern /
world-writable-or-non-root config) pages.

**Revision (D-5, 2026-05-27):** the `warn` tier is no longer dropped — it is
routed to a *non-paging* Informational Detection Finding (sibling rule
`selfdef_watchdog_warn.yml`) so it surfaces on the dashboard + in
`selfdef_findings_by_rule_total` for trend triage, while staying below the
notifier panic floor and carrying no Prometheus alert. The no-page property
of warn is preserved; only its visibility improved. The `ok` tier + the
`-detail` plain-text lines remain unrouted.

### D-5 — warn routed to a non-paging finding

A second tag-prefix rule, identical in shape to D-1 but matching
`"severity":"warn"` at `level: informational`. Mutually exclusive with the
alert rule (a watchdog JSON body carries exactly one of `"severity":"warn"`
/ `"severity":"alert"`). Non-paging is enforced by two independent
mechanisms: (1) Informational is below the notifier dispatcher's panic floor
(Medium default), so the in-process notifier path suppresses it; (2) no
Prometheus alert is wired on the `selfdef watchdog warn-tier finding` metric
bucket, so the metrics path never fires. Dashboard panel id 10 renders the
1h warn count in blue (never red). See `selfdef_watchdog_warn.tests.yaml`.

## Testing

```
cargo test -p selfdef-correlator --test rule_tests
selfdefctl rules lint    # title/tags/falsepositives/author present
```

## References

- SDD-001 — collector → correlator → responder → notifier chain.
- SDD-061 — shared watchdog scan helpers (the sibling single-source-of-truth slice).
- `rules/sigma/hardening/agent_guard_violation.yml` — the tag-prefix +
  meaningful-action precedent this rule follows.
