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
- **D-3** — warn / ok tiers are deliberately NOT paged (local-triage
  signal, mirroring the agent-guard audit-mode precedent). DECIDED.

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

### D-3 — warn/ok are local-triage, not paged

Mirrors the agent-guard precedent (`hardening/agent_guard_violation.yml`):
audit-mode / non-meaningful signal stays out of the pager. A `warn`
(config added/changed/removed) or `ok` watchdog tick is local-triage
signal — visible in journald and on the dashboard, but not a Detection
Finding. Only the `alert` tier (planted exec / writable LOLBin / injection
pattern / world-writable-or-non-root config) pages.

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
