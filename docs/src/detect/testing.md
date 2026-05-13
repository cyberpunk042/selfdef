# Testing rules

Every sigma rule under `rules/sigma/<tactic>/<name>.yml`
should ship with a sibling `<name>.tests.yaml` corpus. The
correlator's discovery test
(`crates/selfdef-correlator/tests/rule_tests.rs`) walks the
rules directory at test time, loads every rule that has a
`.tests.yaml`, runs the cases, and reports failures.

## Corpus shape

```yaml
# rules/sigma/credential_access/ssh_bruteforce.tests.yaml
positive:
  - name: "three failed auths from same IP within 60s"
    events:
      - { time: 0,  raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
      - { time: 10, raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
      - { time: 20, raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
    expect_findings: 1

negative:
  - name: "two failed auths is below threshold"
    events:
      - { time: 0,  raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
      - { time: 10, raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
    expect_findings: 0

  - name: "three failures spaced past the window"
    events:
      - { time: 0,    raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
      - { time: 60,   raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
      - { time: 120,  raw: { SYSLOG_IDENTIFIER: sshd, MESSAGE: "Failed password for root from 198.51.100.1" }, src_endpoint: { ip: "198.51.100.1" } }
    expect_findings: 0
```

`time` is seconds since the corpus epoch. Other fields are
whatever your rule's `detection:` block reads — populate
enough to make positive / negative cases meaningful.

## Running

```bash
cargo test -p selfdef-correlator --test rule_tests
```

A failing test names the rule, the case, and the actual vs
expected finding count. Add new corpora by dropping
`<rule>.tests.yaml` next to the rule; the discovery walker
picks them up automatically.

## What to test for

- **Positive**: every distinct trigger pattern.
- **Negative**: at least one event sequence that *almost*
  matches but shouldn't. This is where false-positive
  pressure surfaces.
- **Boundary**: timeframe edges (one event 1s after the window
  closes, etc.).
- **Field absence**: rules that match on `raw.X` should
  tolerate an event without `raw.X` (no panic, no false
  positive).

## Corpus coverage

Audit finding F-2026-064 flags the absence of an audit
that asserts every shipped rule has a corpus and every
corpus event matches ≥1 rule. Until that lands, do this
check by hand when adding a rule.
