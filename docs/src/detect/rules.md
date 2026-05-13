# Writing rules

selfdef's correlator is the [Sigma](https://sigmahq.io)
engine. Rules live under `rules/sigma/<tactic>/*.yml`,
organised by ATT&CK tactic. The daemon loads every YAML in
`rules_dir` (default `/etc/selfdef/rules`) at startup and
hot-reloads on SIGHUP.

## Anatomy of a rule

```yaml
title: SSH brute-force
id: <uuid>
status: stable
description: |
  Three or more failed SSH auths from the same source IP within
  60 seconds.
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: selfdef
date: 2026-01-01
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  service: journald
detection:
  failed_auth:
    raw.SYSLOG_IDENTIFIER: sshd
    raw.MESSAGE|contains:
      - "Failed password"
      - "Invalid user"
  count_by_src:
    timeframe: 60s
    field: src_endpoint.ip
    threshold: 3
  condition: failed_auth | count_by_src
level: high
falsepositives:
  - Operator typing their own password wrong three times.
```

`raw.<field>` accesses the original collector payload
(e.g. journald's structured fields, Tetragon's
`process_kprobe.policy_name`). Top-level fields like
`src_endpoint.ip` come from the parsed `selfdef_core::Event`.

## Promoting an event to a finding

A matched rule emits a synthetic event with
`category_uid = 2` (Findings). The responder filters on
that category — only findings reach `NotifyAction` and the
other actions. Raw collector events go to the store but not
the notifier.

This is the leverage point for module-level promotion:
`agent-guard` Tetragon events arrive as Process / FileSystem
Activity (categories 1) and need a sigma rule to promote
them. See SDD-001.

## Levels

`level:` maps to `severity_id`:

| Sigma level | severity_id | actionable? |
| --- | --- | --- |
| `informational` | 1 (Informational) | no |
| `low` | 2 (Low) | no |
| `medium` | 3 (Medium) | no |
| `high` | 4 (High) | yes |
| `critical` | 5 (Critical) | yes |

The responder's `is_actionable` filter (in
`selfdef_core::severity`) cuts at `High`.

## Reload semantics

`SIGHUP` triggers a full re-read into a fresh in-memory
ruleset. The old set stays live until the new one validates;
a malformed rule keeps the old set running and logs the
parse error. No in-flight events are dropped during reload.

## See also

- [Testing rules](./testing.md) for the per-rule corpus
  pattern.
- [ATT&CK coverage](./attack_coverage.md) for the matrix the
  shipped ruleset covers.
- [Sigma upstream docs](https://sigmahq.io) for the full
  expression grammar.
