# Tests audit

> Scope: `crates/*/tests/`, in-source `#[cfg(test)]` modules,
> `tests/replay/` corpora. Per-area finding ids prefix `T-`.

The test surface is strong on **per-module happy-path coverage**
(the CLI test suite has 12 integration files exercising every
shipped module's apply / check / uninstall path) and weak on
**cross-subsystem stress, isolation tests for the persistence /
messaging layers, and verification of claimed invariants** (hot
reload, idempotent actions, NATS round-trip).

The most consequential gap is that the new `/metrics` integration
tests don't actually assert the route requires only `Capability::Read`,
and that there's no test today that would fail if the Tetragon
collector's hard-coded `Informational` severity (see I-007) were
ever fixed and then regressed.

---

## Per-suite notes

### `selfdef-cli` (12 integration files)

- **Comprehensive happy-path coverage** of every module's apply
  / check / uninstall + structured-status JSON.
- **Helper duplication**: `workspace_root`, `module_dir`,
  `write_file`, `last_stdout_line` are reimplemented in nine
  module test files. Drift risk — a workspace layout change
  needs nine edits. Recommendation: `tests/common/mod.rs`. **(T-001)**
- **`cli_modules_apply.rs:118`** — `assert!(stdout.contains("Summary:
  2 ok"))`. A cosmetic summary rewording would fail this without
  any real bug. Cross-cutting brittleness pattern. **(T-002)**
- **Dry-run honesty isn't verified**. `module_*.rs` tests run
  apply.sh with `SELFDEF_DRY_RUN=0` (live) and verify
  side-effects. They never assert that dry-run produces **no**
  side effects (e.g., re-run dry-run, verify on-disk state
  unchanged). A regression making dry-run mutate state would
  pass every existing test. **(T-003)**
- **Idempotent reapply is tested for tetragon only**
  (`module_tetragon.rs:159–186`, byte-stable config rendering
  across two applies). Other modules claiming idempotence
  (bridge-l2, vpn-bridge, suricata, polarproxy) have no
  equivalent test. **(T-004)**

### `selfdef-api/tests/m12_api.rs`

- **`/metrics` tests** (recent, well-structured):
  - Content-Type starts-with `text/plain` — passes if header
    omits `version=0.0.4`. Loose. **(T-005)**
  - HELP / TYPE substring checks — passes even if metric
    duplicated or malformed. Substring matching is too permissive
    for exposition format. **(T-005, cont.)**
  - Counter ingest end-to-end via spawned task with
    `receiver_count()` wait — correct, race-free.
- **Missing**: no test asserts `/metrics` accepts a Read-only
  bearer token. The integration test wraps the app with
  `with_full_capability`; nothing verifies that a Read-cap
  request to `/metrics` succeeds and a no-cap request 401s.
  **(T-006)**

### `selfdef-correlator/tests/rule_tests.rs`

- Walks `rules/sigma/` and runs every rule with a sibling
  `.tests.yaml`. Excellent discovery test.
- **Missing**: SIGHUP / hot-reload while events are in flight.
  `m5_sigma.rs:128–164` exercises `load_rules()` in isolation,
  not under live traffic. The claim "rules reload without
  dropping events" is unverified. **(T-007)**

### `selfdef-daemon/tests/m{3..11}_*.rs` (8 files)

- End-to-end pipelines: auditd → bus → store (m3), full alert
  path with wiremock-asserted ntfy POST (m4), Sigma engine over
  a replay corpus (m5), collector replay corpora (m6),
  honeytokens + responder dispatch (m8), ssh-wrap (m9), eBPF
  (m10), forensics (m11).
- Strong coverage for the named milestones. **No daemon-level
  integration test for the AI-machine track** (tetragon
  policies → bus → responder → notifier). That's an end-to-end
  test that would have caught I-007 + I-008. **(T-008)**
- `m4_alert.rs:165–189` — assumes responder dispatches within
  ~200ms. A regression that delayed dispatch by ~1s would only
  be flagged because the wiremock expectation count would fail
  on `verify_on_drop`, not because the timing assertion fired.
  Not strictly brittle but the timing budget is hidden.

### Crates with **zero integration tests**

From the inventory: `selfdef-bus`, `selfdef-collector-auditd`,
`selfdef-collector-canary`, `selfdef-collector-ebpf`,
`selfdef-collector-eventstream`, `selfdef-collector-journald`,
`selfdef-collector-suricata`, `selfdef-collector-tetragon`,
`selfdef-config`, `selfdef-ebpf-common`, `selfdef-nats`,
`selfdef-notifier`, `selfdef-responder`, `selfdef-ssh-wrap`,
`selfdef-store`.

Some of these are reasonable (small surface, well-covered by
in-source unit tests). The ones that worry the audit:

- **`selfdef-store`** — persistence layer for the whole system.
  Unit tests verify schema + single-thread inserts. **No
  concurrent-insert test, no daemon-crash-recovery test.**
  Multi-collector simultaneous writes are the normal mode of
  operation. **(T-009)**
- **`selfdef-nats`** — durability claims (JetStream durable
  consumer survives broker restart) are entirely unverified at
  integration level. **No real NATS server stood up in a test.** **(T-010)**
- **`selfdef-collector-tetragon`** — given I-007's discovery,
  this collector deserves explicit tests covering: every
  Tetragon event class it handles, severity mapping (when
  fixed), field extraction. Today no test would catch a
  regression in the Tetragon → Event translation. **(T-011)**
- **`selfdef-responder`** — daemon-level tests (m4, m8) cover
  dispatch via the live bus, but the responder itself has no
  isolated test for action enumeration ordering, dry-run
  side-effect suppression, or unknown-action handling. **(T-012)**

### `tests/replay/` corpora

- Replay corpora exist for each collector (`auditd`, `journald`,
  `tetragon`, `suricata`, `canary`). Useful for the daemon
  integration tests.
- **No corpus-coverage audit**: sigma rules without a matching
  replay corpus, or replay events that no rule matches. Both are
  fine in absolute terms but worth surfacing for triage. **(T-013)**

---

## Tests that pass for the wrong reason

- `cli_modules_apply.rs:118` (T-002) — Summary substring.
- `m12_api.rs:475–482` (T-005) — Substring matches on Prometheus
  exposition; format violations could pass.
- `m12_api.rs:469` (T-005) — `starts_with("text/plain")` allows
  any `text/plain; <anything>`, missing the Prometheus version
  pragma.

---

## Tests that should exist but don't

Numbered list, in priority order:

1. **AI-machine end-to-end** — daemon test that simulates an
   agent-guard policy firing, asserts the operator gets a
   finding through the responder. Today's failure (I-007 + I-008)
   would be caught.
2. **NATS round-trip with a real server** — JetStream durability
   regression test.
3. **`/metrics` capability gating** — `Read` token allowed,
   no token denied, `Full` allowed.
4. **Concurrent store inserts** — multi-collector simulation.
5. **SIGHUP rule reload under traffic** — verify no events
   dropped.
6. **Dry-run side-effect-suppression** — assert that
   `SELFDEF_DRY_RUN=1` produces no on-disk delta after apply.
7. **Collector reconnect** — Tetragon / Suricata socket
   close-and-reopen.
8. **Bus backpressure** — flood the bus, verify lossy subscribers
   degrade gracefully.
9. **Config-error startup** — daemon receives a malformed
   `selfdef.toml`, exits cleanly with a useful error.
10. **Replay corpus audit** — assert every sigma rule has a
   matching replay corpus entry; every replay corpus event is
   matched by ≥1 rule (or marked benign).

These are all flagged in the ledger as `T-NNN` with severity
`important` or `SDD-debt` — most of them are SDD-debt (we have
no design doc for "what is our test contract for layer X").

---

## Findings raised in this section

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| T-001 | nice | `crates/selfdef-cli/tests/*` | Helper functions duplicated across 9 test files; refactor to `tests/common/mod.rs`. |
| T-002 | nice | `cli_modules_apply.rs:118` and similar | Substring assertions on `Summary:` lines are brittle against cosmetic output changes. |
| T-003 | important | every `module_*.rs` test | Dry-run mode is not negatively asserted — a regression making `SELFDEF_DRY_RUN=1` mutate state would pass every existing test. |
| T-004 | nice | per-module test suites | Idempotent-reapply coverage is tetragon-only; other modules claim it without test. |
| T-005 | important | `m12_api.rs:469–482` | `/metrics` content-type asserted with `starts_with`; exposition body asserted with substring match. Both pass for malformed output. |
| T-006 | important | `m12_api.rs` | No test asserts `/metrics` is accessible with a Read-only token (it is — but a future capability tightening could regress silently). |
| T-007 | important | `selfdef-correlator/tests/` | No SIGHUP-while-processing test. Hot-reload claim from ARCHITECTURE.md is unverified under traffic. |
| T-008 | blocker | daemon integration tests | No AI-machine end-to-end test. The bus-to-notifier breakage flagged as I-007 + I-008 would have been caught by such a test. |
| T-009 | important | `selfdef-store` | No concurrent-insert or crash-recovery test. Store is the persistence path for every collector. |
| T-010 | important | `selfdef-nats` | No real-broker round-trip test. JetStream durability promises are unverified. |
| T-011 | important | `selfdef-collector-tetragon` | No isolation test. Every Tetragon → Event translation goes through the daemon tests only. |
| T-012 | nice | `selfdef-responder` | No isolation test for action dispatch / dry-run / unknown-action handling. |
| T-013 | nice | `rules/sigma/` + `tests/replay/` | No audit of rule ↔ corpus coverage. Stale corpora and untested rules could accumulate silently. |
