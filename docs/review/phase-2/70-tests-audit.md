# Phase 2 — Tests audit

> Scope (per the Phase 2 charter): the new integration tests
> added during the post-Phase-1 cycle. Per-area ids prefix
> `T2-` and roll up to the ledger as `F-2027-NNN`.
>
> What this audit doesn't re-litigate: Phase 1's tests audit
> (every `F-2026-NNN` test finding closed during the previous
> cycle) and the SDD-005 test-contract itself (a separate
> review cycle re-asks "do the four categories still match the
> codebase?" every Phase).

## Headlines

- **No blockers, no important findings**. Test surface is
  largely in good shape: every Phase 2 closure PR shipped
  with regression tests (per
  `docs/review/phase-2/99-findings-ledger.md`'s closure
  notes), the SDD-005 categories are still accurate, and
  the three shared patterns (P-1 dry-run-noop, P-2
  Prometheus parser, P-3 real-broker NATS) are used by the
  modules / surfaces that need them.
- **10 nice findings** clustered into three themes:
  - **P-1 dry-run-noop adoption gaps** — three module-script
    tests (suricata, polarproxy, vpn-bridge profiles) don't
    pair their live-positive tests with the
    `snapshot_tree` / `assert_tree_unchanged` helper.
  - **Test-helper duplication** — `workspace_root()`,
    `module_dir()`, `last_stdout_line()`, `write_stub()` are
    re-implemented across 6+ test files even though
    `crates/selfdef-cli/tests/common/mod.rs` already exports
    canonical versions.
  - **Real-time sleeps in pipeline tests** — `m4_alert.rs`
    and `m8_honeytokens.rs` use `tokio::time::sleep` with
    multi-second deadlines instead of `tokio::time::pause()`,
    contrary to SDD-005's "Time" anti-pattern note.

## Per-area observations

### Area 1 — Category 3 module-script test gaps

The SDD-005 test contract requires every module-script test
to pair a live-positive case with a `dry_run_must_be_a_noop`
case (P-1 pattern). Three modules in the workspace ship only
one or the other:

- `crates/selfdef-cli/tests/module_suricata.rs` runs everything
  under `SELFDEF_DRY_RUN=1` (line ~64). The live-positive path
  — `SELFDEF_DRY_RUN=0` that actually loads suricata rules —
  has no regression test. **(T2-001)**
- `crates/selfdef-cli/tests/module_polarproxy.rs` runs every
  case under `SELFDEF_DRY_RUN=1` (line ~61) but doesn't pair
  with a `snapshot_tree` / `assert_tree_unchanged` assertion;
  the live-positive path is implicitly covered by the dry-run
  alone, which the contract refuses. **(T2-002)**
- `crates/selfdef-cli/tests/module_vpn_bridge_cloudflare.rs`
  and `crates/selfdef-cli/tests/module_vpn_bridge_tailscale.rs`
  cover the live-positive path for each profile but neither
  uses the P-1 helper to guard against the dry-run-becomes-
  live regression. **(T2-003)**

### Area 2 — Test-helper duplication

`crates/selfdef-cli/tests/common/mod.rs` already exports a
canonical `workspace_root` / `module_dir` / `last_stdout_line`
/ `write_executable` / `prepended_path` family (re-exported
under `#[allow(dead_code)]`). Several test files still
re-implement them locally:

- `workspace_root()` and `module_dir()` are duplicated in at
  least `module_suricata.rs`, `module_bridge_l2.rs`,
  `module_polarproxy.rs`, `module_tetragon.rs`,
  `module_integrity_sentinel.rs`, `module_observability.rs`,
  `module_agent_guard.rs`, `module_tetragon_signing.rs`,
  `cli_keys_verify_dir.rs`, `cli_events_follow.rs`,
  `cli_init.rs`, `cli_doctor.rs`, `cli_rbac_check.rs`, and
  `cli_api_rotate_token.rs`. **(T2-004)**
- `last_stdout_line()` exists locally in at least
  `module_observability.rs`, `module_tetragon.rs`,
  `module_integrity_sentinel.rs`, `module_polarproxy.rs`,
  `module_vpn_bridge_cloudflare.rs`, and
  `module_tetragon_signing.rs`. **(T2-005)**
- `write_executable()` is duplicated across the vpn-bridge
  test files (cloudflare, tailscale, multi_instance) and
  `module_tetragon_signing.rs`. **(T2-006)**

Each duplication is byte-identical or near-byte-identical;
deduping reduces churn when a helper grows a new option
(e.g. when `prepended_path` was added in F-2027-014 it had
to be added to ~8 files).

### Area 3 — Real-time sleeps in pipeline tests

`docs/dev/test-contract.md:215-218` is explicit: *"Use
`tokio::time::pause()` and explicit advances rather than
`sleep`-and-poll. The few existing `tokio::time::sleep` calls
in tests are bugs waiting to flake — convert when you touch
them."* Two pipeline tests still violate the contract:

- `crates/selfdef-daemon/tests/m4_alert.rs` lines ~148, ~165,
  ~184 — three `tokio::time::sleep` / `timeout` calls with
  multi-second deadlines, no `tokio::time::pause()`. Slow CI
  scheduler jitter can flake this. **(T2-007)**
- `crates/selfdef-daemon/tests/m8_honeytokens.rs` lines ~114,
  ~120-146 — seven real-time sleeps across three test cases.
  Same flakiness profile. **(T2-008)**

### Area 4 — Test-fixture isolation gaps

- `crates/selfdef-api/tests/m12_api.rs` `dummy_action_set()`
  helper (~line 179) writes to
  `std::env::temp_dir().join("selfdef-api-test-snapshots")`
  and `selfdef-api-test-forensics` — host-global paths shared
  across parallel test runs. Identical-failure-pattern to
  F-2027-024 manifest-isolation (PR #65). Should switch to
  `tempfile::tempdir()` per test. **(T2-009)**
- `crates/selfdef-api/tests/m12_api.rs:56`
  `std::mem::forget(dir)` leaks the SQLite tempdir on
  purpose ("so the SQLite file outlives the test scope"),
  but accumulates stale SQLite files in `/tmp` across test
  runs. The pattern is documented in code but a
  test-fixture-cleanup helper that holds the tempdir on the
  Fixture struct would close the leak. **(T2-010)**

### Area 5 — P-2 Prometheus parser adoption

The hand-rolled Prometheus exposition parser in
`crates/selfdef-api/tests/m12_api.rs::prom` (the SDD-005 P-2
fixture) is the workspace-standard way to validate metrics
bodies. Several metrics tests in the same file bypass it:

- `m12_api.rs::metrics_reflect_ingest_counters_via_record_event`
  (~line 529) uses raw `body.contains("selfdef_findings_total 1")`
  substring checks; would miss duplicate-sample emissions or
  malformed-line shapes that the P-2 parser catches. Convert
  the two existing substring-style tests to consume the parser
  output. **(T2-011)**

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| T2-001 | nice | suricata live-positive test gap | module-test backfill |
| T2-002 | nice | polarproxy P-1 dry-run-noop pair missing | module-test backfill |
| T2-003 | nice | vpn-bridge cloudflare/tailscale P-1 gap | module-test backfill |
| T2-004 | nice | `workspace_root` / `module_dir` duplication | common/mod.rs migration |
| T2-005 | nice | `last_stdout_line` duplication | common/mod.rs migration |
| T2-006 | nice | `write_executable` duplication | common/mod.rs migration |
| T2-007 | nice | m4_alert real-time sleeps | pause()-conversion |
| T2-008 | nice | m8_honeytokens real-time sleeps | pause()-conversion |
| T2-009 | nice | `dummy_action_set` shared tmp paths | api-test isolation |
| T2-010 | nice | `std::mem::forget(dir)` SQLite leak | api-test isolation |
| T2-011 | nice | metrics tests bypass P-2 parser | parser-adoption |

All 11 entries land as F-2027-046 through F-2027-056 with
`nice` severity. Five natural closing-PR clusters:

- **module-test backfill** (T2-001 + T2-002 + T2-003) — three
  modules' P-1 dry-run-noop pairs.
- **common/mod.rs migration** (T2-004 + T2-005 + T2-006) —
  one PR migrates every duplicated helper to the existing
  shared module.
- **pause()-conversion** (T2-007 + T2-008) — convert
  `m4_alert.rs` and `m8_honeytokens.rs` real-time sleeps to
  `tokio::time::pause()`-driven assertions.
- **api-test isolation** (T2-009 + T2-010) — switch the
  shared-tmp helpers to per-test `tempdir()` + hold the
  handle on the Fixture struct.
- **parser-adoption** (T2-011) — one PR converts the
  remaining metrics substring assertions to the P-2 parser.
