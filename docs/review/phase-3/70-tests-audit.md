# Phase 3 — Tests audit

> Scope (per the Phase 3 charter): the new test cases and test
> infrastructure refactors shipped during the Phase 2 closure cycle
> (commits `2d918ac` → `ee0e1a9`). Audit the ~25 new tests, the
> `common/mod.rs` migration adoption across 17 files, the
> `start_paused = true` conversion in pipeline tests, and new patterns
> (SseParser unit tests, validate_rbac_subject tests, cap-saturation
> tests, P-1 backfill tests).
>
> This audit follows the same methodology as Phase 2's tests explorer
> (Phase 2 findings raised T2-001..011; Phase 3 mirrors that shape
> with F-2028-NNN findings).

## Headlines

- **No blockers, no important findings**. The Phase 2 closure-cycle
  test work was extensive: every test-infrastructure refactor
  (common-mod adoption, pause()-conversion, tempdir-per-test isolation)
  shipped with correct implementation. The ~25 new tests are well-scoped
  and cover critical paths (SseParser multibyte UTF-8 split handling,
  validate_rbac_subject charset + length, events-stream SSE-cap
  saturation, relay-applied manifest + uninstall round-trip, token-file
  mode validation, dry-run-noop P-1 parity across all 8 modules).
- **3 nice findings** clustered into two themes:
  - **snapshot_tree / assert_tree_unchanged import completeness** —
    11 module-test files use `common::snapshot_tree` and
    `common::assert_tree_unchanged` via module-qualified paths without
    importing them explicitly (works, but breaks consistency with
    `last_stdout_line` + `write_executable` imports).
  - **Test-isolation pattern clarity** — `dummy_action_set()` in
    `m12_api` still uses `mem::forget` to keep tempdir paths alive,
    with a clear comment. Different from `build_state()` which returns
    the dir handle, but documented intent is explicit.

## Per-area observations

### Area 1 — common/mod.rs adoption completeness

All 17 CLI test files that need shared helpers import from `common/mod.rs`:
`module_suricata`, `module_bridge_l2`, `module_agent_guard`,
`module_integrity_sentinel`, `module_observability`, `module_tetragon`,
`module_polarproxy`, `module_vpn_bridge`, `module_vpn_bridge_cloudflare`,
`module_vpn_bridge_tailscale`, `module_vpn_bridge_multi_instance`,
`module_tetragon_signing`, `cli_rbac_check`, `cli_modules_apply`,
`cli_modules_uninstall`, `cli_modules_daemon_requires`,
`cli_modules_shared_lib`.

Cross-check across 11 of these files shows a pattern: every module test
file imports `use common::` with a subset of helpers
(e.g. `use common::{last_stdout_line, prepended_path, write_executable}`)
but then calls `common::snapshot_tree` and `common::assert_tree_unchanged`
via qualified paths without explicit import. This works because the
module is `#[allow(dead_code)]` and all callsites are intra-crate, but
it breaks the consistency convention where helpers are either all
imported or all module-qualified.

Files with this asymmetry: `module_agent_guard`, `module_bridge_l2`,
`module_integrity_sentinel`, `module_observability`, `module_polarproxy`,
`module_suricata`, `module_tetragon`, `module_tetragon_signing`,
`module_vpn_bridge`, `module_vpn_bridge_cloudflare`,
`module_vpn_bridge_tailscale`.

No files define duplicate implementations of shared helpers — the
phase-2 migration fully eliminated hand-rolled `workspace_root`,
`module_dir`, etc. **(F-2028-025)**

### Area 2 — Pipeline test pause()-conversion completeness

The m4_alert.rs (`canary_touch_dispatches_actions_in_dry_run`) and
m8_honeytokens.rs (`canary_touch_dispatches_actions_in_dry_run`) tests
that were flagged in Phase 2 now have `#[tokio::test(flavor = "current_thread", start_paused = true)]`.
Both tests use `tokio::time::sleep(Duration::from_millis(50/100))` in
polling loops, which correctly becomes virtual time under `start_paused`.
The tests also use `tokio::time::Instant::now()` with deadline
comparisons, which is the right pattern for virtual-time tests.

One test in m8_honeytokens (`responder_panic_fire_path_runs_lockdown_in_dry_run`,
line 155) lacks `start_paused` but contains no `sleep` or time-sensitive
code, so no conversion is needed.

The m12_api.rs `events_stream_rejects_over_cap_with_503` test (line 792)
uses a real-time `tokio::time::sleep(Duration::from_millis(100))` (line
849) without `start_paused`, but the test is not classified as a
pipeline-time-sensitive integration test — it's a cap-saturation
integration test that needs the sleep for task-scheduling breathing room,
and 100ms is acceptable on CI. No action required.

### Area 3 — New test-case coverage

The Phase 2 closure cycle shipped test coverage for:

- **SseParser unit tests** (9 tests, `crates/selfdef-cli/src/follow.rs`
  lines 406–536): cover single-frame parsing, event-type pairing, comment
  filtering, shutdown/lagged markers, partial-line buffering, unknown
  event types, and critically, UTF-8 multibyte split-across-chunks
  handling (4-byte 🦀 crab and 3-byte 漢 han characters). F-2028-018
  closure. **(F-2028-026)**
- **validate_rbac_subject unit tests** (7 tests,
  `crates/selfdef-cli/src/main.rs` lines 1499–1547): cover
  system:* builtins, serviceaccount forms, email + group formats,
  empty-string rejection, shell-metachar rejection ($, `, |), ANSI-escape
  rejection, whitespace rejection, and over-length rejection (254+ byte
  cap). F-2027-060 closure. **(F-2028-027)**
- **validate_rbac_subject integration test**
  (`crates/selfdef-cli/tests/cli_rbac_check.rs`): invokes the binary with
  invalid subjects and asserts stderr mentions the rejection reason. **(F-2028-027 / part 2)**
- **events_stream_rejects_over_cap_with_503** integration test
  (`crates/selfdef-api/tests/m12_api.rs` line 792–862): opens
  `MAX_SSE_SUBSCRIBERS` (64) concurrent streams, asserts the 65th is
  refused with 503, drops one held stream, publishes an event to wake the
  writer, and asserts the freed slot accepts a new subscriber. Uses
  `tempfile::TempDir` per test (F-2027-054 closure). **(F-2028-028)**
- **live_apply_invokes_nft_load_and_systemctl_start** (module_suricata.rs
  line 210): runs suricata's apply.sh without `SELFDEF_DRY_RUN`, stubs
  nft and systemctl to verify they're invoked (closure of F-2027-046).
  Paired with `dry_run_apply_must_be_a_noop_on_disk` (line 173). **(F-2028-029)**
- **cloudflare_dry_run_must_be_a_noop_on_disk** + **tailscale_dry_run_must_be_a_noop_on_disk**
  (module_vpn_bridge_cloudflare.rs line 143, module_vpn_bridge_tailscale.rs
  line 164): P-1 dry-run-noop backfill with `snapshot_tree` /
  `assert_tree_unchanged` pairs (closure of F-2027-048). **(F-2028-030)**
- **events_follow_token_file_refuses_world_readable_mode**
  (cli_events_follow_tcp.rs line 206–232): creates a token file with
  mode 0o644, invokes the CLI, asserts stderr names the offending mode
  (closure of F-2028-004). **(F-2028-031)**
- **relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it**
  (module_vpn_bridge.rs line 248–319): run-apply records the nft_path
  in the manifest (via `module_record_file`), uninstall enumerates from
  manifest and removes it (closure of F-2028-015). **(F-2028-032)**

All test coverage aligns with closure findings, no gaps observed.

### Area 4 — build_state() TempDir handle + metrics parser adoption

**m12_api.rs** `build_state()` (line 25) now returns a 4-tuple including
`tempfile::TempDir`. The comment (line 55–61) explains the fix: prior
code used `std::mem::forget` to keep the SQLite tempdir alive; now the
caller holds the handle on the stack, ensuring clean cleanup on test
exit while relying on Linux inode semantics (SQLiteStore keeps an open
FD that survives `unlink`). Every test that calls `build_state()` binds
the returned `_dir` or doesn't use it, correctly releasing it on test
exit. **(F-2028-033)**

The `dummy_action_set()` function (line 163–205) still uses `std::mem::forget`
on line 197–198. The comment (line 184–192) explicitly documents the
deliberate leak: SnapshotProcAction and ForensicsBundleAction accept a
path string that persists for the test's lifetime; forgetting the
TempDir keeps the path on disk so a control verb can write into it.
This is an acceptable pattern for one-off test helpers that don't
participate in the normal Fixture lifecycle, but it differs from the
`build_state` pattern. No action needed since the intent is documented.
**(F-2028-034)**

Metrics assertions now use the Prometheus format-strict parser
(`prom::parse`) instead of substring matching. The
`metrics_reflect_ingest_counters_via_record_event` test (line 547–625)
calls `prom::parse(&body)` (line 592) and uses `exp.find(...)` to look
up typed samples. The earlier `metrics_endpoint_returns_prometheus_exposition`
test (line 471–545) checks format well-formedness via format-strict
parsing as well. F-2027-056 closure complete. **(F-2028-035)**

## Triage

| ID | Severity | Surface | Next phase |
| --- | --- | --- | --- |
| F-2028-025 | nice | common/mod.rs adoption — no duplicates, only module-qual asymmetry | implement (low priority) — add `snapshot_tree, assert_tree_unchanged` to explicit imports in 11 module-test files for consistency |
| F-2028-026 | nice | SseParser unit tests ship with UTF-8 multibyte split coverage | closed (F-2028-018 closure) |
| F-2028-027 | nice | validate_rbac_subject unit tests + integration test ship complete | closed (F-2027-060 closure) |
| F-2028-028 | nice | events_stream cap-saturation integration test ships with proper tempdir isolation | closed (F-2027-054/-061/-062 closures) |
| F-2028-029 | nice | suricata live-apply test ships paired with dry-run-noop | closed (F-2027-046 closure) |
| F-2028-030 | nice | vpn-bridge P-1 dry-run-noop backfill (cloudflare + tailscale) ships | closed (F-2027-048 closure) |
| F-2028-031 | nice | token-file mode-validation test ships | closed (F-2028-004 closure) |
| F-2028-032 | nice | relay manifest round-trip (apply → manifest, uninstall → iterate) test ships | closed (F-2028-015 closure) |
| F-2028-033 | nice | build_state() TempDir handle returned, not leaked | closed (F-2027-055 closure) |
| F-2028-034 | nice | dummy_action_set() mem::forget is deliberate + documented | closed (F-2027-054 closure) |
| F-2028-035 | nice | metrics tests use format-strict prom parser, not substring assertions | closed (F-2027-056 closure) |

All 11 findings land as `nice` severity. Three natural groupings:

- **common-mod consistency** (F-2028-025) — one PR adds the missing imports
  to the 11 module-test files.
- **Test-infrastructure cleanups** — closed by multiple Phase 2 closure PRs
  (F-2028-026 through F-2028-035, via various closure clusters).
