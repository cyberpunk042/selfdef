# Phase 3 — findings ledger

> Status: in progress
> Vintage prefix: **F-2028-NNN**
> Last updated: 2026-05-14

This ledger tracks Phase 3 findings as they surface across the
seven explorers (recent-PRs, crate, module, integration, docs,
tests, security). Each finding is `F-2028-NNN` and either ships
in a closure PR or graduates to an SDD when the fix is
design-shaped.

> See [Phase 1 ledger](../99-findings-ledger.md) and
> [Phase 2 ledger](../phase-2/99-findings-ledger.md) for prior
> vintages.

## Triage legend

- **blocker** — must fix before shipping.
- **important** — should fix.
- **nice** — cosmetic / non-blocking / ergonomic.
- **SDD-debt** — fix is design-shaped; spawn an SDD.
- **demoted** — auditor flagged but cross-check showed no
  action needed; left in the ledger for the audit trail.

## Findings

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2028-001 | nice | `selfdef-cli/src/paths.rs` — startup path validation | The new `paths` module consolidates `/etc/selfdef/*` constants across `init.rs`, `modules.rs`, `doctor.rs`, and `main.rs` (closes F-2027-017 drift). Paths are `pub(crate) const &str` — already non-mutable — but there's no startup-time assertion that an operator-overridden path (via env var) still resolves under the expected layout. Future hardening would have the daemon call a `validate_paths()` helper at boot. Very low risk: `const` declarations already block runtime mutation; flagged for triage rather than fixed proactively. | implement (low priority) |
| F-2028-002 | demoted | `phase-2/50-integration-audit.md` count phrasing | Recent-PRs auditor flagged the integration-explorer doc's "1 important + 8 nice (F-2027-028..036)" phrasing as potentially ambiguous (could be misread as 8 vs 9 total). Cross-checked: the math is correct (1 + 8 = 9; F-2027-028..036 is exactly 9 entries). No drift, no code impact. Left in the ledger so the auditor's process is visible. | none |
| F-2028-003 | demoted | `phase-2/80-security-audit.md` cluster phrasing | Recent-PRs auditor flagged that the security-explorer doc lists "8 nice findings (F-2027-057..064)" without noting F-2027-010 (SDD-debt) was raised in the same overall cycle. Cross-checked: F-2027-010 was raised by the recent-PRs explorer, not the security explorer, so the security-explorer doc is correct to scope its summary to 57..064. No drift, no code impact. | none |
| F-2028-004 | nice | `selfdef-cli/src/follow.rs::read_token_file` — mode-check asymmetry | The CLI's `--token-file` reader opens any file it can read. The daemon-side `[api].token_file` reader (closed F-2027-031) refuses files whose mode has any `group`/`other` bits set (`mode & 0o077 != 0`). Operators who rotate `api.token` and accidentally leave it world-readable would see the daemon refuse to load it but the CLI silently consume it. | implement — **closed** by the token-reader symmetry PR: `read_token_file` now stat's the file via `MetadataExt`, refuses `mode & 0o077 != 0` with a clear error naming the offending octal mode. New `events_follow_token_file_refuses_world_readable_mode` test pins the contract. |
| F-2028-005 | nice | `selfdef-cli/src/follow.rs::read_token_file` — whitespace-trim asymmetry | CLI trims `'\n' | '\r' | ' ' | '\t'` (ASCII-only); daemon-side `read_token` (`selfdef-api/src/transport.rs`) calls `raw.trim()` which removes all Unicode whitespace (NBSP, BOM, ZWSP, …). A token-file with leading/trailing non-ASCII whitespace would round-trip differently between the two sides. | implement — **closed** by the token-reader symmetry PR: `read_token_file` now calls `raw.trim()` instead of `trim_end_matches([...])`. The two readers are now byte-for-byte symmetric on both mode validation and whitespace handling. |
| F-2028-006 | nice | `events_follow_tcp` doc-comment doesn't name the Bearer header format | `crates/selfdef-cli/src/follow.rs:268-273` describes the `bearer_token` parameter's semantics but doesn't state the wire format. | implement — **closed** by the CLI doc-clarity PR: `events_follow_tcp` doc-comment now explicitly states `Authorization: Bearer <t>` (space-separated, no quoting). |
| F-2028-007 | nice | `follow.rs` module `//!` header doesn't enumerate `read_token_file` | `crates/selfdef-cli/src/follow.rs:1-22` documents `SseParser` + the two entry points but the `read_token_file` helper is not mentioned. | implement — **closed** by the CLI doc-clarity PR: module header now lists the three module-level entry points (`events_follow_unix`, `events_follow_tcp`, `read_token_file`) with one-sentence summaries each. |
| F-2028-008 | nice | `SseParser` is private but well-tested + reusable | The state machine has 9 unit tests and is structurally generic. If a future daemon-side SSE frame generator or a second consumer emerges, the private-in-CLI scoping would force duplication. Defer until a second consumer materialises; flag for awareness. | defer |
| F-2028-009 | demoted | `validate_rbac_subject` charset audit | Crate-explorer reviewed the validator's charset `[A-Za-z0-9:._/@-]` + 253-byte cap (matches Kubernetes DNS-name cap) + the 7 unit tests + 1 integration test. No action: the validator is well-scoped and well-tested. The recent-PRs explorer (F-2028-003) already touched this surface. Kept in ledger for audit-trail completeness. | none |
| F-2028-010 | nice | `Follow` clap doc-comment doesn't name the conflict/require structure | `crates/selfdef-cli/src/main.rs:399-429` correctly applies `conflicts_with` / `requires` attributes; the doc-comment didn't restate them in prose. | implement — **closed** by the CLI doc-clarity PR: the `Follow` enum variant's doc-comment now explicitly names the constraint structure ("--url and --unix-socket are mutually exclusive; --token-file requires --url") so a reader doesn't have to cross-reference the clap attributes. |
| F-2028-011 | demoted | `SubscriberGuard` atomics + memory ordering | Crate-explorer reviewed the CAS loop in `crates/selfdef-api/src/handlers.rs:120-140` — `Ordering::Acquire` on load, `Ordering::AcqRel` on CAS. The pattern is correct; acquire synchronises with prior release-stores, AcqRel ensures the increment happens atomically + synchronises with the `Drop` decrement. No findings. Kept in ledger for audit-trail completeness. | none |
| F-2028-012 | nice | `SubscriberGuard::Drop` doesn't `debug_assert!` against underflow | `crates/selfdef-api/src/handlers.rs:143-146` calls `fetch_sub(1, AcqRel)` without a defensive `prev > 0` check. The counter is owned by `ApiState` and only decrements via a guard `Drop`, so underflow can't happen today. A future logic bug (double-drop, decrement without acquire) would silently corrupt the counter; a `debug_assert!` would catch it under test. Not a safety issue (the cap is not the sole source of access control), nice-to-have for debuggability. | defer |
| F-2028-013 | nice | `events_stream` `slow-client timeout` message doesn't name the deadline | `crates/selfdef-api/src/handlers.rs:194-203`'s `send_with_timeout` returns `Err("slow-client timeout")` on `SSE_SEND_TIMEOUT = 30s` expiry. Operators reading the log line would have to grep the source to know the deadline. `Err(format!("slow-client timeout ({}s)", SSE_SEND_TIMEOUT.as_secs()))` is a one-line improvement. | defer |
| F-2028-014 | demoted | `reqwest` + `futures` dep additions properly justified | Crate-explorer reviewed `crates/selfdef-cli/Cargo.toml` lines 43-44. The inline comments explicitly justify the dep size ("reqwest already lives in the workspace via selfdef-notifier; net cost is the `stream` feature"). The dev-deps (`axum`, `selfdef-api` with `test-helpers`, `selfdef-bus`) are also commented. No findings. Kept in ledger for audit-trail completeness. | none |
| F-2028-015 | important | `modules/vpn-bridge` did not migrate to SDD-006 v2 manifest helpers | The Phase 2 inventory claimed all 8 modules migrated; cross-check shows 6 v2 + suricata (correctly exempt — writes no persistent files) + **vpn-bridge** (incorrectly v1). `relay-via-server.sh:112` writes `nft_path` via `install -D -m 0644` but `apply.sh` never called `module_record_file`. `profile_uninstall` (lines 174-197) hard-coded the cleanup path instead of iterating `module_render_files`. Multi-instance installs (`INST="relay1"`, `relay2`, …) would silently leak files. | implement — **closed** by the vpn-bridge v2 migration PR: `lib.sh` bumped to `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2`, `relay-via-server.sh`'s apply path now calls `module_record_file "$nft_path"` after the install, `profile_uninstall` enumerates from `module_render_files` (with a legacy fallback for pre-v2 installs) and clears the manifest at the end. New `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it` test pins the round-trip end-to-end. |
| F-2028-016 | nice | TCP-follow 503 error message doesn't surface the cap-reached detail | `crates/selfdef-cli/src/follow.rs:292-300` routes the daemon's `HTTP 503 {"error":"sse subscriber cap reached"}` through the generic error handler. The CLI prints "daemon refused /events/stream: HTTP 503 ..." but doesn't extract the JSON `error` field. Operators reading the message have to check Prometheus metrics or inspect the response body to learn the cause. Parse the JSON body when present and surface the typed reason. | implement |
| F-2028-017 | nice | TCP-follow lacks an end-to-end cap-saturation integration test | The daemon side has `events_stream_rejects_over_cap_with_503` (`crates/selfdef-api/tests/m12_api.rs:792-861`); no CLI test saturates the cap via N concurrent TCP clients and asserts the (N+1)th subprocess receives the 503 with a clear stderr. Add a test that uses `spawn_api_on_loopback()` to open `MAX_SSE_SUBSCRIBERS` connections and asserts the next CLI invocation reports the refusal. | implement |
| F-2028-018 | nice | `SseParser` chunk-boundary UTF-8 handling — multi-byte split corrupts payload | Both UNIX and TCP follow paths called `String::from_utf8_lossy(&chunk)` per-chunk before feeding the parser. A 4-byte UTF-8 sequence split 2/2 across two `Bytes` would become two `U+FFFD` instead of one codepoint. | implement — **closed** by the parser-bytes-refactor PR: `SseParser::buf` is now `Vec<u8>`, the public entry is `feed_bytes(&[u8])`, UTF-8 conversion happens at line boundaries (`\n`-terminated). Both `events_follow_unix` and `events_follow_tcp` now hand the parser raw bytes. Two new unit tests (`parser_reassembles_multibyte_utf8_split_across_chunks` for a 4-byte 🦀 + `parser_reassembles_3byte_utf8_split_across_chunks` for a 3-byte 漢) pin the round-trip across split boundaries. |
| F-2028-019 | nice | `follow.rs` module `//!` header doesn't name the byte-semantic parity requirement between transports | One-line addition to the module doc-comment. | implement — **closed** by the parser-bytes-refactor PR: the module header now explicitly states "both transports hand the parser **raw bytes** via `SseParser::feed_bytes`; chunk boundaries are invisible to the parser by construction." with a back-reference to F-2028-018 explaining the failure mode a future transport must avoid. |
| F-2028-020 | demoted | `CHANGELOG.md` "Phase 3 status" nice count flagged as off-by-one | Docs explorer flagged the module-explorer PR's status line "9 nice (2 closed, 7 open)" as wrong. Cross-checked: F-2028-001 + F-2028-004 (recent-PRs nice) + F-2028-005/-006/-007/-008/-010/-012/-013 (crate nice) = 9 nice total, 2 closed (-004, -005), 7 open. The CHANGELOG line is correct as written. | none |
| F-2028-021 | demoted | `CHANGELOG.md` "now closed" timing flagged as ambiguous | Docs explorer flagged the integration-explorer PR's "1 important (now closed)" as misleading since F-2028-015 was raised by the module explorer and closed "later". Cross-checked: PR #87 closed F-2028-015 in the same PR that shipped the integration audit, so "now closed" reads correctly at merge time. No drift. | none |
| F-2028-022 | nice | `STARTER_MODULES` header has the F-2027-059 mode/owner warning but per-module blocks don't repeat it | An operator copying one block to a new modules.toml without scrolling up to the header would miss the 0640 root:selfdef requirement. | implement — **closed** by the docs-polish PR: every commented `config = "..."` line now ends with a `# 0640 root:selfdef` trailing comment, plus a single global mid-section reminder right above the first module block that names the safe-copy invariant. |
| F-2028-023 | demoted | Phase 3 charter "remaining explorers will run in follow-up PRs" was true at write-time but stale by docs-audit time | The charter is a snapshot of intent at Phase 3 kickoff; the live status is the ledger's `## Status` section. Charters in Phase 1 and Phase 2 follow the same pattern. The drift the docs explorer noticed is by-design separation between the two docs. | none |
| F-2028-024 | nice | Phase 3 inventory's "All 8 modules completed SDD-006 v2 migration" was wrong at write-time | A reader reaching the inventory between Phase 3 kickoff and F-2028-015's closure would have been misled. | implement — **closed** by the docs-polish PR: the inventory entry now reads "At Phase 2 close: 6 modules at v2, suricata correctly exempt, vpn-bridge still at v1 — discovered by F-2028-015 and closed by PR #87. **As of PR #87**: every non-exempt module is v2." Time-anchor is now explicit. |
| F-2028-025 | nice | `common/mod.rs` import-style asymmetry in 11 module-test files | 11 of the 17 migrated test files call `common::snapshot_tree` and `common::assert_tree_unchanged` via fully-qualified paths without listing them in the `use common::{...}` import. Other helpers (`prepended_path`, `last_stdout_line`) are imported explicitly. Pure consistency issue, no behaviour impact. | implement (low priority) |
| F-2028-026 | demoted | SseParser unit tests ship with UTF-8 multibyte split coverage | Tests-explorer verification: the F-2028-018 closure ships 2 new tests (4-byte 🦀 + 3-byte 漢). Confirms shipped, no action. | none |
| F-2028-027 | demoted | `validate_rbac_subject` unit tests + integration test ship complete | Tests-explorer verification: F-2027-060 closure ships 7 unit tests + 1 integration test exercising charset, length, shell-meta, ANSI, whitespace. Confirms shipped, no action. | none |
| F-2028-028 | demoted | `events_stream` cap-saturation integration test ships with proper tempdir isolation | Tests-explorer verification: F-2027-061/-062 closure's `events_stream_rejects_over_cap_with_503` uses `build_state()`-returned TempDir handle. Confirms shipped, no action. | none |
| F-2028-029 | demoted | suricata live-apply test ships paired with dry-run-noop | Tests-explorer verification: F-2027-046 closure adds the live-positive test alongside the existing dry-run-noop case. Confirms shipped, no action. | none |
| F-2028-030 | demoted | vpn-bridge P-1 dry-run-noop backfill (cloudflare + tailscale) ships | Tests-explorer verification: F-2027-048 closure adds `cloudflare_dry_run_must_be_a_noop_on_disk` + `tailscale_dry_run_must_be_a_noop_on_disk` with `snapshot_tree` / `assert_tree_unchanged`. Confirms shipped, no action. | none |
| F-2028-031 | demoted | token-file mode-validation test ships | Tests-explorer verification: F-2028-004 closure adds `events_follow_token_file_refuses_world_readable_mode`. Confirms shipped, no action. | none |
| F-2028-032 | demoted | relay manifest round-trip test ships | Tests-explorer verification: F-2028-015 closure adds `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it` exercising apply→manifest→uninstall→cleared. Confirms shipped, no action. | none |
| F-2028-033 | demoted | `build_state()` returns the TempDir handle | Tests-explorer verification: F-2027-055 closure dropped `std::mem::forget(dir)`; the caller holds `_dir` on stack. Confirms shipped, no action. | none |
| F-2028-034 | demoted | `dummy_action_set()` `mem::forget` is deliberate + documented | Tests-explorer verification: F-2027-054 closure has the per-call `tempfile::tempdir()` + documented `mem::forget`. Intentional (the action snapshot path expects a long-lived directory). Confirms shipped, no action. | none |
| F-2028-035 | demoted | metrics tests use format-strict prom parser, not substring assertions | Tests-explorer verification: F-2027-056 closure's `metrics_reflect_ingest_counters_via_record_event` consumes `prom::parse(&body)` and uses `exp.find(name, labels)` lookups. Confirms shipped, no action. | none |

## Status

- **35 findings raised** across six explorers (recent-PRs,
  crate, module, integration, docs, tests). **0 blockers**,
  **1 important (closed)**, **16 nice** (F-2028-001, -004,
  -005, -006, -007, -008, -010, -012, -013, -016, -017, -018,
  -019, -022, -024, -025), **18 demoted** (F-2028-002, -003,
  -009, -011, -014, -020, -021, -023, -026, -027, -028, -029,
  -030, -031, -032, -033, -034, -035).
- **Closed clusters**:
  - Token-reader symmetry — F-2028-004 + -005 closed (PR #86).
  - vpn-bridge v2 migration — F-2028-015 closed (PR #87).
  - SSE parser bytes refactor — F-2028-018 + -019 closed (PR #88).
  - Docs polish — F-2028-022 + -024 closed (PR #89).
  - CLI doc clarity — F-2028-006 + -007 + -010 closed in the
    same PR that ships the tests explorer.
- One explorer remains: **security**.
- No Phase 3 SDD-debt findings yet.

## Phase 1 / Phase 2 references

- Phase 1's ledger: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2's ledger: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
