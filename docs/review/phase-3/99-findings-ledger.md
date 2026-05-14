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
| F-2028-001 | nice | `selfdef-cli/src/paths.rs` — startup path validation | The new `paths` module consolidates `/etc/selfdef/*` constants across `init.rs`, `modules.rs`, `doctor.rs`, and `main.rs`. No assertion that a future maintainer's edit keeps the paths under the expected layout. | implement — **closed** by the Phase-3-polish PR: `paths.rs` gains a `const _: () = { … }` block that asserts every public constant starts with `/etc/selfdef/` (and that `AGENT_GUARD_CONFIG` lives under `MODULES_PER_MODULE_DIR`). Compile-time only, zero runtime cost. |
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
| F-2028-012 | nice | `SubscriberGuard::Drop` doesn't `debug_assert!` against underflow | Future logic bug would silently corrupt the counter. | defer — **closed** by the Phase-3-polish PR: both the global `fetch_sub` and the per-token `fetch_sub` now `debug_assert!(prev > 0, …)` with diagnostic messages naming the offending fingerprint on per-token underflow. Plus a `debug_assert!(false, …)` on the "per-token entry missing on drop" branch so future logic bugs that bypass the increment can't ship silently. |
| F-2028-013 | nice | `events_stream` `slow-client timeout` message doesn't name the deadline | Operators reading the log line had to grep the source to know the timeout value. | defer — **closed** by the Phase-3-polish PR: the writer task's timeout-branch now returns `Err("slow-client timeout (30s)")`. The literal is documented inline next to `SSE_SEND_TIMEOUT` so a future const change updates both. |
| F-2028-014 | demoted | `reqwest` + `futures` dep additions properly justified | Crate-explorer reviewed `crates/selfdef-cli/Cargo.toml` lines 43-44. The inline comments explicitly justify the dep size ("reqwest already lives in the workspace via selfdef-notifier; net cost is the `stream` feature"). The dev-deps (`axum`, `selfdef-api` with `test-helpers`, `selfdef-bus`) are also commented. No findings. Kept in ledger for audit-trail completeness. | none |
| F-2028-015 | important | `modules/vpn-bridge` did not migrate to SDD-006 v2 manifest helpers | The Phase 2 inventory claimed all 8 modules migrated; cross-check shows 6 v2 + suricata (correctly exempt — writes no persistent files) + **vpn-bridge** (incorrectly v1). `relay-via-server.sh:112` writes `nft_path` via `install -D -m 0644` but `apply.sh` never called `module_record_file`. `profile_uninstall` (lines 174-197) hard-coded the cleanup path instead of iterating `module_render_files`. Multi-instance installs (`INST="relay1"`, `relay2`, …) would silently leak files. | implement — **closed** by the vpn-bridge v2 migration PR: `lib.sh` bumped to `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2`, `relay-via-server.sh`'s apply path now calls `module_record_file "$nft_path"` after the install, `profile_uninstall` enumerates from `module_render_files` (with a legacy fallback for pre-v2 installs) and clears the manifest at the end. New `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it` test pins the round-trip end-to-end. |
| F-2028-016 | nice | TCP-follow 503 error message doesn't surface the cap-reached detail | The CLI printed `daemon refused /events/stream: HTTP 503 {"error":"sse subscriber cap reached"}` (the raw JSON body) rather than extracting the `error` field. | implement — **closed** by the SSE-503 PR: `events_follow_tcp` now `serde_json::from_str`'s the body and extracts the `error` field when present, falling back to raw body for non-JSON errors. Operators now see `daemon refused /events/stream: HTTP 503 sse subscriber cap reached`. |
| F-2028-017 | nice | TCP-follow lacks an end-to-end cap-saturation integration test | The daemon side has `events_stream_rejects_over_cap_with_503`; the CLI side had no equivalent. | implement — **closed** by the SSE-503 PR: new `events_follow_url_surfaces_cap_reached_reason_on_503` test saturates the cap via `MAX_SSE_SUBSCRIBERS` in-process reqwest streams, then spawns the CLI subprocess via `spawn_blocking` and asserts the stderr names both `503` and `sse subscriber cap reached`. |
| F-2028-018 | nice | `SseParser` chunk-boundary UTF-8 handling — multi-byte split corrupts payload | Both UNIX and TCP follow paths called `String::from_utf8_lossy(&chunk)` per-chunk before feeding the parser. A 4-byte UTF-8 sequence split 2/2 across two `Bytes` would become two `U+FFFD` instead of one codepoint. | implement — **closed** by the parser-bytes-refactor PR: `SseParser::buf` is now `Vec<u8>`, the public entry is `feed_bytes(&[u8])`, UTF-8 conversion happens at line boundaries (`\n`-terminated). Both `events_follow_unix` and `events_follow_tcp` now hand the parser raw bytes. Two new unit tests (`parser_reassembles_multibyte_utf8_split_across_chunks` for a 4-byte 🦀 + `parser_reassembles_3byte_utf8_split_across_chunks` for a 3-byte 漢) pin the round-trip across split boundaries. |
| F-2028-019 | nice | `follow.rs` module `//!` header doesn't name the byte-semantic parity requirement between transports | One-line addition to the module doc-comment. | implement — **closed** by the parser-bytes-refactor PR: the module header now explicitly states "both transports hand the parser **raw bytes** via `SseParser::feed_bytes`; chunk boundaries are invisible to the parser by construction." with a back-reference to F-2028-018 explaining the failure mode a future transport must avoid. |
| F-2028-020 | demoted | `CHANGELOG.md` "Phase 3 status" nice count flagged as off-by-one | Docs explorer flagged the module-explorer PR's status line "9 nice (2 closed, 7 open)" as wrong. Cross-checked: F-2028-001 + F-2028-004 (recent-PRs nice) + F-2028-005/-006/-007/-008/-010/-012/-013 (crate nice) = 9 nice total, 2 closed (-004, -005), 7 open. The CHANGELOG line is correct as written. | none |
| F-2028-021 | demoted | `CHANGELOG.md` "now closed" timing flagged as ambiguous | Docs explorer flagged the integration-explorer PR's "1 important (now closed)" as misleading since F-2028-015 was raised by the module explorer and closed "later". Cross-checked: PR #87 closed F-2028-015 in the same PR that shipped the integration audit, so "now closed" reads correctly at merge time. No drift. | none |
| F-2028-022 | nice | `STARTER_MODULES` header has the F-2027-059 mode/owner warning but per-module blocks don't repeat it | An operator copying one block to a new modules.toml without scrolling up to the header would miss the 0640 root:selfdef requirement. | implement — **closed** by the docs-polish PR: every commented `config = "..."` line now ends with a `# 0640 root:selfdef` trailing comment, plus a single global mid-section reminder right above the first module block that names the safe-copy invariant. |
| F-2028-023 | demoted | Phase 3 charter "remaining explorers will run in follow-up PRs" was true at write-time but stale by docs-audit time | The charter is a snapshot of intent at Phase 3 kickoff; the live status is the ledger's `## Status` section. Charters in Phase 1 and Phase 2 follow the same pattern. The drift the docs explorer noticed is by-design separation between the two docs. | none |
| F-2028-024 | nice | Phase 3 inventory's "All 8 modules completed SDD-006 v2 migration" was wrong at write-time | A reader reaching the inventory between Phase 3 kickoff and F-2028-015's closure would have been misled. | implement — **closed** by the docs-polish PR: the inventory entry now reads "At Phase 2 close: 6 modules at v2, suricata correctly exempt, vpn-bridge still at v1 — discovered by F-2028-015 and closed by PR #87. **As of PR #87**: every non-exempt module is v2." Time-anchor is now explicit. |
| F-2028-025 | nice | `common/mod.rs` import-style asymmetry in 11 module-test files | 11 of 17 migrated test files used `common::snapshot_tree` / `common::assert_tree_unchanged` via fully-qualified paths without listing them in `use common::{...}`. | implement — **closed** by the Phase-3-polish PR: 10 module-test files (agent_guard, bridge_l2, integrity_sentinel, suricata, vpn_bridge, vpn_bridge_cloudflare, vpn_bridge_tailscale, observability, tetragon, polarproxy) now import `assert_tree_unchanged` and `snapshot_tree` alongside their existing helpers; call sites rewrite from `common::snapshot_tree(...)` to bare `snapshot_tree(...)`. Style is now consistent. |
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
| F-2028-036 | demoted | `events_follow_tcp` URL scheme validation | Security-explorer review: reqwest's `Client::get(url)` accepts only `http`/`https` URLs at the client-builder level; a `file://` URL is rejected by reqwest before any I/O happens. No additional scheme validation needed at the CLI. | none |
| F-2028-037 | important | SSE subscriber cap is global, not per-token; one malicious bearer-holder can DoS legitimate operators | `crates/selfdef-api/src/handlers.rs::SubscriberGuard` increments a global `Arc<AtomicUsize>` shared across all callers. Authenticated-only DoS. | implement — **closed** by the SDD-007 implementation PR: `bearer_auth` now threads a SHA-256 `TokenFingerprint` into request extensions; `events_stream` consults the new per-token counter map (`MAX_SSE_SUBSCRIBERS_PER_TOKEN = 8`) before the global cap; refusal returns 503 with a distinguishable `"per-token sse cap reached"` reason; `SubscriberGuard::Drop` decrements both counters and prunes the HashMap entry when the per-token count hits zero (no leak). 3 new integration tests pin the per-token-cap, per-token-isolation, and drop-prunes contracts. |
| F-2028-038 | demoted | TCP-follow 503 error-message detail (duplicate of F-2028-016) | Security explorer independently surfaced the same observation as the integration explorer's F-2028-016. Same underlying surface; both closed by the SSE-503 PR's `serde_json` body extraction. | none (closed by F-2028-016) |
| F-2028-039 | SDD-debt | Per-token SSE subscriber quota | F-2028-037's design counterpart. | design — **closed** by the SDD-007 implementation PR. D-1 (SHA-256 fingerprint), D-2 (dual-counter SubscriberGuard + HashMap pruning), D-3 (deferred terminate-on-revoke), D-5 (3 new integration tests), and D-6 (distinguishable 503 reasons) all shipped. D-4 (config knobs `max_sse_subscribers_per_token` / `max_sse_subscribers`) deferred to a thin follow-up that plumbs the constants through `ApiConfig`. SDD-007 status: implemented. |

## Status

- **39 findings raised** across **all seven Phase 3 explorers**
  (recent-PRs, crate, module, integration, docs, tests,
  security). **0 blockers**, **2 important** (F-2028-015
  closed, F-2028-037 open gated on SDD-007), **16 nice**
  (F-2028-001, -004, -005, -006, -007, -008, -010, -012, -013,
  -016, -017, -018, -019, -022, -024, -025), **20 demoted**
  (F-2028-002, -003, -009, -011, -014, -020, -021, -023,
  -026..035, -036, -038), **1 SDD-debt** (F-2028-039 open).
- **Closed clusters**:
  - Token-reader symmetry — F-2028-004 + -005 closed (PR #86).
  - vpn-bridge v2 migration — F-2028-015 closed (PR #87).
  - SSE parser bytes refactor — F-2028-018 + -019 closed (PR #88).
  - Docs polish — F-2028-022 + -024 closed (PR #89).
  - CLI doc clarity — F-2028-006 + -007 + -010 closed (PR #90).
  - SSE 503 cluster — F-2028-016 + -017 closed (PR #91).
  - SDD-007 design — landed (PR #92).
  - SDD-007 implementation — F-2028-037 + -039 closed in
    the same PR (Phase 3's `important` finding shipped;
    SDD-007 status flipped to `implemented`).
- **All seven explorers have run; the only `important` finding
  has shipped.** **Phase 3 is closed for blockers, important,
  and SDD-debt findings.** The Phase-3-polish PR closed
  F-2028-001, -012, -013, -025 (4 of 5 remaining open nice).
  The remaining single open nice — **F-2028-008** (SseParser
  visibility) — is explicitly `defer` per the crate audit
  ("no immediate consumer / no observed misuse"). Phase 3
  is effectively wrapped.

## Phase 1 / Phase 2 references

- Phase 1's ledger: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2's ledger: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
