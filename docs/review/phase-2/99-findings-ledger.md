# Phase 2 findings ledger

> Status: in progress. Six of the seven explorers run so far —
> recent-PRs (10 findings, all closed except 1 SDD-debt), crate
> (11 findings, all closed), module (6 findings, all closed),
> integration (9 findings, all closed), docs (9 findings, all
> closed), and tests (11 findings, all fresh and open). One
> explorer remains (security).
> Last updated: 2026-05-13 (Phase 2 tests explorer — adds
> F-2027-046 through F-2027-056).

Numbering convention: `F-2027-NNN`. The `2027` prefix maps the
finding's vintage (Phase 2 audit cycle) so it never collides
with Phase 1's `F-2026-NNN`. Numbering is monotonic within the
phase regardless of year.

## How to read the table

| Column | Meaning |
| --- | --- |
| id | Stable identifier; cite this in PR descriptions and SDDs. |
| severity | blocker / important / nice / SDD-debt. blocker = must fix before next release; important = should fix; nice = ergonomic / cosmetic; SDD-debt = needs a design doc first. |
| surface | The file / module / endpoint the finding lives in. |
| summary | One-line description. |
| next phase | design / implement / closed-by-... |

## Blocker findings (0)

None.

## Important findings (3 — all closed)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-003 | important | `selfdef-collector-eventstream::unsafe_geteuid` | `/proc/self/status` parse failure returns UID `0` (permissive); operators never notice the integrity check is degraded. | implement — **closed** by Phase 2 first-fixes PR (`read_euid` now returns `Option<u32>`; failure path emits a `tracing::warn!` and falls back to "root-only" — strict-safe instead of permissive). |
| F-2027-008 | important | `selfdefctl doctor` rbac category | Emits a `warn:` pointer to `selfdefctl rbac check` whenever agent-guard is in pod-label scope, even if the operator never ran rbac-check. The warn count inflates the summary line, suggesting failure where there is none. | implement — **closed** by Phase 2 first-fixes PR (`check_rbac_posture` now emits `Skipped` for pod-label with detail "posture not verified — run `selfdefctl rbac check --probe`"; warn count stays at 0). |
| F-2027-035 | important | `selfdef-collector-eventstream::check_path_integrity` | Uses `std::fs::metadata` (stat, not lstat); a symlink at the configured path passes the check based on the target's metadata. The follow-up `tokio::fs::File::open` follows the same symlink. Combined with the stat→open TOCTOU window, the opt-in integrity check has a defeatable gap. | implement — **closed** by Phase 2 eventstream-integrity PR (renamed to `open_with_integrity_check`; opens with `O_NOFOLLOW` (symlinks → `IntegritySymlink`), fstats the returned FD instead of stat-then-open, rejects non-regular files; FD threaded through to the reader so there's only one open syscall). |

## Nice findings (52 — 49 closed, 3 open)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-001 | nice | `selfdef-cli/src/modules.rs` SDD-003 refusal message | Profile name embedded in the error; could include the exact copy-pasteable TOML snippet. | implement — **closed** by Phase 2 nice-cluster PR (refusal embeds the `[profiles.details.<profile>]` stanza inline). |
| F-2027-002 | nice | `docs/dev/test-contract.md` P-3 NATS pattern | Missing `cargo test -- --include-ignored` runtime guidance. | doc — **closed** by Phase 2 nice-cluster PR (P-3 now documents the `--include-ignored` invocation + nats-server 2.10+ JetStream requirement). |
| F-2027-004 | nice | `selfdef-cli/src/main.rs::discover_daemon_pid` | Missing `systemctl` on PATH yields "command not found" instead of a friendly diagnostic. | implement — **closed** by Phase 2 nice-cluster PR (`discover_daemon_pid` short-circuits on `ErrorKind::NotFound` with a `pgrep selfdefd` pointer). |
| F-2027-005 | nice | `selfdef-daemon`'s rule-signing reload | SIGHUP reloads rules through the verifier but not the verifier itself; a rotated public-key path needs a full daemon restart. | implement — **closed** by Phase 2 verifier-reload PR (`Correlator::reload_verifier` re-reads the configured public-key file in-place; daemon's SIGUSR2 handler fans out to verifier reload + rule re-verify alongside the existing api-token reload). |
| F-2027-006 | nice | `modules/tetragon/install/apply.sh` | Spawns `selfdefctl keys verify` once per policy file (N spawns for N policies). | implement — **closed** by Phase 2 nice-cluster PR (new `selfdefctl keys verify-dir <dir>` verb; tetragon apply.sh + check.sh both batched to one invocation). |
| F-2027-007 | nice | `selfdefctl rbac check --probe` | Built-in subject set is `system:authenticated` + `system:unauthenticated` only; common mistakes (`system:masters`, default ServiceAccount) aren't probed. | implement — **closed** by Phase 2 nice-cluster PR (built-in set now also probes `system:masters` and `system:serviceaccount:default:default`; `--as` still composes on top). |
| F-2027-009 | nice | `selfdefctl init` `STARTER_CONFIG` | Template doesn't show a `[notifier.ntfy]` example; operators discover the shape only in `/usr/share/selfdef/selfdef.toml.example`. | doc — **closed** by Phase 2 nice-cluster PR (commented `[notifier.ntfy]` stanza embedded in the starter). |
| F-2027-011 | nice | `selfdef-signing::SIGNATURE_SUFFIX` + `signature_path_for` | Both are `pub` but no external caller exists; tests build the `.minisig` path by hand. Either deprecate or surface in the crate `//!`. | doc — **closed** by Phase 2 selfdef-signing API-surface PR (kept `pub` and surfaced in the crate `//!` "Public helpers" section, with usage guidance: `signature_path_for` for path construction, `SIGNATURE_SUFFIX` for shell-out filtering). |
| F-2027-012 | nice | `selfdef-signing::SigningError::Io` | `#[from] io::Error` loses the path the io call was against; sibling variants (`BadPublicKey`, `BadSignature`) carry full context. | implement — **closed** by Phase 2 selfdef-signing API-surface PR (the `Io(#[from])` variant is gone; replaced by three typed variants `ReadPublicKey`, `ReadTarget`, `ReadSignature`, each carrying `{ path, source }`). |
| F-2027-013 | nice | `selfdef-signing` crate `//!` header | Walks operator through `minisign -G`/`-S` + daemon load path but doesn't mention the `signature_path_for` / `SIGNATURE_SUFFIX` public helpers. | doc — **closed** by Phase 2 selfdef-signing API-surface PR (new "Public helpers" + "Error model" sections in the `//!`). |
| F-2027-014 | nice | `selfdef-api::with_full_capability` | `pub fn` documented as "test-only convenience" but reachable from any consumer; rename or feature-gate to prevent silent auth-bypass via misuse. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (helper now gated behind `test-helpers` Cargo feature; release builds elide it; integration tests enable the feature via a circular dev-dep). |
| F-2027-015 | nice | `selfdef-api::metrics::{run_ingest, Metrics::*}` | Re-exported as `run_metrics_ingest` with zero rustdoc; gating contract ("only spawn when API is enabled") lives in the daemon's wire-up comment, not the signature. | doc — **closed** by Phase 2 CLI/api-ergonomics PR (`run_ingest` doc now states the api-enabled gate contract + the lag-accounting semantics inline). |
| F-2027-016 | nice | `selfdef-api::ApiServer::run` `NoTransport` error | Same error for "api enabled but no transport set" and "api disabled"; operator-facing message could distinguish. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (error message now spells out exactly which TOML keys to set or which to flip false). |
| F-2027-017 | nice | `selfdef-cli` starter-config path constants | `init.rs` and `modules.rs` independently define defaults for the same `/etc/selfdef/` paths; drift risk. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (new `crate::paths` module holds the canonical layout; `init.rs`, `modules.rs`, `doctor.rs`, and `main.rs` all import from it). |
| F-2027-018 | nice | `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` env override | Test-only knob documented only in a source comment; not in `docs/dev/operator-health-check.md` or `--help`. | doc — **closed** by Phase 2 CLI/api-ergonomics PR (`docs/dev/operator-health-check.md` has a new "Environment overrides" section + the doctor verb's `--help` references it). |
| F-2027-019 | nice | `selfdef-correlator` crate `//!` header | Stops at M5's "SshBruteforceRule gone"; doesn't advertise the post-PR-#58 surface (`reload_verifier`, `has_verifier`, SIGUSR2). | doc — **closed** by Phase 2 correlator-observability PR (crate header now documents both reload signals, `reload_verifier`, `verifier_source`, and the SDD-004 signing posture). |
| F-2027-020 | nice | `selfdef-correlator::load_rules` | Logs `rules = N` but not the verifier source path it verified them against; post-SIGUSR2 operators can't eye-ball "did the verifier swap?". | implement — **closed** by Phase 2 correlator-observability PR (`load_rules` now emits `info!(rules, verifier_key)` when the verifier branch was taken). |
| F-2027-021 | nice | `selfdef-correlator` verifier source getter | No public `verifier_source()` getter — tests, `selfdefctl doctor`, dashboards all want to answer "which `policy.pub` is the daemon trusting right now?". | implement — **closed** by Phase 2 correlator-observability PR (new `Correlator::verifier_source() -> Option<PathBuf>`; 3 tests cover the none/present/post-reload paths). |
| F-2027-022 | nice | `modules/detect-host` — `[install] kind = "debian-package"` | Only module using this install kind; the contract isn't documented in `docs/dev/modules.md` or in the module's own README. | doc — **closed** by Phase 2 module-cleanup PR (`docs/src/modules.md` `[install]` block now documents all three `kind` values inline; `detect-host`'s README points at it). |
| F-2027-023 | nice | `modules/tetragon/install/apply.sh:49` signing-failure recover-step | `selfdefctl keys verify-dir … \|\| true` prints the failing files but the subsequent `die` doesn't reference them — operator has to scroll back to find which file failed. | implement — **closed** by Phase 2 module-cleanup PR (apply.sh now captures verifier output, prints it, and embeds the first failing file path in the `die` message). |
| F-2027-024 | nice | seven script-based modules (bridge-l2, observability, tetragon, integrity-sentinel, polarproxy, suricata, vpn-bridge) | Don't opt into SDD-006 v2 manifest helpers; `uninstall.sh` hand-curates paths that `apply.sh` writes, recreating the drift risk v2 was designed to remove. | implement — **closed** by Phase 2 v2-helpers migration PR (5 modules migrated to v2 — bridge-l2, integrity-sentinel, polarproxy, observability, tetragon — each with a legacy-fallback path so pre-v2 installs still uninstall cleanly; `suricata` is N/A — renders no files outside its own dir; `vpn-bridge`'s per-profile sub-script pattern is queued for a follow-up). |
| F-2027-025 | nice | `modules/vpn-bridge/install/profiles/relay-via-server.sh:20-23` | `$SELFDEF_INSTANCE_ID` is interpolated into nftables table names and per-instance config paths without going through the `safe_name` validator. Operator-controlled, so defense-in-depth — but tightening costs nothing. | implement — **closed** by Phase 2 module-cleanup PR (`_relay_inst_defaults` now `safe_name "$INST" \|\| die "..."` before any interpolation). |
| F-2027-026 | nice | per-module READMEs | All 9 are silent on `SELFDEF_MODULE_LIB_VERSION_REQUIRED` and the v2 helpers. New contributors won't discover the v2 surface. | doc — **closed** by Phase 2 module-cleanup PR (`docs/dev/module-helpers.md` gains a "Per-module adoption" table — single source of truth — plus a 4-step bumping recipe). |
| F-2027-027 | nice | `modules/{bridge-l2,suricata,polarproxy}/install/check.sh` | Missing the conventional `DRY_RUN=0` initialization that every other module's `check.sh` sets. Cosmetic but inconsistent with the v2 lib's caller contract. | implement — **closed** by Phase 2 module-cleanup PR (all three check.sh now set `DRY_RUN=0` before sourcing the lib). |
| F-2027-028 | nice | SSE reader `crates/selfdef-cli/src/follow.rs:120-124` | Silently ignores non-`data:` lines including `:ping` keep-alives, but also a hypothetical malformed `:error …` comment. No way to surface protocol anomalies. | implement — **closed** by Phase 2 seam-1 PR (reader is now frame-aware: tracks `event:` field per frame; recognises `:ping` keep-alives as silent; surfaces any other `:`-comment to stderr as `# sse-comment: …`). |
| F-2027-029 | nice | SSE seam end-of-stream marker | The writer task at `crates/selfdef-api/src/handlers.rs:110-112` exits silently on client disconnect or shutdown; the reader can't distinguish "daemon shut down" from "daemon crashed mid-stream". An `event: shutdown` frame would close the gap. | implement — **closed** by Phase 2 seam-1 PR (writer emits `event: shutdown` with a `data:` reason when the bus closes or returns a non-Lagged error; reader prints `# daemon stream shutdown: <reason>` to stderr and exits 0). |
| F-2027-030 | nice | SSE lagged-event seam test gap | `crates/selfdef-cli/tests/cli_events_follow.rs:162-197` exercises the lagged-event path with hand-crafted bytes; no end-to-end test against a real bus overflow. | implement — **closed** by Phase 2 seam-1 PR (`m12_api.rs::events_stream_emits_lagged_frame_on_real_bus_overflow` builds a 2-slot bus, hits /events/stream, publishes 100 events, and asserts the response body contains `event: lagged`). |
| F-2027-031 | nice | `selfdef-api::TokenReloader::reload` | Re-reads the token file but doesn't validate the mode-0600 invariant the writer asserts at rotate-token time. A `chmod 0644` after a successful rotate silently weakens the bearer-token surface. | implement — **closed** by Phase 2 seam-2 PR (`read_token` now checks `mode & 0o077 == 0` before reading; refuses with new typed `ServerError::LooseTokenMode` variant; prior in-memory tokens stay in place). |
| F-2027-032 | nice | `selfdef-daemon` SIGUSR2 handler | Runs three reload paths (tokens, verifier, rules) independently and logs each result separately. Operator has to correlate multiple log lines to know the overall reload outcome. A summary line at the end would close the gap. | implement — **closed** by Phase 2 seam-2 PR (handler now tracks per-branch outcome (`ok` / `failed` / `skipped`) and emits one summary line `SIGUSR2 reload summary tokens=… verifier=… rules=…` at the end). |
| F-2027-033 | nice | `selfdef-correlator::walk_yaml` rule enumeration | `std::fs::read_dir` order is undefined; rules with the same priority fire in fs-dependent order. Add a `paths.sort()`. | implement — **closed** by Phase 2 seam-3 PR (`walk_yaml` now sorts lexicographically before returning). |
| F-2027-034 | nice | `SigmaError::Signature` ordering | Signature check runs before the YAML parse; a malformed-but-signed rule yields `Signature` error instead of `Yaml`. Counter-intuitive when the signature actually was valid (over malformed bytes). | implement — **closed** by Phase 2 seam-3 PR (`load_dir_maybe_verified` now reads + parses YAML first, then verifies the signature — malformed bytes surface `SigmaError::Yaml`; verifier is still consulted before the rule is added to the engine so the security contract is unchanged). |
| F-2027-036 | nice | eventstream collector long-lived FD | After the initial integrity check, the `BufReader::new(file)` FD is held for the daemon's lifetime; nothing re-validates ownership or mode if `logrotate` replaces the file. Operator-facing doc warning needed. | doc — **closed** by Phase 2 eventstream-integrity PR (`docs/dev/first-run.md` § "Optional: eventstream integrity" now warns that the check runs once at startup against the FD; operators who rotate the file post-startup must restart the daemon to re-assert on the new file). |
| F-2027-037 | nice | `docs/dev/signing.md:102-114` | Documents SIGUSR2 as a verifier-reload signal but doesn't mention that the same signal also reloads API tokens (post-PR-#58/#69/#70 the fan-out covers tokens + verifier + rules). | doc — **closed** by Phase 2 docs-operator-refresh PR (signing.md SIGUSR2 section now enumerates all three reload branches + the summary log line). |
| F-2027-038 | nice | `docs/dev/rbac-posture.md:35-36, 90-91` | Built-in probe set listed as 2 subjects (`system:authenticated` + `system:unauthenticated`); F-2027-007's closure expanded it to 4 (also `system:masters` and `system:serviceaccount:default:default`). | doc — **closed** by Phase 2 docs-operator-refresh PR (both sites now enumerate the full four built-in subjects with one-line rationale per subject). |
| F-2027-039 | nice | `docs/dev/test-contract.md` | No "Per-test isolation overrides" section pointing at the `MODULE_INSTALLED_MANIFEST` env pattern landed in PR #65 (and similar overrides). | doc — **closed** by Phase 2 docs-final-cluster PR (new "Per-test isolation overrides" section with a table of host-global env vars + the F-NNN cross-references). |
| F-2027-040 | nice | Inconsistent runbook section structure | `first-run.md` has 11 sections, `signing.md` has 8, `rbac-posture.md` has 5 (no Env / Exit-codes / Tests sections). Pick canonical shape and apply. | doc — **closed** by Phase 2 docs-final-cluster PR (new `docs/dev/README.md` documents a canonical 7-section shape for new runbooks and indexes the existing ones; aggressive reformatting deferred per audit's lighter-touch recommendation). |
| F-2027-041 | nice | README verb tour | `selfdefctl init`, `doctor`, `events follow`, `keys verify-dir`, expanded `rbac check` are reachable via `--help` but not called out in the README's verb section. | doc — **closed** by Phase 2 docs-operator-refresh PR (`events follow` added to the Read-only section; `keys verify-dir`, F-2027-007 RBAC expansion, F-2027-031 mode-0600 enforcement now in the Security opt-ins table). |
| F-2027-042 | nice | README "Security opt-ins" | Cites only `F-2026-` follow-ups; doesn't mention Phase 2 closure findings (`F-2027-005` verifier reload, `F-2027-007` expanded RBAC probes, `F-2027-014` `with_full_capability` feature-gating, `F-2027-035` eventstream TOCTOU). | doc — **closed** by Phase 2 docs-operator-refresh PR (new "Phase 2 hot-reload surfaces" sub-section calls out F-2027-005, -014, -032, -035 with one-line summaries). |
| F-2027-043 | nice | README quickstart `cargo deb -p selfdef-daemon` | Builds only the daemon; the CLI is a separate target (`selfdefctl`). Quickstart doesn't tell operators they need to package the CLI separately. | doc — **closed** by Phase 2 docs-operator-refresh PR (quickstart now builds `cargo deb -p selfdef-cli` alongside the daemon and `dpkg -i` both). |
| F-2027-044 | nice | `ARCHITECTURE.md:12, 199` SIGUSR2 fan-out | Topology diagram labels SIGUSR2 as `(api tokens)` only; post-PR-#58/#69/#70 also covers verifier reload + rule re-verify + summary log. | doc — **closed** by Phase 2 docs-operator-refresh PR (diagram label updated to `tokens + verifier + rules`; F-2027-005 / -031 / -032 / -035 cross-references added in the security-properties section). |
| F-2027-045 | nice | SDDs don't cross-ref `F-2027-NNN` follow-ups | SDD-003 (drove F-2027-001 + -025), SDD-004 (F-2027-005 + -006), SDD-006 (F-2027-024) have no "Follow-up findings" tail section. Lineage is discoverable from the ledger but not from the SDD reader's vantage. | doc — **closed** by Phase 2 docs-final-cluster PR (SDD-003, SDD-004, SDD-006 each gain a "Follow-up findings (F-2027-045)" tail section listing the F-2027-NNN entries that iterated on each SDD's surface). |
| F-2027-046 | nice | `module_suricata.rs` live-positive test gap | Test runs only under `SELFDEF_DRY_RUN=1`; the live-positive path that actually loads suricata rules has no regression test. SDD-005 D-1 requires both paths. | implement |
| F-2027-047 | nice | `module_polarproxy.rs` P-1 dry-run-noop pair missing | All cases run `SELFDEF_DRY_RUN=1` but no `snapshot_tree` / `assert_tree_unchanged` to guard against dry-run-becomes-live regression. | implement — **closed as false positive** (re-verified during the module-test-backfill PR — `module_polarproxy.rs::dry_run_apply_must_be_a_noop_on_disk` at line 231 already implements the P-1 snapshot pattern; the explorer's report was stale). |
| F-2027-048 | nice | `module_vpn_bridge_{cloudflare,tailscale}.rs` P-1 gap | Live-positive coverage present but no P-1 paired test. | implement — **closed** by Phase 2 module-test-backfill PR (new `cloudflare_dry_run_must_be_a_noop_on_disk` + `tailscale_dry_run_must_be_a_noop_on_disk` cases use `snapshot_tree` / `assert_tree_unchanged` against the existing fixtures). |
| F-2027-049 | nice | `workspace_root()` / `module_dir()` duplication | Re-implemented in ~14 module test files; `crates/selfdef-cli/tests/common/mod.rs` already exports canonical versions. | implement — **closed** by Phase 2 common-mod migration PR (17 test files now import from `common`; the 12 module-specific `module_dir()` wrappers are one-liners that delegate to `common::module_dir("<slug>")`). |
| F-2027-050 | nice | `last_stdout_line()` duplication | Re-implemented in 6+ test files; common version exists. | implement — **closed** by Phase 2 common-mod migration PR (every test file uses `common::last_stdout_line` directly). |
| F-2027-051 | nice | `write_executable()` duplication | Duplicated across 4 vpn-bridge / tetragon-signing tests. | implement — **closed** by Phase 2 common-mod migration PR (every test file uses `common::write_executable` + `common::prepended_path` + `common::write_file` directly). |
| F-2027-052 | nice | `m4_alert.rs` real-time sleeps | Three `tokio::time::sleep`/`timeout` calls with multi-second deadlines; SDD-005 forbids. | implement |
| F-2027-053 | nice | `m8_honeytokens.rs` real-time sleeps | Seven real-time sleeps across three test cases; same anti-pattern. | implement |
| F-2027-054 | nice | `dummy_action_set` shared tmp paths | `m12_api.rs` helper writes to host-global `temp_dir().join("selfdef-api-test-snapshots")`; parallel runs trample. | implement — **closed** by Phase 2 api-test isolation PR (helper now uses `tempfile::tempdir()` per call so each test gets its own snap+forensics scratch). |
| F-2027-055 | nice | `std::mem::forget(dir)` SQLite leak | `m12_api.rs:56` leaks tempdirs on purpose; SQLite files accumulate in `/tmp` across runs. | implement — **closed** by Phase 2 api-test isolation PR (`build_state()` now returns the `TempDir` handle as a 4th tuple element; 12 callers hold it via `_dir`; second leak site at line 694 replaced with a `let _dir_holder = dir` stack hold). |
| F-2027-056 | nice | metrics tests bypass P-2 parser | `m12_api.rs::metrics_reflect_ingest_counters_via_record_event` uses raw `body.contains(...)`; should consume the P-2 parser output. | implement — **closed** by Phase 2 parser-adoption PR (the four substring assertions are now `exp.find(name, labels)` lookups against the parsed `Exposition`; format-strict validation kicks in for free). |

## SDD-debt findings (1)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-010 | SDD-debt | `selfdefctl events follow` TCP transport | UNIX socket only; TCP operators are out. Either pull in an HTTP client dep (size/security tradeoff) or document a remote-tunneling pattern (operator UX tradeoff). | design |

## Status

- **56 findings raised** across six explorers (recent-PRs: 10;
  crate: 11; module: 6; integration: 9; docs: 9; tests: 11).
- **0 blockers**, **3 important (all closed)**, **52 nice (49
  closed, 3 open)**, **1 SDD-debt (F-2027-010 open)**.
- Tests-explorer remaining open clusters: F-2027-046
  (suricata live-positive) and `pause()`-conversion (F-2027-052
  + -053). The `common/mod.rs` migration, module-test
  backfill, api-test isolation, and parser-adoption clusters
  are all closed.
- One explorer remains (security). Will add more findings in
  follow-up PRs.
- Three explorers remain (docs, tests, security). Each will
  add more findings in follow-up PRs. The only remaining open
  Phase 2 SDD-debt is F-2027-010 (`events follow` TCP transport),
  waiting on a design decision.

## Phase 1 references

Phase 1's ledger lives at [`../99-findings-ledger.md`](../99-findings-ledger.md).
Every `F-2026-NNN` entry there is closed — Phase 2 does not
re-litigate Phase 1 closures. If a Phase 1 fix is found to be
broken, that's a new Phase 2 finding with its own `F-2027-NNN`
id (and a back-reference to the original `F-2026-NNN`).
