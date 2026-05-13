# Phase 2 findings ledger

> Status: in progress. Two of the seven explorers run so far —
> recent-PRs (10 findings, all closed except 1 SDD-debt) and
> crate (11 findings, all open `nice`). Five explorers remain
> (module, integration, docs, tests, security).
> Last updated: 2026-05-13 (Phase 2 module-cleanup PR — closes
> F-2027-022, -023, -025, -026, -027; F-2027-024 stays open
> for the v2-helpers migration follow-up).

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

## Important findings (2)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-003 | important | `selfdef-collector-eventstream::unsafe_geteuid` | `/proc/self/status` parse failure returns UID `0` (permissive); operators never notice the integrity check is degraded. | implement — **closed** by Phase 2 first-fixes PR (`read_euid` now returns `Option<u32>`; failure path emits a `tracing::warn!` and falls back to "root-only" — strict-safe instead of permissive). |
| F-2027-008 | important | `selfdefctl doctor` rbac category | Emits a `warn:` pointer to `selfdefctl rbac check` whenever agent-guard is in pod-label scope, even if the operator never ran rbac-check. The warn count inflates the summary line, suggesting failure where there is none. | implement — **closed** by Phase 2 first-fixes PR (`check_rbac_posture` now emits `Skipped` for pod-label with detail "posture not verified — run `selfdefctl rbac check --probe`"; warn count stays at 0). |

## Nice findings (24 — 23 closed, 1 open)

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
| F-2027-024 | nice | seven script-based modules (bridge-l2, observability, tetragon, integrity-sentinel, polarproxy, suricata, vpn-bridge) | Don't opt into SDD-006 v2 manifest helpers; `uninstall.sh` hand-curates paths that `apply.sh` writes, recreating the drift risk v2 was designed to remove. | implement — full v2 migration is a substantial follow-up touching 7 modules' apply/uninstall pairs. Stays open. |
| F-2027-025 | nice | `modules/vpn-bridge/install/profiles/relay-via-server.sh:20-23` | `$SELFDEF_INSTANCE_ID` is interpolated into nftables table names and per-instance config paths without going through the `safe_name` validator. Operator-controlled, so defense-in-depth — but tightening costs nothing. | implement — **closed** by Phase 2 module-cleanup PR (`_relay_inst_defaults` now `safe_name "$INST" \|\| die "..."` before any interpolation). |
| F-2027-026 | nice | per-module READMEs | All 9 are silent on `SELFDEF_MODULE_LIB_VERSION_REQUIRED` and the v2 helpers. New contributors won't discover the v2 surface. | doc — **closed** by Phase 2 module-cleanup PR (`docs/dev/module-helpers.md` gains a "Per-module adoption" table — single source of truth — plus a 4-step bumping recipe). |
| F-2027-027 | nice | `modules/{bridge-l2,suricata,polarproxy}/install/check.sh` | Missing the conventional `DRY_RUN=0` initialization that every other module's `check.sh` sets. Cosmetic but inconsistent with the v2 lib's caller contract. | implement — **closed** by Phase 2 module-cleanup PR (all three check.sh now set `DRY_RUN=0` before sourcing the lib). |

## SDD-debt findings (1)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-010 | SDD-debt | `selfdefctl events follow` TCP transport | UNIX socket only; TCP operators are out. Either pull in an HTTP client dep (size/security tradeoff) or document a remote-tunneling pattern (operator UX tradeoff). | design |

## Status

- **27 findings raised** across three explorers (recent-PRs: 10;
  crate: 11; module: 6).
- **0 blockers**, **2 important (both closed)**, **24 nice (23
  closed, 1 open — F-2027-024 v2-helpers migration)**, **1
  SDD-debt (F-2027-010 open)**.
- The only remaining `nice` finding is F-2027-024 — a substantial
  follow-up that opts the seven script-based modules into v2
  manifest helpers; queued for its own PR.
- Four explorers remain (integration, docs, tests, security).
  Each will add more findings in follow-up PRs.

## Phase 1 references

Phase 1's ledger lives at [`../99-findings-ledger.md`](../99-findings-ledger.md).
Every `F-2026-NNN` entry there is closed — Phase 2 does not
re-litigate Phase 1 closures. If a Phase 1 fix is found to be
broken, that's a new Phase 2 finding with its own `F-2027-NNN`
id (and a back-reference to the original `F-2026-NNN`).
