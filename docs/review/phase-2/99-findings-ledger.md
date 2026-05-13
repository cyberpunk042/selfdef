# Phase 2 findings ledger

> Status: in progress. Two of the seven explorers run so far —
> recent-PRs (10 findings, all closed except 1 SDD-debt) and
> crate (11 findings, all open `nice`). Five explorers remain
> (module, integration, docs, tests, security).
> Last updated: 2026-05-13 (Phase 2 CLI/api-ergonomics PR —
> closes F-2027-014 through F-2027-018).

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

## Nice findings (18 — 15 closed, 3 open)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-001 | nice | `selfdef-cli/src/modules.rs` SDD-003 refusal message | Profile name embedded in the error; could include the exact copy-pasteable TOML snippet. | implement — **closed** by Phase 2 nice-cluster PR (refusal embeds the `[profiles.details.<profile>]` stanza inline). |
| F-2027-002 | nice | `docs/dev/test-contract.md` P-3 NATS pattern | Missing `cargo test -- --include-ignored` runtime guidance. | doc — **closed** by Phase 2 nice-cluster PR (P-3 now documents the `--include-ignored` invocation + nats-server 2.10+ JetStream requirement). |
| F-2027-004 | nice | `selfdef-cli/src/main.rs::discover_daemon_pid` | Missing `systemctl` on PATH yields "command not found" instead of a friendly diagnostic. | implement — **closed** by Phase 2 nice-cluster PR (`discover_daemon_pid` short-circuits on `ErrorKind::NotFound` with a `pgrep selfdefd` pointer). |
| F-2027-005 | nice | `selfdef-daemon`'s rule-signing reload | SIGHUP reloads rules through the verifier but not the verifier itself; a rotated public-key path needs a full daemon restart. | implement — **closed** by Phase 2 verifier-reload PR (`Correlator::reload_verifier` re-reads the configured public-key file in-place; daemon's SIGUSR2 handler fans out to verifier reload + rule re-verify alongside the existing api-token reload). |
| F-2027-006 | nice | `modules/tetragon/install/apply.sh` | Spawns `selfdefctl keys verify` once per policy file (N spawns for N policies). | implement — **closed** by Phase 2 nice-cluster PR (new `selfdefctl keys verify-dir <dir>` verb; tetragon apply.sh + check.sh both batched to one invocation). |
| F-2027-007 | nice | `selfdefctl rbac check --probe` | Built-in subject set is `system:authenticated` + `system:unauthenticated` only; common mistakes (`system:masters`, default ServiceAccount) aren't probed. | implement — **closed** by Phase 2 nice-cluster PR (built-in set now also probes `system:masters` and `system:serviceaccount:default:default`; `--as` still composes on top). |
| F-2027-009 | nice | `selfdefctl init` `STARTER_CONFIG` | Template doesn't show a `[notifier.ntfy]` example; operators discover the shape only in `/usr/share/selfdef/selfdef.toml.example`. | doc — **closed** by Phase 2 nice-cluster PR (commented `[notifier.ntfy]` stanza embedded in the starter). |
| F-2027-011 | nice | `selfdef-signing::SIGNATURE_SUFFIX` + `signature_path_for` | Both are `pub` but no external caller exists; tests build the `.minisig` path by hand. Either deprecate or surface in the crate `//!`. | implement |
| F-2027-012 | nice | `selfdef-signing::SigningError::Io` | `#[from] io::Error` loses the path the io call was against; sibling variants (`BadPublicKey`, `BadSignature`) carry full context. | implement — split into `Io { path, source }` per call site. |
| F-2027-013 | nice | `selfdef-signing` crate `//!` header | Walks operator through `minisign -G`/`-S` + daemon load path but doesn't mention the `signature_path_for` / `SIGNATURE_SUFFIX` public helpers. | doc — depends on the C2-001 decision. |
| F-2027-014 | nice | `selfdef-api::with_full_capability` | `pub fn` documented as "test-only convenience" but reachable from any consumer; rename or feature-gate to prevent silent auth-bypass via misuse. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (helper now gated behind `test-helpers` Cargo feature; release builds elide it; integration tests enable the feature via a circular dev-dep). |
| F-2027-015 | nice | `selfdef-api::metrics::{run_ingest, Metrics::*}` | Re-exported as `run_metrics_ingest` with zero rustdoc; gating contract ("only spawn when API is enabled") lives in the daemon's wire-up comment, not the signature. | doc — **closed** by Phase 2 CLI/api-ergonomics PR (`run_ingest` doc now states the api-enabled gate contract + the lag-accounting semantics inline). |
| F-2027-016 | nice | `selfdef-api::ApiServer::run` `NoTransport` error | Same error for "api enabled but no transport set" and "api disabled"; operator-facing message could distinguish. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (error message now spells out exactly which TOML keys to set or which to flip false). |
| F-2027-017 | nice | `selfdef-cli` starter-config path constants | `init.rs` and `modules.rs` independently define defaults for the same `/etc/selfdef/` paths; drift risk. | implement — **closed** by Phase 2 CLI/api-ergonomics PR (new `crate::paths` module holds the canonical layout; `init.rs`, `modules.rs`, `doctor.rs`, and `main.rs` all import from it). |
| F-2027-018 | nice | `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` env override | Test-only knob documented only in a source comment; not in `docs/dev/operator-health-check.md` or `--help`. | doc — **closed** by Phase 2 CLI/api-ergonomics PR (`docs/dev/operator-health-check.md` has a new "Environment overrides" section + the doctor verb's `--help` references it). |
| F-2027-019 | nice | `selfdef-correlator` crate `//!` header | Stops at M5's "SshBruteforceRule gone"; doesn't advertise the post-PR-#58 surface (`reload_verifier`, `has_verifier`, SIGUSR2). | doc — **closed** by Phase 2 correlator-observability PR (crate header now documents both reload signals, `reload_verifier`, `verifier_source`, and the SDD-004 signing posture). |
| F-2027-020 | nice | `selfdef-correlator::load_rules` | Logs `rules = N` but not the verifier source path it verified them against; post-SIGUSR2 operators can't eye-ball "did the verifier swap?". | implement — **closed** by Phase 2 correlator-observability PR (`load_rules` now emits `info!(rules, verifier_key)` when the verifier branch was taken). |
| F-2027-021 | nice | `selfdef-correlator` verifier source getter | No public `verifier_source()` getter — tests, `selfdefctl doctor`, dashboards all want to answer "which `policy.pub` is the daemon trusting right now?". | implement — **closed** by Phase 2 correlator-observability PR (new `Correlator::verifier_source() -> Option<PathBuf>`; 3 tests cover the none/present/post-reload paths). |

## SDD-debt findings (1)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-010 | SDD-debt | `selfdefctl events follow` TCP transport | UNIX socket only; TCP operators are out. Either pull in an HTTP client dep (size/security tradeoff) or document a remote-tunneling pattern (operator UX tradeoff). | design |

## Status

- **21 findings raised** across two explorers (recent-PRs: 10;
  crate: 11).
- **0 blockers**, **2 important (both closed)**, **18 nice
  (15 closed, 3 open)**, **1 SDD-debt (F-2027-010 open)**.
- Of the crate explorer's 11 entries, only the selfdef-signing
  API-surface cluster (F-2027-011 + F-2027-012 + F-2027-013)
  remains open; that's the next follow-up PR.
- Five explorers remain (module, integration, docs, tests,
  security). Each will add more findings in follow-up PRs.

## Phase 1 references

Phase 1's ledger lives at [`../99-findings-ledger.md`](../99-findings-ledger.md).
Every `F-2026-NNN` entry there is closed — Phase 2 does not
re-litigate Phase 1 closures. If a Phase 1 fix is found to be
broken, that's a new Phase 2 finding with its own `F-2027-NNN`
id (and a back-reference to the original `F-2026-NNN`).
