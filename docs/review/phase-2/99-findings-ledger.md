# Phase 2 findings ledger

> Status: in progress. First-pass entries from the recent-PRs
> audit; the other six explorers (crate, module, integration,
> docs, tests, security) run in follow-up PRs.
> Last updated: 2026-05-13

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
| F-2027-003 | important | `selfdef-collector-eventstream::unsafe_geteuid` | `/proc/self/status` parse failure returns UID `0` (permissive); operators never notice the integrity check is degraded. | implement — emit a startup warning when the proc read fails so operators see the silent fallback. |
| F-2027-008 | important | `selfdefctl doctor` rbac category | Emits a `warn:` pointer to `selfdefctl rbac check` whenever agent-guard is in pod-label scope, even if the operator never ran rbac-check. The warn count inflates the summary line, suggesting failure where there is none. | implement — flip to `skip:` ("posture not verified") or expand the warn message ("posture not verified — run `selfdefctl rbac check --probe`"). |

## Nice findings (7)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-001 | nice | `selfdef-cli/src/modules.rs` SDD-003 refusal message | Profile name embedded in the error; could include the exact copy-pasteable TOML snippet. | implement |
| F-2027-002 | nice | `docs/dev/test-contract.md` P-3 NATS pattern | Missing `cargo test -- --include-ignored` runtime guidance. | doc |
| F-2027-004 | nice | `selfdef-cli/src/main.rs::discover_daemon_pid` | Missing `systemctl` on PATH yields "command not found" instead of a friendly diagnostic. | implement |
| F-2027-005 | nice | `selfdef-daemon`'s rule-signing reload | SIGHUP reloads rules through the verifier but not the verifier itself; a rotated public-key path needs a full daemon restart. | implement — SIGUSR2 could re-load the verifier too. |
| F-2027-006 | nice | `modules/tetragon/install/apply.sh` | Spawns `selfdefctl keys verify` once per policy file (N spawns for N policies). | implement — batch `selfdefctl keys verify --all <dir>` verb. |
| F-2027-007 | nice | `selfdefctl rbac check --probe` | Built-in subject set is `system:authenticated` + `system:unauthenticated` only; common mistakes (`system:masters`, default ServiceAccount) aren't probed. | implement — expand the built-in set OR make it configurable. |
| F-2027-009 | nice | `selfdefctl init` `STARTER_CONFIG` | Template doesn't show a `[notifier.ntfy]` example; operators discover the shape only in `/usr/share/selfdef/selfdef.toml.example`. | doc — embed a commented `[notifier.ntfy]` block in the starter. |

## SDD-debt findings (1)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2027-010 | SDD-debt | `selfdefctl events follow` TCP transport | UNIX socket only; TCP operators are out. Either pull in an HTTP client dep (size/security tradeoff) or document a remote-tunneling pattern (operator UX tradeoff). | design |

## Status

- **10 findings raised** from one explorer (recent-PRs audit).
- **0 blockers**, 2 important, 7 nice, 1 SDD-debt.
- Other six explorers (crate, module, integration, docs,
  tests, security) will add more findings in follow-up PRs.

## Phase 1 references

Phase 1's ledger lives at [`../99-findings-ledger.md`](../99-findings-ledger.md).
Every `F-2026-NNN` entry there is closed — Phase 2 does not
re-litigate Phase 1 closures. If a Phase 1 fix is found to be
broken, that's a new Phase 2 finding with its own `F-2027-NNN`
id (and a back-reference to the original `F-2026-NNN`).
