# Phase 2 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-13

## Why Phase 2 now

Phase 1's [findings ledger](../99-findings-ledger.md) closed out
in this session: every blocker, important, and SDD-debt finding
either shipped via one of the six SDD implementation PRs (#37,
#38, #39, #40, #41, #42) or via the seven deferred-follow-up
PRs (#43–#49). After that, the post-audit synthesis PRs landed
— `selfdefctl doctor` (#50), `selfdefctl init` (#51), README +
ARCHITECTURE.md refreshes (#52, #53), `selfdefctl events follow`
(#54). 18 PRs total since the Phase 1 closeout.

Each one shipped tests and docs, but the cadence didn't include
a structural audit pass over the new code. Phase 2 is that pass.
Same methodology as Phase 1 (seven explorers, F-NNNN findings,
SDDs where the fix is design-shaped), different vintage prefix:
**F-2027-NNN** so the two ledgers never collide.

## What changed since Phase 1 closeout

New crate:
- `selfdef-signing` — minisign-compatible detached signature
  verifier (PR #45).

New CLI verbs (all in `crates/selfdef-cli/src/`):
- `events follow` (`follow.rs`) — live tail of `/events/stream`
  over UNIX socket (PR #54).
- `doctor` (`doctor.rs`) — cross-cutting health check (PR #50).
- `init {config, modules, checklist}` (`init.rs`) — first-run
  bootstrap (PR #51).
- `keys verify` (in `main.rs`) — minisign signature debug (PR #45).
- `api rotate-token` (in `main.rs`) — API token hot-rotation
  (PR #44).
- `rbac check` (in `main.rs`) — k8s RBAC posture check (PR #49).

New daemon-side machinery:
- Eventstream collector integrity gate (`integrity_check =
  true`, PR #43).
- API token hot-rotation via `Arc<RwLock<Option<LoadedTokens>>>`
  + SIGUSR2 (PR #44).
- Correlator opt-in signed-rule verification
  (`Engine::load_dir_verified`, PR #45).
- Daemon refuses to start when
  `[security].require_signed_rules = true` but the public-key
  path is missing.

New module-side machinery:
- Shared module-script library v2 with manifest helpers
  (`packaging/lib/module-lib.sh`, PR #47).
- Tetragon module's `require_signed_policies` toggle (PR #46).
- vpn-bridge's per-profile `instanced` capability (SDD-003).

New docs surface:
- `docs/dev/first-run.md`, `operator-health-check.md`,
  `signing.md`, `rbac-posture.md`, `module-helpers.md`,
  `test-contract.md`.
- README + ARCHITECTURE.md refreshed.

New tests: ≈50 new tests across `crates/*/tests/`, mostly
integration tests for the new verbs + module-script
verification paths.

## Scope of this Phase

Same shape as Phase 1's seven explorers:

| Explorer | Scope for Phase 2 |
| --- | --- |
| Crate audit | The new `selfdef-signing` crate + the extended surfaces on `selfdef-cli`, `selfdef-api`, `selfdef-correlator`, `selfdef-collector-eventstream`. |
| Module audit | The new `require_signed_policies` knob in `tetragon`, the v2 manifest helpers across all 8 modules, vpn-bridge per-profile instanced. |
| Integration audit | The new seams: SSE → CLI follow consumer, SIGUSR2 → token reload, minisign verify → correlator load, integrity check → collector refusal. |
| Docs audit | Six new `docs/dev/<feature>.md` runbooks, README + ARCHITECTURE.md, six SDDs (all `implemented`). |
| Tests audit | The new integration tests — coverage gaps, missing edge cases, drift between test assertions and shipped error messages. |
| Recent-PRs audit | The 18 PRs shipped post-Phase-1. Same retrospective shape as Phase 1's [70-recent-prs-audit.md](../70-recent-prs-audit.md). |
| Security audit | New attack surfaces: the SSE endpoint (read-cap exposure), the operator-side `init` config templates (defaults), `rbac check --probe` shelling out to kubectl. |

## Out of scope (defer to Phase 3)

- Cross-host fleet behaviour (NATS bridge under load).
- Performance / load benchmarks.
- Real-cluster k8s integration (`rbac check --probe` against a
  live cluster).
- Phase 1 ledger entries that flipped to "closed" — Phase 2
  doesn't re-litigate already-closed findings; if a Phase 1
  fix is broken, that's a new finding under Phase 2's prefix.

## Methodology

Same as Phase 1:

1. Each explorer surveys their area, lists every concrete
   observation that's actionable.
2. Observations get triaged into:
   - **blocker** — must fix before shipping;
   - **important** — should fix;
   - **nice** — cosmetic or non-blocking;
   - **SDD-debt** — needs a design doc to scope the fix.
3. Each observation becomes an `F-2027-NNN` entry in the Phase 2
   findings ledger with surface, summary, and next-phase
   recommendation.
4. SDD-debt findings cluster into one or more SDDs under
   `docs/sdd/00N-*.md` (continuing the 001..006 numbering).

## Status

This PR opens Phase 2 with:
- the charter (this file)
- a structured inventory of what's been added since Phase 1
- one explorer's first-pass output (recent-PRs audit)
- the Phase 2 ledger with the initial findings

The remaining explorers will run in follow-up PRs. Phase 2
closes when every important / blocker has either a "closed by
<PR>" back-reference or a tracked SDD.

## Naming

Phase 1 findings used `F-2026-NNN` (calendar year of the audit).
Phase 2 uses `F-2027-NNN` so the two never collide and the
prefix maps the finding's vintage at a glance. If Phase 2 runs
deep into 2027 and Phase 3 starts in 2028, that's `F-2028-NNN`.
The number does not roll over within a year — F-2027-001 is the
first finding in this Phase, F-2027-100 is the hundredth,
whether they land on the same day or six months apart.
