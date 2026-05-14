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
| F-2028-004 | nice | `selfdef-cli/src/follow.rs::read_token_file` — mode-check asymmetry | The CLI's `--token-file` reader opens any file it can read. The daemon-side `[api].token_file` reader (closed F-2027-031) refuses files whose mode has any `group`/`other` bits set (`mode & 0o077 != 0`). Operators who rotate `api.token` and accidentally leave it world-readable would see the daemon refuse to load it but the CLI silently consume it. Symmetry options: (a) port the daemon's mode check into `read_token_file`, or (b) document the asymmetry explicitly so operators don't expect the CLI to enforce. Not a security gap (the operator controls both ends), but worth resolving so the two readers behave the same way. | implement |

## Status

- **4 findings raised** by the first Phase 3 explorer
  (recent-PRs). **0 blockers**, **0 important**, **2 nice**
  (F-2028-001, F-2028-004), **2 demoted** (F-2028-002,
  F-2028-003 — auditor cross-check showed both were
  documentation-phrasing concerns rather than drift).
- Six explorers remain: crate, module, integration, docs,
  tests, security. Each will add findings in follow-up PRs.
- No Phase 3 SDD-debt findings yet.

## Phase 1 / Phase 2 references

- Phase 1's ledger: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2's ledger: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
