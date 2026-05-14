# Operator runbooks (F-2027-040)

This directory holds the runbooks an operator opens when
turning on, debugging, or rotating an audit-shipped feature.
Each runbook is its own file, named `<feature>.md`. This
README is the index.

## Index

| Runbook | Covers |
| --- | --- |
| [`first-run.md`](./first-run.md) | First-run bootstrap: `selfdefctl init {config,modules,checklist}` + the 11-step opt-in walk. |
| [`signing.md`](./signing.md) | Rule signing: key generation, deploy, enforce, SIGHUP / SIGUSR2 reload, rotation. |
| [`rbac-posture.md`](./rbac-posture.md) | Kubernetes RBAC posture check for `agent-guard`'s pod-label scope. |
| [`operator-health-check.md`](./operator-health-check.md) | `selfdefctl doctor` cross-cutting health check: categories, output formats, exit codes. |
| [`test-contract.md`](./test-contract.md) | Contributor-facing: SDD-005 test contract, the four categories, the three shared patterns, per-test isolation overrides. |
| [`module-helpers.md`](./module-helpers.md) | Contributor-facing: the `packaging/lib/module-lib.sh` v1/v2 helper library + per-module adoption table. |
| [`integrations.md`](./integrations.md) | Contributor-facing: SDD-008 D-1 integration crate template (modules-vs-integrations boundary, Cargo manifest skeleton, channel-trait skeleton, extension recipe). |

## Canonical runbook shape (F-2027-040)

New `docs/dev/<feature>.md` runbooks aim for the following
section structure. Existing runbooks predate this convention
and may not match exactly; bringing them into line is a low-
priority docs-only task and not a blocker for new runbooks
borrowing the same skeleton.

1. **Headline + one-paragraph TL;DR** — what feature, what
   problem it solves, where the contract lives in code.
2. **Configuration knobs** — every `[section].key` the runbook
   touches, with default values and a one-liner per key.
3. **Commands** — copy-pasteable shell snippets the operator
   runs, in the order they're typically invoked. Include
   expected output where it's stable.
4. **Tests** — pointer to the integration test that exercises
   the same surface, so a future contributor changing the
   surface knows where to land the regression test.
5. **Troubleshooting** (optional) — common failure modes
   keyed by error message; what to look for in `journalctl`.
6. **Env overrides** (optional) — test-only knobs that change
   default paths; see `test-contract.md` § "Per-test isolation
   overrides" for the workspace-wide pattern.
7. **Threat model / what this doesn't fix** (optional) —
   for security-relevant features; spell out the residual risk
   the operator carries even with the feature turned on.

Contributor-facing runbooks (`test-contract.md`,
`module-helpers.md`) reshape 1-4 to fit:

1. **Source of truth** — where the canonical artifact lives in
   the tree.
2. **Caller contract** — required env vars / helper names /
   versioning.
3. **Reference content** — the actual table / list / API.
4. **Extension recipe** — how to add a new entry / bump a
   version.

## Cross-references

- `docs/sdd/` — seven implemented Software Design Documents
  (001..007) plus the draft SDD-008 charter on notifications
  orchestration + integrations taxonomy. Each `docs/dev/`
  runbook traces back to one or more SDDs in its TL;DR.
- `docs/review/` (Phase 1) and `docs/review/phase-2/` —
  audit-cycle findings ledger. Most `F-2027-NNN` references
  in the runbooks resolve against
  `docs/review/phase-2/99-findings-ledger.md`.
- `README.md` at the repo root — operator quick-start; points
  out to specific runbooks for each opt-in feature.
- `ARCHITECTURE.md` at the repo root — daemon-side wiring +
  cross-crate seams; complementary to the operator runbooks.
