# Tetragon TracingPolicies

Kernel-level enforcement and observability rules for Tetragon.

Policy types:
- `observe-*.yaml` — emit events only, never block.
- `enforce-*.yaml` — block specific syscalls. Deploy with caution; test in
  `audit` mode first.

Shipped policies:
- `observe-sensitive-files.yaml` — credential-file reads (T1552.001).
- `observe-selfdef-tamper.yaml` — writes to selfdef's own binary
  (`/usr/bin/selfdefd`) + config (`/etc/selfdef/`) by anything outside the
  legitimate update path (T1554). **Carries `selfdef.io/validation:
  REQUIRED-ON-TETRAGON-HOST`** — authored against the proven
  `security_file_open` pattern but NOT yet verified to load + fire on a live
  kernel. Validate per the steps in its annotations (confirm it loads, fires
  on a non-excluded write, and does NOT storm on normal daemon/upgrade
  activity) before relying on it for tamper-detection. Observe-only, so it
  cannot break anything in the meantime. Closes the F-2026-099 design gap (the
  legit-writer `matchBinaries` exclusion was the non-trivial part).

Reference: https://tetragon.io/docs/concepts/tracing-policy/

**Note:** A policy that blocks writes to `.env` files broke a user's workflow
once. Don't be that user — start every enforce policy in audit mode for at
least a week.
