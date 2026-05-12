# Tetragon TracingPolicies

Kernel-level enforcement and observability rules for Tetragon.

Policy types:
- `observe-*.yaml` — emit events only, never block.
- `enforce-*.yaml` — block specific syscalls. Deploy with caution; test in
  `audit` mode first.

Reference: https://tetragon.io/docs/concepts/tracing-policy/

**Note:** A policy that blocks writes to `.env` files broke a user's workflow
once. Don't be that user — start every enforce policy in audit mode for at
least a week.
