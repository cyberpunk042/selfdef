# Phase 2 — recent-PRs audit (post-Phase-1 closeout)

Companion to Phase 1's [70-recent-prs-audit.md](../70-recent-prs-audit.md).
Same shape: walk the 18 PRs shipped since Phase 1 closeout and
flag observations that didn't get caught at PR-review time.

## Methodology

For each PR: read the diff, read the description, check the
tests, check the docs. Look for:

- **Coverage gaps** — features the PR added without
  corresponding tests.
- **Drift** — claims in the PR description that don't match
  the code that landed.
- **Documentation drift** — feature shipped, docs reference
  the old shape.
- **Inconsistencies** — error messages, exit codes, default
  paths that don't match siblings.
- **Cargo cult patterns** — a habit copied across PRs that
  one could argue isn't quite right.

Outcomes feed F-2027-NNN entries in
[99-findings-ledger.md](99-findings-ledger.md).

## PRs surveyed

| # | Title | Audit pass |
| --- | --- | --- |
| #37 | SDD-001 AI-machine end-to-end | review-clean |
| #38 | SDD-002 daemon_requires | review-clean |
| #39 | SDD-003 vpn-bridge multi-instance | observation: F-2027-001 |
| #40 | SDD-006 shared-lib | review-clean |
| #41 | SDD-005 test contract | observation: F-2027-002 |
| #42 | SDD-004 security threat-model | review-clean |
| #43 | eventstream integrity (F-2026-026 followup) | observation: F-2027-003 |
| #44 | API token hot-rotation (F-2026-023 followup) | observation: F-2027-004 |
| #45 | rule signing | observation: F-2027-005 |
| #46 | TracingPolicy signing (F-2026-024 followup) | observation: F-2027-006 |
| #47 | shared-lib v2 manifest helpers (F-2026-050) | review-clean |
| #48 | dry-run-noop migration (F-2026-030 full close) | review-clean |
| #49 | k8s RBAC posture check (F-2026-025 followup) | observation: F-2027-007 |
| #50 | `selfdefctl doctor` | observation: F-2027-008 |
| #51 | `selfdefctl init` | observation: F-2027-009 |
| #52 | README refresh | review-clean |
| #53 | ARCHITECTURE.md refresh | review-clean |
| #54 | `selfdefctl events follow` | observation: F-2027-010 |

## Observations (raw, pre-triage)

The findings below get full ledger entries; this section
captures the audit's first-pass observations with enough
context to triage each one. Severity ratings are the auditor's
recommendation; final triage in the ledger.

### F-2027-001 — vpn-bridge: profile name in error messages doesn't match config key

PR #39 introduced `[profiles.details.<profile_name>].instanced
= false` to declare per-profile multi-instance capability. The
resolver's refusal message reads:

> `module 'vpn-bridge' profile 'tailscale' does not support
> multi-instance ... declare the profile instanced via
> [profiles.details.tailscale].instanced = true`

The exact key path is correct, but operators inspecting their
config see `[profiles.details.tailscale]` and have to mentally
map "profile" ↔ "tailscale". No ambiguity in this example, but
when profile names contain hyphens (e.g. `cloudflare-tunnel`),
operators sometimes copy-paste the wrong shape. **nice**: add
the exact TOML snippet (escaped) to the error message instead
of describing it.

### F-2027-002 — test-contract.md missing "real-broker NATS" runtime guidance

PR #41's `docs/dev/test-contract.md` (SDD-005's runbook) lists
the three shared patterns including P-3 (real-broker NATS
fixture). The doc mentions `apt install nats-server` but
doesn't cover (a) the version required to support JetStream
features the tests use, (b) the cargo invocation to actually
run the gated tests:

```sh
cargo test -p selfdef-nats -- --include-ignored
```

**nice**: append the exact `cargo test --include-ignored`
incantation to the P-3 section.

### F-2027-003 — eventstream integrity check: euid reader is a /proc shim

PR #43's `unsafe_geteuid()` reads `/proc/self/status` and
parses the `Uid:` line. This works on Linux (the project's
declared target) but fails silently — returning `0` — on any
host where `/proc/self/status` is unreadable. The fallback
makes the check more permissive than intended (root-owned
files pass even if the daemon's effective UID isn't actually
root). **important**: surface the read failure as a logged
warning at startup so operators notice when the check is
degraded.

### F-2027-004 — `api rotate-token --pid auto` shells to systemctl unconditionally

PR #44's `discover_daemon_pid()` runs
`systemctl show -p MainPID --value selfdefd.service`. If the
host isn't running systemd (containerised dev, restricted
distros, FreeBSD compat layer), the error message is
"systemctl exited 127: command not found" which is
diagnostic-light. **nice**: detect missing `systemctl` early
and emit "no `systemctl` on PATH; pass `--pid <pid>` directly".

### F-2027-005 — Rule signing: SIGHUP picks up new sidecars but not a changed pubkey path

PR #45 wires the verifier at daemon-startup. SIGHUP reloads
rules through the *existing* verifier — fine for adding new
signed rules, but a rotated public-key path requires a daemon
restart. The `docs/dev/signing.md` runbook calls this out, but
operators following the rotation path probably hit it. **nice**:
SIGUSR2 (the existing api-token reload signal) could also
reload the verifier from the current `[security]` config; or
add a separate `selfdefctl keys reload` verb.

### F-2027-006 — Tetragon policy verifier: `selfdefctl keys verify` shells out per file

PR #46's apply.sh iterates every `*.yml` in `policy_dir` and
runs `selfdefctl keys verify $p` once per file. On a host with
50 policies, that's 50 process spawns. Not a hot path (apply is
operator-initiated), but a single `selfdefctl keys verify
--all <dir>` would amortise the public-key load. **nice**:
batch-verify verb.

### F-2027-007 — `rbac check`: builtin subject list is fixed at 2

PR #49's `extra_subjects` lets operators add `--as <subject>`
but the built-in set is hard-coded to `system:authenticated`
and `system:unauthenticated`. Common-mistake subjects like
`system:masters` (all kubeadm clusters) or
`system:serviceaccount:default:default` aren't probed by
default. **nice**: expand the built-in set, or make it
configurable via a doc-recommended `--as` list operators
copy-paste.

### F-2027-008 — `doctor`: rbac category emits a `warn:` pointer, not a real check

PR #50's doctor reports "agent-guard scope = pod-label — run
`selfdefctl rbac check --probe` to verify" as a `warn:` line.
Doctor never probes the cluster itself (deliberate per the
design). But the `warn:` count in the summary line ("1 warn")
suggests something is wrong when actually nothing is — just
the operator hasn't run rbac-check yet. **important**: either
flip this to `skip:` (which doesn't increment the warn count)
or make the warn message clearer ("posture not verified" vs
"posture failed").

### F-2027-009 — `init config`: doesn't ship a complete `[notifier.ntfy]` example

PR #51's `STARTER_CONFIG` template has `channels = []` under
`[notifier]` and the comment "Add `\"ntfy\"`, `\"signal\"` once
the matching `[notifier.<name>]` block is configured". But the
template never shows the `[notifier.ntfy]` block shape. New
operators discovering the file have to find it in
`/usr/share/selfdef/selfdef.toml.example` (which the comment
points at). **nice**: include a commented `[notifier.ntfy]`
block in the starter so operators don't need to context-switch.

### F-2027-010 — `events follow`: UNIX socket only; TCP operators are out

PR #54 deliberately scoped to UNIX socket, with the runbook
suggesting `curl --no-buffer` for TCP deployments. Reasonable
trade-off (avoids pulling hyper into the CLI), but operators
deploying selfdef on a remote box accessed via TCP+token can't
use the CLI's `events follow` at all. **nice / SDD-debt**:
either add TCP transport (introduces a hyper / `reqwest` dep)
or document a `socat` / `ssh -L` pattern for remote operators.

## Closed without finding

The 11 PRs marked "review-clean" passed the audit without an
actionable observation. That's a high pass rate vs Phase 1's
recent-PRs audit (where about half the PRs had observations),
which the author attributes to:

- Most Phase-2-eligible PRs were the SDD implementations the
  audit itself designed — they had clear contracts and
  shipped against them.
- The doctor + init operator-UX PRs were intentionally
  conservative: no new daemon behaviour, no new on-disk side
  effects, lots of integration tests against fake servers.
- Documentation PRs (#52, #53) don't introduce observable
  shape that the audit can flag.

The 10 observations above are clustered in the "shipped real
new code" PRs (#43, #44, #45, #46, #49, #50, #51, #54). Most
are `nice`-tier ergonomic issues; one is `important` (F-2027-003
silent euid fallback) and one borderline (`F-2027-008`
doctor's warn vs skip semantics).
