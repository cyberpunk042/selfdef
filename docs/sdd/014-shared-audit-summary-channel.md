# SDD-014 — `shared-audit-summary` notifier channel (Stage-2 PR 2/4)

> Status: **review** — second Stage-2 SDD per SDD-012 Q-H ordering
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-16
> Closes findings: SDD-012 Q-C (audit-log sharing on SAIN-01)
> Derived from: SDD-012 (integration design); SDD-013 ([deployment.target] config); SDD-008 (notifications orchestration)

## Problem

SDD-012 Q-C resolved: **selfdef writes to its own audit log AND, when `[deployment.target] = "sain01"`, appends a summary line per event to `/mnt/vault/context/security_audit.log`**.

The shared `security_audit.log` is the operator's single chronological timeline across sovereign-os (guardian-core daemon writes Tetragon kills there) and selfdef (events from agent-guard + notifier chains). Operators get ONE timeline for cross-component review without losing selfdef's full per-event richness in its own log.

This SDD specifies the new notifier channel that emits these summary lines.

## Required coverage

### 1. New crate or module

`crates/selfdef-integration-shared-audit-summary/` — small crate alongside the existing 12 notifier channels (mirrors the per-channel-crate pattern from SDD-008's notifier orchestration).

Alternative: a module inside `selfdef-notifier` rather than a separate crate. **Recommend separate crate** for the same reason `selfdef-integration-write` was its own crate (per D-024): one crate per transport keeps responsibility crisp.

### 2. Channel config

```toml
# /etc/selfdef/selfdef.toml addition (post-SDD-013):
[deployment]
target = "sain01"

[notifier.shared_audit_summary]
enabled = true                                              # default false; auto-enabled when target=sain01
path = "/mnt/vault/context/security_audit.log"              # operator-overridable
selfdef_audit_path = "/mnt/vault/context/selfdef-audit.jsonl"  # full selfdef audit log (set by SDD-013)
```

When `target = "sain01"` AND `[notifier.shared_audit_summary].enabled` is unset, treat as `true` (auto-enable). Operator can explicitly set `enabled = false` to opt out.

When `target = "generic"`, this channel never auto-enables (matches SDD-012 Q-G: non-SAIN-01 deployments work identically).

### 3. Summary-line format

Each line is a single fixed-shape record (newline-delimited):

```
<ISO8601-UTC> <component> <severity> <event-id> <kind> see <selfdef-audit-path>:<line-number>
```

Examples:

```
2026-05-16T03:45:12Z selfdef WARN evt-9f2a CONN_ANOMALY        see /mnt/vault/context/selfdef-audit.jsonl:127
2026-05-16T03:45:14Z selfdef INFO evt-9f2b CORRELATOR_ALERT    see /mnt/vault/context/selfdef-audit.jsonl:128
2026-05-16T03:45:30Z selfdef ERROR evt-9f2c POLICY_VIOLATION   see /mnt/vault/context/selfdef-audit.jsonl:129
```

Fields:

| Field | Type | Purpose |
|---|---|---|
| `<ISO8601-UTC>` | timestamp | Matches sovereign-os guardian-core's format for diff-ability |
| `<component>` | always `selfdef` | Discriminator — guardian-core writes `tetragon`; selfdef writes `selfdef`; future components write their own |
| `<severity>` | `INFO`, `WARN`, `ERROR` | Operator filter target |
| `<event-id>` | 4-8 alphanumeric chars | Stable id for cross-referencing |
| `<kind>` | CONN_ANOMALY, CORRELATOR_ALERT, POLICY_VIOLATION, etc. | Event taxonomy (defined in SDD-008) |
| `see <path>:<line>` | pointer | Operator runs `sed -n '127p' /mnt/vault/context/selfdef-audit.jsonl` to read full event |

**No structured data in the shared log.** Full event detail stays in selfdef-audit.jsonl. The shared log is a forensic-timeline index.

### 4. Atomic-append semantics

Per the SAIN-01 architecture (info-hub `wiki/sources/src-sain-01-sovereign-node-spec.md` § Auditor): `tank/context` has `sync=always` + `copies=2`. The shared log lives there, so:

- Each append is one `write(2)` syscall with the full line + newline (line < 4096 bytes guaranteed by format).
- `O_APPEND | O_SYNC` open flags ensure ordering across guardian-core + selfdef writers without flock.
- No mid-line concurrent writes possible (atomic-write contract).

If `selfdef-audit.jsonl` isn't on `tank/context` (operator misconfigured) — the shared log still receives summary lines; the pointer just points at a non-`sync=always` file. Operator's choice; warn at daemon startup if mismatched.

### 5. Error handling

If `/mnt/vault/context/security_audit.log` can't be written (path absent; permission denied; disk full):

- Log the error to selfdef's own log (NOT silent failure)
- Continue with the OTHER notifier channels (don't fail the whole notification chain because one channel is misconfigured)
- `selfdefctl doctor` adds a check: shared-audit-summary path writable

This matches selfdef's existing 12-channel resilience pattern (one channel failure doesn't break the others).

### 6. Channel wiring (legacy + engine paths)

Per SDD-008 (notifications-orchestration), selfdef has two channel-routing layers:

- **Legacy chain**: `[notifier.channels.<name>]` arrays in selfdef.toml
- **Engine path**: structured profile → channel resolution

`shared-audit-summary` MUST wire into both:

- **Legacy**: add a new channel handler at `selfdef-daemon::notifier::chain::dispatch_channel("shared-audit-summary", ...)` matching the `[notifier.shared_audit_summary]` config block.
- **Engine**: add to the engine's channel registry; engine profiles can opt-in/out per profile (e.g. `[engine.profiles.high].channels = ["wall", "write", "shared-audit-summary"]`).

### 7. CLI integration

```sh
# Operator visibility
sudo selfdefctl status                          # gains a 'shared-audit-summary: enabled' line when active
sudo selfdefctl notify test shared-audit-summary  # writes a test summary line; verify operator can tail the shared log
sudo selfdefctl doctor                          # warns on misconfigured path
```

### 8. Regression-prevention tests

Tests for this PR (in `crates/selfdef-integration-shared-audit-summary/tests/`):

```rust
#[test]
fn summary_line_format_matches_spec() { /* fields + ordering + ISO8601 */ }

#[test]
fn channel_disabled_by_default_for_generic_target() { /* SDD-012 Q-G */ }

#[test]
fn channel_auto_enabled_for_sain01_target() { /* unless explicit enabled = false */ }

#[test]
fn explicit_disable_overrides_auto_enable() { /* enabled = false respected */ }

#[test]
fn append_failure_logged_to_selfdef_audit_does_not_break_chain() { /* resilience */ }

#[test]
fn concurrent_appends_are_atomic() { /* tmpfs + 2 threads writing 1000 lines each; no torn writes */ }
```

Integration tests: `tests/it/notifier_shared_audit_summary.rs` — daemon-level, exercises the chain + engine paths.

## Goals

1. **One operator timeline** — shared log gives chronological cross-component view without losing per-component depth.
2. **Forensic boundary preserved** — selfdef-audit.jsonl owns the full event; shared log is index-only.
3. **Atomic appends** — no torn writes between guardian-core + selfdef writers.
4. **Non-SAIN-01 unchanged** — `target=generic` deployments never see this channel (Q-G honored).
5. **One-channel failure doesn't break others** — resilience pattern matches the existing 12 channels.

## Non-goals (this SDD)

- Does NOT implement Tetragon perimeter coexistence (SDD-015).
- Does NOT implement `oracle-triage` channel (SDD-016).
- Does NOT alter the existing 12 notifier channels in any way.
- Does NOT define the schema of selfdef-audit.jsonl (that's selfdef-audit module's responsibility; the shared-audit-summary channel just emits pointers into it).
- Does NOT decide rotation policy for the shared log (operator-managed via `logrotate` per existing pattern).

## Open sub-questions

- **Q14-A** — Format-version field in the summary line? Recommend: **NO** — keep the format dead-simple; if it changes, bump selfdef major version + document in release notes.
- **Q14-B** — Should ERROR severity events also notify a higher-tier channel (Slack / ntfy / wall)? Recommend: **YES — but as a separate composition** in selfdef.toml (`[engine.profiles.high].channels = [...]`); not a hardcoded coupling here. Each channel stays independent.
- **Q14-C** — Should the channel ALSO emit a JSONL twin under `/mnt/vault/context/security_audit.jsonl` for machine readers? Recommend: **DEFER** — start with text-only; add JSONL if/when operator wants machine consumption (Stage-2+ next round if needed).
- **Q14-D** — Operator-supplied custom format string? Recommend: **NO** — flexibility costs alignment with guardian-core's format. Lock the format.

## Way forward

1. **This PR** — spec.
2. **Impl PR** — crate + tests + CLI wiring + doctor check.
3. **SDD-015 PR** — Tetragon perimeter coexistence (per Q-A).
4. **SDD-016 PR** — `oracle-triage` channel (per Q-D).

Stage-2 progress: SDD-013 ✅ merged → this SDD → SDD-015 → SDD-016.

## Cross-references

- SDD-012 § Q-C (the design this implements)
- SDD-013 (deployment.target config — required predecessor)
- SDD-008 (notifications orchestration — the 12-channel pattern)
- SDD-002 (config plumbing pattern)
- SDD-005 (test contract)
- sovereign-os `scripts/hooks/post-install/tetragon-policy-load.sh` (guardian-core writes to the same `/mnt/vault/context/security_audit.log` — format alignment target)
- sovereign-os `profiles/sain-01.yaml` `hardware.storage.datasets.tank/context` (`sync=always` makes the append-contract durable)
- D-024 (per-user transport → write crate; precedent for one-crate-per-transport pattern)
