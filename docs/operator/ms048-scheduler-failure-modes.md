# MS048 Goldilocks Scheduler — Operator Failure-Mode Runbook

> **M01173** per `backlog/milestones/MS048-goldilocks-scheduler-hardware-aware-resource-routing.md`. Authoritative operator runbook for every documented failure mode of the scheduler stack (M01155–M01174). Pairs with the sovereign-os alert rules in `cyberpunk042/sovereign-os/config/prometheus/alerts/selfdef-scheduler.rules.yml`.
>
> **Doctrinal anchor**: [Peace Machine + Core Law](https://github.com/cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/doctrine/peace-machine-and-core-law.md) — peace-machine clause *"disciplined enough to explain itself"*. Every failure mode below is observable + named + remediated; no silent failure modes.
>
> **Reading order**: operator alerts in the cockpit cite the `cd_link` label. Find the matching row in §1 (alert→failure-mode mapping), then jump to the named §N section for the journald signature + remediation.

## 1. Alert → failure-mode index

Alert names match `cyberpunk042/sovereign-os/config/prometheus/alerts/selfdef-scheduler.rules.yml`.

| Alert | `cd_link` | Section |
|---|---|---|
| `SelfdefSchedulerTextfileEmitFailed` | `observer-fault` | [§2 Textfile emit failed](#2-textfile-emit-failed) |
| `SelfdefSchedulerObserverSilent` | `observer-silent` | [§3 Observer silent](#3-observer-silent) |
| `SelfdefSchedulerAllSubstratesDegraded` | `substrate-blind` | [§4 All substrates blind](#4-all-substrates-blind) |
| `SelfdefSchedulerSubstrateDegraded` | `substrate-partial` | [§5 Partial substrate degradation](#5-partial-substrate-degradation) |
| `SelfdefSchedulerBlackwellVramExhaustion` | `blackwell-exhaustion` | [§6 Blackwell + host pressure](#6-blackwell--host-pressure) |
| `SelfdefSchedulerHumanGateQueueHigh` | `human-gate-backlog` | [§7 Human-gate backlog](#7-human-gate-backlog) |
| `SelfdefSchedulerMultipleBackpressureFiring` | `multi-surface-pressure` | [§8 Multiple backpressure surfaces firing](#8-multiple-backpressure-surfaces-firing) |
| — (silent failures not in alerts but documented) | | [§9 Audit chain integrity breaks](#9-audit-chain-integrity-breaks) |
| — | | [§10 Config file errors](#10-config-file-errors) |
| — | | [§11 Permission / disk-full / read-only ZFS](#11-permission--disk-full--read-only-zfs) |

---

## 2. Textfile emit failed

**Alert**: `SelfdefSchedulerTextfileEmitFailed` (critical, 5m).
**Indication**: `selfdef_scheduler_textfile_emit_failed > 0` for 5+ minutes.

### Journald signature

```
[selfdef-scheduler-textfile X.Y.Z] starting one-shot poll
  textfile: /var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom
  ...
  FAIL writing textfile: <io error>
```

Followed by either `FAIL writing failure sentinel: <io error>` (catastrophic — both writes failed) or no follow-up message (failure sentinel succeeded; that's what node_exporter is scraping).

### Likely causes

| Cause | Detect | Remediation |
|---|---|---|
| Textfile collector dir doesn't exist | `ls -ld /var/lib/node_exporter/textfile_collector` returns ENOENT | `mkdir -p /var/lib/node_exporter/textfile_collector && chown selfdef: /var/lib/node_exporter/textfile_collector` |
| Disk full on the partition | `df /var/lib/node_exporter` shows 100% | Clear other textfiles, expand the dataset, or relocate via `[emit] textfile_path = "..."` in `/etc/selfdef/scheduler.toml` |
| Permission denied | `ls -ld <textfile dir>` shows no `selfdef` write perm | `chown selfdef: <dir>` or relocate via TOML |
| systemd `ReadWritePaths` doesn't include the path | Service unit `ReadWritePaths` line doesn't list the path | Add the path to `/etc/systemd/system/selfdef-scheduler-textfile.service.d/override.conf` |

### Recovery

After remediation, the next timer tick (within 60s) re-attempts the write. No daemon restart needed.

---

## 3. Observer silent

**Alert**: `SelfdefSchedulerObserverSilent` (critical, 2m).
**Indication**: `time() - selfdef_scheduler_last_run_unix > 300` for 2+ minutes.

### Journald signature

**No recent journal entries** from `selfdef-scheduler-textfile.service`. Check:

```bash
systemctl status selfdef-scheduler-textfile.timer
systemctl status selfdef-scheduler-textfile.service
journalctl -u selfdef-scheduler-textfile -n 50 --since=-10min
```

### Likely causes

| Cause | Detect | Remediation |
|---|---|---|
| Timer not enabled | `systemctl is-enabled selfdef-scheduler-textfile.timer` says `disabled` | `systemctl enable --now selfdef-scheduler-textfile.timer` |
| Timer masked | `systemctl status` shows `masked` | `systemctl unmask selfdef-scheduler-textfile.timer` |
| Service permanently failing | `systemctl status` shows `failed (Result: exit-code)` repeated rapidly | Read `journalctl` for the underlying error; correlate to §2 / §10 / §11 |
| Binary missing | `which selfdef-scheduler-textfile` returns nothing | Reinstall the selfdef package |
| TimeoutStartSec exceeded | Journal shows `Start operation timed out. Terminating.` | Substrate read is hung; one of `nvidia-smi`, `/proc/pressure/*`, `/var/lib/selfdef/*` is blocked. Investigate per §4. |

### Recovery

After fixing the underlying problem: `systemctl restart selfdef-scheduler-textfile.timer` to clear the failure-state.

---

## 4. All substrates blind

**Alert**: `SelfdefSchedulerAllSubstratesDegraded` (critical, 10m).
**Indication**: `selfdef_scheduler_substrate_degraded_count == 3` for 10+ minutes (PSI + DCGM + human-gate ALL reporting Unavailable or Errored).

### Journald signature

```
poll: degraded_count=3 cpu_psi=0.000 blackwell_vram=0.000 queue=0
```

The cockpit's "substrate degradation reasons" table panel shows three rows (one per source) with their reason text. Read that text first before opening this section.

### Likely causes by source

**PSI source unavailable** (typical reason text: *"/proc/pressure not present (kernel < 4.20 or CONFIG_PSI=n)"*):
- Kernel too old → upgrade to 4.20+ (sain-01 is on Linux 6.12 per M067).
- CONFIG_PSI=n → enable + rebuild kernel.
- Container without PSI exposure → bind-mount `/proc/pressure` from host or run on the host.

**DCGM source unavailable** (typical reason text: *"nvidia-smi not found on PATH"* OR *"nvidia driver not loaded"*):
- nvidia driver not installed/loaded → `nvidia-smi` from a separate shell to verify; reinstall driver if needed; reboot.
- `nvidia-smi` not on `PATH` for the `selfdef` user → either install to `/usr/bin/` (default) or override via `[substrate] nvidia_smi_bin = "/opt/cuda/bin/nvidia-smi"` in scheduler.toml.

**Human-gate source unavailable** (typical reason text: *"state root /var/lib/selfdef not present"*):
- selfdefd hasn't been deployed yet (fresh host) → deploy the rest of selfdef first; the scheduler will start emitting healthy human-gate readings once any IPS primitive has written its `pending-restores.json`.
- State dir was relocated → update `[substrate] state_root = "..."` in scheduler.toml.

### Recovery

After each source returns to Healthy, the scheduler resumes emitting non-zero measurements and `substrate_degraded_count` returns toward 0. No daemon restart needed.

---

## 5. Partial substrate degradation

**Alert**: `SelfdefSchedulerSubstrateDegraded` (warning, 30m).
**Indication**: `selfdef_scheduler_substrate_degraded_count` is 1 or 2 for 30+ minutes.

### Behavior

The scheduler continues to operate, but with a reduced ground-truth signal. The degraded source's measurement is 0.0 (PSI fraction or DCGM fraction) or 0 (human-gate count). The cockpit visibly shows WHICH source is degraded — the operator must decide whether to:

- Accept the partial blindness (e.g. brand-new host where nvidia drivers aren't installed and won't be).
- Restore the source per §4's per-source remediation.
- Disable the source via TOML (e.g. `[substrate.dcgm_indices] blackwell = 0 gpu3090 = 0` and accept that gpu3090_util is always blackwell_util on a single-GPU host).

### Honest-offline note

A degraded substrate is NOT a bug — it's a discrete signal. Acting on a 0.0 measurement from a degraded source is the operator's choice; the scheduler does not pretend the value is "really 0". See `substrate_health.degraded_count()` in DriverReading + the per-source `kind="unavailable|errored",reason="..."` Prometheus labels.

---

## 6. Blackwell + host pressure

**Alert**: `SelfdefSchedulerBlackwellVramExhaustion` (critical, 5m).
**Indication**: `selfdef_scheduler_blackwell_vram_high == 1 AND (cpu_pressure OR ram_pressure)` for 5+ minutes.

### Doctrinal context

This is the dump-line-18193 critical pattern: oracle GPU saturated AND host can't keep up. From [Peace Machine + Core Law](https://github.com/cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/doctrine/peace-machine-and-core-law.md): when Blackwell-VRAM-high coincides with CPU or RAM pressure, the workstation is in **resource exhaustion** — autonomous routing must defer to operator-supervised throttling.

### Operator action

1. Surface the eight-axis choice surface — flip the operator into `private` or `careful` profile (MS040) until pressure clears.
2. Throttle inference requests at the gateway (`gateway throttle --inflight 1`).
3. Check sovereign-os M076 load-balancing profile selection — perhaps the wrong profile is active for current workload.

### Recovery

Once Blackwell VRAM drops below `0.90 - 0.10 = 0.80` (R11333 + hysteresis) OR CPU+RAM pressure both clear, the alert resolves. No daemon action; this is operator-judgment territory.

---

## 7. Human-gate backlog

**Alert**: `SelfdefSchedulerHumanGateQueueHigh` (warning, 30m).
**Indication**: `selfdef_scheduler_human_gate_queue_depth > 10` for 30+ minutes.

### Doctrinal context

Peace-machine clause: *"sovereign enough that intelligence remains in the user's hands"*. When pending operator-restore decisions across the 14 IPS primitives exceed the threshold, the scheduler defers autonomous routing — it WILL NOT make a routing decision that creates more pending operator work while the existing queue is over threshold.

### Operator action

Open the sovereign-os cockpit cards for the IPS-quattuordectet pending queues (14 cards, sorted by urgency) and approve/reject the pending restore decisions. The `selfdef_scheduler_human_gate_queue_depth` gauge updates within 60s of decision clearance.

### Recovery

Once the depth drops below 5 (`human_gate_queue_high - hysteresis_margin` from R11349 + the hysteresis applied at the source) the alert resolves and the scheduler resumes autonomous routing.

---

## 8. Multiple backpressure surfaces firing

**Alert**: `SelfdefSchedulerMultipleBackpressureFiring` (warning, 15m).
**Indication**: ≥3 of 6 backpressure surfaces firing simultaneously for 15+ minutes.

### Operator action

This is "the workstation is under multi-axis stress." Cross-reference the per-surface state booleans in the scheduler dashboard. Common patterns:

- `cpu_pressure + ram_pressure + io_pressure` → host is saturated; throttle workload OR migrate to fleet member.
- `blackwell_vram_high + gpu3090_busy + human_gate_queue_high` → inference saturation + operator backlog; pause autonomous routing.
- `cpu_pressure + io_pressure + human_gate_queue_high` → kernel-level work blocked by audit + decision queue; clear human-gate first.

### Recovery

Resolves automatically as surfaces clear below thresholds with hysteresis.

---

## 9. Audit chain integrity breaks

**No alert** (chain integrity is a manual verification step, not a per-poll signal). **Indication**: operator runs `verify_chain` via the CLI (or future cockpit panel) and gets `ChainBreak { line: N, detail: "..." }`.

### Likely causes

| Cause | Detect | Remediation |
|---|---|---|
| Tampering | `verify_chain` reports `prev_event_sha256=<x>, expected <y>` mismatch at a specific line | Forensic: snapshot the file, escalate per MS003-multisig audit-trail incident-response runbook. Restore from ZFS send/recv replica + identify the gap. |
| Missing rotation generation | `verify_chain_across_generations` reports a gap | Check `.N` files for accidental `rm`/`mv`; ZFS rollback to a known-good snapshot. |
| Malformed JSON line | `ChainBreak { detail: "malformed json: ..." }` | A previous emit was interrupted (kill -9, panic). Truncate the file at the last well-formed line + restart timer. |

### Doctrinal context

Core Law clause *"ZFS remembers"*. Chain integrity breaks are HIGH-severity because they suggest either tampering or partial-write corruption — both undermine reversibility. Standing rule: never auto-truncate; always operator-supervised.

---

## 10. Config file errors

**Indication**: journald shows `FAIL loading config from /etc/selfdef/scheduler.toml: <error>`.

### Likely causes

| Cause | Detect | Remediation |
|---|---|---|
| TOML syntax error | Error message contains `config parse (...): ...` | `toml validate /etc/selfdef/scheduler.toml` or compare against `packaging/config/scheduler.toml.example`; fix syntax. |
| Validation failure | Error message contains `config validation: ...` | Read the message — `thresholds.X out of range`, `audit_rotate_bytes < 1024`, `empty path` — fix the offending field. |
| File mode unreadable | `ls -l /etc/selfdef/scheduler.toml` doesn't show `selfdef` read perm | `chown selfdef: /etc/selfdef/scheduler.toml && chmod 640 /etc/selfdef/scheduler.toml` |

### Behavior on error

The binary FALLS BACK to compiled-in defaults rather than refusing to start. This keeps the timer from flapping while the operator fixes the config. The error is logged to journald on every poll until fixed.

---

## 11. Permission / disk-full / read-only ZFS

**Indication**: any IO write error in journald (`Permission denied`, `No space left on device`, `Read-only file system`).

### Permission denied

Check:
- Service unit `User=selfdef Group=selfdef`
- Target paths owned/writable by `selfdef`
- systemd `ProtectSystem=strict` + `ReadWritePaths=` — paths NOT in `ReadWritePaths` are read-only even for root

Fix: update `ReadWritePaths` in the service unit (preferred), or `chown selfdef: <path>`, or update scheduler.toml to point at a path that's already writable.

### No space left on device

Cascading failures: textfile write fails → sentinel write fails → systemd marks service as `failed` → §3 fires.

Recovery: free space on the ZFS dataset; expand the dataset; relocate the audit log to a different dataset via TOML.

### Read-only file system

ZFS has gone read-only (typically: pool fault). Surface in the sovereign-os ZFS health dashboard immediately. The scheduler will continue to log to journald but will write zero artifacts. This is a SEV-1 host-level issue — escalate per sovereign-os M068 ZFS architecture incident runbook.

---

## Cross-references

- **Catalog**: `cyberpunk042/selfdef/backlog/milestones/MS048-goldilocks-scheduler-hardware-aware-resource-routing.md`
- **Source**: `cyberpunk042/selfdef/crates/selfdef-scheduler/src/{psi,dcgm,human_gate,backpressure_driver,prometheus_exporter,ocsf_emitter,decision_audit,config}.rs`
- **Binary**: `cyberpunk042/selfdef/crates/selfdef-scheduler/src/bin/selfdef-scheduler-textfile.rs`
- **systemd**: `cyberpunk042/selfdef/packaging/systemd/selfdef-scheduler-textfile.{service,timer}`
- **Config template**: `cyberpunk042/selfdef/packaging/config/scheduler.toml.example`
- **Alert rules**: `cyberpunk042/sovereign-os/config/prometheus/alerts/selfdef-scheduler.rules.yml`
- **Dashboard**: `cyberpunk042/sovereign-os/docs/observability/dashboards/sovereign-os-selfdef-scheduler.json`
- **Single-pane-of-glass extension**: `cyberpunk042/sovereign-os/docs/observability/dashboards/sovereign-os-ips-host-overview.json` (MS048 row)
- **Doctrine**: `cyberpunk042/devops-solutions-information-hub/wiki/spine/doctrine/peace-machine-and-core-law.md`

## Standing rule

This document is **operator-binding** — every failure mode named in this runbook is implemented at the journald-signature level by the source. New failure modes documented here MUST land alongside their source implementation (the runbook is the contract; the source is the proof). When source emits a new error message, this document gets a new section.

We do not minimize anything.
