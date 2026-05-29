# SDD-066 — Process-quarantine action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** SDD-065 IP-block action surface (paired enforcement
primitive). Where SDD-065 acts at the network perimeter (drop the
source IP), SDD-066 acts at the process boundary (freeze the
attacker's running shell/binary mid-flight, preserve memory state
for forensics, then operator decides: release or kill).
**Pairs with:** SDD-049 (authority model), SDD-051 (policy bus),
SDD-064 (observed discipline), SDD-065 (IP-block sibling). MS5b
cockpit operator-UX pattern reused.

## Purpose

Selfdef-responder already carries `SnapshotProcAction` (best-effort
/proc copy on detection) and `KillPidAction` (SIGTERM). Between
"snapshot + observe" and "kill + lose evidence" there is a critical
operator-actionable middle: **freeze the process, preserve memory
+ open files + sockets, surface to operator queue, let operator
decide release-or-kill-or-extend-freeze**.

SDD-066 specifies this third action — structured, authority-tier
bounded, fully audited, with kernel-side freeze TTL via cgroups
v2 freezer cgroup expiry (mirrors SDD-065's nftables flag-timeout
"kernel does the right thing if userland dies" principle).

## Non-goals

- Not a replacement for `KillPidAction` (operator may still want to
  kill outright for very high-severity events; SDD-066 is the
  buy-time-for-forensics path).
- Not a generic cgroups manager — narrow to freezer-class enforcement.
- Not a process-memory-dump tool — `SnapshotProcAction` already
  handles best-effort /proc copy; SDD-066 invokes that helper as a
  pre-freeze step but doesn't reimplement it.

## Surface

### 1. CLI verbs — `selfdefctl quarantine-pid / release-pid / kill-quarantined`

```
selfdefctl quarantine-pid <pid> --reason <text>
                          [--duration <human>]   # default 5m; max 24h
                          [--scope <process|tree>]  # SIGSTOP pid OR entire process group
                          [--authority <tier>]
                          [--dry-run]

selfdefctl release-pid <pid-or-handle> [--force]
selfdefctl kill-quarantined <pid-or-handle> [--signal TERM|KILL]
```

Exit codes:
- `0` — quarantine applied or dry-run plan emitted.
- `2` — authority tier insufficient.
- `3` — pid already quarantined under conflicting handle.
- `4` — cgroups v2 backend unreachable (freezer cgroup missing).
- `5` — pid disappeared between resolve and freeze (process exited).
- `1` — generic error.

### 2. Library surface — `selfdef-responder::QuarantineProcessAction`

```rust
pub struct QuarantineProcessAction {
    backend:   Arc<dyn ProcessQuarantineBackend>,
    snapshot:  Arc<dyn SnapshotBackend>,   // selfdef-action-side reuse
    audit:     Arc<dyn AuditWriter>,
    authority: AuthorityTier,
    duration:  Duration,
    reason_prefix: String,
}

#[async_trait]
impl Action for QuarantineProcessAction { /* … */ }
```

Pre-freeze sequence (single atomic action transaction):

1. Resolve pid from event (`pid_from_event` already exists in
   selfdef-responder).
2. Invoke snapshot backend best-effort (`/proc/<pid>/{cmdline,
   environ, maps, status}` capture into per-event dir; reuses
   `SnapshotProcAction` infrastructure).
3. Apply freeze via backend.
4. Record audit envelope + enqueue pending-release decision
   (same MS5 pattern as SDD-065).

### 3. Backend trait — `ProcessQuarantineBackend`

```rust
#[async_trait]
pub trait ProcessQuarantineBackend: Send + Sync {
    async fn freeze_process(
        &self,
        req: FreezeRequest,
    ) -> Result<FreezeReceipt, QuarantineError>;

    async fn release_process(
        &self,
        handle: QuarantineHandle,
    ) -> Result<ReleaseReceipt, QuarantineError>;

    async fn pending_releases(&self) -> Vec<PendingRelease> { Vec::new() }
    async fn mark_release_decided(&self, _: &QuarantineHandle) -> bool { false }
}
```

Default implementations:

#### 3a. `Cgroupv2FreezerBackend` (production)

- Owns `/sys/fs/cgroup/selfdef.slice/quarantine-<handle>.scope`.
- On freeze: `cgcreate` + write pid to `cgroup.procs` + write `1` to
  `cgroup.freeze`. Optionally also include child pids when
  `scope=tree`.
- On release: write `0` to `cgroup.freeze` + `cgdelete` the scope.
- Kernel-side TTL: a systemd transient unit
  `selfdef-quarantine-<handle>.timer` set with
  `OnActiveSec=<duration>` + `ExecStart=/bin/sh -c "echo 0 >
  /sys/fs/cgroup/.../cgroup.freeze && rmdir ..."` — so even if
  selfdefd crashes, the process unfreezes naturally.
- Requires `CAP_SYS_ADMIN` (cgroup write) — documented exception
  to the 12-clause sibling-observer hardening pattern. Lives in
  selfdefd's main slice, not in observer siblings.

#### 3b. `SignalBackend` (fallback for non-cgroups hosts)

- `kill(-SIGSTOP, pid)` + scheduled `kill(-SIGCONT, pid)` after
  duration via tokio sleep.
- No kernel-side TTL — userland-only; if selfdefd crashes during
  quarantine, the process stays SIGSTOP'd forever. Documented as
  inferior to cgroupv2 backend; only used when /sys/fs/cgroup/
  unavailable.

#### 3c. `InMemoryBackend` (test/hermetic)

- Tracks freeze state in HashMap without touching real processes.
- For unit-test + integration-test substrate.

### 4. Authority + TTL matrix

| Authority tier        | Max freeze duration | Requires operator confirmation? |
|-----------------------|---------------------|---------------------------------|
| `autonomous`          | 2 min               | No (buy-time only; kernel auto-releases)  |
| `responder`           | 15 min              | No (correlator-driven, surfaced to queue) |
| `operator`            | 1 hour              | No (CLI initiated)                        |
| `operator-overridden` | 24 hours            | Yes (`--confirm-extended`)                |

Shorter ceilings than SDD-065 because freezing a process suspends
its work; multi-hour freeze risks operator pain (the operator's own
shells could be frozen). 24h is the absolute ceiling for the
operator-extended path.

### 5. Audit + observability

Per-freeze audit envelope (selfdef-audit-log-writer):

```json
{
  "ts":     "2026-05-29T18:00:00Z",
  "action": "quarantine_process",
  "pid":    12345,
  "scope":  "process",
  "reason": "anomalous_outbound (responder)",
  "duration_sec": 900,
  "authority":    "responder",
  "source":       "selfdef-correlator",
  "handle":       "qpr-2026-05-29-001",
  "snapshot_dir": "/var/lib/selfdef/snapshots/qpr-...",
  "outcome":      "frozen"
}
```

Textfile gauges (new 20th sibling observer
`selfdef-quarantine-textfile.sh`, OnBootSec=600s):

- `selfdef_quarantine_active_count`     — currently-frozen pids
- `selfdef_quarantine_pending_releases` — operator-queue depth
- `selfdef_quarantine_handles_total`    — monotonic since startup
- `selfdef_quarantine_releases_total{authority=…}`
- `selfdef_quarantine_oldest_expiry_unix`
- `selfdef_quarantine_last_run_unix`
- `selfdef_quarantine_textfile_emit_failed`

### 6. Operator UX (sovereign-os consumer side)

Reuse the SDD-065 MS5b cockpit pattern:

- New `scripts/cockpit/quarantine-queue.py` — reads
  `/var/lib/selfdef/quarantine/pending-releases.json`.
- New `card_quarantine_queue` in dashboard `serve.py` — sorted by
  most-urgent-release-decision-first. Each entry shows:
  pid · cmdline (truncated) · reason · time-remaining ·
  pre-rendered `selfdefctl release-pid <handle>` and
  `selfdefctl kill-quarantined <handle>` commands.
- New sovereign-os Prometheus alert
  `SelfdefQuarantineLongHeld` — fires when any handle held
  > 12h (operator-decision-debt indicator).

### 7. Cross-action coordination with SDD-065

When the correlator emits a brute-force responder verdict, it can
chain BOTH actions: BlockIpAction (perimeter drop) + QuarantineProcessAction
(freeze the sshd child or other shell-spawned process). The
operator queue surfaces them together via a paired-handle row in
the cockpit:

```
sshd-bf-2026-05-29-017
  - block:      203.0.113.42 (responder, 32m left)
  - quarantine: pid 12345    (responder, 14m left)
  [ extend-block 24h ]  [ release-process ]  [ extend-quarantine 1h ]
```

## Implementation order (6 milestones)

| MS | Slice | Depends on |
|----|-------|-----------|
| 1  | `selfdef-process-quarantine-backend` crate — trait + InMemoryBackend + ~10 TDD tests | none |
| 1b | Cgroupv2FreezerBackend + SignalBackend feature-gated | MS1 |
| 2  | `selfdef-responder::QuarantineProcessAction` wired to trait + reuses SnapshotProcAction | MS1 |
| 3  | `selfdefctl quarantine-pid / release-pid / kill-quarantined` CLI verbs | MS2 |
| 4  | 20th sibling textfile observer + sovereign-os alerts + Grafana dashboard | MS1 |
| 5  | MS5b cockpit consumer (pattern reuse of SDD-065 §6) + paired-handle row | MS5a (SDD-065 pattern) |

Each milestone gets failing TDD test first, L1+L3 nspawn test
where applicable, audit-trail replay verification.

## Test contract

L1 (Cargo unit):
- FreezeRequest validation
- Authority-tier matrix enforcement
- Pid resolution + scope=tree expansion

L2 (integration):
- Cgroupv2FreezerBackend round-trips in a netns/cgroup test harness
- SignalBackend round-trips in a sandbox process (sleep 60 victim)

L3 (stage-acceptance, nspawn):
- Full chain: simulated anomalous-outbound event → correlator
  emits responder verdict → QuarantineProcessAction fires →
  process frozen + snapshot dir populated → TTL expires →
  kernel releases → audit chain intact.

L5 (operator):
- Cockpit shows pending-release queue + paired-handle row.
- Operator copy-pastes `selfdefctl release-pid <handle>`,
  process unfreezes, audit shows operator authority.

## Open questions (deferred to operator review)

- **Scope=tree definition.** Just immediate children, or full
  process subtree? Tradeoff: tree-freeze catches forked shells
  but risks freezing system services that share a parent.
  Proposal: stop at the first cgroup boundary (don't cross into
  user.slice from system.slice).
- **Snapshot-before-freeze race.** Process can free heap between
  snapshot and freeze. Acceptable? Or do we want to freeze-then-
  snapshot-then-unfreeze-then-refreeze for atomicity? Cost: ~30ms
  extra suspend. Proposal: freeze first then snapshot — operator
  cares more about preserving the post-attack state than the
  pre-detection state.
- **Cross-tenant safety.** What if a pid is reused by a different
  user between resolve and freeze? Proposal: backend captures
  `/proc/<pid>/uid_map` and `start_time_ticks` at request time;
  rejects if either changes between resolve and freeze.

## Standing-rule alignment

- **R10212 read-only doctrine:** enforcement in selfdef;
  sovereign-os consumes (alerts + dashboards + cockpit-shells-
  selfdefctl).
- **"We do not minimize anything":** action carries full audit +
  observability + authority + idempotency + TTL + pre-snapshot +
  operator-pending-queue.
- **"Cannot mark done if it hasn't reached Prod":** acceptance =
  6-milestone slice landing on selfdef + sovereign-os main, L3
  CI green, operator-UX surfaced in cockpit dashboard.
