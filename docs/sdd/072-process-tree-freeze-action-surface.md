# SDD-072 — Process-tree freeze action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS septet (SDD-065/066/067/068/069/070/071) → octet
expansion. The septet covers network perimeter + single-process boundary
+ shell session + API token + MFA grant + kernel-namespace
containment + filesystem-binding. SDD-072 adds the
**process-graph containment axis** — recursively SIGSTOP every
descendant of a target pid (not just the parent), so a fork-bomb
or multi-worker exploit can be frozen as a tree.
**Pairs with:** SDD-066 (single-pid quarantine) and SDD-070 (netns
containment) at the kernel-containment family. The trio offers
operator a three-grain containment menu:
- SDD-066: stop one process
- SDD-070: contain one process's network
- SDD-072: stop the entire descendant tree

## Purpose

The septet's missing eighth axis: **descendant-tree containment**.
Existing options leave the workload's children running:
- SDD-066 process-freeze stops the parent. Children survive,
  often re-attached to PID 1, and continue malicious work.
- SDD-070 netns isolates the parent's network but children may
  have already inherited working sockets via fork.
- SDD-071 unbind cuts a filesystem path; children with already-open
  fds still read freely.

SDD-072 fills the gap: walks `/proc/<pid>/task/*/children` (or the
faster pidfd/cgroup-v2 `cgroup.procs` view when available), then
SIGSTOP each one in a deterministic post-order so children are
frozen before their parent gets a chance to fork more. Releases
in pre-order so the parent resumes last.

Operator decides per incident:
- Single pid is malicious + childless → SDD-066 (faster, simpler)
- Pid has worker pool but only network is the threat → SDD-070
- Pid tree (and its descendants) are all suspect → SDD-072

## Non-goals

- Not a cgroup freezer. We use SIGSTOP/SIGCONT for kernel-version
  portability; cgroup-v2 freezer is a future MS1b optimisation.
- Not a fork-prevention mechanism. While the tree is frozen no
  new children can fork (parent is stopped), but if a single
  unstopped grandchild remained, it could keep forking. That's
  acceptable — operator either uses `--strict` (re-walk + re-stop
  every 100ms until tree stabilises) or moves on to SDD-066 on
  individual offenders.
- Not a process killer. SDD-072 freezes; killing belongs to a
  dedicated future SDD-073+.

## Surface

### 1. CLI verbs

```
selfdefctl freeze-tree <root-pid> --reason <text>
                       [--duration <human>]   # default 30m; max 8h
                       [--authority <tier>]
                       [--strict]              # re-walk every 100ms
                       [--include-self|--exclude-self]  # default include
                       [--dry-run]

selfdefctl thaw-tree <root-pid-or-handle> [--force]
```

### 2. Library — `selfdef-responder::ProcessTreeFreezeAction`

Standard Action pattern. Extracts root pid from
`event.actor.process.pid`. Returns `Skipped` when no pid is
present. Walks descendants at execute-time, not at request-time
(tree shape may change between observation and action).

### 3. Backend trait

```rust
pub enum TreeScope {
    /// SIGSTOP root + every descendant once.
    Descendants,
    /// Strict mode: re-walk + re-stop every 100ms until tree
    /// stabilises (no new pids appear for 2 consecutive sweeps).
    /// Useful for fork-bomb containment.
    StrictDescendants,
    /// Children only (one level down). Faster, suitable for
    /// multi-worker patterns where grandchildren are trusted.
    ChildrenOnly,
}

#[async_trait]
pub trait ProcessTreeFreezeBackend: Send + Sync {
    async fn freeze_tree(
        &self, req: FreezeTreeRequest,
    ) -> Result<FreezeTreeReceipt, ProcessTreeFreezeError>;
    async fn thaw_tree(
        &self, handle: ProcessTreeHandle,
    ) -> Result<ThawReceipt, ProcessTreeFreezeError>;
    async fn pending_thaws(&self) -> Vec<PendingTreeThaw> { Vec::new() }
    async fn mark_thaw_decided(&self, _: &ProcessTreeHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max freeze window |
|-----------------------|-------------------|
| `autonomous`          | 5 min             |
| `responder`           | 30 min            |
| `operator`            | 4 hours           |
| `operator-overridden` | 8 hours           |

Longer than SDD-071 because frozen processes are stable (no fd
EBADF, no path-vanish surprises) — but shorter than SDD-067/068
because long-frozen pid-trees accumulate kernel resources (locked
memory, file-table entries) the longer they're held.

### 5. Audit + observability

26th sibling textfile observer
`selfdef-process-tree-freezes-textfile.sh` (OnBootSec=780s). Same
6 canonical gauges as the prior septet observers, plus one extra
counter — `selfdef_process_tree_freezes_frozen_pid_count` —
because a freeze-tree receipt covers many pids.

### 6. Operator UX

MS5b cockpit card `card_process_tree_freezes_queue` adjacent to
the seven septet cards — completes the **octet-paired-handle row**.

## Implementation order — same 5-MS pattern (now octuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate (TDD-first L1)
- **MS2** — `ProcessTreeFreezeAction` in selfdef-responder
- **MS3** — `selfdefctl freeze-tree` / `thaw-tree` verbs
- **MS4a** — 26th sibling textfile observer (selfdef)
- **MS4b** — sovereign-os consumer surface (alerts + dashboard #46
  + observability-status vertical 26)
- **MS5a** — production adapter (`/proc/<pid>/task/*/children` walk
  + `kill(-1, SIGSTOP)` cascade) — deferred by environment until
  L3 nspawn substrate available
- **MS5b** — cockpit `process-tree-freezes-queue.py` + octet-paired-handle row

## Open questions

- **Race with target's own forking.** Between walk and stop, the
  parent may fork. `--strict` mode handles this; non-strict
  accepts the race as a soft failure (operator can re-issue).
  Proposal: log the race in receipt as `pids_added_post_walk` so
  operator sees it without re-walking.
- **SIGSTOP semantics on uninterruptible sleep.** A pid in
  D-state can't be stopped immediately; SIGSTOP is queued. The
  receipt should distinguish `frozen` (in T-state) from
  `signalled_pending_d_state` (signal sent, awaiting D-state exit).
- **PID-reuse hazard on thaw.** Between freeze + thaw the same
  numeric pid could (in theory) be a different process if the
  original exited and the table wrapped. Mitigation: store
  `(pid, start_time)` tuples in the handle, check on thaw.
- **systemd-resurrection of services.** systemd may notice a
  unit's main pid is stopped and try to restart it. Proposal:
  when freezing a systemd-managed service pid, also issue
  `systemctl stop <unit>` first. Out of scope for v1; document.

## Standing-rule alignment

R10212 read-only doctrine: SDD-072 IS the enforcement primitive,
runs in selfdef (not sovereign-os). Sovereign-os consumes via
the textfile observer + cockpit queue + observability vertical 26.

Same as SDD-065..071 standing-rule binding.
