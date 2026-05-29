# SDD-075 — Per-process capability-drop action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS dectet (SDD-065..074) → undectet expansion. The
dectet covers network perimeter + single-process boundary + shell
session + API token + MFA grant + kernel-namespace containment +
filesystem-binding + process-graph + per-connection severance +
in-memory secret-residency. SDD-075 adds the **per-process
privilege-set axis** — drop specific Linux capabilities from a
running pid's effective + permitted + inheritable + bounding sets
without killing it.
**Pairs with:** SDD-066 (single-pid freeze) and SDD-070 (netns
containment) at the kernel-containment family, complementing them
with **least-privilege graduation** — operator can dial back a
specific capability rather than the whole process.

## Purpose

The dectet's missing eleventh axis: **per-process capability
reduction**. Existing options are too coarse:
- SDD-066 freeze stops the process entirely.
- SDD-070 netns severs ALL network reachability.
- SDD-068 token-revoke kills app-level credentials but leaves
  CAP_NET_ADMIN / CAP_SYS_PTRACE / CAP_BPF etc. intact.
- SDD-074 env-scrub clears cached secrets but the process retains
  the ambient kernel-level privileges that let it acquire new ones.

SDD-075 fills the gap: identify a running pid + a specific
capability (or comma-separated list), then drop that capability
from the process's effective + permitted + inheritable + bounding
sets using `PR_CAPBSET_DROP` (per-thread, persistent across
syscalls). The process keeps running, all its non-affected
syscalls keep working — but the next attempt to invoke any
syscall gated by the dropped capability returns EPERM.

Operator decides per incident:
- Attacker has CAP_NET_ADMIN to flip nftables → SDD-075 (drop
  just that cap, observe re-attempt)
- Attacker has CAP_SYS_PTRACE attaching to other processes →
  SDD-075 (drop CAP_SYS_PTRACE)
- Attacker has CAP_BPF loading bpf programs → SDD-075
- Process is fully compromised, multi-cap attack surface → SDD-066
  freeze, not SDD-075

## Non-goals

- Not a full LSM policy switch. AppArmor/SELinux profile pivots
  are a future SDD (live-attach a stricter profile). SDD-075
  operates at the POSIX-capability layer only.
- Not for kernel threads or pid 1 (sacrosanct — same as SDD-072).
- Not for adding capabilities back (Linux disallows it). Restore
  semantically means clearing the operator-decision queue +
  audit-log only; the process must restart to regain the dropped
  capability.

## Surface

### 1. CLI verbs

```
selfdefctl drop-cap <pid> --caps <CAP1[,CAP2,...]> --reason <text>
                    [--duration <human>]   # default 30m; max 8h
                    [--authority <tier>]
                    [--scope <bounding|all-sets>]  # default all-sets
                    [--dry-run]

selfdefctl restore-cap <handle> [--force]
```

`restore-cap` does NOT actually re-grant the capability (the
kernel disallows it). It clears the operator queue + audit record.
Operator must restart the process to recover the capability.

### 2. Library — `selfdef-responder::CapabilityDropAction`

Standard Action pattern. Reads `(pid, caps)` from
`event.metadata.profiles["drop_caps:CAP1,CAP2"]` (custom). Returns
`Skipped` when no pid or no caps.

### 3. Backend trait

```rust
pub enum CapScope {
    /// Drop only from bounding set (PR_CAPBSET_DROP). Effective +
    /// permitted + inheritable still hold; bounding gate prevents
    /// re-acquisition. Use when operator wants the process to keep
    /// using the cap NOW but not be able to pass it to children.
    BoundingOnly,
    /// Drop from effective + permitted + inheritable + bounding
    /// (full drop). Use when operator wants the capability gone
    /// completely from this pid. Default.
    AllSets,
}

#[async_trait]
pub trait CapabilityDropBackend: Send + Sync {
    async fn drop_caps(
        &self, req: DropCapsRequest,
    ) -> Result<DropCapsReceipt, CapabilityDropError>;
    async fn restore_caps(
        &self, handle: CapabilityDropHandle,
    ) -> Result<RestoreReceipt, CapabilityDropError>;
    async fn pending_restores(&self) -> Vec<PendingCapsRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &CapabilityDropHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max drop window |
|-----------------------|-----------------|
| `autonomous`          | 5 min           |
| `responder`           | 30 min          |
| `operator`            | 4 hours         |
| `operator-overridden` | 8 hours         |

Mid-tier ceilings — capability drops are sticky (can't be undone
within the process lifetime), but the operator-decision queue TTL
limits accumulation.

### 5. Audit + observability

29th sibling textfile observer
`selfdef-capability-drops-textfile.sh` (OnBootSec=870s). Same 6
canonical gauges as the prior dectet observers plus:
- `selfdef_capability_drops_by_cap{cap="CAP_NET_ADMIN|CAP_SYS_PTRACE|..."}` (labeled gauge for incident-pattern detection)

### 6. Operator UX

MS5b cockpit card `card_capability_drops_queue` adjacent to the
ten dectet cards — completes the **undectet-paired-handle row**.

## Implementation order — same 5-MS pattern (now undecuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate (TDD-first L1)
- **MS2** — `CapabilityDropAction` in selfdef-responder
- **MS3** — `selfdefctl drop-cap` / `restore-cap` verbs
- **MS4a** — 29th sibling textfile observer (selfdef) with extra by-cap gauge
- **MS4b** — sovereign-os consumer surface (alerts + dashboard #49
  + observability-status vertical 29)
- **MS5a-state-journal** — FsBackend pattern (see info-hub wiki/
  patterns/01_drafts/ms5a-state-journal-vs-enforcement-layer-separation.md)
- **MS5a-enforcement** — `prctl(PR_CAPBSET_DROP, …)` adapter
  (CAP_SETPCAP required) — deferred until L3 nspawn substrate
- **MS5b** — cockpit `capability-drops-queue.py` + undectet-paired-handle row

## Open questions

- **Capability-name canonicalisation.** Operator types `CAP_NET_ADMIN`
  but kernel/proc expect lowercase or numeric. Proposal: accept
  both forms in CLI + canonicalise to uppercase in storage + emit
  numeric to kernel. Validator rejects unknown names.
- **Cap-set vs cap-name mismatch.** Some caps don't exist on older
  kernels (CAP_BPF, CAP_PERFMON, CAP_CHECKPOINT_RESTORE added
  late). Proposal: validator accepts the full known modern set
  (~41 caps), enforcement adapter (MS5a-enforcement) maps to
  numeric + warns on missing.
- **Self-targeted drop hazard.** If operator drops CAP_SETPCAP
  from selfdefd itself, the daemon can never drop caps again.
  Proposal: refuse-when-target-pid == selfdefd-pid; document.
- **Container interaction.** Process inside a container has its
  caps already limited by container runtime's bounding set; SDD-075
  drops further. Should report current bounding set in receipt
  for operator awareness. Documented as future MS5a-enforcement
  observability.

## Standing-rule alignment

R10212 read-only doctrine: SDD-075 IS the enforcement primitive
(selfdef). Sovereign-os consumes via observer + cockpit + vertical
29. Same as SDD-065..074 standing-rule binding.
