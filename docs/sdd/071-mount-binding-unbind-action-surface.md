# SDD-071 — Mount-binding unbind action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS hexet (SDD-065/066/067/068/069/070) → septet
expansion. The hexet covers network perimeter + process boundary +
shell session + API token + MFA grant + kernel-namespace
containment. SDD-071 adds the **filesystem-binding axis** —
forcibly unbind a malicious bind-mount or overlay that exposes
host secrets / sensitive paths to a compromised process or
container, without killing the workload.
**Pairs with:** SDD-066 (process-freeze) and SDD-070 (netns
containment) at the kernel-containment family. Together they
offer a layered response: freeze the process, contain its
namespace, and revoke its filesystem visibility.

## Purpose

The hexet's missing seventh axis: **filesystem-binding revocation**.
Existing options:
- SDD-066 process-freeze stops the workload entirely.
- SDD-070 netns-isolation severs network reachability but the
  process keeps reading `/etc/shadow` via an old bind-mount.
- SDD-068 token-revoke kills the cloud path but the host secret
  exposed through an overlay remains visible.

SDD-071 fills the gap: workload keeps executing in its existing
namespace, but the specific bind-mount path mapping host secrets
into the process's mount-ns is detached. The process loses its
view of the leaked path immediately (lazy `umount -l`); existing
open fds continue to function (so partially-read data isn't
truncated mid-read, preserving forensic continuity), but no new
opens against the unbound path can occur.

Operator decides per incident:
- Freeze (SDD-066) when you want full preservation but can stop work.
- Isolate (SDD-070) when you want live-running observation with
  no network exfil.
- Unbind (SDD-071) when the specific compromise is **a malicious
  filesystem exposure** and the workload can keep running once the
  exposure is severed (most common in container-escape patterns
  where the attacker mount-binds host paths into their container).

## Non-goals

- Not a per-file revocation. fanotify-class file-level deny lives
  in a future SDD; SDD-071 operates at the mount-table granularity.
- Not a mount manager. We don't create or repair legitimate
  bind-mounts; we **revoke** suspected-malicious ones.
- Not a process-killer. If unbinding alone doesn't fix the
  incident, escalate to SDD-066 freeze or SDD-070 isolate as
  separate, layered actions.
- Not container-runtime aware (yet). For container bind-mounts
  the operator must know the container's mount-ns target path;
  SDD-071 takes that as input, doesn't infer it.

## Surface

### 1. CLI verbs

```
selfdefctl unbind-mount <mount-point> --reason <text>
                        [--duration <human>]   # default 30m; max 6h
                        [--authority <tier>]
                        [--scope <bind|overlay|all>]  # default bind
                        [--lazy]                # default true; --no-lazy for forced
                        [--dry-run]

selfdefctl rebind-mount <mount-point-or-handle> [--force]
```

The `--scope` flag distinguishes:
- `bind`: a single bind-mount target (e.g. `/var/lib/selfdef/x`).
- `overlay`: the upper or lower layer of an overlayfs that's
  leaking host content.
- `all`: every bind-mount whose source matches a pattern (rare;
  guarded behind operator-overridden tier).

### 2. Library — `selfdef-responder::MountBindingUnbindAction`

Standard Action pattern. Extracts mount-point from event payload
(`event.observable.path` or a custom event field). When no
mount-point is present, returns `ActionOutcome::Skipped`.

### 3. Backend trait

```rust
pub enum UnbindScope {
    Bind,
    Overlay,
    AllMatching(String),  // pattern; operator-overridden tier only
}

#[async_trait]
pub trait MountBindingUnbindBackend: Send + Sync {
    async fn unbind_mount(
        &self, req: UnbindMountRequest,
    ) -> Result<UnbindMountReceipt, MountBindingUnbindError>;
    async fn rebind_mount(
        &self, handle: MountBindingHandle,
    ) -> Result<RebindReceipt, MountBindingUnbindError>;
    async fn pending_rebinds(&self) -> Vec<PendingMountRebind> { Vec::new() }
    async fn mark_rebind_decided(&self, _: &MountBindingHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max unbind window |
|-----------------------|-------------------|
| `autonomous`          | 5 min             |
| `responder`           | 20 min            |
| `operator`            | 1 hour            |
| `operator-overridden` | 6 hours           |

Shortest of the IPS-spine because filesystem visibility changes
are surprisingly disruptive (logging paths, config reload paths,
PID-file paths can all break). Operator-essential to rebind cleanly.

### 5. Audit + observability

25th sibling textfile observer
`selfdef-mount-bindings-textfile.sh` (OnBootSec=750s). Same 6
canonical gauges as the prior hexet observers:
- `selfdef_mount_bindings_state_dir_present`
- `selfdef_mount_bindings_active_count`
- `selfdef_mount_bindings_pending_rebinds`
- `selfdef_mount_bindings_oldest_expiry_unix`
- `selfdef_mount_bindings_last_run_unix`
- `selfdef_mount_bindings_textfile_emit_failed`

### 6. Operator UX

MS5b cockpit card `card_mount_bindings_queue` adjacent to the six
hexet cards — completes the **septet-paired-handle row**.

## Implementation order — same 5-MS pattern (now septuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate (TDD-first L1)
- **MS2** — `MountBindingUnbindAction` in selfdef-responder
- **MS3** — `selfdefctl unbind-mount` / `rebind-mount` verbs
- **MS4a** — 25th sibling textfile observer (selfdef)
- **MS4b** — sovereign-os consumer surface (alerts + dashboard #45
  + observability-status vertical 25)
- **MS5a** — production adapter (Linux `umount2(MNT_DETACH)` /
  `mount(MS_BIND)` for rebind) — deferred by environment until L3
  nspawn substrate available
- **MS5b** — cockpit `mount-bindings-queue.py` + septet-paired-handle row

## Open questions

- **Lazy-vs-force default.** `umount -l` (MS_DETACH) is safe (open
  fds stay valid); `umount -f` (MS_FORCE) drops them. Default is
  lazy; operator can override with `--no-lazy`. Proposal: this
  default is right — preserving open fds matches the forensic
  continuity story.
- **Mount-ns scope.** A bind-mount in a container's private
  mount-ns is invisible from the host. SDD-071 v1 operates only on
  host-visible mount-ns entries; container-mount-ns work
  (`nsenter -t <pid> -m umount …`) is v2.
- **Auto-remount.** Many systems (e.g. systemd, kubelet) auto-remount
  paths they own. If we unbind their mount, they may remount it
  within seconds. Detection: monitor `/proc/self/mountinfo` change
  count post-unbind for 30s; if mount reappears, mark handle
  `Contested` and surface to operator. Proposal: include
  `Contested` variant in `MountBindingHandle`.
- **Idempotency.** Two operators issuing unbind for the same mount
  within 5s should not double-error. Same `idempotency_key` shape
  as the prior six primitives.

## Standing-rule alignment

R10212 read-only doctrine: SDD-071 IS the enforcement primitive,
runs in selfdef (not sovereign-os). Sovereign-os consumes via the
textfile observer + cockpit queue + observability vertical 25.

Same as SDD-065..070 standing-rule binding.
