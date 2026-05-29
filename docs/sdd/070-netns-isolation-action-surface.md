# SDD-070 — Network-namespace isolation action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS pentet (SDD-065/066/067/068/069) → hexet
expansion. The pentet covers network perimeter + process boundary
+ shell session + API token + MFA grant. SDD-070 adds the
**kernel-containment axis** — isolate a process into a fresh
network namespace so it KEEPS RUNNING (preserves forensic state)
but cannot communicate with anything (no inbound, no outbound,
no peer processes).
**Pairs with:** SDD-066 (process-quarantine — freeze the process)
and SDD-065 (block-ip — drop the source IP). Together they offer
operator a graduated response choice: freeze (lose forward
progress, preserve state) vs. isolate (keep forward progress,
contain blast radius).

## Purpose

The pentet's missing sixth axis: **kernel-namespace containment**.
Existing options:
- SDD-065 IP-block drops perimeter traffic but the process still
  runs and may exfiltrate via existing connections.
- SDD-066 process-freeze stops the process entirely.
- SDD-068 token-revoke kills the cloud-token path but local
  syscalls continue.

SDD-070 fills the middle: process keeps executing (so debugger
can inspect it live, so memory state stays representative of
attack), but `setns()` into a clean netns means:
- No outbound: process's old socket fds get EBADF on next write.
- No inbound: process is unreachable from the host.
- No peer-process communication via abstract unix sockets.
- DNS resolution fails closed (no resolv.conf in new netns).

Operator decides per incident: freeze (SDD-066) for full
preservation, or isolate (SDD-070) for live observation under
contained blast radius.

## Non-goals

- Not a network-policy mechanism. nftables rules belong in
  SDD-065. SDD-070 is per-process kernel containment.
- Not a Linux container runtime. We don't manage cgroups or
  mounts. Just net+pid+ipc namespace isolation via `nsenter` and
  `setns`.
- Not a sandbox for new processes. SDD-070 isolates EXISTING
  processes; new-process sandboxing is bubblewrap/firejail-class.

## Surface

### 1. CLI verbs

```
selfdefctl isolate-pid <pid> --reason <text>
                       [--duration <human>]   # default 30m; max 12h
                       [--authority <tier>]
                       [--namespaces <net|pid|ipc|all>]  # default net
                       [--dry-run]

selfdefctl release-isolation <pid-or-handle> [--force]
```

The `--namespaces` flag scopes which kernel namespaces to swap.
`net` only (default) lets the process continue talking to its
existing tty/files; `all` adds pid + ipc for full containment.

### 2. Library — `selfdef-responder::NetnsIsolationAction`

Standard Action pattern. Extracts pid from event.actor.process.pid.

### 3. Backend trait

```rust
pub enum IsolationScope {
    NetOnly,
    NetPidIpc, // "all"
}

#[async_trait]
pub trait NetnsIsolationBackend: Send + Sync {
    async fn isolate_pid(
        &self, req: IsolatePidRequest,
    ) -> Result<IsolatePidReceipt, NetnsIsolationError>;
    async fn release_isolation(
        &self, handle: NetnsIsolationHandle,
    ) -> Result<ReleaseReceipt, NetnsIsolationError>;
    async fn pending_releases(&self) -> Vec<PendingNetnsRelease> { Vec::new() }
    async fn mark_release_decided(&self, _: &NetnsIsolationHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max isolation window |
|-----------------------|----------------------|
| `autonomous`          | 5 min                |
| `responder`           | 30 min               |
| `operator`            | 2 hours              |
| `operator-overridden` | 12 hours             |

Shorter than SDD-067/068 because indefinite isolation effectively
makes the host think the process is dead while it's actually
running — operator-essential to release cleanly.

### 5. Audit + observability

24th sibling textfile observer
`selfdef-netns-isolations-textfile.sh` (OnBootSec=720s). Same 6
canonical gauges as the prior pentet observers.

### 6. Operator UX

MS5b cockpit card `card_netns_isolations_queue` adjacent to
the five pentet cards — completes the **hexet-paired-handle row**.

## Implementation order — same 5-MS pattern (now sextuply-validated)

## Open questions

- **Existing socket fd lifecycle.** When process moves to new
  netns, its existing socket fds become EBADF on next syscall.
  This may crash naive processes — acceptable forensic side-effect
  or hazard? Proposal: acceptable; document.
- **DNS-fail handling.** Process may infinite-loop on DNS retries.
  Should isolated netns provide a stub resolver returning NXDOMAIN
  immediately rather than no-resolv-conf?
- **Container-runtime collision.** If victim pid is already inside
  a Docker container netns, our isolation may break container
  health. Proposal: refuse isolation when `/proc/<pid>/ns/net`
  inode doesn't match host's `/proc/1/ns/net` inode (i.e.,
  already containerized).

## Standing-rule alignment

R10212 + same as SDD-065..069.
