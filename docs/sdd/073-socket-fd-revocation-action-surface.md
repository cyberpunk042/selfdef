# SDD-073 — Socket-fd revocation action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** IPS octet (SDD-065/066/067/068/069/070/071/072) →
nonet expansion. The octet covers network perimeter +
single-process boundary + shell session + API token + MFA grant +
kernel-namespace containment + filesystem-binding + process-graph
containment. SDD-073 adds the **in-flight connection axis** —
force-close a specific socket fd (TCP, Unix, or netlink) owned by
a target process, severing one established connection without
killing the process or blocking the whole peer.
**Pairs with:** SDD-065 (perimeter block) for the network-axis
gradient. Together they offer a 3-grain network response:
- SDD-073: kill one connection
- SDD-070: isolate one process's network entirely
- SDD-065: drop a peer IP from everyone

## Purpose

The octet's missing ninth axis: **per-connection severance**.
Existing options are too narrow or too broad:
- SDD-065 IP-block drops the peer from every process on the host.
  Other innocent users of that peer get cut off too.
- SDD-070 netns-isolate severs all the process's connections at
  once. Loses forensic visibility into the legitimate-looking ones.
- SDD-066 process-freeze stops the process; you can't observe
  it continuing to attempt re-connection.

SDD-073 fills the gap: identify a specific `(pid, fd)` tuple from
event data or operator input, then `shutdown(fd, SHUT_RDWR)` +
`close(fd)` via either ptrace-attach (kernel ≤ 5.10) or the
pidfd_getfd(2) + close mechanism (kernel ≥ 5.10). The process
keeps running, all its other connections keep flowing, only the
named fd transitions to EBADF on next syscall.

Operator decides per incident:
- Specific C2 socket identified, want to observe re-attempt → SDD-073
- Whole process's network is the threat → SDD-070
- Peer IP is malicious to ALL hosts → SDD-065

## Non-goals

- Not a tcp-killer at the L4 level. We don't send RSTs from a
  kernel module; we close fds from userspace via pidfd_getfd.
  (Future SDD could add an `ss --kill` mode for stateless RST.)
- Not for kernel sockets. SDD-073 only revokes userspace-owned
  fds; kthread sockets are out of scope.
- Not for sealed/dup-shared fds across processes. If the same
  underlying socket is held by multiple pids via SCM_RIGHTS, we
  close one pid's fd — other holders still have it. Acceptable;
  operator can re-issue per-pid.

## Surface

### 1. CLI verbs

```
selfdefctl revoke-fd <pid> <fd> --reason <text>
                    [--duration <human>]   # default 30m; max 4h
                    [--authority <tier>]
                    [--protocol <tcp|unix|netlink|any>]  # default any
                    [--dry-run]

selfdefctl restore-fd <handle> [--force]
```

`restore-fd` doesn't actually re-open the fd (impossible — fd
numbers aren't re-bindable). It clears the revocation handle so
the operator queue empties, and records the decision in audit.

### 2. Library — `selfdef-responder::SocketFdRevocationAction`

Standard Action pattern. Reads `(pid, fd)` from
`event.network.socket_fd` (custom field; falls back to extracting
from `event.observable.process.fds`). Returns `Skipped` if pid
or fd is missing.

### 3. Backend trait

```rust
pub enum SocketProtocol {
    Tcp,
    Unix,
    Netlink,
    Any,
}

#[async_trait]
pub trait SocketFdRevocationBackend: Send + Sync {
    async fn revoke_fd(
        &self, req: RevokeFdRequest,
    ) -> Result<RevokeFdReceipt, SocketFdRevocationError>;
    async fn restore_fd(
        &self, handle: SocketFdHandle,
    ) -> Result<RestoreReceipt, SocketFdRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingFdRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &SocketFdHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max revocation window |
|-----------------------|-----------------------|
| `autonomous`          | 2 min                 |
| `responder`           | 15 min                |
| `operator`            | 1 hour                |
| `operator-overridden` | 4 hours               |

Shortest of the IPS nonet because fd numbers are recyclable —
the process may close+reopen a different fd in the same slot
within seconds. Long-held revocations risk stale state.

### 5. Audit + observability

27th sibling textfile observer
`selfdef-socket-fd-revocations-textfile.sh` (OnBootSec=810s).
Same 6 canonical gauges as the prior octet observers, plus:
- `selfdef_socket_fd_revocations_by_protocol{protocol="tcp|unix|netlink"}` (labeled gauge)

### 6. Operator UX

MS5b cockpit card `card_socket_fd_revocations_queue` adjacent to
the eight octet cards — completes the **nonet-paired-handle row**.

## Implementation order — same 5-MS pattern (now nonuply-validated)

- **MS1** — backend trait + `InMemoryBackend` substrate (TDD-first L1)
- **MS2** — `SocketFdRevocationAction` in selfdef-responder
- **MS3** — `selfdefctl revoke-fd` / `restore-fd` verbs
- **MS4a** — 27th sibling textfile observer (selfdef)
- **MS4b** — sovereign-os consumer surface (alerts + dashboard #47
  + observability-status vertical 27)
- **MS5a** — production adapter (pidfd_open + pidfd_getfd + close)
  — deferred by environment until L3 nspawn substrate available
- **MS5b** — cockpit `socket-fd-revocations-queue.py` + nonet-paired-handle row

## Open questions

- **Pidfd_getfd ENOSYS on kernel < 5.10.** Fallback to ptrace-attach
  is racier. Proposal: refuse-with-clear-error rather than degrading
  silently; operator can use SDD-070 netns instead.
- **Fd-reuse race.** Between observation and revoke, the process
  may close+reopen a different connection on the same fd number.
  Mitigation: include `inode` from `/proc/<pid>/fdinfo/<fd>` in
  the request; validator checks current inode matches before
  closing.
- **Multi-pid SCM_RIGHTS shares.** Documented non-goal; receipt
  notes "single-pid fd revoked; other holders unaffected".
- **TIME_WAIT state visibility.** Closed TCP fd leaves a TIME_WAIT
  for ~60s. The textfile observer should NOT count those as
  "active connections to attacker" — they're closed. Document.

## Standing-rule alignment

R10212 read-only doctrine: SDD-073 IS the enforcement primitive,
runs in selfdef (not sovereign-os). Sovereign-os consumes via
the textfile observer + cockpit queue + observability vertical 27.

Same as SDD-065..072 standing-rule binding.
