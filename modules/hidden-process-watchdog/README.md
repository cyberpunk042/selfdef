# hidden-process-watchdog

Surfaces processes hidden from the `/proc` directory
listing by a rootkit, by comparing the kernel-authoritative
PID set (direct `/proc/<pid>` stat across the PID range)
against what `readdir(/proc)` / `ps` report. A PID that is
alive but absent from the listing is the hidden-process
signature.

## Why this matters

A core rootkit capability is hiding the attacker's process
so `ps`, `top`, and `ls /proc` don't show it:

- **Userland rootkits** (LD_PRELOAD-based, e.g.
  `libprocesshider`) hook `readdir`/`readdir64` in libc so
  any program listing `/proc` skips the hidden PID — but
  the process runs normally and its `/proc/<pid>` directory
  is still reachable by *exact path*.
- **LKM rootkits** hook the kernel's `getdents` syscall to
  filter the directory stream, with the same blind spot.

The detection exploits the asymmetry: hiding the entry from
the *directory stream* (readdir/getdents) is easy; making
`stat("/proc/<pid>")` on the *exact path* also fail is much
harder and rarer. So:

```
A = readdir(/proc)          # filtered by the rootkit
B = test -d /proc/<pid>     # direct path, bypasses the filter
hidden = B \ A              # alive but not listed
```

Any PID in `hidden` has no benign explanation.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if any hidden PID detected → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No hidden PIDs | `ok` | `no_hidden_process` |
| 1+ hidden PIDs | `alert` | `hidden_process_detected` |

(There is no `warn` tier — a hidden process is binary: it's
either there, which is bad, or not.)

## How the probe works

1. **Set A**: glob `/proc/[0-9]*` (a readdir) → the
   rootkit-filterable view.
2. **Set B**: loop `pid` from 1 to `pid_max` (capped at
   200000 by default for bounded runtime) and `test -d
   /proc/$pid` — a direct path stat that does NOT go
   through readdir.
3. **Hidden = B − A**. For each hidden PID, read
   `/proc/<pid>/comm` + `/proc/<pid>/exe` by direct path
   (often still readable) to identify the process.

`pid_max` is read from `/proc/sys/kernel/pid_max`; the
200000 cap (override `SELFDEF_HIDDENPROC_CAP`) keeps the
probe fast on hosts with a 4M pid_max while still covering
the realistic low/normal PID range malware uses.

## Cadence

`OnBootSec=12min` + `OnUnitActiveSec=4h` + jitter,
`Nice=19` + `IOSchedulingClass=idle`. A hidden process is
active-compromise; 4h catches it reasonably fast without
continuous probing overhead.

## MITRE coverage

- **T1014** Rootkit — PRIMARY; process hiding is a defining
  rootkit behavior.
- **T1564** Hide Artifacts — the hidden process IS the
  hidden artifact.
- **T1055** Process Injection — injected/hollowed processes
  are sometimes hidden the same way.
- **T1562.006** Impair Defenses: Indicator Blocking — the
  rootkit blocks the ps/proc indicator; this defeats the
  blocking.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-hidden-process -n 1 --no-pager

# Per-PID detail (with comm + exe path)
journalctl -t selfdef-hidden-process-detail --since "1 day ago"

# Investigate a hidden PID
sudo cat /proc/<pid>/comm
sudo readlink /proc/<pid>/exe
sudo cat /proc/<pid>/maps | head
sudo ls -la /proc/<pid>/cwd /proc/<pid>/root

# Cross-check with rkhunter + the kernel-module watchdog
sudo selfdefctl modules check kernel-module-watchdog
sudo rkhunter --check --enable hidden_procs

# If LD_PRELOAD userland rootkit suspected:
cat /etc/ld.so.preload      # should be absent or empty
```

## Caveats

- **Race conditions**: a process that exits between the
  readdir (A) and the direct-stat (B) can appear as a
  false "hidden" (it was alive for B, gone for A) — or
  vice versa. The scan re-runs every 4h; a persistent
  hidden PID across scans is the real signal, a one-shot
  blip on a busy host may be a race. The detail log lets
  the operator confirm.
- **Sophisticated LKM rootkits** that ALSO hook the
  path-stat (`/proc/<pid>` lookup) defeat this technique —
  but that's much rarer + pairs with kernel-module-watchdog
  (which catches the rootkit's module load) + host-sentinel
  (Tetragon do_init_module kprobe).
- **PID-namespace containers**: a process in a child PID
  namespace appears under different PIDs; the host scan
  sees the host-namespace PIDs (no false positive — both A
  and B use the host's /proc).
- **Runtime cost**: the brute-force loop is CPU-light
  (stat syscalls) but tight; Nice=19 + idle I/O keep it
  invisible to operators.

## Coexistence

- **kernel-module-watchdog**: complementary — catches the
  rootkit's MODULE load; this catches its hidden PROCESS.
  Together they cover both halves of an LKM rootkit.
- **rkhunter-cron**: rkhunter has its own hidden-process +
  hidden-port checks via different methods; this is a
  focused, structured-event version.
- **host-sentinel (Tetragon)**: real-time kprobe on module
  load + ld.so.preload open; this is the periodic
  process-visibility cross-check.
- **listening-ports-watchdog**: a hidden process often
  opens a hidden port; if the rootkit hides the process but
  not the socket, listening-ports catches it — and vice
  versa.
