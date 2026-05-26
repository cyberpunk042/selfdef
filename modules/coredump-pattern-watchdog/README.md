# coredump-pattern-watchdog

Boot + every-2h verification that `kernel.core_pattern`
has not been hijacked to pipe core dumps to an attacker
program. A `core_pattern` of `|/tmp/evil` runs that
program **as root** on the next crash of any process — a
quiet privilege-escalation + persistence trigger. MITRE
**T1546** / **T1574**.

## Why this matters

When `kernel.core_pattern` begins with `|`, the kernel
pipes a crashing process's core dump to the named program —
and runs that program **as root**, regardless of who owned
the crashing process. An attacker does:

```
echo '|/tmp/.x %p' > /proc/sys/kernel/core_pattern
# then crash any process (or just wait for one):
kill -SIGSEGV $$        # in a throwaway subshell
# → /tmp/.x runs as root
```

It's stealthy: no new service, no cron entry, no new
account — just one sysctl write that turns the NEXT crash
anywhere on the system into root code execution. It's a
known privilege-escalation + persistence primitive and has
appeared in real Linux malware.

This module verifies the live `core_pattern` against an
allowlist of legitimate pipe handlers and alerts on
anything else.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if core_pattern pipes to a non-allowlisted program → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| Plain pattern (`core`, `core.%p`) | `ok` | `core_pattern_safe` |
| Pipe to an allowlisted handler that exists | `ok` | `core_pattern_allowlisted_pipe` |
| Plain pattern targeting /tmp, /var/tmp, /dev/shm | `warn` | `core_pattern_tmp_target` |
| Allowlisted handler path but binary missing on disk | `alert` | `core_pattern_pipe_missing_binary` |
| Pipe to a NON-allowlisted program | `alert` | `core_pattern_hijacked` |

## Allowlist

Legitimate pipe handlers:
- `/usr/lib/systemd/systemd-coredump` + `/lib/systemd/
  systemd-coredump` (systemd-coredump)
- `/usr/share/apport/apport` (Ubuntu apport)

Anything else with a leading `|` is treated as a hijack.

## Cadence

`OnBootSec=5min` + `OnUnitActiveSec=2h` + jitter —
`core_pattern` is a RUNTIME sysctl an attacker can flip at
any moment (no reboot needed), so a 2h cadence bounds
detection; the boot catch confirms it came up clean.

## MITRE coverage

- **T1546** Event Triggered Execution — PRIMARY; the
  core-dump pipe is an event-triggered (on-crash) root
  exec primitive.
- **T1574** Hijack Execution Flow — hijacking the kernel's
  crash-handler path.
- **T1548** Abuse Elevation Control Mechanism — the handler
  runs as root regardless of the crashing process's uid.
- **T1543** Create or Modify System Process — the
  persistent root-trigger.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-coredump-pattern -n 1 --no-pager

# Live value
cat /proc/sys/kernel/core_pattern
sysctl kernel.core_pattern

# Investigate a hijack alert — what is the pipe target?
ls -la /tmp/.x; file /tmp/.x        # the attacker binary

# Restore a safe value (or let systemd-coredump own it)
sudo sysctl -w kernel.core_pattern='|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h'
# or plainest:
sudo sysctl -w kernel.core_pattern='core'
# persist via /etc/sysctl.d if needed
```

## Caveats

- **Custom crash-reporters**: a site that legitimately
  pipes cores to its own handler (e.g. a Breakpad/Crashpad
  collector) will alert. Add that handler to the allowlist
  via an operator-prefixed wrapper, or accept the known
  alert.
- **Detection only** — does not lock core_pattern.
  coredumpd-redirect SETS a safe systemd-coredump pattern;
  this DETECTS a hijack of whatever is set. Pair them.
- **2h cadence** misses a hijack-crash-restore within the
  window; auditd watching writes to
  /proc/sys/kernel/core_pattern (via a sysctl-write rule)
  is the real-time complement, as is tetragon.
- **%-specifiers** in a legit pattern (e.g. `%p %u`) are
  parsed correctly — only the FIRST token after `|` (the
  program path) is allowlist-checked.

## Coexistence

- **coredumpd-redirect**: the config-side companion — it
  SETS core_pattern to the locked-down systemd-coredump
  handler; this DETECTS any later hijack. Set + detect pair.
- **coredump-suid-restrict + apport-disable**: complementary
  core-dump-defense family — suid-dumpable=0 (no setuid
  memory dumps), apport-disable (remove apport handler),
  and this (detect pattern hijack). Together they cover the
  whole core-dump attack/leak surface.
- **kernel-cmdline-watchdog + audit-config-watchdog**:
  sibling defense-evasion detectors; a core_pattern hijack
  often accompanies other tampering those catch.
