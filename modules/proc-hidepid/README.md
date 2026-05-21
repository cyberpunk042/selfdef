# proc-hidepid

Adds `hidepid=` mount option to `/proc` so non-root users cannot
enumerate other users' processes. Reduces the T1057 Process
Discovery + T1083 File and Directory Discovery attack surfaces
from the cheap-and-noisy `ps aux` enumeration that's typically
attacker-step-1 on a host.

## hidepid levels

| Value | Name | Effect on non-root |
|---|---|---|
| 0 | off (default) | Sees every `/proc/<pid>` |
| 1 | noaccess (off in newer kernels) | Can ENUMERATE other users' /proc but cannot READ |
| 2 | noaccess | Cannot OPEN other users' /proc/<pid>; entries STILL VISIBLE in getdents() (ls /proc returns total PID count) |
| 4 | invisible | Other users' /proc/<pid> entries are NOT VISIBLE — getdents() filters them out |

selfdef ships:
- `noaccess` (default; hidepid=2) — most operator workflows
  continue to work
- `invisible` (hidepid=4; refuse-to-brick gate) — strongest +
  breaks several daemons

## Why this matters

Attacker step 1 after landing an unprivileged shell:

```bash
ps auxf
```

The output reveals:
- Every running daemon (postfix, mysqld, postgres, nginx) with
  command-line args (paths to config files, sometimes credentials
  inline)
- Operator's running shell + commands
- Recently-spawned helper PIDs (sudo invocations, ssh
  authentications)
- The full environment surface for next-step enumeration

With `hidepid=2`, non-root `ps aux` shows ONLY own-user processes.
The attacker must escalate privs FIRST before enumerating, +
the escalation paths are themselves narrower.

## Profiles

| Profile | hidepid | Refuse-to-brick gate | Compatibility |
|---|---|---|---|
| `noaccess` (default) | 2 | none | High — most distros work out of the box |
| `invisible` | 4 | `acknowledge_hidepid=true` + optional `bypass_gid` | Lower — dbus + monitoring daemons may need bypass_gid |

The bypass_gid option (invisible profile only) names a group
that bypasses hidepid; members can see all /proc entries.
Operator sets this to their monitoring group (node-exporter,
netdata, datadog-agent) to keep observability functional.

## MITRE coverage

- **T1057** Process Discovery — direct prevention; attacker's
  `ps aux` returns only their own processes.
- **T1083** File and Directory Discovery — `/proc/<pid>/cmdline`
  / `environ` / `cwd` enumeration blocked.
- **T1518** Software Discovery — `ps aux | grep <daemon-name>`
  reconnaissance blocked.

## What this does NOT block

- **Root + CAP_SYS_PTRACE-holding processes** — they see everything.
  Container runtimes (docker, podman) often run as root.
- **Network-port enumeration** — `ss -lntu` shows listeners across
  all users; hidepid doesn't affect that. Pair with
  `loopback-only-dns` + `ssh-hardening` to narrow the surface.
- **systemd-controlled cgroup view** — `systemctl status` for
  cross-user units may reveal process info via cgroup paths even
  with hidepid=4.

## Operator workflow

```bash
# Verify live mount option
findmnt /proc -o TARGET,OPTIONS

# Test as non-root user
sudo -u nobody ps aux | wc -l
# noaccess profile: returns only nobody's processes (typically 0-1)
# invisible profile: same; getdents-filtered

# Inspect another user's process as root (always works)
sudo cat /proc/1/cmdline | tr '\0' ' '
```

## Coexistence

- **systemd**: works correctly with hidepid (uses CAP_SYS_PTRACE
  via systemd-logind for cross-user actions).
- **dbus**: usually OK with hidepid=2; may need bypass_gid with
  hidepid=4.
- **monitoring (prometheus node-exporter, netdata)**: needs
  bypass_gid set to its runtime group, OR runs as root.

## Why systemd-mount instead of /etc/fstab

systemd's `proc.mount` unit composes correctly with the initramfs-
mounted /proc + handles re-mount on settings change. Editing
/etc/fstab takes effect at NEXT REBOOT only, and the
implementation-specific quirks (Debian's `proc /proc proc
defaults` line + RHEL's lack of explicit fstab entry) make a
unified module fragile.

Our proc.mount unit:
- Composes with initramfs proc mount (DefaultDependencies=no +
  Before=local-fs.target)
- ConditionVirtualization=!container so it doesn't fight
  container runtimes
- Re-mount succeeds live IF /proc isn't busy (most cases)

## Caveats

- **Live re-mount may fail** if a process holds an /proc file
  open. apply.sh logs a NOTICE in that case; the change takes
  effect at next reboot.
- **Container images** running on the host: hidepid doesn't
  propagate into container /proc namespaces (each container has
  its own /proc); container's own /proc options matter
  separately.
- **Some kernel-doctor scripts** (mostly Bash) rely on
  cross-user /proc enumeration and break under hidepid=4.
  Compatibility note in operator-extension docs.
