# kernel-usermodehelper-watchdog

Boot + daily delta of the kernel usermode-helper paths against a
learned baseline. Catches a kernel callout path the kernel runs as
root on a (frequently unprivileged-triggerable) event. MITRE
**T1574** / **T1548**.

## Why this matters

The kernel **executes these paths as root** (full root, kernel
context) on triggers that an unprivileged user can often cause:

- `kernel.modprobe` — run to **autoload a module**, e.g. when a
  user creates a socket of an unloaded protocol family, mounts an
  unloaded filesystem, etc. Default `/sbin/modprobe`.
- `kernel.hotplug` — the legacy hotplug helper. **Deprecated** —
  modern systems leave it **empty** (udev uses a netlink socket). A
  non-empty value means the kernel will exec that path on device
  events.
- `kernel.poweroff_cmd` — run on orderly poweroff. Default
  `/sbin/poweroff`.

read live from `/proc/sys/kernel/` and set persistently from
`/etc/sysctl.conf` + `/etc/sysctl.d/*.conf`. Setting
`kernel.modprobe=/tmp/x` is a **classic local privilege escalation**:
the attacker triggers a module autoload (trivial, unprivileged) and
the kernel runs their program as root.

This is distinct from **coredump-pattern-watchdog**
(`kernel.core_pattern` `|pipe`), **modprobe-config-watchdog**
(`/etc/modprobe.d`), and **sysctl-hardening-watchdog**
(network/hardening sysctls); this is the **usermode-helper exec**
surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any usermode-helper change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| `/proc/sys/kernel` unreadable + no sysctl config | `ok` | `no_usermodehelper` |
| No delta | `ok` | `usermodehelper_intact` |
| A helper value / sysctl line added / changed / removed | `warn` | `usermodehelper_changed` |
| A helper path under `/tmp` `/var/tmp` `/dev/shm` `/home`, a relative helper, OR a non-empty `kernel.hotplug` | `alert` | `usermodehelper_suspicious` |

## What's recorded

- `helper:<name>:<value>` — live `/proc/sys/kernel/<name>` value.
- `sysctl:<file>:<key>=<value>` — a `sysctl.d` / `sysctl.conf` line
  setting a helper (the persistent source).

## Cadence

`OnBootSec=81min` + `OnCalendar=*-*-* 13:10:00` — extends the
staggered ladder after openssl-conf (13:00). A planted
`kernel.modprobe`/`hotplug` path is exploitable the instant any
unprivileged autoload/hotplug trigger fires, so the daily catch
bounds dwell time; the boot catch confirms the helper paths after a
restart (sysctl.d is re-applied at boot).

## MITRE coverage

- **T1574** Hijack Execution Flow — the kernel routes a root exec
  through the helper path.
- **T1548** Abuse Elevation Control Mechanism — a writable
  `kernel.modprobe` is direct, trivial local privilege escalation.

## Operator workflow

```bash
journalctl -t selfdef-kernel-usermodehelper -n 1 --no-pager
journalctl -t selfdef-kernel-usermodehelper-detail --since "1 day ago"

# Inspect live + persistent values
for k in modprobe hotplug poweroff_cmd; do
  printf '%s = %s\n' "kernel.$k" "$(cat /proc/sys/kernel/$k 2>/dev/null)"; done
grep -rinE 'kernel[./](modprobe|hotplug|poweroff_cmd)' \
     /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null

# Remediate (example) + re-baseline:
sudo sysctl -w kernel.modprobe=/sbin/modprobe
sudo rm /var/lib/selfdef/kernel-usermodehelper-baseline.tsv
sudo systemctl start selfdef-kernel-usermodehelper.service
```

## Caveats

- **usrmerge distros** may legitimately use `/usr/sbin/modprobe` /
  `/usr/sbin/poweroff`; those absolute, non-writable paths are not
  flagged (only writable/relative paths and a non-empty `hotplug`
  alert). Any change still fires `warn` (re-baseline).
- **Live value vs config**: the live `/proc` value is the effective
  state; a transient `sysctl -w` that isn't persisted shows as a
  `helper:` delta without a matching `sysctl:` line — investigate.
- **`/proc` not readable** (some hardened/container contexts) →
  falls back to the sysctl-config view; if neither is available it
  is a clean `no_usermodehelper` no-op.
- **Real-time** detection of a write to these sysctls is better done
  with an audit-rules watch / eBPF on the sysctl write; this is the
  periodic baseline complement.

## Coexistence

- **coredump-pattern-watchdog**: `kernel.core_pattern` `|pipe`
  helper; this covers `modprobe`/`hotplug`/`poweroff_cmd`.
- **modprobe-config-watchdog / modules-load-watchdog**: modprobe.d
  and module auto-load lists; this is the kernel's modprobe *binary*
  path.
- **sysctl-hardening-watchdog**: the broad hardening sysctls; this
  is the narrow, high-value usermode-helper exec subset.
