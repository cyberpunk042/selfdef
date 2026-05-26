# kernel-cmdline-watchdog

Boot + daily delta of the kernel command line
(`/proc/cmdline`) against a learned baseline, plus a
known-weakening-flag denylist. Catches a GRUB edit that
removed a hardening boot param or added a security-
disabling one before an attack. MITRE **T1562.001** /
**T1601**.

## Why this matters

The kernel command line is set at boot (by GRUB) and
can't be changed on a running kernel — so a change only
appears ACROSS a reboot. An attacker with GRUB/console
access (the same surface `bootloader-password-detect`
defends) or who edits `grub.cfg` + reboots can weaken the
kernel's security posture invisibly:

| Edit | Effect |
|---|---|
| remove `audit=1` | audit subsystem starts disabled |
| remove `lockdown=integrity/confidentiality` | kernel lockdown off |
| remove `init_on_alloc=1`/`init_on_free=1` | no heap zeroing → use-after-free exploitation easier |
| add `mitigations=off` | ALL CPU-vuln mitigations (Spectre/Meltdown/etc.) off |
| add `nosmep`/`nosmap` | disable SMEP/SMAP → kernel exploit easier |
| add `nokaslr` | disable kernel ASLR |
| add `selinux=0`/`apparmor=0` | disable MAC |
| add `single`/`init=/bin/sh`/`rd.break` | boot to a root shell, bypass init |

This module baselines the cmdline + alerts on (1) any
drift across boots, and (2) the PRESENCE of any denylisted
weakening flag — even at baseline time, so an already-
weakened host is flagged on first install.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on cmdline change or weakening flag → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| Unchanged + no weakening flag | `ok` | `cmdline_intact` |
| Changed, no weakening flag (operator kernel tuning?) | `warn` | `cmdline_changed` |
| A weakening flag present (matched baseline) | `alert` | `weakening_flag_present` |
| A weakening flag newly added vs baseline | `alert` | `weakening_flag_added` |

## Weakening-flag denylist

`mitigations=off`, `nosmep`, `nosmap`, `nokaslr`,
`noexec=off`, `selinux=0`, `apparmor=0`, `init_on_alloc=0`,
`init_on_free=0`, `audit=0`, `lockdown=none`, `single`,
`init=/bin/sh`, `init=/bin/bash`, `systemd.confirm_spawn`,
`rd.break`.

## Cadence

`OnBootSec=4min` + daily 06:25. The **boot catch is the
important one** — cmdline only changes across a reboot, so
checking shortly after each boot catches a GRUB-edit
weakening immediately. Daily is a backstop.

## MITRE coverage

- **T1562.001** Impair Defenses: Disable or Modify Tools —
  PRIMARY; removing audit=1/lockdown= or adding
  mitigations=off disables kernel defenses.
- **T1601** Modify System Image — narrowly; boot-param
  modification alters the running system image's posture.
- **T1542** Pre-OS Boot — the GRUB-edit surface this
  detects results from (pairs with bootloader-password-
  detect).
- **T1014** Rootkit — disabling lockdown/SMEP/SMAP eases
  kernel rootkit installation.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-kernel-cmdline -n 1 --no-pager

# What changed (was/now)
journalctl -t selfdef-kernel-cmdline-detail --since "1 day ago"

# Manual
cat /proc/cmdline

# Investigate a weakening flag
# - Is it in the GRUB config (persistent) or a one-time edit?
grep -r 'GRUB_CMDLINE' /etc/default/grub
sudo grep -h 'linux' /boot/grub*/grub.cfg | grep -o 'mitigations=off\|nosmep' 

# Re-baseline after a legit kernel-arg change (operator added
# a tuning param + updated grub + rebooted)
sudo rm /var/lib/selfdef/kernel-cmdline-baseline.txt
sudo systemctl start selfdef-kernel-cmdline.service
```

## Caveats

- **Legit kernel tuning** (operator adds `transparent_
  hugepage=never`, `intel_iommu=on`, etc. + reboots) fires
  `cmdline_changed` (warn) — re-baseline. Only the
  denylist flags escalate to alert.
- **`mitigations=off` is sometimes set intentionally** on
  air-gapped perf-critical hosts where the operator
  accepts the CPU-vuln risk — that host's operator
  acknowledges the persistent alert or removes the flag
  from the denylist via an operator-prefixed wrapper.
- **Boot-only change**: the module can't catch a cmdline
  weakening until the NEXT boot (the running kernel keeps
  its cmdline). bootloader-password-detect is the
  prevent-side (stops the GRUB edit); this is the
  detect-side (catches it at next boot).

## Coexistence

- **bootloader-password-detect**: the matched pair —
  bootloader-password PREVENTS the GRUB edit (password on
  edit); this DETECTS the result (changed cmdline at next
  boot) if the edit happened anyway.
- **kernel-lockdown + aslr-baseline + audit-config-
  watchdog**: those CONFIGURE/ENFORCE the protections this
  cmdline drift would disable; this watches the boot-param
  layer that controls whether they even start.
- **secure-boot-status**: complementary boot-chain
  visibility.
- **kernel-module / hidden-process watchdogs**: a weakened
  cmdline (nosmep/lockdown off) eases the rootkit install
  those detect.
