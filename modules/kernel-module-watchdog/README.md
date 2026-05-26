# kernel-module-watchdog

Daily + boot delta of the loaded-kernel-module set
(`/proc/modules`) against a learned baseline. A NEW
kernel module that wasn't in the known-good set is a
high-signal LKM-rootkit / unexpected-driver indicator.
The fifth and final delta-detection watchdog, covering
the kernel-module persistence surface.

## Why this matters

Loadable Kernel Modules (LKMs) run in ring 0 with full
kernel privilege. An attacker who loads a malicious
module can:
- Hook syscalls to hide files, processes, network
  connections (the classic LKM rootkit — Diamorphine,
  Reptile, etc.).
- Intercept keystrokes / credentials at the kernel
  layer.
- Disable other security modules (unhook auditd, LSM).
- Persist below the userspace detection horizon.

Loading a module changes `/proc/modules`. Baselining the
module set + diffing it daily (and at boot, after the
legitimate driver-load wave) catches the addition. The
module escalates to ALERT when an added module has no
matching `.ko` under `/lib/modules/$(uname -r)` — the
signature of an out-of-tree / injected / unsigned module,
which is exactly what a rootkit is.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on any ADDED module → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| 1–2 added (in-tree) | `warn` | `new_module` |
| 3+ added (in-tree) | `alert` | `mass_new_modules` |
| Any added module with no `.ko` under /lib/modules | `alert` | `out_of_tree_module` (rootkit signature) |

## Out-of-tree detection

For each added module, the scanner searches
`/lib/modules/$(uname -r)` for a matching `<name>.ko`
(handling the `_` vs `-` naming variance + compressed
`.ko.xz`/`.ko.zst`). A module loaded into the running
kernel with NO corresponding file on disk is the
canonical injected-rootkit indicator — it was loaded via
`insmod /tmp/evil.ko` (then the file deleted) or via
direct `init_module()` from memory.

## Baseline file

`/var/lib/selfdef/kernel-modules-baseline.tsv` (mode
0600), one module name per line. Re-baseline after a
legitimate driver addition (new hardware, operator
modprobe):
```bash
sudo rm /var/lib/selfdef/kernel-modules-baseline.tsv
sudo systemctl start selfdef-kernel-modules.service
```
Preserved across uninstall (forensic).

## Cadence

`OnBootSec=8min` + `OnCalendar=*-*-* 05:55:00` + jitter.
Boot+8min captures the module set after the kernel's
legitimate boot-time driver load completes; daily 05:55
extends the staggered ladder after account-watchdog
(05:50).

## MITRE coverage

- **T1547.006** Boot or Logon Autostart Execution: Kernel
  Modules and Extensions — PRIMARY; loading a malicious
  LKM is the exact technique.
- **T1014** Rootkit — LKM rootkits are the dominant Linux
  rootkit class; out-of-tree-module detection is the
  signature.
- **T1562.001** Impair Defenses: Disable or Modify Tools
  — a rootkit module that unhooks auditd / LSM is caught
  as a new module load.
- **T1205** Traffic Signaling — some kernel-module
  backdoors implement port-knock magic-packet triggers.

## Operator workflow

```bash
# Last scan summary
journalctl -t selfdef-kernel-modules -n 1 --no-pager

# Per-module detail (added/removed)
journalctl -t selfdef-kernel-modules-detail --since "1 day ago"

# Manual inventory
lsmod | awk 'NR>1{print $1}' | sort

# Investigate an out-of-tree alert
modinfo <module>            # if it errors "not found", it's not on disk
sudo cat /proc/modules | grep <module>
# Cross-check against rkhunter-cron + aide-bridge findings

# Re-baseline after legit driver addition
sudo rm /var/lib/selfdef/kernel-modules-baseline.tsv
sudo systemctl start selfdef-kernel-modules.service
```

## Caveats

- **Hot-plug hardware** (USB devices, removable media)
  loads drivers on demand → recurring add/remove churn
  for `usb_storage`, `cdc_acm`, etc. Operator re-baselines
  on a host with stable hardware, OR accepts the warn-tier
  churn for hot-plug modules.
- **Module autoload on first use** (e.g. `ip_tables`
  loads when first iptables rule is added) → a `new_module`
  the first time. Re-baseline once steady-state.
- **A sophisticated rootkit hides itself from
  /proc/modules** (unlinks from the module list). This
  module catches the NAIVE case; pair with `rkhunter-cron`
  (which checks for hidden modules via alternate methods)
  + `host-sentinel` (Tetragon `do_init_module` kprobe,
  which catches the LOAD syscall regardless of later
  hiding).
- **Daily cadence** misses a load-then-unload within the
  window; the host-sentinel eBPF kprobe is the real-time
  complement.

## Coexistence

- **host-sentinel**: PRIMARY complement — its Tetragon
  `do_init_module` kprobe catches the module-LOAD syscall
  in real time, even if the module later hides from
  /proc/modules. This watchdog is the periodic
  catch-anyway backstop.
- **rkhunter-cron**: complementary — rkhunter checks for
  hidden modules + known-rootkit signatures; this does
  baseline-delta. Different detection methods, same target.
- **rare-filesystems-disable + rare-network-protocols-
  disable + bluetooth-disable**: those BLOCK specific
  modules from loading (modprobe blacklist); this DETECTS
  any module that did load.
- **suid-sgid + cron-job + listening-ports + account
  watchdogs**: sibling delta-detection family — kernel
  modules are the fifth persistence surface alongside
  setuid / scheduled-tasks / listeners / accounts.
- **kernel-lockdown**: complementary — lockdown mode can
  block unsigned module loading entirely; this detects
  what loaded where lockdown isn't enforcing.
