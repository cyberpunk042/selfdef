# sysctl-hardening-watchdog

Boot + daily delta of the sysctl config files
(`/etc/sysctl.conf` + `/etc/sysctl.d/*` + runtime/local) against
a learned baseline, flagging **weakening** of security-relevant
kernel sysctls. MITRE **T1562.001** (Impair Defenses).

## Why this matters

An attacker who drops `/etc/sysctl.d/99-x.conf` weakening kernel
hardening re-opens exploitation primitives that hardening closed:

```
kernel.kptr_restrict = 0           # leak kernel pointers (exploit aid)
kernel.yama.ptrace_scope = 0       # ptrace any process (credential theft)
fs.protected_symlinks = 0          # symlink-race attacks
kernel.unprivileged_bpf_disabled = 0
kernel.kexec_load_disabled = 0     # load an arbitrary kernel
fs.suid_dumpable = 1               # dump setuid process memory
```

These take effect at the next boot or `sysctl -p`. This watchdog
watches the config files **as a whole** for weakening — the
per-setting baselines (`aslr`, `kernel-yama`, `sysctl-network`)
SET specific values; this catches an attacker adding a weakening
line in any sysctl file.

## Watched security sysctls

| Sysctl | Hardened | Weak (alert) |
|---|---|---|
| `kernel.kptr_restrict` | 1/2 | 0 |
| `kernel.dmesg_restrict` | 1 | 0 |
| `kernel.unprivileged_bpf_disabled` | 1 | 0 |
| `kernel.kexec_load_disabled` | 1 | 0 |
| `kernel.yama.ptrace_scope` | ≥1 | 0 |
| `kernel.modules_disabled` | 1 | 0 |
| `kernel.sysrq` | 0 | ≠0 |
| `kernel.unprivileged_userns_clone` | 0 | ≠0 |
| `kernel.randomize_va_space` | 2 | ≠2 |
| `kernel.perf_event_paranoid` | ≥2 | <2 |
| `fs.protected_hardlinks` | 1 | 0 |
| `fs.protected_symlinks` | 1 | 0 |
| `fs.protected_fifos` | 1/2 | 0 |
| `fs.protected_regular` | 1/2 | 0 |
| `fs.suid_dumpable` | 0 | ≠0 |

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any sysctl-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No sysctl config | `ok` | `no_sysctl_config` |
| No delta | `ok` | `sysctl_hardening_intact` |
| Any config change | `warn` | `sysctl_hardening_changed` |
| A NEWLY-ADDED security sysctl set to its WEAK value | `alert` | `sysctl_hardening_weakened` |

The alert is delta-based — a pre-existing weak value is flagged
once at baseline for vetting, then not re-alerted.

## What's recorded

- `file:<path>:<sha12>` — hash of each sysctl config (catches any
  change, including non-security sysctls → `warn`).
- `sysctl:<key>:<value>` — each security-relevant sysctl set
  (`/`-separator normalized to `.`).

## Cadence

`OnBootSec=35min` + `OnCalendar=*-*-* 09:00:00` — extends the
staggered ladder after request-key (08:55). Weakened values take
effect at boot or `sysctl -p`, so the boot catch confirms the
config after a restart.

## MITRE coverage

- **T1562.001** Impair Defenses: Disable or Modify Tools —
  weakening kernel-hardening sysctls.
- **T1068** Exploitation for Privilege Escalation (adjacent) —
  the weakened primitives (kptr leak, ptrace, bpf) aid local
  exploits.

## Operator workflow

```bash
journalctl -t selfdef-sysctl-hardening -n 1 --no-pager
journalctl -t selfdef-sysctl-hardening-detail --since "1 day ago"

# Current declared values + the effective (running) value
grep -rhE 'kptr_restrict|ptrace_scope|protected_|unprivileged_bpf|kexec_load|suid_dumpable' \
     /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null
sysctl kernel.kptr_restrict kernel.yama.ptrace_scope fs.protected_symlinks 2>/dev/null

# Investigate a weakened alert, then re-harden + re-baseline:
sudo $EDITOR /etc/sysctl.d/<file>.conf   # remove/fix the weakening line
sudo sysctl --system                     # re-apply
sudo rm /var/lib/selfdef/sysctl-hardening-baseline.tsv
sudo systemctl start selfdef-sysctl-hardening.service
```

## Caveats

- **A weakening in the CONFIG may differ from the RUNNING value**
  (set via `sysctl -w` without persisting, or overridden by a
  later-ordered file). This module watches the persisted config
  (next-boot reality); pair with a runtime check (`sysctl <key>`)
  for the live value.
- **Some weak values are legitimate** in specific roles
  (`kernel.sysrq=1` on a debug host); the alert surfaces it for
  vetting (re-baseline to accept). Other changes are `warn`.
- **Daily+boot cadence** misses a weaken-apply-revert within the
  window; an audit-rules watch on `/etc/sysctl.*` writes is the
  real-time complement.

## Coexistence

- **aslr-baseline / kernel-yama-baseline / sysctl-network-baseline**:
  SET specific sysctls (randomize_va_space, ptrace_scope, network);
  this watches the config files as a whole for weakening of the
  broader security set, including sysctls without a dedicated
  module. Prevention + comprehensive-detection.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  files; this adds the per-sysctl weakening-semantic view.
