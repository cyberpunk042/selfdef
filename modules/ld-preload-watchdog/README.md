# ld-preload-watchdog

Surfaces userland-rootkit LD_PRELOAD hooks. Flags any
`/etc/ld.so.preload` entry, any global `LD_PRELOAD` /
`LD_LIBRARY_PATH` in system env files, and escalates to
ALERT when a preload library sits in a writable/temp path
or doesn't exist on disk. LD_PRELOAD is the dominant
userland-rootkit injection vector.

## Why this matters

`LD_PRELOAD` forces the dynamic linker to load an
attacker library into EVERY dynamically-linked process
BEFORE the real libc — letting it hook `readdir` (hide
files/processes), `open`/`read` (hide its own config),
`accept` (backdoor a network service), `pam_authenticate`
(steal/bypass credentials). It's the engine behind
userland rootkits like **Jynx**, **Azazel**, **beurk**,
**libprocesshider**.

Two persistence surfaces:
- **`/etc/ld.so.preload`** — a system-wide file; every
  process inherits it. Empty/absent by default; ANY entry
  warrants a look.
- **Global env** (`/etc/environment`, `/etc/profile.d/*`,
  root's shell rc) — an `export LD_PRELOAD=...` that
  applies to all login shells / the whole system.

The ALERT tier fires when the preload lib is in `/tmp`,
`/var/tmp`, `/dev/shm`, `/home`, `/run`, or is a path that
doesn't exist (deleted-after-load) — none of which a
legitimate preload uses.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 on any ld.so.preload entry OR global LD_PRELOAD → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| Nothing found | `ok` | `no_ld_preload` |
| Preload entry under a trusted path | `warn` | `ld_preload_present` |
| Preload lib under /tmp /var/tmp /dev/shm /home /run, or non-existent path | `alert` | `suspicious_ld_preload` |

## Surfaces checked

| Surface | Detail |
|---|---|
| `/etc/ld.so.preload` | each library line (comments stripped) |
| `/etc/environment` | LD_PRELOAD / LD_LIBRARY_PATH assignments |
| `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc` | login-shell preload exports |
| `/root/.bashrc`, `.bash_profile`, `.profile` | root's shell preload exports |

## Cadence

`OnBootSec=8min` + `OnUnitActiveSec=6h` + jitter. A
persistence entry fires at boot; 6h bounds detection of a
mid-day injection.

## MITRE coverage

- **T1574.006** Hijack Execution Flow: Dynamic Linker
  Hijacking — PRIMARY; LD_PRELOAD is the exact technique.
- **T1014** Rootkit — userland rootkits are LD_PRELOAD-
  based; this is their persistence artifact.
- **T1556** Modify Authentication Process — preloaded
  pam_authenticate hooks bypass/steal credentials.
- **T1564** Hide Artifacts — readdir hooks hide files /
  processes (pairs with hidden-process-watchdog).

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-ld-preload -n 1 --no-pager

# Per-finding detail
journalctl -t selfdef-ld-preload-detail --since "1 day ago"

# Manual inventory
cat /etc/ld.so.preload 2>/dev/null || echo "absent (good)"
grep -rIs LD_PRELOAD /etc/environment /etc/profile /etc/profile.d/ \
    /etc/bash.bashrc /root/.bashrc /root/.profile 2>/dev/null

# Investigate a flagged lib
file /path/to/lib.so
sha256sum /path/to/lib.so
# Cross-check with rkhunter + hidden-process-watchdog

# Remove an illegitimate preload
sudo rm /etc/ld.so.preload     # if attacker-planted
# (or remove the specific line / env export)
```

## Caveats

- **Legitimate LD_PRELOAD users exist**: `snoopy`
  (command logger), some HPC libraries, `libeatmydata`
  (test envs), fakeroot. These trip the `warn` tier;
  operator confirms + (future) adds an allowlist.
- **Per-process LD_PRELOAD** set transiently in a
  service's unit/env is NOT in these global files — this
  module checks the GLOBAL surfaces. tetragon's
  security_file_open eBPF + per-process /proc/<pid>/environ
  scanning would catch transient ones (heavier; future).
- **A rootkit already preloaded** could hook this script's
  own libc calls (it reads files via libc). Mitigation:
  the systemd unit's ProtectSystem + the cross-check with
  host-sentinel (Tetragon, eBPF — operates below libc) +
  rkhunter. No single userland check is rootkit-proof;
  defense-in-depth is.

## Coexistence

- **host-sentinel (Tetragon)**: PRIMARY complement — its
  `security_file_open` kprobe on `/etc/ld.so.preload`
  catches the WRITE in real time, below libc (rootkit
  can't hook eBPF). This module is the periodic content
  cross-check.
- **hidden-process-watchdog + kernel-module-watchdog**:
  sibling rootkit detectors — LD_PRELOAD (userland) +
  hidden-process (either) + kernel-module (LKM) cover the
  three rootkit classes.
- **rkhunter-cron**: rkhunter has its own preload check;
  this is a focused structured-event version.
- **integrity-sentinel + aide-bridge**: would flag
  /etc/ld.so.preload appearing/changing as a watched-file
  event.
