# audit-rules

Installs Linux audit subsystem rules that drive the `selfdef-
collector-auditd` ingestion pipeline. The auditd collector
(documented in SDD-059) already handles 7 record types end-to-end;
this module provides the **rule configuration** that causes the
kernel to emit those records in the first place.

Without rules, auditd is silent except for the userspace USER_*
auth events the PAM stack already emits.

## Profiles

| Profile | Rule set | Use case |
|---|---|---|
| `base` (default) | high-signal subset: ld.so.preload watch, sudo/su exec, kmod load/unload, /etc/{passwd,shadow,sudoers} watch | balanced — minimal performance cost, broad detection |
| `paranoid` | base + every privilege-escalation syscall + every credential-file open + execve audit | thorough — measurable audit-overhead, deep telemetry |

## Rules shipped (base profile)

| Rule | Audit kind it triggers | Collector handler (SDD-059) |
|---|---|---|
| `-w /etc/ld.so.preload -p wa -k selfdef-ldpreload` | path watch → SYSCALL | (fallback; future multi-line) |
| `-w /etc/passwd -p wa -k selfdef-passwd` | path watch → SYSCALL | (fallback) |
| `-w /etc/shadow -p wa -k selfdef-shadow` | path watch → SYSCALL | (fallback) |
| `-w /etc/sudoers -p wa -k selfdef-sudoers` | path watch → SYSCALL | (fallback) |
| `-w /usr/bin/sudo -p x -k selfdef-sudo-exec` | exec watch → SYSCALL | (fallback) |
| `-w /usr/bin/su -p x -k selfdef-su-exec` | exec watch → SYSCALL | (fallback) |
| `-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k selfdef-kmod` | kernel-module syscalls → SYSCALL | (fallback; complementary to host-sentinel kmod-watch Tetragon policy) |
| `-a always,exit -F arch=b64 -F a0=10 -S socket -k selfdef-rawsock` | raw socket creation → SYSCALL | (fallback) |
| `--loginuid-immutable` | enforce loginuid immutability | n/a (kernel-side enforcement) |

## Rules shipped (paranoid profile, additions on top of base)

| Rule | Audit kind it triggers |
|---|---|
| `-a always,exit -F arch=b64 -S execve -S execveat -k selfdef-exec` | every exec → SYSCALL+EXECVE |
| `-a always,exit -F arch=b64 -S ptrace -k selfdef-ptrace` | every ptrace → SYSCALL |
| `-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k selfdef-setid` | uid/gid changes → SYSCALL |
| `-w /etc/cron.d -p wa -k selfdef-cron` | cron config writes |
| `-w /var/spool/cron -p wa -k selfdef-cron` | per-user crontab writes |

## Coverage relative to MS016 deferred eBPF programs

| MS016 deferred | audit-rules base | audit-rules paranoid | Tetragon (host-sentinel) | aya-rs eBPF (deferred) |
|---|---|---|---|---|
| proc-ancestry | partial via -S execve (paranoid) | thorough | n/a | ground-truth (deferred) |
| hidden-process | n/a (auditd can't enumerate tasks) | n/a | n/a | ground-truth (deferred) |
| ld-preload-watch | partial via path watch | partial | full (selfdef-host-ld-preload-watch policy) | LD_PRELOAD env-var watch (deferred) |
| kmod-watch | full via -S init_module / delete_module | same | full (selfdef-host-kmod-watch policy) | signed/unsigned classification (deferred) |
| tcp-fingerprint | n/a (auditd doesn't see packets) | n/a | n/a | XDP/tc-bpf SYN inspection (deferred) |

audit-rules + host-sentinel together provide overlapping coverage
for ld-preload-watch + kmod-watch at the kernel-audit + Tetragon
layers. The aya-rs eBPF substrate is the future arc for the 3
genuinely-eBPF-required programs (proc-ancestry, hidden-process,
tcp-fingerprint).

## Install

```bash
selfdefctl modules apply audit-rules
```

The apply script:
1. Validates `auditctl` + `augenrules` are present
2. Writes rule files to `/etc/audit/rules.d/`
3. Runs `augenrules --load` to atomic-swap the live rule set
4. Records a manifest of files written for clean uninstall

`audit-rules` plays nicely with operator-authored rules — it only
writes files prefixed `50-selfdef-*` and only removes those on
uninstall. Pre-existing `/etc/audit/rules.d/*.rules` files are
untouched.

## Why this module exists

selfdef-collector-auditd has been shipping a tail-and-parse loop
against `/var/log/audit/audit.log` since cycle-3. SDD-059 ratified
7 typed record handlers (AVC + SECCOMP + ANOM_ABEND +
ANOM_PROMISCUOUS + 3 USER_*) covering the kernel-emitted side.

But without rules, the kernel emits almost nothing. Operator-
installed Linux distros vary wildly: Debian ships `auditd` with
ZERO rules by default; RHEL ships a STIG-flavored baseline that
may or may not align with selfdef's collector. This module
guarantees a known rule set is loaded so the collector reliably
sees the events SDD-059 promised handlers for.
