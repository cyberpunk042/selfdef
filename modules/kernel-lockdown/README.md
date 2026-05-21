# kernel-lockdown

Kernel hardening sysctl baseline. Installs a drop-in at
`/etc/sysctl.d/50-selfdef-kernel-lockdown.conf` (+ optionally
`50-selfdef-kernel-lockdown-strict.conf`) that disables a curated
set of high-signal attack vectors at the kernel layer.

## Profiles

| Profile | What it disables | Reversibility |
|---|---|---|
| `balanced` (default) | kexec / unprivileged BPF / userfaultfd / dmesg unrestricted-read / unrestricted perf_event_open / SUID coredumps / ptrace_scope drift | Reversible at runtime (`sysctl key=value`) |
| `strict` | balanced + kernel.modules_disabled=1 + sysrq off + IPv4 send_redirects off | **kernel.modules_disabled = IRREVERSIBLE until reboot** |

`strict` is gated by `acknowledge_modules_disabled = true` in the
module config — same refuse-to-brick pattern as `usbguard`. The
apply step refuses to set `kernel.modules_disabled=1` without the
flag.

## MITRE coverage

| Vector | Sysctl | Technique |
|---|---|---|
| Runtime kernel image replacement | `kernel.kexec_load_disabled=1` | T1574.012 (related to Hijack Execution Flow) |
| Unprivileged BPF LPE primitives | `kernel.unprivileged_bpf_disabled=1` + `net.core.bpf_jit_harden=2` | T1068 Exploitation for Privilege Escalation |
| userfaultfd race conditions | `vm.unprivileged_userfaultfd=0` | T1068 |
| Information leak via dmesg | `kernel.dmesg_restrict=1` | T1592 |
| perf_event_open syscall LPE | `kernel.perf_event_paranoid=3` | T1068 |
| SUID coredump leaks | `fs.suid_dumpable=0` | T1003.008 / T1552.004 |
| ptrace cross-process | `kernel.yama.ptrace_scope=1` | T1055.008 |
| Late kernel-module rootkit | `kernel.modules_disabled=1` (strict) | T1014 / T1547.006 |
| Magic SysRq DoS | `kernel.sysrq=0` (strict) | T1499 |

## Coexistence with other sysctl files

The shipped drop-ins are at `50-selfdef-kernel-lockdown*.conf`.
systemd-sysctl loads files in lex order, so earlier-named drop-ins
(00-…, 10-…, 30-…) are OVERRIDDEN by ours; later-named ones
(60-…, 99-…) override OURS. Operator-tuned `99-operator.conf`
files keep working.

## Interaction with audit-rules + host-sentinel

This module disables kernel.modules_disabled in strict mode; the
`audit-rules` base profile + `host-sentinel` kmod-watch
TracingPolicy both watch for `init_module` / `finit_module`. Once
modules_disabled=1, those events become RARE (kernel rejects the
syscall, no module actually loads) but the audit subsystem still
emits the attempted-call record — operator gets visibility into
attack attempts even when the attack itself can't succeed.

## Recovery

If kernel.modules_disabled=1 + a needed module is missing →
reboot. The next boot reads the drop-in fresh; if you remove
`50-selfdef-kernel-lockdown-strict.conf` before reboot, the new
boot won't re-set the flag and modules load normally.

For the balanced profile, every sysctl is runtime-reversible:

```bash
sudo sysctl kernel.kexec_load_disabled=0    # for example
```

## Why not Linux Kernel Lockdown (LSM)?

`kernel.lockdown` (CONFIG_SECURITY_LOCKDOWN_LSM) is the kernel's
own "integrity"/"confidentiality" mode. It's stronger than the
sysctl-driven baseline here but requires:
- kernel built with the LSM enabled (not all distros do)
- secure boot to set the mode securely
- non-trivial operator opt-in (`/sys/kernel/security/lockdown`)

This module's sysctl baseline is the universally-portable starting
point. A future `kernel-lsm-lockdown` module can layer on top.
