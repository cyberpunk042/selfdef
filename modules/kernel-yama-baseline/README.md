# kernel-yama-baseline

Sets `kernel.yama.ptrace_scope` to restrict which processes
may attach to which other processes via `ptrace(2)`.
Blocks the canonical in-host credential-theft chain: an
attacker who lands as unprivileged user X cannot
`gdb -p <pid-of-user-X-other-process>` to scrape its
memory for SSH keys, gpg-agent secrets, browser passwords.

## Why this matters

`ptrace(2)` is the kernel hook gdb / strace / lldb /
process-injection toolkits depend on. The default policy on
many distros allows any user to ptrace any of their own
processes. That sounds harmless until you consider:

| Attacker scenario | What ptrace gives them |
|---|---|
| Compromised browser tab (Chrome zero-day, malicious extension) | Attach to ssh-agent → dump unlocked private keys |
| Compromised dev-tool (npm/pip supply-chain backdoor) | Attach to gpg-agent → dump unlocked passphrase + key material |
| Compromised script run by operator | Attach to the operator's interactive shell → siphon command history, env vars, credentials |
| LD_PRELOAD-based injection blocked by namespace constraints | Use ptrace instead of LD_PRELOAD |

The `yama` Linux Security Module enforces a kernel-level
restriction that makes most of these chains impossible
without escalating to root (which the attacker by
definition doesn't have).

## Profiles

| Profile | Value | Effect | Workflow break |
|---|---|---|---|
| `relaxed` (default) | 1 | Parent-only attach: a process can ptrace only its descendants | None on a properly-configured host; Ubuntu default since 10.10 |
| `strict` | 2 | Admin-only attach: only processes with `CAP_SYS_PTRACE` may ptrace any other process | gdb attach by non-root operator requires `sudo gdb` or `setcap cap_sys_ptrace+ep /usr/bin/gdb` |
| `paranoid` | 3 | No attach at all; sysctl write to lower values returns `EINVAL` until reboot | gdb attach to ANY existing process dies; starting a process under `gdb ./bin` still works |

## Refuse-to-brick gate

The `paranoid` profile is **irreversible until reboot**.
Apply refuses unless the config file contains
`acknowledge_paranoid = true`:

```bash
sudo cat > /etc/selfdef/modules/kernel-yama-baseline.toml <<EOF
profile = "paranoid"
acknowledge_paranoid = true
EOF
sudo selfdefctl modules apply kernel-yama-baseline
```

This is the 10th refuse-to-brick gate across the module
ecosystem (joining sudoers/ssh/kernel-lockdown/firewall/
audit-immutable patterns).

## File

`/etc/sysctl.d/50-selfdef-yama.conf` rendered per-profile
with selfdef header marker for uninstall ownership check.
Loaded at boot via `sysctl --system`; apply.sh also writes
live via `sysctl -w` (subject to the EINVAL-if-live=3
caveat — once 3 has been set, the kernel refuses to
decrease without reboot).

## MITRE coverage

- **T1055.008** Process Injection: Ptrace System Calls —
  PRIMARY; this is exactly the technique that yama
  restricts.
- **T1003** OS Credential Dumping — narrows the in-memory
  scrape vectors (ssh-agent, gpg-agent, mimikatz-equivalent
  Linux variants).
- **T1611** Escape to Host — defender-side; a compromised
  container that breaks confinement to host-user namespace
  still cannot ptrace host processes if yama=2|3.
- **T1574** Hijack Execution Flow: dynamic-linker bypass —
  attacker who can't LD_PRELOAD because of mount namespace
  often falls back to ptrace; yama blocks both ends.

## Operator workflow

```bash
# Inspect live value
sysctl kernel.yama.ptrace_scope

# Check yama is the active LSM
cat /sys/module/yama/parameters/ptrace_scope 2>/dev/null || echo "yama not loaded"
cat /sys/kernel/security/lsm

# Switch to strict on operator workstations
sudo sed -i 's/^profile.*/profile = "strict"/' /etc/selfdef/modules/kernel-yama-baseline.toml
sudo selfdefctl modules apply kernel-yama-baseline

# Operator wants to gdb-attach under strict
sudo gdb -p <pid>           # works (sudo grants CAP_SYS_PTRACE)
# OR file-cap (operator decision; broad grant):
sudo setcap cap_sys_ptrace+ep /usr/bin/gdb
gdb -p <pid>                # now works without sudo
```

## Caveats

- **paranoid is one-way** until reboot — confirmed via
  refuse-to-brick gate.
- **yama LSM may not be enabled** in custom-built kernels.
  apply.sh logs WARN if `kernel.yama.ptrace_scope` is
  unreadable; module behaves as no-op.
- **Container runtimes** typically have their own
  ptrace_scope (sometimes 0 — relaxed inside the
  container). This module sets HOST scope; container
  internal value is per-container-runtime configuration.
- **Crash-debugging tooling** (perf, systemd-coredump,
  drgn) generally works at any ptrace_scope because they
  use different kernel APIs OR require CAP_SYS_PTRACE
  anyway. Operator on these tools is not affected.
- **strict profile** may surprise operators who use gdb
  attach in regular workflow. Document in operator-onboard
  runbook.

## Coexistence

- **kernel-lockdown**: orthogonal — kernel-lockdown handles
  kptr_restrict + dmesg_restrict + perf_event_paranoid;
  this module handles ptrace specifically. Both apply
  together with no conflict.
- **sysctl-network-baseline**: orthogonal — network sysctls,
  not security-LSM sysctls.
- **apparmor-baseline + tetragon**: orthogonal MAC + EBPF
  layer; ptrace_scope is enforced earlier (LSM hook on
  ptrace_access_check).
- **proc-hidepid**: complementary; proc-hidepid limits
  WHICH processes a user can SEE in /proc, this module
  limits which processes they can ATTACH to once seen.
- **agent-guard + integrity-sentinel**: complementary
  attack-detection; ptrace blocking is prevention.
