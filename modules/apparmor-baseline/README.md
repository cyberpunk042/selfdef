# apparmor-baseline

AppArmor MAC layer baseline — flips an operator-curated set of
profiles between complain (LOG violations) and enforce (BLOCK
violations) modes. Defense-in-depth alongside Tetragon
(host-sentinel + agent-guard) at the LSM hook layer.

## Why AppArmor on top of Tetragon

Different mechanisms, different attack assumptions:

| Layer | Mechanism | Reacts to | Bypass |
|---|---|---|---|
| `host-sentinel` (Tetragon) | eBPF kprobe at LSM hook OR syscall entry | Operator-curated TracingPolicies | Kernel bug; eBPF disabled |
| `apparmor-baseline` | LSM hook check against profile rules | Per-binary profile | LSM disabled; AppArmor module unloaded |
| `audit-rules` | Linux audit subsystem at syscall | Operator-curated audit rules | auditd disabled |

All three trigger at the kernel LSM/syscall layer but via
different mechanisms. An attacker must defeat ALL THREE to land
an undetected exploit on a hardened host. Operationally each
covers different gaps:
- Tetragon: kernel-event surface; OPERATOR-PULL via TracingPolicy
- AppArmor: per-binary syscall+path restrictions; DECLARATIVE
  per-binary policy
- audit: syscall-level event surface; COVERAGE for events
  Tetragon's kprobes miss

## Profiles

| Profile | Mode | Use |
|---|---|---|
| `complain` (default) | LOG violations only | Baseline collection (1-2 weeks) to identify false positives BEFORE blocking |
| `enforce` | BLOCK violations at LSM | After complain-mode shakedown confirms zero false-positive denials |

## Curated profile set

`/etc/selfdef/apparmor/selfdef-curated-profiles.list` ships with
~17 high-signal profiles covering:
- **Browsers**: firefox, chromium, google-chrome (operator-clicked
  malicious content; biggest attack surface on a workstation)
- **Document viewers**: evince, okular (PDF + image preview =
  common phishing payload format)
- **Network daemons**: sshd, nginx, postfix, dovecot, dhclient,
  chronyd
- **Container runtimes**: lxc-start, docker
- **System tooling**: auditd, syslog-ng, man

Profiles that aren't INSTALLED-and-LOADED are silently skipped
(operator may not have all packages). Operator-tunable via
direct edit of the list file (selfdef respects subsequent
operator modifications).

## MITRE coverage

AppArmor at LSM hook layer blocks SYSCALL-level abuse patterns:
- **T1611** Escape to Host — container-escape via syscall path
  manipulation blocked when sandboxed binary's profile prohibits
  the syscall.
- **T1083** File and Directory Discovery — profile's read-rules
  limit which paths a confined process can enumerate.
- **T1059** Command and Scripting Interpreter — shell-spawn via
  exec() blocked unless explicitly allowed by profile.
- **T1574.006** Boot/Logon Autostart: LD_PRELOAD — profile
  enforces that the binary's lib search path respects
  AppArmor-allowed prefixes only.

## Cross-distro support

| Distro | Status | Operator step |
|---|---|---|
| Ubuntu / Debian | apparmor default; many profiles shipped | works out of box; `apt install apparmor-profiles apparmor-profiles-extra` for fuller coverage |
| openSUSE / SUSE | apparmor default | works out of box |
| Fedora / RHEL / Arch | SELinux default; AppArmor possible but operator-pull | operator runs `dnf install apparmor-utils` + boot with `lsm=apparmor` kernel parameter |

If the running kernel doesn't expose `/sys/kernel/security/
apparmor`, apply.sh refuses with a clear error.

## Mutex with SELinux

The Linux kernel can run multiple LSMs simultaneously via the
`lsm=` kernel parameter, but in practice operators pick one MAC
LSM per host. apparmor-baseline assumes AppArmor; a future
`selinux-baseline` module would handle SELinux. The two modules
will declare `conflicts = ["selinux-baseline"]` once both ship.

## Operator workflow

```bash
# Check live AppArmor state
sudo aa-status

# Inspect denied events in the journal (complain mode → DENIED
# entries appear without blocking)
sudo journalctl -k --grep "apparmor=.DENIED."

# Tune a specific profile (operator-pull complain-mode iteration)
sudo aa-genprof /path/to/binary    # interactive trace+approve

# Switch a specific profile to enforce manually
sudo aa-enforce /etc/apparmor.d/usr.bin.firefox

# After complain-mode baseline (1-2 weeks), flip selfdef to enforce
# profile in /etc/selfdef/modules/apparmor-baseline.toml
sudo selfdefctl modules apply apparmor-baseline
```

## Caveats

- **Many distro-shipped profiles are minimal**. The
  apparmor-profiles + apparmor-profiles-extra packages add a
  lot. Operator's first task is `aa-status` to see what's
  loaded.
- **`/usr/bin/man` profile is intentionally restrictive** —
  catches "man piped to shell" persistence exploits but can
  break operator workflow if they extensively pipe man output.
- **First enforce-mode boot may surface false-positive denials**
  the complain-mode baseline missed — operator must be ready to
  flip back to complain via `aa-complain <profile>` from a
  recovery session.
