# kdump-disable

Disables `kdump.service` (and sibling `kexec-tools.service` +
`kdump-tools.service`) so the kernel doesn't capture a full
vmcore image when it panics. The vmcore contains EVERY process's
RAM contents — passwords, TLS session keys, SSH host keys,
operator's shell history, signed-message buffers, the works.

## Why this matters

Default RHEL + Fedora install enables `kdump.service` which:
1. Reserves a chunk of RAM at boot (via `crashkernel=` kernel
   cmdline parameter; typically 128M-1G)
2. On panic, kexec's into a stripped-down kernel
3. That kernel writes /proc/vmcore (the panicked kernel's full
   memory) to `/var/crash/<timestamp>/vmcore`

The vmcore file:
- Contains every running process's memory at panic time
- Is readable by ANYONE in the `kdump` group (or root only,
  depending on distro)
- Is OFTEN forgotten in /var/crash for months after the panic
- Is the BIGGEST credential-leak surface short of `coredumpctl
  dump` for SUID processes

T1003 OS Credential Dumping has multiple paths; vmcore is one
of the highest-yield ones because the dump contains LIVE
in-memory secrets (not just on-disk).

## Profiles

| Profile | atd-style mask | Operator-restart |
|---|---|---|
| `mask` (default) | stopped + disabled + **masked** | Requires explicit `systemctl unmask` |
| `stop` | stopped + disabled (not masked) | `systemctl start kdump` (one command) |

## What this does NOT block

- **crashkernel= memory reservation**: even with kdump.service
  disabled, the kernel may still reserve RAM at boot if
  `crashkernel=` is in /proc/cmdline. To reclaim that RAM,
  operator edits `/etc/default/grub` to remove `crashkernel=`
  from `GRUB_CMDLINE_LINUX_DEFAULT` then runs
  `update-grub` + reboot. check.sh logs a NOTE about this.
- **Existing /var/crash/<timestamp>/vmcore files**: this
  module doesn't delete them. Operator runs:
  ```bash
  sudo rm -rf /var/crash/*/vmcore
  sudo find /var/crash -mindepth 2 -delete
  ```
- **systemd-coredump per-process dumps**: handled by the
  separate coredumpd-redirect module.

## MITRE coverage

- **T1003** OS Credential Dumping — high-yield path (vmcore
  contains live memory of every process at panic time).
- **T1552.001** Unsecured Credentials: Credentials In Files —
  forgotten /var/crash vmcore files often contain plaintext
  credentials from operator processes.
- **T1591** Gather Victim Org Information — the vmcore reveals
  internal hostnames, IPs, service topology to anyone who can
  read it.

## Operator workflow

```bash
# Verify kdump is disabled + masked
systemctl status kdump kexec-tools 2>&1 | head -20

# Verify crashkernel= isn't reserving RAM at boot
cat /proc/cmdline | tr ' ' '\n' | grep crashkernel
# If present: edit /etc/default/grub, remove crashkernel=N, then:
sudo update-grub && sudo reboot

# Cleanup stale vmcore artifacts
ls -la /var/crash/
sudo rm -rf /var/crash/*

# To temporarily re-enable for debugging a crash bug
sudo systemctl unmask kdump
sudo systemctl enable --now kdump
# (run repro, capture, re-disable)
sudo selfdefctl modules apply kdump-disable
```

## Caveats

- **Operator debugging kernel bugs WILL want kdump**. The whole
  point is post-panic forensics for the operator. Selfdef's
  default position: a workstation/IPS host does NOT trade
  credential-leak surface for kernel-debug-convenience.
  Operator running into reproducible panics enables kdump for
  the debug cycle then re-disables.
- **kdump is not the only path to vmcore**. Live kernel
  introspection (eBPF, /dev/mem with CAP_SYS_RAWIO) can read
  similar data. Combined with kernel-lockdown (which disables
  unprivileged BPF) + standard `mem` restrictions, this module
  closes the most-common path.
- **No effect on per-process coredumps**. Separate concern;
  handled by coredumpd-redirect.

## Coexistence

- **coredumpd-redirect**: per-process coredumps (when an
  unprivileged program crashes). vmcore is per-KERNEL
  (system-wide panic). The two cover different leak surfaces.
- **kernel-lockdown**: blocks unprivileged BPF + userfaultfd
  exploits that could read kernel memory at runtime. kdump-
  disable removes the easier post-panic dump path.
- **aide-bridge**: if vmcore files exist in /var/crash, AIDE
  flags them as "added" — operator sees the leak surface
  surface immediately.
