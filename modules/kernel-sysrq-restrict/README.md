# kernel-sysrq-restrict

Controls `kernel.sysrq` — the kernel-level command
trigger reachable from any physical-or-serial-console
keyboard via the Magic SysRq key sequence
(Alt+SysRq+<letter>). Defaults to full-enable on some
distros, granting anyone at the console instant kernel-
level reboot, kill-all, sync, OOM-trigger primitives —
no userspace credentials required.

## Why this matters

Magic SysRq is the Linux kernel's "press this key to
talk directly to the kernel" facility. From the local
keyboard or serial console an attacker can:

| Key combo | Effect |
|---|---|
| `Alt+SysRq+B` | Immediate reboot (no shutdown; no fs sync) |
| `Alt+SysRq+O` | Immediate poweroff |
| `Alt+SysRq+E` | SIGTERM every process except init |
| `Alt+SysRq+I` | SIGKILL every process except init |
| `Alt+SysRq+F` | Trigger OOM killer (kills random heavy process) |
| `Alt+SysRq+T` | Dump every process's stack to dmesg |
| `Alt+SysRq+W` | Dump uninterruptible-state processes |
| `Alt+SysRq+S` | Sync filesystems |
| `Alt+SysRq+U` | Remount all filesystems read-only |
| `Alt+SysRq+C` | Trigger kernel panic + crashdump |

Every one of these is a DoS / data-availability attack
primitive that bypasses userspace auth entirely. The
attacker only needs:
- Physical access to keyboard, OR
- Serial console access (over IPMI / Out-of-Band / DC),
  OR
- Network-attached console with no auth (rare but
  exists).

## Profiles

| Profile | Value | Effect |
|---|---|---|
| `off` (default) | 0 | Magic SysRq disabled entirely |
| `safe-subset` | 132 | bitmask = 4 (log control) + 128 (reboot/poweroff). Operator at console can emergency-reboot a hung system; loses dump / kill / OOM primitives |
| `full` | 1 | All commands enabled — for development hosts where operator regularly uses sync / dump / OOM-trigger |

## kernel.sysrq bitmask reference

| Bit | Value | Command class |
|---|---|---|
| 0 | 1 | enable console log level control |
| 1 | 2 | enable keyboard control (SAK + raw) |
| 2 | 4 | enable console log + sysrq enable |
| 3 | 8 | enable debugging dumps (stack, memory) |
| 4 | 16 | enable sync command |
| 5 | 32 | enable remount-read-only |
| 6 | 64 | enable process signaling (kill-all) |
| 7 | 128 | allow reboot / poweroff |
| 8 | 256 | allow nicing all RT tasks |

## File

`/etc/sysctl.d/50-selfdef-sysrq.conf` rendered per-
profile with selfdef header marker. Loaded at boot via
`sysctl --system`; apply.sh also writes live.

## MITRE coverage

- **T1499** Endpoint Denial of Service — primary;
  Magic SysRq is the canonical physical-DoS primitive.
- **T1495** Firmware Corruption — narrowly related;
  kernel.sysrq+C (panic) on hosts with auto-reboot can
  trigger pre-boot firmware paths.
- **T1561.001** Disk Wipe: Disk Content Wipe —
  Alt+SysRq+I-then-B sequence prevents fs sync before
  reboot, potentially corrupting on-disk state.
- **T1200** Hardware Additions — narrowly; attacker
  with USB keyboard now has DoS primitive even on
  hosts without operator login.

## Operator workflow

```bash
# Inspect live value
sysctl kernel.sysrq
cat /proc/sys/kernel/sysrq

# Test (with off profile, should NOT trigger reboot)
echo "1" | sudo tee /proc/sysrq-trigger    # 1=show high-priority tasks; if off, EPERM

# Switch to safe-subset on a host the operator manages locally
sudo sed -i 's/^profile.*/profile = "safe-subset"/' \
    /etc/selfdef/modules/kernel-sysrq-restrict.toml
sudo selfdefctl modules apply kernel-sysrq-restrict

# Test from console: Alt+SysRq+B should still reboot;
# Alt+SysRq+T (dump) should be no-op
```

## Caveats

- **Operator emergency rescue**: with `off` profile,
  the operator can NOT emergency-reboot via SysRq on a
  hung system. They must power-cycle. Use
  `safe-subset` if operator-physical access for
  rescue is expected.
- **Crash debugging**: kernel devs use SysRq+T / SysRq+W
  to dump task state. Disabling those breaks crash-
  debug workflow. Development hosts may want `full`.
- **Some kernels are CONFIG_MAGIC_SYSRQ=n at build**
  — sysctl is absent; apply.sh logs unreadable; module
  becomes no-op.
- **/proc/sysrq-trigger is a separate write target**:
  even with kernel.sysrq=0, a root process can still
  write to /proc/sysrq-trigger. This module restricts
  the keyboard/serial trigger; in-kernel /proc trigger
  is governed by separate root-only permissions.

## Coexistence

- **kernel-yama-baseline + kernel-lockdown + sysctl-
  network-baseline + file-protections-baseline +
  unprivileged-userns-baseline**: orthogonal kernel-
  sysctl families. All ship separate drop-ins
  (different filenames); no conflict.
- **bootloader-password-detect**: complementary
  physical-access defense. bootloader-password
  defeats edit-at-boot; this module defeats kernel-
  level DoS post-boot.
- **wol-disable**: complementary — wol-disable
  defeats LAN-side wake attacks; this defeats
  console-side DoS attacks.
- **services-disable-printing + bluetooth-disable**:
  same orthogonal physical-surface reduction family.
