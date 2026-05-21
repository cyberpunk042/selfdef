# secure-boot-status

Probes UEFI Secure Boot state at boot + every 6 hours. Emits a
structured JSON event tagged `selfdef-secure-boot` to the
journal. This module does NOT enable or disable Secure Boot
(operator-pull firmware setting only); it surfaces the state
so the operator's correlator + notifier flag the host as a
non-SB or setup-mode boot.

## Why this matters

Secure Boot verifies the chain-of-trust from UEFI firmware →
shim → bootloader → kernel. With SB DISABLED, an attacker who
gains pre-OS code execution (BIOS firmware exploit, USB rescue
boot, malicious initrd) can chain a bootkit that survives
disk wipes. T1542.003 Pre-OS Boot: Bootkit.

A defender can't easily prevent SB from being toggled (it's a
physical-access firmware setting); but the defender CAN ensure
SB-state changes are LOUDLY VISIBLE in the event stream so:
- Unattended host that suddenly boots with SB disabled → attacker
  had physical access in the window
- Setup-mode reboot → operator-pull enrollment ceremony in
  progress, OR attacker bypassing SB by entering setup-mode

## State enums

| State | Source | Meaning |
|---|---|---|
| `enabled` | SecureBoot-<GUID>=1 | SB active; verifying signatures |
| `disabled` | SecureBoot-<GUID>=0 | SB toggled off (physical-access or firmware update) |
| `setup-mode` | SetupMode-<GUID>=1 | PK key enrollment mode active |
| `unavailable` | /sys/firmware/efi missing | Legacy BIOS boot (no UEFI exists) |
| `unknown` | efivar present but unexpected byte | Probe failed; firmware quirk |

## Profiles

| Profile | Behavior on SB disabled |
|---|---|
| `monitor` (default) | Emit event with severity=warn; service exits 0 (no unit failure) |
| `require` | Same event + service exits 1 → unit failed → operator-alertable via the standard journald collector + notifier path |

## Event severity ladder

| Severity | State |
|---|---|
| `ok` | enabled |
| `warn` | disabled |
| `alert` | setup-mode (unusual; operator-noticed) |
| `info` | unavailable (legacy BIOS — not an attack signal) |

## Probe sources

The wrapper script tries three sources in order:

1. **Raw efivar** — reads `/sys/firmware/efi/efivars/
   SecureBoot-<GUID>` via `od -tu1 -N5` to extract byte 5
   (the SecureBoot value). Most authoritative; no helper
   dependencies.
2. **mokutil --sb-state** — Debian/Ubuntu helper; parses
   "SecureBoot enabled" or "SecureBoot disabled" output.
3. **bootctl status** — systemd-bootd helper; parses
   "Secure Boot: enabled/disabled" output.

If all three fail, state reports `unknown` + severity=warn.

## Timer schedule

- `OnBootSec=60s` — first probe 60s after boot.
- `OnUnitActiveSec=6h` — re-probe every 6 hours.
- `RandomizedDelaySec=10m` — jitter so a fleet doesn't synchronize.
- `Persistent=true` — catch up missed probes after suspend/
  hibernate.

## MITRE coverage

- **T1542.003** Pre-OS Boot: Bootkit — defender-side
  visibility; SB-disabled events highlight a successful or
  attempted bootkit attack vector enablement.
- **T1601** Modify System Image — pre-OS firmware image
  modification (BIOS flashing); often requires SB-disabled to
  persist; this probe surfaces the disabled state.

## Operator workflow

```bash
# Inspect current state
sudo journalctl -t selfdef-secure-boot -n 1

# Force a probe now
sudo systemctl start selfdef-secure-boot-status.service
sudo journalctl -t selfdef-secure-boot -n 1

# Verify timer is firing
systemctl list-timers selfdef-secure-boot-status.timer

# Check live state directly via mokutil
sudo mokutil --sb-state

# Check via bootctl (systemd-boot hosts)
sudo bootctl status | grep -i secure
```

## Caveats

- **Operator-controlled firmware setting**: SB cannot be enabled
  from Linux userspace (requires reboot into firmware settings
  + operator approval). This module is OBSERVATIONAL only.
- **dual-boot Windows + Linux**: Windows requires SB to be
  enabled for some Defender features; operator on dual-boot
  typically wants SB enabled.
- **Custom-kernel hosts**: operator-built kernels need to be
  signed with a key enrolled in shim's MOK (Machine Owner
  Key) database OR SB must be disabled. require profile would
  flag these — operator on custom-kernel hosts uses monitor.
- **Hardware lacking UEFI** (older servers, embedded): state
  reports `unavailable` + severity=info. Neither monitor nor
  require flags this as a failure.

## Coexistence

- **kernel-lockdown** strict: kernel.modules_disabled=1
  defends the runtime-module-load path. Secure Boot defends
  the boot-image-trust path. Both together: an attacker who
  can't load runtime modules ALSO can't replace the
  bootloader/kernel/initrd.
- **aide-bridge**: AIDE diff captures /boot changes. SB +
  aide-bridge: SB signs the chain at boot; aide-bridge
  flags post-boot modifications.
