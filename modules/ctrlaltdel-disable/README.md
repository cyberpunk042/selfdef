# ctrlaltdel-disable

Masks `ctrl-alt-del.target` so a console-present attacker
cannot trigger an immediate system reboot via Ctrl+Alt+Del.
Pairs with `kernel-sysrq-restrict` to close the
physical-console DoS surface.

## Why this matters

On a default systemd host, pressing Ctrl+Alt+Del at the
console (physical keyboard, KVM, serial console, IPMI
remote console) triggers `ctrl-alt-del.target` → an
immediate clean reboot. systemd 248+ also implements a
"burst" action: 7 presses within 2 seconds forces an
IMMEDIATE reboot (no clean shutdown — like the kernel
reboot syscall).

For a host where an attacker has console reach but not
login credentials, this is a free denial-of-service
primitive:
- Attacker at the keyboard reboots the host at will.
- Reboot during a long-running operation corrupts state.
- Burst-reboot skips fs sync → potential data corruption.

The defense: make Ctrl+Alt+Del a no-op (mask the target)
or at minimum disable the dangerous burst immediate-reboot.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | `systemctl mask ctrl-alt-del.target` — Ctrl+Alt+Del does nothing |
| `burst-guard` | leave single-press reboot working but set `CtrlAltDelBurstAction=none` in a logind.conf.d drop-in (systemd 248+) — disables the 7-presses-emergency-reboot |

`mask` is the right default for servers + IPS hosts where
no one should reboot from the console. `burst-guard` is for
operator workstations where Ctrl+Alt+Del-reboot is an
expected operator convenience but the burst-emergency
path should still be closed.

## Files

| Path | Profile | Purpose |
|---|---|---|
| (systemd unit mask) | mask | symlinks ctrl-alt-del.target → /dev/null |
| `/etc/systemd/logind.conf.d/50-selfdef-cad.conf` | burst-guard | `CtrlAltDelBurstAction=none` |

Header marker on the logind drop-in for uninstall
ownership check.

## MITRE coverage

- **T1499** Endpoint Denial of Service — primary; console
  reboot is a physical-DoS primitive.
- **T1529** System Shutdown/Reboot — direct; this is the
  technique's console-keyboard variant.
- **T1561.001** Disk Wipe: Disk Content Wipe — narrowly;
  burst immediate-reboot skips fs sync, risking
  on-disk corruption.
- **T1200** Hardware Additions — narrowly; attacker
  plugging a USB keyboard gains the C-A-D primitive.

## Operator workflow

```bash
# Verify the target is masked (mask profile)
systemctl is-enabled ctrl-alt-del.target     # expect: masked

# Verify burst guard (burst-guard profile)
cat /etc/systemd/logind.conf.d/50-selfdef-cad.conf
loginctl show-session  # CtrlAltDel state varies by version

# Re-enable Ctrl+Alt+Del reboot (operator decision)
sudo systemctl unmask ctrl-alt-del.target

# Switch to burst-guard on a workstation
sudo sed -i 's/^profile.*/profile = "burst-guard"/' \
    /etc/selfdef/modules/ctrlaltdel-disable.toml
sudo selfdefctl modules apply ctrlaltdel-disable
```

## Caveats

- **Operator rescue**: with `mask`, the operator at the
  console can no longer Ctrl+Alt+Del-reboot a hung host.
  They must use the power button or remote management.
  Use `burst-guard` if console-reboot convenience matters.
- **Some KVM/IPML consoles map their own reboot key** —
  this module only governs the in-OS Ctrl+Alt+Del path,
  not the BMC's hardware reset line.
- **systemd < 248 lacks CtrlAltDelBurstAction** — the
  burst-guard profile's drop-in is ignored; use `mask`
  on older systemd.
- **Container hosts**: ctrl-alt-del.target is host-scope;
  containers have no console keyboard. Host applies it.

## Coexistence

- **kernel-sysrq-restrict**: complementary — both close
  physical-console DoS surfaces. sysrq governs the Magic
  SysRq key; this governs Ctrl+Alt+Del. Apply both for
  full console-DoS lockdown.
- **bootloader-password-detect**: complementary — that
  defends the boot-time GRUB-edit path; this defends the
  running-system console-reboot path.
- **wol-disable**: complementary — wol-disable defeats
  LAN-side wake; this defeats console-side reboot.
- **services-disable-printing + bluetooth-disable +
  nscd-disable**: same service-mask family; orthogonal
  scopes.
