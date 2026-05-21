# bluetooth-disable

Stops + masks the Bluetooth service stack (bluez, obex,
bluealsa), rfkills the radio, and blacklists btusb + sibling
kernel modules on hosts that don't pair. Removes the entire
BlueZ / Bluetooth-controller attack surface.

## Why this matters

Bluetooth has a long string of remotely-exploitable CVEs:

- **BlueBorne (CVE-2017-1000251 family)**: in-range
  unauthenticated RCE on Linux BlueZ; chained via L2CAP /
  SDP / RFCOMM parsing flaws.
- **BlueDucky (CVE-2023-45866)**: keystroke-injection via
  HID profile spoofing — attacker pairs as an unauth HID
  keyboard, types arbitrary commands to a logged-in shell.
- **KNOB (CVE-2019-9506)**: encryption-key negotiation
  downgrade → eavesdrop on paired traffic.
- **BIAS (CVE-2020-10135)**: authentication bypass against
  previously-paired devices.
- Continued **BLE pairing CVEs** in 2024/2025 (BlueZ +
  controller firmware).

The attacker needs only RF range (~10m typical, much longer
with directional antennas). On a server or IPS host with no
Bluetooth peripherals, this entire stack is dead surface —
mask it and the attacks become impossible regardless of
which CVE drops next.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask bluetooth.service + obex.service + bluealsa.service; rfkill block radio; modprobe blacklist btusb + bluetooth + 4 controller-driver modules with `install … /bin/true` so modprobe load is defeated |
| `stop` | stop + disable only; rfkill block; module-load remains permitted (defense weaker; one-shot operator-pull re-enable easier) |

`mask` is the right default for servers + IPS hosts (no
operator-workflow break). `stop` is for operator
workstations where occasional Bluetooth use (file transfer,
audio device) is plausible.

## Units covered

| Unit | Purpose |
|---|---|
| `bluetooth.service` | bluetoothd daemon |
| `bluetooth.target` | systemd target umbrella |
| `obex.service` | OBEX file-transfer profile |
| `bluealsa.service` | ALSA-Bluetooth audio bridge |

apply.sh probes each via `systemctl list-unit-files` and
only acts on those that exist (no-op on hosts without
bluez).

## Kernel modules blacklisted (mask profile only)

| Module | Role |
|---|---|
| `btusb` | USB-attached Bluetooth controller driver |
| `btintel` | Intel-controller firmware-load helper |
| `btbcm` | Broadcom-controller firmware-load helper |
| `btmtk` | MediaTek-controller firmware-load helper |
| `btrtl` | Realtek-controller firmware-load helper |
| `bluetooth` | Linux Bluetooth core stack (L2CAP/SDP/RFCOMM) |

`/etc/modprobe.d/selfdef-bluetooth-blacklist.conf` uses BOTH
`blacklist <m>` (skip auto-load on coldplug) AND
`install <m> /bin/true` (defeats explicit `modprobe <m>`).
Header marker for uninstall ownership check.

## rfkill belt-and-suspenders

`rfkill block bluetooth` soft-blocks the radio at the
kernel layer. Combined with modprobe blacklist + service
mask, this is triple-defense:
1. Service can't start (mask).
2. Module can't load (blacklist + install /bin/true).
3. If somehow both #1 + #2 are bypassed, rfkill keeps the
   radio off until `rfkill unblock` runs.

## MITRE coverage

- **T1011** Exfiltration Over Other Network Medium — primary;
  Bluetooth is the canonical "other network medium" for
  short-range data exfil.
- **T1200** Hardware Additions — defender-side; an attacker
  pairing a rogue HID (BlueDucky) is the textbook hardware-
  addition case. Disabling the stack defeats the pairing.
- **T1557** Adversary-in-the-Middle — KNOB / BIAS-class
  attacks downgrade encryption to MITM a paired link;
  disabling pairing eliminates the vector.
- **T1543.002** Create or Modify System Process: systemd
  service — defender-side; bluetoothd has spawned
  unprivileged-attacker-controlled child processes in
  several CVEs.

## Operator workflow

```bash
# Verify the stack is silent
systemctl status bluetooth obex bluealsa 2>/dev/null | grep -E 'Loaded:|Active:'
rfkill list bluetooth
lsmod | grep -E 'btusb|bluetooth' || echo "no bt modules loaded"

# Inspect the blacklist file
cat /etc/modprobe.d/selfdef-bluetooth-blacklist.conf

# Verify port 0 binding is absent (HCI sockets are not IP;
# `hciconfig` would show no controller)
which hciconfig && hciconfig -a 2>&1 | head -5

# Re-enable for one-shot use (operator-pull):
sudo selfdefctl modules switch-profile bluetooth-disable stop  # OR uninstall
sudo systemctl unmask bluetooth bluetooth.target
sudo rfkill unblock bluetooth
sudo modprobe btusb   # may require removing the install /bin/true line
sudo systemctl start bluetooth
# After use, re-apply:
sudo selfdefctl modules apply bluetooth-disable
```

## Caveats

- **A reboot is the cleanest re-application boundary**. mask
  + blacklist take effect at the next module-load attempt
  (boot, hotplug). For an already-running btusb instance,
  `rmmod btusb` is needed (or wait for reboot).
- **Operator who actively uses Bluetooth audio / mice /
  keyboards**: do NOT install this module on those hosts.
  An attacker who can RF-attack the operator's headphones
  is a different threat model than an attacker who can
  pair to a server.
- **Wireless mice / keyboards on USB dongles** typically use
  proprietary 2.4 GHz, NOT Bluetooth. They are unaffected.
- **BLE-based smartcards / FIDO2 tokens** (some YubiKey
  variants) require Bluetooth. Operator using those needs
  this module disabled OR a hardware-USB-only token instead.
- **kdump-disable / kexec**: blacklisting modules in
  modprobe.d is unaffected by kdump path.

## Coexistence

- **usbguard**: orthogonal — handles USB-class devices.
  BlueDucky attacker pairing a fake-HID is over the
  Bluetooth radio, NOT a USB connection, so usbguard
  doesn't see it.
- **usb-storage-mass-disable**: orthogonal — different
  attack surface.
- **services-disable-printing**: same pattern (mask
  network-listening service stack on hosts that don't use
  it); the two modules can be applied together with no
  conflict.
- **wol-disable**: complementary — wol-disable handles
  power-on attacks via the wired-NIC; bluetooth-disable
  handles attacks via the Bluetooth controller.
