# wwan-disable

Disables cellular / WWAN modems on hosts that don't use
mobile broadband — rfkill-blocks the WWAN radio, masks
`ModemManager`, and (in `mask` profile) modprobe-
blacklists the USB-modem driver stack. Removes an
out-of-band, often-unmonitored network path plus the
modem-firmware CVE surface. Completes the RF-surface
family with `wireless-disable` + `bluetooth-disable` +
`wol-disable`.

## Why this matters

A cellular modem (built into many laptops, present on some
servers via mini-PCIe/M.2 or a USB dongle) is a SECOND
network interface that:
- **Bypasses the wired network's monitoring + firewall** —
  an attacker who brings up the modem has an out-of-band
  path that `nftables-baseline` (which governs the wired
  interfaces) + the SOC's network taps never see. Ideal
  covert C2 / exfil channel.
- **Carries modem-firmware + driver CVEs** — the cellular
  baseband + the `qmi_wwan`/`cdc_mbim`/`option` drivers
  parse attacker-influenceable data from the carrier/RF.
- **Auto-connects** via ModemManager + a saved APN,
  potentially before the operator's security stack is up.

On a host that should only ever talk over its wired NIC,
the modem is pure liability — disable it.

## Profiles

| Profile | Effect |
|---|---|
| `rfkill` (default) | `rfkill block wwan` + stop/disable/mask ModemManager. Reversible live. |
| `mask` | rfkill + ModemManager mask + modprobe.d blacklist the USB-WWAN driver stack (cdc_mbim, qmi_wwan, cdc_ncm, cdc_wdm, option, qcserial, usb_wwan, mhi*) with `install … /bin/true`. Survives reboot. |

## Anti-lockout guard

apply.sh checks for a non-WWAN NIC with carrier before
disabling. If none is found (the host might be reachable
ONLY over cellular — e.g. a remote IoT gateway), it logs a
WARN and proceeds (assuming console or pending wired
access), flagging it for operator verification.

## MITRE coverage

- **T1011** Exfiltration Over Other Network Medium —
  PRIMARY; the modem is the canonical out-of-band exfil
  medium that bypasses the monitored network.
- **T1090** Proxy / out-of-band C2 — a covert cellular
  channel.
- **T1190** Exploit Public-Facing Application — modem
  driver/baseband CVEs reachable from the carrier/RF side.
- **T1200** Hardware Additions — a plugged-in USB cellular
  dongle is neutralized (mask blacklists usb_wwan/option).

## Operator workflow

```bash
# Verify the modem is off
rfkill list wwan
systemctl status ModemManager 2>/dev/null | grep -E 'Loaded:|Active:'
mmcli -L 2>/dev/null || echo "no modems (good)"
ip link | grep -iE 'ww|wwan'

# Re-enable for a one-off (rfkill profile)
sudo systemctl unmask ModemManager
sudo rfkill unblock wwan
sudo systemctl start ModemManager

# Switch to mask (survives reboot) on a confirmed wired host
sudo sed -i 's/^profile.*/profile = "mask"/' \
    /etc/selfdef/modules/wwan-disable.toml
sudo selfdefctl modules apply wwan-disable
```

## Caveats

- **Cellular-only hosts** (remote gateways, failover-LTE
  appliances): do NOT apply — you'll cut yourself off. The
  anti-lockout WARN flags this.
- **mask needs a reboot** to fully unload an already-loaded
  modem driver; rfkill + ModemManager mask are immediate.
- **Failover designs** that use cellular as a backup WAN
  intentionally keep the modem — skip this module there,
  or use rfkill profile + an operator-controlled unblock
  in the failover script.
- **Wi-Fi is separate** — `wireless-disable` handles 802.11;
  this handles cellular/WWAN. Apply both on wired-only
  hosts.

## Coexistence

- **wireless-disable + bluetooth-disable + wol-disable**:
  the RF/wake-surface family — Wi-Fi, Bluetooth, wired
  Wake-on-LAN, and now cellular. Apply all on wired-only
  servers for full RF + out-of-band surface reduction.
- **nftables-baseline / firewalld-baseline**: the firewall
  governs the wired interfaces; this removes the cellular
  interface that would otherwise bypass it entirely.
- **listening-ports-watchdog**: complementary — if a modem
  IS up, that catches a service bound to it; this removes
  the interface so there's nothing to bind.
- **rare-network-protocols-disable**: same modprobe-
  blacklist pattern; orthogonal scope.
