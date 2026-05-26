# wireless-disable

Disables Wi-Fi on wired-only servers — rfkill-blocks the
WLAN radio and (in `mask` profile) modprobe-blacklists the
`cfg80211`/`mac80211` stack + common Wi-Fi drivers. Removes
the WoWLAN / rogue-AP / Wi-Fi-firmware-CVE attack surface
on hosts that have no business being on wireless. Completes
the RF-surface-reduction set with `bluetooth-disable` +
`wol-disable`.

## Why this matters

A server or IPS host with an enabled-but-unused Wi-Fi NIC
carries surface it never needs:
- **Wi-Fi firmware/driver CVEs** — iwlwifi, ath, brcmfmac
  have had remote-triggerable parsing bugs (a malicious
  beacon/probe-response in RF range exploits the driver).
- **WoWLAN (Wake-on-Wireless-LAN)** — the wireless parallel
  of WoL; a magic packet over the air wakes the host
  (`wol-disable` handles the wired side; this handles
  wireless).
- **Rogue-AP auto-association** — a misconfigured supplicant
  associating to an attacker AP.
- **Covert exfil channel** — an attacker bringing up the
  unused Wi-Fi as a second, unmonitored network path.

If the host is wired-only, disabling Wi-Fi closes all of
this.

## Profiles

| Profile | Effect |
|---|---|
| `rfkill` (default) | `rfkill block wifi` — radio off, reversible live without reboot. No module changes. |
| `mask` | rfkill + modprobe.d blacklist `cfg80211`/`mac80211` + common drivers (iwlwifi, ath*, rtw*, brcmfmac, mt76) with `install … /bin/true`. Survives reboot; strongest. |

## Anti-lockout guard

apply.sh checks for a wired NIC with carrier BEFORE
disabling. If none is found (the host might be reachable
ONLY over Wi-Fi), it logs a WARN — disabling could cut
remote access. It proceeds (assuming console or pending
wired access) but flags it for operator verification. Run
this from console, or confirm wired connectivity first.

## MITRE coverage

- **T1011** Exfiltration Over Other Network Medium — an
  unused Wi-Fi NIC is a covert exfil path; disabling it
  closes the medium.
- **T1190** Exploit Public-Facing Application — Wi-Fi
  driver/firmware CVEs are RF-range-reachable.
- **T1200** Hardware Additions — a plugged-in USB Wi-Fi
  dongle is neutralized (mask blacklists the common USB
  Wi-Fi drivers too).
- **T1542** Pre-OS Boot — WoWLAN wake parallels the WoL
  pre-boot attack.

## Operator workflow

```bash
# Verify Wi-Fi is off
rfkill list wifi
ip link | grep -iE 'wl|wlan'        # interfaces should be DOWN/absent
lsmod | grep -E 'cfg80211|mac80211' # (mask) empty after reboot

# Re-enable for a one-off (rfkill profile)
sudo rfkill unblock wifi

# Switch to mask (survives reboot) on a confirmed wired host
sudo sed -i 's/^profile.*/profile = "mask"/' \
    /etc/selfdef/modules/wireless-disable.toml
sudo selfdefctl modules apply wireless-disable
```

## Caveats

- **Wireless-only hosts**: do NOT apply on a laptop / host
  whose only network is Wi-Fi — you'll cut yourself off.
  The anti-lockout WARN flags this; heed it.
- **mask needs a reboot** to fully unload an already-loaded
  cfg80211 (or `rmmod` the stack, which has many deps).
  rfkill is immediate.
- **WWAN/cellular (ww*) is separate** — this module targets
  802.11 Wi-Fi; a `wwan-disable` parallel would handle
  cellular modems.
- **Some BMCs/iDRACs expose Wi-Fi** independently of the OS
  — this module governs the OS stack, not the BMC radio.

## Coexistence

- **bluetooth-disable + wol-disable**: the RF/wake-surface
  family — Bluetooth radio, wired Wake-on-LAN, and now
  Wi-Fi. Apply all three on wired-only servers for full
  RF + wake surface reduction.
- **rare-network-protocols-disable + rare-filesystems-
  disable**: same modprobe-blacklist pattern; orthogonal
  scopes.
- **nftables-baseline / firewalld-baseline**: the firewall
  governs IP traffic on active interfaces; this removes an
  entire interface class from existence.
- **wol-disable**: explicitly complementary — wol-disable
  is the wired-wake defense, this is the wireless-wake +
  wireless-surface defense.
