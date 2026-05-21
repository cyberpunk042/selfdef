# wol-disable

Disables Wake-on-LAN on every wired NIC at boot AND after
resume from suspend/hibernate. Blocks an attacker on the same
LAN from waking the host via WoL magic packet.

## Why this matters

Wake-on-LAN works at the NIC firmware layer — when WoL is
enabled (default on most desktop NICs), the NIC's PHY+MAC chips
remain partially powered when the host is in S3/S4/S5 sleep
states. A "magic packet" (6×0xFF + 16×MAC-address) received on
the listening NIC triggers the host to boot.

Attack patterns:
- **T1542 Pre-OS Boot**: attacker on the LAN wakes the host
  into pre-boot UEFI environment + chains a pre-OS exploit
  (BIOS firmware exploit, Secure Boot bypass).
- **Operator-tracking**: attacker correlates power-up events
  with their WoL probes → builds operator-presence map.
- **Bypassing operator-shutdown policy**: operator powers off
  for the weekend; attacker wakes the host to perform attacks
  during the unsupervised window.

The defense is straightforward: disable WoL. Most operators
don't actually use WoL (they keep the host on, suspend instead,
or accept the power-on time of a cold start).

## Profiles

| Profile | Effect |
|---|---|
| `enforce` (default) | At boot + resume, ethtool -s <iface> wol d on every wired NIC |
| `audit` | Service installs but ONLY REPORTS current WoL state per NIC. No changes. |

audit mode is for the operator who suspects WoL is in use by an
operator-tool but isn't sure WHICH NIC.

## NIC selection

Walks `/sys/class/net/*` and selects wired NICs ONLY (skip
loopback, wireless, bridges, docker/veth/vnet/tun/tap/dummy).
Wireless WoL (WoWLAN) is a separate mechanism not affected.

## Service trigger

The service unit `WantedBy=multi-user.target sleep.target` so
it fires at:
1. Boot (multi-user.target) — disables WoL after the kernel
   loads the NIC drivers.
2. Resume from suspend/hibernate (sleep.target) — re-disables
   WoL because the kernel resets the setting on resume.

## MITRE coverage

- **T1542** Pre-OS Boot — primary; blocks LAN-side
  power-on-to-vulnerable-boot-state.
- **T1078** Valid Accounts — narrows the operator-presence
  inference surface (attacker can't trigger power-up to test
  whether operator is at the host).
- **T1496** Resource Hijacking — defender side; prevents
  attacker-triggered wake events that would consume operator's
  power budget.

## Operator workflow

```bash
# Check current WoL state across all NICs
for iface in /sys/class/net/*; do
    i=$(basename "$iface")
    case "$i" in lo|br*|veth*|docker*|tun*|tap*) continue ;; esac
    [[ -d "$iface/wireless" ]] && continue
    state=$(ethtool "$i" 2>/dev/null | awk -F': ' '/Wake-on/ {print $2; exit}')
    echo "$i: wol=$state"
done

# Verify service is running and re-applies on resume
sudo systemctl status selfdef-wol-disable

# Manually test re-application
sudo systemctl restart selfdef-wol-disable

# If operator actually NEEDS WoL on a specific NIC:
sudo systemctl disable selfdef-wol-disable    # OR
# Edit /etc/selfdef/modules/wol-disable.toml to profile = "audit"
sudo ethtool -s eth0 wol g   # operator manually re-enables on eth0
```

## Caveats

- **Some operator workflows depend on WoL** (smart-home wake
  via OpenWakeWord trigger, scheduled-task wake via cron-
  scheduled magic-packet sender). Operator on these workflows
  uses audit profile + carefully omits the relevant NIC, OR
  doesn't install this module at all.
- **Cloud VMs** + **containers** typically don't support WoL
  (NICs report `Wake-on: pumbg` but ignore the SET). Service
  logs "unsupported" + moves on.
- **WoWLAN (Wireless Wake-on-LAN)** is a separate mechanism
  enabled via `iw phy <phy> wowlan ...`. This module doesn't
  touch wireless. A future `wowlan-disable` module is the
  parallel for wireless NICs.
- **Bus-power-only NICs** (USB-Ethernet adapters) may not
  retain WoL state across reboots; the service re-applies on
  every boot anyway.

## Coexistence

- **kernel-lockdown** strict: doesn't touch NIC firmware
  settings.
- **fail2ban-bridge**: defends against network-LIVE attacks.
  wol-disable defends against network-SLEEP attacks (when the
  host is powered down between operator sessions).
