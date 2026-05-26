# pci-device-watchdog

Boot + daily delta of the PCI/PCIe device inventory
(`/sys/bus/pci/devices`) against a learned baseline. On a
host whose hardware is static, a NEW PCI device is an
evil-maid hardware implant, a hot-plugged malicious PCIe/
Thunderbolt card (DMA attack), or an unauthorized device.
MITRE **T1200 Hardware Additions**.

## Why this matters

The PCI device set on a server or fixed workstation is
constant across boots. A change means hardware changed —
and on a host nobody should be opening, that's an attack:

- **Evil-maid implant**: an attacker with brief physical
  access slots a malicious PCIe card (a rogue NIC for
  out-of-band exfil, a capture card, a DMA-capable FPGA).
  It appears as a new PCI device after the reboot it
  requires.
- **Thunderbolt/USB4 DMA attack**: Thunderbolt tunnels
  PCIe; a malicious TB device gets DMA to system memory
  (the "Thunderclap" class) → reads memory, plants
  implants. It appears as a hot-plugged PCI device.
- **Unauthorized passthrough / card swap**: a GPU, NIC, or
  storage controller added outside change control.

A device REMOVED is also flagged — hardware pulled
(possible tamper, theft, or a card removed to cover
tracks).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any PCI device added/removed → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `pci_inventory_intact` |
| A device REMOVED | `warn` | `pci_device_removed` |
| A device ADDED | `alert` | `pci_device_added` (implant / DMA device) |

## What's recorded

`slot  vendor:device  class` per PCI device, read directly
from `/sys/bus/pci/devices/*/{vendor,device,class}` — NO
`pciutils`/`lspci` dependency (works on minimal hosts).

## Cadence

`OnBootSec=7min` + `OnCalendar=*-*-* 06:45:00` — the boot
catch is primary (most PCIe is not hot-plug, so a slotted
implant appears after the reboot it needs); the daily scan
catches Thunderbolt/USB4 PCIe-tunnel hot-plug devices.

## MITRE coverage

- **T1200** Hardware Additions — PRIMARY; a new PCI device
  is the exact artifact of a hardware-addition attack.
- **T1190** Exploit Public-Facing Application — narrowly; a
  rogue NIC adds a network surface.
- **T1011** Exfiltration Over Other Network Medium — a
  rogue NIC/modem card is an out-of-band exfil path.
- **T1052** Exfiltration Over Physical Medium — a capture/
  storage card.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-pci-device -n 1 --no-pager

# Per-device detail (slot + vendor:device id + class)
journalctl -t selfdef-pci-device-detail --since "1 day ago"

# Identify a flagged device
lspci -nn -s <slot> 2>/dev/null     # if pciutils installed
cat /sys/bus/pci/devices/<slot>/{vendor,device,class}
# Look up the vendor:device id at https://pci-ids.ucw.cz/

# Re-baseline after a legit hardware change (operator added
# a card under change control)
sudo rm /var/lib/selfdef/pci-device-baseline.tsv
sudo systemctl start selfdef-pci-device.service
```

## Caveats

- **Hot-plug-capable hosts** (some servers with hot-plug
  PCIe bays, Thunderbolt docks) see legitimate add/remove
  churn → on those, re-baseline after each authorized
  change, or accept the warn-tier noise for the hot-plug
  slots.
- **VMs**: virtio/emulated devices are stable per VM config;
  a hypervisor hot-add of a passthrough device shows here —
  which is the point (unauthorized passthrough detection).
- **Boot-only for most implants** — a non-hot-plug PCIe
  implant only appears after reboot; pair with physical
  security + `bootloader-password-detect` +
  `secure-boot-status` for the pre-OS layer.
- **Defense-in-depth, not prevention** — to PREVENT DMA
  attacks, enable the IOMMU (`intel_iommu=on` /
  `amd_iommu=on`) + kernel `iommu.strict=1`; this module
  DETECTS the device regardless.

## Coexistence

- **usbguard + usb-storage-mass-disable**: complementary —
  those govern USB-class devices; this governs PCI/PCIe
  (including Thunderbolt-tunneled PCIe). Together they
  cover the two main hardware-addition buses.
- **kernel-cmdline-watchdog**: complementary — verify the
  IOMMU boot params (intel_iommu=on) that mitigate the DMA
  attack this detects haven't been removed.
- **secure-boot-status + bootloader-password-detect**:
  the pre-OS physical-access layer; this is the
  post-boot hardware-inventory layer.
- **listening-ports-watchdog**: a rogue NIC card often
  brings up a new interface + listener — that catches the
  software side, this the hardware side.
