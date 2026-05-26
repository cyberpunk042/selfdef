#!/usr/bin/env bash
# selfdef pci-device-watchdog — boot + daily delta of the
# PCI/PCIe device inventory vs a learned baseline.
#
# On a host whose hardware is static (a server, a fixed
# workstation), the PCI device set never changes between
# boots. A NEW device is:
#   - an evil-maid hardware implant (malicious PCIe card
#     slotted while the operator was away);
#   - a hot-plugged Thunderbolt/USB4 device doing a DMA
#     attack (Thunderbolt tunnels PCIe);
#   - an unauthorized GPU/NIC/storage card or a VM
#     passthrough device added without change control.
#
# We read /sys/bus/pci/devices (no pciutils dependency) and
# record vendor:device class per slot. A removed device is
# also flagged (hardware pulled — possible tamper or theft).
#
# Severity:
#   ok    → no delta
#   warn  → a device REMOVED (hardware pulled)
#   alert → a device ADDED (hardware implant / DMA device)

set -u

PROFILE="${SELFDEF_PCIDEV_PROFILE:-report}"
BASELINE="${SELFDEF_PCIDEV_BASELINE:-/var/lib/selfdef/pci-device-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

if [[ -d /sys/bus/pci/devices ]]; then
    for d in /sys/bus/pci/devices/*; do
        [[ -e "$d" ]] || continue
        slot=$(basename "$d")
        vendor=$(cat "$d/vendor" 2>/dev/null || echo "?")
        device=$(cat "$d/device" 2>/dev/null || echo "?")
        class=$(cat "$d/class" 2>/dev/null || echo "?")
        printf '%s\t%s:%s\t%s\n' "$slot" "${vendor#0x}" "${device#0x}" "${class#0x}"
    done | sort -u > "$current"
fi

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-pci-device -- "$(printf '{"tag":"selfdef-pci-device","severity":"ok","event":"baseline_initial","profile":"%s","devices":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="pci_inventory_intact"
if (( n_added > 0 )); then
    severity="alert"; event="pci_device_added"
elif (( n_removed > 0 )); then
    severity="warn"; event="pci_device_removed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1"("$2")"}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1"("$2")"}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-pci-device","severity":"%s","event":"%s","profile":"%s","devices":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$cur_count" "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-pci-device -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r s vd c; do [[ -n "$s" ]] && logger -t selfdef-pci-device-detail -- "ADDED slot=${s} id=${vd} class=${c}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r s vd c; do [[ -n "$s" ]] && logger -t selfdef-pci-device-detail -- "REMOVED slot=${s} id=${vd} class=${c}"; done

# Refresh baseline so a confirmed-legit hardware change is trusted.
cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 || n_removed > 0 )); then
    exit 1
fi
exit 0
