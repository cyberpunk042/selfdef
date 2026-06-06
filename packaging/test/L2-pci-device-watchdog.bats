#!/usr/bin/env bats
# L2 functional suite for pci-device-watchdog.
#
# pci-device-watchdog tracks PCI/PCIe inventory drift. On a host
# whose hardware is static (server, fixed workstation), the PCI
# device set never changes between boots. Severity:
#   ok    → no delta (pci_inventory_intact)
#   warn  → device REMOVED — hardware pulled (theft / tamper)
#   alert → device ADDED — evil-maid PCIe implant OR DMA-attack
#           Thunderbolt/USB4 device OR unauthorized passthrough
#
# Uses SELFDEF_PCIDEV_SYSDIR env-var override (added 2026-06-06) to
# point at a fixture tree replicating /sys/bus/pci/devices/*/{vendor,
# device,class} layout.
#
# Run with: bats packaging/test/L2-pci-device-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pci-device-watchdog/systemd/pci-device-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/pci-device-baseline.tsv"
    SYSDIR="${TMP}/sys"
    mkdir -p "${SYSDIR}"
}

teardown() { rm -rf "${TMP}"; }

# mk_device <slot> <vendor> <device> <class>
mk_device() {
    local slot="$1" vendor="$2" device="$3" class="$4"
    mkdir -p "${SYSDIR}/${slot}"
    printf '0x%s\n' "${vendor}" > "${SYSDIR}/${slot}/vendor"
    printf '0x%s\n' "${device}" > "${SYSDIR}/${slot}/device"
    printf '0x%s\n' "${class}"  > "${SYSDIR}/${slot}/class"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_PCIDEV_PROFILE="${PROFILE:-report}" \
    SELFDEF_PCIDEV_BASELINE="${BASELINE}" \
    SELFDEF_PCIDEV_SYSDIR="${SYSDIR}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the PCI inventory + chmod 0600" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"     # Intel LPC bridge
    mk_device "0000:01:00.0" "10de" "1b80" "030200"     # NVIDIA GPU
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"devices":2'
    # Each line has 3 tab-separated fields (slot, vendor:device, class).
    awk -F'\t' 'NF==3{ok=1} END{exit ok?0:1}' "${BASELINE}"
}

@test "unchanged inventory on second run → ok / pci_inventory_intact" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_inventory_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "device ADDED → alert / pci_device_added (the implant signature)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd                          # baseline = {one device}
    mk_device "0000:02:00.0" "13fe" "deed" "020000"     # added: unknown NIC
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_device_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":1'
}

@test "multiple devices ADDED → alert (each implant fires the same path)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    mk_device "0000:03:00.0" "1234" "5678" "0c0330"     # Thunderbolt-style
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":2'
}

@test "device REMOVED → warn / pci_device_removed (hardware pulled)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    mk_device "0000:01:00.0" "10de" "1b80" "030200"
    run_wd                          # baseline = {2 devices}
    rm -rf "${SYSDIR}/0000:01:00.0" # GPU pulled
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_device_removed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"removed":1'
}

@test "ADDED takes precedence over REMOVED when both happen (implant signal wins)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    mk_device "0000:01:00.0" "10de" "1b80" "030200"
    run_wd                          # baseline = {1f.0, 01:00.0}
    rm -rf "${SYSDIR}/0000:01:00.0"
    mk_device "0000:02:00.0" "13fe" "deed" "020000"     # add a new one
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # added > 0 triggers alert / pci_device_added (not the warn-tier
    # removed branch). The implant signal is the more-critical one.
    cap | grep -q '"event":"pci_device_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":1'
    cap | grep -qE '"removed":1'
}

@test "the emitted JSON carries every promised schema field" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd                                 # baseline-initial
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    run_wd                                 # delta-shape JSON
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-pci-device"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"devices":[0-9]+'
    printf '%s' "${line}" | grep -qE '"added":[0-9]+'
    printf '%s' "${line}" | grep -qE '"removed":[0-9]+'
    printf '%s' "${line}" | grep -q '"added_sample":'
    printf '%s' "${line}" | grep -q '"removed_sample":'
}

@test "added_sample carries 'slot(vendor:device)' rows" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:02:00.0(13fe:deed)'
}

@test "enforce profile + device added → exit 1" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PCIDEV_PROFILE=enforce \
        SELFDEF_PCIDEV_BASELINE="${BASELINE}" \
        SELFDEF_PCIDEV_SYSDIR="${SYSDIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "enforce profile + unchanged → exit 0" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}
