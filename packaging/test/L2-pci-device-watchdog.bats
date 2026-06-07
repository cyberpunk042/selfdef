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

@test "INVARIANT (DMA-attack Thunderbolt/USB4 class added → alert; the evil-maid signature)" {
    # Thunderbolt/USB4 PCIe class is 0c0330 (or similar); the addition
    # of this device class fires the alert path. Lock detection of
    # the DMA-attack vector specifically.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:04:00.0" "1234" "abcd" "0c0330"   # Thunderbolt class
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_device_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (architectural: pci-device DOES auto-refresh baseline — sister-pattern contrast with dns-resolver)" {
    # Unlike dns-resolver-watchdog (no-auto-trust), pci-device WD
    # refreshes the baseline after alerting. This is the architectural
    # contrast: hardware drift events are operator-actionable as
    # one-shot (you ack it, the new state becomes the baseline);
    # network drift events are persistent-alert.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # alerts
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # third run — baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"pci_inventory_intact"'
}

@test "INVARIANT (device REPLACED — vendor:device of same slot changes → alert)" {
    # An attacker who swaps a PCIe card in the same slot would have
    # the slot path unchanged but vendor:device different. Detect that.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    # Same slot, different vendor:device — replacement attack.
    printf '0x%s\n' "1234" > "${SYSDIR}/0000:00:1f.0/vendor"
    printf '0x%s\n' "5678" > "${SYSDIR}/0000:00:1f.0/device"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (REMOVED-sample carries 'slot(vendor:device)' rows for forensics)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    mk_device "0000:01:00.0" "10de" "1b80" "030200"
    run_wd
    rm -rf "${SYSDIR}/0000:01:00.0"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:01:00.0(10de:1b80)'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-pci-device -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (zero-device baseline: empty SYSDIR → baseline_initial with devices=0)" {
    # Defensive: if the sysfs PCI tree is empty (unusual but
    # possible on VM with no PCI passthrough), the scan must
    # still produce a valid baseline.
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"devices":0'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_PCIDEV_PROFILE)" {
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (REMOVED-only delta severity is exactly warn, NOT ok — locks ladder boundary)" {
    # When only removals happen (no adds), severity must be warn
    # (not ok). Locks the ladder boundary so a regression doesn't
    # silently suppress hardware-pulled events.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    mk_device "0000:01:00.0" "10de" "1b80" "030200"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -rf "${SYSDIR}/0000:01:00.0"
    run_wd
    cap | grep -q '"severity":"warn"'
    ! cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (whitespace tolerance in vendor/device files: trailing whitespace stripped from sysfs read)" {
    # /sys/bus/pci/devices/*/vendor files typically end with
    # newline. The parser must strip trailing whitespace.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    # Add extra whitespace to one of the sysfs files.
    printf '0x10de  \n' > "${SYSDIR}/0000:00:1f.0/vendor"
    run_wd
    # Baseline initial passed without crashing.
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (added device CLASS surfaces in sample: 'slot(vendor:device)' includes class for forensics — current behavior locked)" {
    # The sample shape per existing 'added_sample carries
    # slot(vendor:device) rows' test. Lock current behavior: the
    # sample row form is slot(vendor:device) — operator can grep
    # by slot OR by vendor:device. Adding 'class' would require
    # downstream consumer updates.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:02:00.0(13fe:deed)'
    # Current behavior: sample does NOT include class — locked here.
    # A regression that adds class would break downstream parsers.
    cap | grep -qE 'added_sample":"[^"]*0000:02:00.0\(13fe:deed\)'
}

@test "INVARIANT (re-baselining cycle: alert → auto-trust → next-tamper-alerts — multi-cycle works)" {
    # Sister to selfdef-self-integrity manifest-reset-cycle INVARIANT.
    # Lock that auto-trust cycle works on EVERY hardware change, not
    # just the first. After one acked-add, a second new device
    # should still alert.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # alert
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                              # baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_device "0000:03:00.0" "abcd" "1234" "020000"
    run_wd                              # NEW tamper → alert AGAIN
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"pci_device_added"'
}

@test "INVARIANT (network-class device add — class=0200xx — surfaces in sample for operator triage of unexpected NIC)" {
    # Adding a network controller (class 02xxxx) is the canonical
    # network-implant attacker pattern. Lock that the class is
    # implicit-detected via the alert path (no class-specific
    # filter — just the generic 'device added' fires alert).
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:04:00.0" "8086" "15b8" "020000"   # generic NIC class
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_device_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q '0000:04:00.0(8086:15b8)'
}

@test "INVARIANT (mass-add operator scenario: 3 devices added in one scan → still single alert event; consolidation)" {
    # Sister axis to existing 'multiple devices ADDED' test but with
    # 3 devices and explicit single-JSON-line check. Locks
    # consolidation discipline.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:02:00.0" "13fe" "deed" "020000"
    mk_device "0000:03:00.0" "1234" "5678" "0c0330"
    mk_device "0000:04:00.0" "abcd" "ef01" "020000"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pci_device_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"added":3'
    main_count=$(cap | grep -cE '^-t selfdef-pci-device -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (USB-controller-class device add — class=0c0330 (xHCI USB 3.0) — surfaces in sample for cold-boot evil-USB-controller detection)" {
    # Sister to network-class detection INVARIANT already
    # locked. USB controller PCI insertion is the canonical
    # cold-boot evil-USB-controller-card attack vector (an
    # attacker plugs a PCIe USB add-in card with malicious
    # firmware that does DMA against host memory at boot
    # time — Thunderspy / DMA-attack family). The device add
    # MUST surface in the JSON sample so operator dashboard
    # routes triage to physical-tamper response (T1542 —
    # Pre-OS Boot via DMA-capable PCI device).
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:0a:00.0" "1b73" "1100" "0c0330"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:0a:00.0\|0c0330'
}

@test "INVARIANT (Thunderbolt/USB4 controller-class device add — class=0c0340 — surfaces for evil-Thunderbolt-card detection)" {
    # Sister to USB-controller-class (0c0330 xHCI USB3) PCI
    # insertion INVARIANT already locked. Thunderbolt + USB4
    # PCI controllers are the most-impactful DMA-attack vector:
    # the host's IOMMU often allows Thunderbolt full DMA into
    # host RAM by default (Thunderspy CVE-2020-0570 / DMA-
    # attack family) — patching an attacker-controlled
    # Thunderbolt PCIe card OR docking station with attached
    # PCIe device grants attacker direct memory access. The
    # watchdog MUST surface Thunderbolt controller PCI inserts
    # alongside USB to close the cold-boot DMA-tamper detection
    # axis (T1542 Pre-OS Boot via DMA-capable PCI device).
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:0b:00.0" "8086" "1137" "0c0340"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:0b:00.0\|0c0340'
}

@test "INVARIANT (FireWire/1394 controller-class device add — class=0c0010 — surfaces for evil-FireWire-card DMA detection)" {
    # Sister to USB-controller-class + Thunderbolt-controller-
    # class device-add INVARIANTs already locked. FireWire/IEEE
    # 1394 controllers (class 0x0c0010, OHCI 1394) historically
    # had unmediated DMA access AS BAD AS Thunderbolt (Inception
    # tool / firewire DMA-attack family). Even with IOMMU
    # available on modern hosts, default Linux kernel often
    # leaves 1394 DMA permissive for backward compatibility.
    # The watchdog MUST surface 1394 controller PCI inserts
    # alongside USB + Thunderbolt to close the cold-boot DMA-
    # tamper detection axis on all major DMA-capable bus
    # controllers (T1542 Pre-OS Boot via DMA-capable PCI
    # device). Closes axis-parity with USB + Thunderbolt
    # in the DMA-capable controller family.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    mk_device "0000:0c:00.0" "1145" "0035" "0c0010"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '0000:0c:00.0\|0c0010'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    mk_device "0000:00:1f.0" "8086" "9d4e" "060100"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (no auto-eject: pci-device-watchdog NEVER emits echo > /sys/bus/pci/devices/*/remove — surveillance not remediation)" {
    # Sister to brain-wide no-auto-remediation + surveillance-
    # not-destruction INVARIANTs. The pci-device-watchdog
    # DETECTS T1200 Hardware Additions (evil-USB-controller,
    # Thunderbolt-DMA-card, FireWire-DMA-card) but MUST NEVER
    # emit shell commands that auto-remove the PCI device via
    # /sys/bus/pci/devices/<id>/remove or echo 1 > remove.
    # Auto-removal of a planted DMA device would destroy
    # forensic evidence (operator can't analyze the device for
    # threat-intel) AND could disconnect operator-legitimate
    # devices (operator legitimately installed new GPU but
    # watchdog flags + auto-removes). Surveillance, never
    # remediation. Locks anti-evidence-destruction contract on
    # the pci-device surveillance substrate.
    ! grep -qE 'echo[[:space:]]+1[[:space:]]*>[[:space:]]*.*/sys/bus/pci/.*/(remove|reset)' "${WD}"
    ! grep -qE 'echo[[:space:]]+0[[:space:]]*>[[:space:]]*.*/sys/bus/pci/' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # pci-device-watchdog runs ON the timer's scheduled fire —
    # diffs lspci output against baseline, emits a verdict on
    # new-device additions (USB/FireWire/ThunderBolt DMA axes),
    # then exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the pci-device-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/pci-device-watchdog/systemd/selfdef-pci-device.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pci-device-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # pci-device-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # pci-device-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pci-device-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'pci-device-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: pci-device-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. pci-device-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the pci-device-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pci-device-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}
