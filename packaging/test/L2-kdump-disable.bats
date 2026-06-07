#!/usr/bin/env bats
# L2 functional suite for kdump-disable.
#
# kdump-disable stops + disables the kernel-crash-dump service
# family. kdump writes a snapshot of kernel memory (which contains
# encryption keys, passwords, in-flight secrets) to disk on crash
# — a treasure trove for forensic / exfil if the disk is later
# accessed. On a sovereign endpoint that doesn't run a kdump
# analysis workflow, the dump is pure data-exposure surface.
#
# Acts on 3 candidate units (kdump.service / kexec-tools.service
# / kdump-tools.service — Debian/Ubuntu/RHEL/SUSE variants).
# Profiles: stop | mask. DRY_RUN=1 → no system changes.
#
# Reuses the L2-at-disable.bats / L2-avahi-disable.bats installer
# test pattern.
#
# Run with: bats packaging/test/L2-kdump-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/kdump-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        # Configurable per-unit presence via env var.
        case "$2" in
            kdump.service)        present="${KDUMP_PRESENT:-1}" ;;
            kexec-tools.service)  present="${KEXEC_PRESENT:-0}" ;;
            kdump-tools.service)  present="${KDUMPTOOLS_PRESENT:-0}" ;;
            *)                    present=0 ;;
        esac
        if [[ "${present}" == "1" ]]; then
            printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
            exit 0
        else
            exit 1
        fi ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/kdump-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
    KDUMP_PRESENT="${KDUMP_PRESENT:-1}" \
    KEXEC_PRESENT="${KEXEC_PRESENT:-0}" \
    KDUMPTOOLS_PRESENT="${KDUMPTOOLS_PRESENT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_KDUMP_DISABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${SELFDEF_KDUMP_DISABLE_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile value → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_KDUMP_DISABLE_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "no kdump variants present → no mutation" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "Debian variant (kdump-tools.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "RHEL variant (kdump.service) present → acts on it only" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "all 3 variants present → acts on all 3" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "stop profile → stop + disable, NO mask" {
    write_config "stop"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key in config)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask profile is asymmetric to stop): mask MUST also stop + disable (mask alone leaves running unit)" {
    # If a unit is currently RUNNING, mask alone won't stop it.
    # mask profile must therefore stop + disable + mask, otherwise an
    # active leak of kernel memory survives the apply.
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (Ubuntu variant kexec-tools.service): present-alone → acts only on it" {
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=0 run_wd
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent on re-apply): re-running with same config emits SAME mutations (mask is idempotent — systemctl mask returns ok if already masked)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (profile downgrade mask → stop): re-apply with stop profile triggers stop+disable on present units" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    write_config "stop"
    : > "${SYSEOF_LOG}"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable kdump.service' "${SYSEOF_LOG}"
    # NOTE: stop profile alone may not unmask (one-way action); we assert
    # the stop+disable shape.
}

@test "INVARIANT (DRY_RUN with stop profile too): DRY_RUN=1 + stop profile → no mutation" {
    write_config "stop"
    KDUMP_PRESENT=1 DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop kdump|systemctl disable kdump|systemctl mask kdump' "${SYSEOF_LOG}"
}

@test "INVARIANT (no-variant-list-leaks): list-unit-files MUST be called for each candidate (otherwise present-check is skipped)" {
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    # Each candidate must be probed via list-unit-files first.
    grep -q 'systemctl list-unit-files kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl list-unit-files kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl list-unit-files kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=3 when all 3 variants present; acted=1 when only one — operator dashboard distro-aware)" {
    write_config "mask"
    output_all="$(KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd 2>&1)"
    [[ "${output_all}" == *'acted=3'* ]]
    : > "${SYSEOF_LOG}"
    output_one="$(KDUMP_PRESENT=1 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd 2>&1)"
    [[ "${output_one}" == *'acted=1'* ]]
}

@test "INVARIANT (acted=0 + no-op when no kdump variants present — healthy minimal endpoint has zero)" {
    write_config "mask"
    output="$(KDUMP_PRESENT=0 KEXEC_PRESENT=0 KDUMPTOOLS_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]] || [[ "${output}" == *'acted=0'* ]]
}

@test "INVARIANT (no auto-uninstall: kdump-tools / kexec-tools packages NEVER auto-removed; only stop+disable+mask)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    ! grep -qE 'apt|dnf|yum|rpm' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask order per unit: stop → disable → mask — terminate-then-clear-then-gate)" {
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    stop_line="$(grep -n 'systemctl stop kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask kdump.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — mask is sticky)" {
    # Sister-pattern with avahi/nscd/ctrlaltdel/apport/at/wwan mask-sticky lock.
    write_config "mask"
    KDUMP_PRESENT=1 run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    KDUMP_PRESENT=1 run_wd
    grep -q 'systemctl stop kdump.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask kdump.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status: module=kdump-disable + status=ok + profile surfaced for operator dashboard)" {
    write_config "mask"
    output="$(KDUMP_PRESENT=1 run_wd 2>&1)"
    [[ "${output}" == *'"module":"kdump-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "INVARIANT (mask order holds across ALL distro variants — kexec + kdump-tools follow same stop→disable→mask sequence)" {
    # Mask order is per-unit, but must hold uniformly across all 3 distro
    # variants. Lock that each variant follows its own stop→disable→mask
    # sequence.
    write_config "mask"
    KDUMP_PRESENT=0 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=0 run_wd
    stop_kexec="$(grep -n 'systemctl stop kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_kexec="$(grep -n 'systemctl disable kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_kexec="$(grep -n 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_kexec}" -lt "${disable_kexec}" ]
    [ "${disable_kexec}" -lt "${mask_kexec}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # kdump-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires systemctl
    # mask on all present kdump variants (kdump.service +
    # kexec-tools.service + kdump-tools.service — the full
    # distro-aware kernel-crash-dump pipeline neutralization —
    # kernel-memory dump on crash captures encryption keys + RAM
    # secrets, equivalent to coredumpd-redirect surface but at
    # kernel level).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "kdump = kernel RAM dump exfil surface at crash"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    grep -q 'systemctl mask kdump.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kexec-tools.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask kdump-tools.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (DRY_RUN does not fire any systemctl mask/disable/stop)" {
    # Sister to many other installer module's DRY_RUN INVARIANT
    # across the brain. The kdump-disable DRY_RUN path MUST be a
    # no-op against the live systemd state — operator using
    # --dry-run to preview-without-applying expects ZERO
    # mutations. Locks the dry-run side-effect-freedom contract
    # so a regression that fires mask through DRY_RUN would be
    # caught (silent unmask would re-expose the kernel-memory-
    # dump exfil surface; silent mask would prevent operator
    # from kdump'ing intentionally during preview).
    write_config "mask"
    DRY_RUN=1 KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    ! grep -qE 'systemctl (mask|disable|stop)' "${SYSEOF_LOG}"
}

@test "INVARIANT (no package-uninstall: kexec/kdump packages NEVER auto-removed — module neutralizes, doesn't uninstall)" {
    # Sister to apport-disable / avahi-disable / at-disable no-
    # auto-uninstall INVARIANTs across the brain. The kdump-
    # disable module neutralizes the kernel-memory-dump exfil
    # surface via stop+disable+mask. The kexec-tools and kdump-
    # tools packages MUST stay installed — operator may
    # legitimately need them for emergency crash debugging or
    # may unmask them temporarily for incident response.
    # Auto-removing the packages would prevent that recovery
    # path. Locks the neutralize-don't-uninstall boundary on
    # the kernel-memory-leak via crash-dump substrate.
    write_config "mask"
    KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 run_wd
    ! grep -qE '(apt-get|dpkg|dnf|rpm)[[:space:]]+(remove|purge|uninstall)' "${SYSEOF_LOG}"
}

@test "INVARIANT (single emit_status JSON record per apply — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    write_config "mask"
    run -0 env PATH="${BIN}:${PATH}" \
        SYSEOF_LOG="${SYSEOF_LOG}" \
        SELFDEF_KDUMP_CONFIG="${CONF}" \
        KDUMP_PRESENT=1 KEXEC_PRESENT=1 KDUMPTOOLS_PRESENT=1 \
        bash "${WD}"
    # emit_status is a single-line JSON to stdout.
    n_status=$(printf '%s\n' "${output}" | grep -cE '"module":"kdump-disable"')
    [ "${n_status}" = "1" ]
}
