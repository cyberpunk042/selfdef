#!/usr/bin/env bats
# L2 functional suite for nscd-disable.
#
# nscd-disable stops + disables nscd (the Name Service Cache
# Daemon, part of glibc). nscd has a history of vulnerabilities
# (CVE-2014-0475 + CVE-2022-23218 family) and is largely
# obsoleted by systemd-resolved / sssd / direct nsswitch caching.
# On modern systems it's typically pure attack surface — its
# cache also poisons local name resolution in ways that defeat
# operator forensics.
#
# Acts on 2 units (nscd.service + nscd.socket). Profiles: stop |
# mask. DRY_RUN=1 → no system changes.
#
# Run with: bats packaging/test/L2-nscd-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nscd-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            nscd.service|nscd.socket)
                if [[ "${NSCD_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/nscd-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_NSCD_CONFIG="${CONF}" \
    NSCD_PRESENT="${NSCD_PRESENT:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_NSCD_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NSCD_CONFIG="${SELFDEF_NSCD_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_NSCD_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "nscd not present → no mutation" {
    write_config "mask"
    NSCD_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on BOTH nscd.service + nscd.socket" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask nscd.socket' "${SYSEOF_LOG}"
}

@test "stop profile acts on both (stop + disable, NO mask)" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable nscd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key — secure default)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (stop profile is reversible): stop fires `disable` (allowing later re-enable) but NOT mask" {
    # Stop+disable means the unit file remains intact (operator
    # can re-enable later); mask makes the unit unreloadable until
    # explicit `unmask`. The two profiles must be cleanly distinct.
    write_config "stop"
    run_wd
    grep -q 'systemctl disable nscd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask nscd' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask profile is sticky): mask fires `mask` (unit can't be re-enabled without explicit unmask)" {
    write_config "mask"
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask nscd.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (stop also fires the .socket unit not just .service)" {
    # nscd.socket can re-activate nscd.service on demand — disabling
    # only .service would let .socket bring it back. Both must be
    # touched.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop nscd.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable nscd.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent stop): re-applying stop profile fires the same systemctl set (no spurious mask escalation)" {
    write_config "stop"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    # Both runs fire the same mutating commands — no drift from
    # stop to mask across applies.
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (idempotent mask): re-applying mask profile fires the same set (no escalation to extra units)" {
    write_config "mask"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "emit_status surfaces profile + result in JSON" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"nscd-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}

@test "nscd not present + DRY_RUN=1 → still no mutation (dry-run is short-circuited correctly)" {
    write_config "mask"
    DRY_RUN=1 NSCD_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "INVARIANT (mask is a superset of stop: stop+disable+mask sequence; stop omits the mask step)" {
    # Mask = stop + disable + mask. Operator escalation path is
    # stop → mask without re-applying disable.
    write_config "mask"
    run_wd
    grep -q 'systemctl stop nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable nscd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted count surfaces in JSON: acted=2 when both nscd units present — operator dashboard)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=2'* ]]
    [[ "${output}" == *'skipped=0'* ]]
}

@test "INVARIANT (acted=0 + no-op message when nscd absent — operator dashboard distinguishes 'applied' vs 'not-present')" {
    write_config "mask"
    output="$(NSCD_PRESENT=0 run_wd 2>&1)"
    [[ "${output}" == *'no-op'* ]]
    [[ "${output}" == *'nscd not present'* ]] || [[ "${output}" == *'nscd not installed'* ]]
}

@test "INVARIANT (mask order: stop → disable → mask — NOT mask → stop): swap would leave running service unmaskable in flight" {
    # The systemctl mask is a runtime-permanent gate. Stop first
    # to terminate in-flight + disable to clear boot trigger +
    # mask last for permanent gate. Locks the sequence.
    write_config "mask"
    run_wd
    stop_line="$(grep -n 'systemctl stop nscd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_line="$(grep -n 'systemctl disable nscd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_line="$(grep -n 'systemctl mask nscd.service' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_line}" -lt "${disable_line}" ]
    [ "${disable_line}" -lt "${mask_line}" ]
}

@test "INVARIANT (.socket also follows stop→disable→mask order — symmetric ordering across all units)" {
    # Same order MUST hold for nscd.socket as for .service. Sister-pattern
    # with avahi-disable .socket symmetric ordering.
    write_config "mask"
    run_wd
    stop_socket="$(grep -n 'systemctl stop nscd.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    disable_socket="$(grep -n 'systemctl disable nscd.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    mask_socket="$(grep -n 'systemctl mask nscd.socket' "${SYSEOF_LOG}" | head -1 | cut -d: -f1)"
    [ "${stop_socket}" -lt "${disable_socket}" ]
    [ "${disable_socket}" -lt "${mask_socket}" ]
}

@test "INVARIANT (downgrade mask → stop does NOT auto-unmask — operator-explicit unmask required)" {
    # Mask is sticky like avahi-disable's mask + ctrlaltdel-disable's mask.
    write_config "mask"
    run_wd
    : > "${SYSEOF_LOG}"
    write_config "stop"
    run_wd
    grep -q 'systemctl stop nscd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl unmask nscd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (acted=2 + present-unit detail surfaces in JSON for operator dashboard)" {
    # acted=2 (both .service + .socket touched) AND skipped=0 (nothing
    # skipped) AND no error markers — full operator-dashboard observability.
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'acted=2'* ]]
    [[ "${output}" == *'skipped=0'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    # No error/warning markers in success path.
    [[ "${output}" != *'"status":"error"'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # nscd-disable TOML; parser must tolerate without altering the
    # profile-gated behavior. mask-with-noise still fires
    # systemctl mask on BOTH nscd.service AND nscd.socket (the
    # full attack-surface neutralization — nscd has CVE-2014-0475 +
    # CVE-2022-23218 history, obsoleted by systemd-resolved / sssd /
    # direct nsswitch caching).
    cat > "${CONF}" <<'TOMLEOF'
profile = "mask"
operator_note = "nscd = obsolete glibc cache, CVE history"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'systemctl mask nscd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl mask nscd.socket' "${SYSEOF_LOG}"
}
