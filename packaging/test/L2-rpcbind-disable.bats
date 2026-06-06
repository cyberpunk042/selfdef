#!/usr/bin/env bats
# L2 functional suite for rpcbind-disable.
#
# rpcbind-disable stops + disables rpcbind + rpc-statd + rpc-
# gssd. rpcbind (formerly portmap) is the RPC port mapper —
# required by NFSv3 + NIS but unnecessary on hosts that don't
# export NFS or run NIS. Historically a CVE magnet (CVE-2017-
# 8779 / DoS, etc.) and an open-internet-facing service exposes
# the entire RPC program surface to network attackers.
#
# Acts on 5 units. SAFETY GUARD: if nfs-server.service is active,
# logs a WARN (but does not hard-fail — operator may be
# intentionally retiring NFS, AND NFSv4-only exports are
# unaffected by rpcbind masking).
#
# Profiles: stop | mask.
#
# Run with: bats packaging/test/L2-rpcbind-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rpcbind-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
case "$1" in
    list-unit-files)
        case "$2" in
            rpcbind.service|rpcbind.socket|rpc-statd.service|rpc-statd-notify.service|rpc-gssd.service)
                if [[ "${RPC_PRESENT:-1}" == "1" ]]; then
                    printf 'UNIT FILE     STATE\n%s   enabled\n' "$2"
                    exit 0
                else
                    exit 1
                fi ;;
        esac ;;
    is-active)
        # Honor the NFS_SERVER_ACTIVE flag.
        case "$2" in
            nfs-server.service)
                [[ "${NFS_SERVER_ACTIVE:-0}" == "1" ]] && exit 0 || exit 3 ;;
        esac
        exit 3 ;;
esac
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/rpcbind-disable.toml"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_RPCBIND_CONFIG="${CONF}" \
    RPC_PRESENT="${RPC_PRESENT:-1}" \
    NFS_SERVER_ACTIVE="${NFS_SERVER_ACTIVE:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_RPCBIND_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RPCBIND_CONFIG="${SELFDEF_RPCBIND_CONFIG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RPCBIND_CONFIG="${CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be mask|stop"* ]]
}

@test "rpcbind not present → no mutation" {
    write_config "mask"
    RPC_PRESENT=0 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "mask profile acts on all 5 RPC units" {
    write_config "mask"
    run_wd
    for unit in rpcbind.service rpcbind.socket rpc-statd.service rpc-statd-notify.service rpc-gssd.service; do
        grep -q "systemctl mask ${unit}" "${SYSEOF_LOG}"
    done
}

@test "INVARIANT: nfs-server ACTIVE → logs WARN but DOES NOT hard-fail (operator intent respected)" {
    write_config "mask"
    NFS_SERVER_ACTIVE=1 run_wd
    # The script should still mask the units — the WARN is informational.
    grep -q 'systemctl mask rpcbind.service' "${SYSEOF_LOG}"
}

@test "stop profile acts on all 5 units (stop + disable, NO mask)" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop rpcbind.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rpc-statd.service' "${SYSEOF_LOG}"
    ! grep -q 'systemctl mask' "${SYSEOF_LOG}"
}

@test "DRY_RUN=1 → no systemctl mutation" {
    write_config "mask"
    DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "default profile is mask (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'systemctl mask rpcbind.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (rpcbind.socket coverage in mask): the .socket variant is masked too (not just .service)" {
    # rpcbind.socket can re-activate rpcbind.service on demand
    # via systemd socket activation — both must be masked.
    write_config "mask"
    run_wd
    grep -q 'systemctl mask rpcbind.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (rpcbind.socket coverage in stop): the .socket variant is stopped + disabled too" {
    write_config "stop"
    run_wd
    grep -q 'systemctl stop rpcbind.socket' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rpcbind.socket' "${SYSEOF_LOG}"
}

@test "INVARIANT (rpc-statd-notify): stop profile acts on the rpc-statd-notify.service unit too" {
    # rpc-statd-notify is the rpc-statd companion — both must be
    # disabled. A regression that drops it would let rpc-statd
    # come back via notify.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop rpc-statd-notify.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rpc-statd-notify.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (rpc-gssd): stop profile acts on rpc-gssd (NFSv4 Kerberos client)" {
    # rpc-gssd is the NFSv4 Kerberos GSS-API helper. Locks that
    # the full 5-unit set is acted on.
    write_config "stop"
    run_wd
    grep -q 'systemctl stop rpc-gssd.service' "${SYSEOF_LOG}"
    grep -q 'systemctl disable rpc-gssd.service' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mask): re-applying mask fires the same systemctl set" {
    write_config "mask"
    run_wd
    first_log="$(cat "${SYSEOF_LOG}")"
    : > "${SYSEOF_LOG}"
    run_wd
    second_log="$(cat "${SYSEOF_LOG}")"
    diff <(printf '%s\n' "${first_log}") <(printf '%s\n' "${second_log}") >/dev/null
}

@test "INVARIANT (nfs-server-active + DRY_RUN): WARN logged but DRY_RUN still suppresses mutation" {
    write_config "mask"
    NFS_SERVER_ACTIVE=1 DRY_RUN=1 run_wd
    ! grep -qE 'systemctl stop|systemctl disable|systemctl mask' "${SYSEOF_LOG}"
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "mask"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"rpcbind-disable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=mask'* ]]
}
