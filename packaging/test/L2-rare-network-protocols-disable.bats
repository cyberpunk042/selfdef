#!/usr/bin/env bats
# L2 functional suite for rare-network-protocols-disable.
#
# rare-network-protocols-disable installs a modprobe blacklist
# for rarely-used network-protocol kernel modules. Each disabled
# protocol is one less network-protocol code path attackers can
# target. Profiles:
#   baseline → dccp + sctp + rds + tipc (4 modules — the high-CVE
#              ones that ship enabled by default on most distros)
#   strict   → baseline + atm + can + appletalk + decnet + ipx +
#              netrom + ax25 + rose + x25 (13 modules total —
#              every historical network protocol any modern
#              endpoint shouldn't need)
#
# Adds SELFDEF_RAREPROTO_MODPROBE_FILE env-var (added 2026-06-06)
# for L2 testability.
#
# Run with: bats packaging/test/L2-rare-network-protocols-disable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rare-network-protocols-disable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    CONF="${TMP}/rare-network-protocols-disable.toml"
    MODPROBE_FILE="${TMP}/selfdef-rare-network-protocols-blacklist.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_RARENET_CONFIG="${CONF}" \
    SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_RARENET_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RARENET_CONFIG="${SELFDEF_RARENET_CONFIG}" \
        SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_RARENET_CONFIG="${CONF}" \
        SELFDEF_RAREPROTO_MODPROBE_FILE="${MODPROBE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile blacklists 4 high-CVE protocols (dccp + sctp + rds + tipc)" {
    write_config "baseline"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    for m in dccp sctp rds tipc; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
    # Strict-only protocols NOT present.
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
    ! grep -q 'blacklist ipx' "${MODPROBE_FILE}"
}

@test "strict profile blacklists 13 protocols (baseline + 9 legacy)" {
    write_config "strict"
    run_wd
    for m in dccp sctp rds tipc atm can appletalk decnet ipx netrom ax25 rose x25; do
        grep -q "blacklist ${m}" "${MODPROBE_FILE}"
    done
}

@test "blacklist file is chmod 0644 (modprobe.d convention)" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${MODPROBE_FILE}")" = "644" ]
}

@test "blacklist carries header-marker + timestamp + profile" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef rare-network-protocols-disable' "${MODPROBE_FILE}"
    grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "${MODPROBE_FILE}"
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
}

@test "INVARIANT: DRY_RUN does not write blacklist file" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${MODPROBE_FILE}" ]
}

@test "default profile is baseline (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${MODPROBE_FILE}" ]
    grep -q 'profile=baseline' "${MODPROBE_FILE}"
    ! grep -q 'blacklist atm' "${MODPROBE_FILE}"
}
