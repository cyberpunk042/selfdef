#!/usr/bin/env bats
# L2 bats functional tests for the nm-vpn-plugin-watchdog scan script.
#
# NetworkManager (root) loads the service plugin .so / helper named in each
# /etc/NetworkManager/VPN/*.name descriptor: `[libnm] plugin=<.so>` is
# loaded into the root NM process and `[VPN Connection] program=<bin>` is
# run as root. A planted .name with plugin=/tmp/evil.so loads attacker code
# into root NetworkManager (T1574). Distinct INI-style `key=value` format
# with comment lines starting with `#` or `;`.
#
# Runs the actual scan script with `logger` shadowed on PATH and the VPN
# descriptor dir + baseline in a tmp sandbox via SELFDEF_NMVPN_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-nm-vpn-plugin-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nm-vpn-plugin-watchdog/systemd/nm-vpn-plugin-watchdog.sh"
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
    VPND="${TMP}/VPN"; mkdir -p "${VPND}"
    NAME="${VPND}/openvpn.name"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_NMVPN_PROFILE="${PROFILE:-report}" \
    SELFDEF_NMVPN_BASELINE="${BASELINE}" \
    SELFDEF_NMVPN_DIRS="${DIRS:-$VPND}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no NM VPN descriptors → ok / no_nm_vpn" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_nm_vpn"'
    cap | grep -q '"severity":"ok"'
}

@test "benign plugin + program, first run → ok / baseline_initial" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n[VPN Connection]\nprogram=/usr/lib/NetworkManager/nm-openvpn-service\n' > "${NAME}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged descriptor on second run → ok / nm_vpn_intact" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nm_vpn_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "plugin .so under a writable root → alert" {
    printf '[libnm]\nplugin=/tmp/evil.so\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "service program under a writable root → alert" {
    printf '[VPN Connection]\nprogram=/dev/shm/svc\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash plugin path → alert" {
    printf '[libnm]\nplugin=sub/dir/evil.so\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign key added after baseline → warn / nm_vpn_changed" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n[VPN Connection]\nprogram=/usr/lib/NetworkManager/nm-openvpn-service\n' > "${NAME}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nm_vpn_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "plugin + program under /usr/lib are NOT flagged (no alert)" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n[VPN Connection]\nprogram=/usr/lib/NetworkManager/nm-openvpn-service\n' > "${NAME}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable plugin line is NOT flagged" {
    printf '[libnm]\n; plugin=/tmp/evil.so\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '[libnm]\nplugin=/tmp/evil.so\n' > "${NAME}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — NM VPN plugin inventory enumerates NM-root code-load surface)" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (plugin .so under /var/tmp): writable-root expansion" {
    printf '[libnm]\nplugin=/var/tmp/evil.so\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin .so under /home): user-writable hijack coverage" {
    printf '[libnm]\nplugin=/home/user/evil.so\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (service program under /tmp): writable-root on program axis" {
    printf '[VPN Connection]\nprogram=/tmp/svc\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (service program under /var/tmp): writable-root expansion on program axis" {
    printf '[VPN Connection]\nprogram=/var/tmp/svc\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable .name file → alert)" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    chmod 0666 "${NAME}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (comments via #-prefix also skipped — not just ;-prefix)" {
    # INI dialect supports both ; and # for comments. Lock that
    # # is also skipped.
    printf '[libnm]\n# plugin=/tmp/evil.so\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nm-vpn-plugin -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: nm-vpn-plugin-watchdog does NOT refresh baseline on suspicious-plugin detection — alert STAYS until operator updates)" {
    # T1574 NetworkManager-root code-load primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    # Sister to gss-mech, ld-preload, musl-ld-path, postfix-exec —
    # the active-injection class never auto-trusts.
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    run_wd
    printf '[libnm]\nplugin=/tmp/evil.so\n' > "${NAME}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-descriptor scan: a second .name in same dir ALSO scanned — not just openvpn)" {
    # NM-VPN dir may carry many descriptors (openvpn / openconnect /
    # vpnc / wireguard / pptp). Attacker may plant a NEW descriptor
    # with a writable plugin path. Watchdog must enumerate every
    # .name in the dir, not stop at the first one.
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    printf '[libnm]\nplugin=/tmp/evil-openconnect.so\n' > "${VPND}/openconnect.name"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: a second VPN dir ALSO scanned — both system + local VPN dirs)" {
    # NM may consult /etc/NetworkManager/VPN/ + /usr/lib/NetworkManager/VPN/
    # (system-provided vs operator-overridden). Watchdog must walk
    # multiple dirs when SELFDEF_NMVPN_DIRS contains multiple paths.
    VPND2="${TMP}/VPN2"; mkdir -p "${VPND2}"
    printf '[libnm]\nplugin=/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so\n' > "${NAME}"
    printf '[libnm]\nplugin=/tmp/evil-extra.so\n' > "${VPND2}/extra.name"
    DIRS="${VPND} ${VPND2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin .so under /home — user-writable hijack on NetworkManager VPN dlopen surface)" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — an
    # attacker with regular user account can drop a malicious VPN
    # plugin .so into their home and have it dlopen()'d into
    # NetworkManager (running AS ROOT) the next time NM walks the
    # VPN descriptor directory. Locks axis-symmetry across the
    # writable-root family on the NetworkManager VPN-plugin
    # dlopen-load surface (T1574 — Hijack Execution Flow via
    # shared object substitution).
    printf '[libnm]\nplugin=/home/user/.evil-nm-plugin.so\n' > "${NAME}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash plugin path 'sub/dir/p.so' → alert: PWD-at-exec attacker primitive on NM VPN loader)" {
    # Sister to krb5-plugins-watchdog + musl-ld-path-watchdog +
    # gss-mech-watchdog relative-with-slash INVARIANTs already
    # locked. A plugin path with embedded slashes BUT no leading
    # slash (e.g. 'sub/dir/p.so' instead of '/sub/dir/p.so') is
    # NOT a fully-qualified absolute path — NetworkManager's
    # dlopen() will resolve it relative to its CWD at load time.
    # An attacker who can affect NM's CWD (PWD-at-exec primitive
    # — via systemd WorkingDirectory= injection) gets to control
    # where the plugin .so loads from. Locks detection of the
    # relative-with-slash variant on the NM VPN-plugin surface.
    printf '[libnm]\nplugin=sub/dir/p.so\n' > "${NAME}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
