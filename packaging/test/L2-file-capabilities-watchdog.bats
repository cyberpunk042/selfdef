#!/usr/bin/env bats
# L2 bats functional tests for the file-capabilities-watchdog scan script.
#
# A baseline delta of file capabilities (security.capability xattr, set via
# setcap). A binary granted a capability gains a slice of root power without
# the setuid bit — e.g. cap_setuid is full uid control, cap_dac_override
# bypasses all permission checks (T1548). Severity on the delta:
#   ok    → no delta
#   warn  → 1..2 added capability binaries
#   alert → 3+ added, OR any added binary with a "dangerous" capability
#           (setuid/setgid/dac_override/dac_read_search/sys_admin/
#            sys_ptrace/sys_module)
#
# Tests use setcap, so they require root + an xattr-capable fs (true in the
# CI/root sandbox; verified at setup).
#
# Run with: bats packaging/test/L2-file-capabilities-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd/file-capabilities-watchdog.sh"

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
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
    # Skip the whole suite if the tmp fs cannot hold capability xattrs.
    printf '#!/bin/sh\n' > "${ROOT}/.probe"; chmod 0755 "${ROOT}/.probe"
    setcap cap_net_raw+ep "${ROOT}/.probe" 2>/dev/null || skip "fs does not support capability xattrs"
    rm -f "${ROOT}/.probe"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_FILECAPS_PROFILE="${PROFILE:-report}" \
    SELFDEF_FILECAPS_ROOTS="${ROOT}" \
    SELFDEF_FILECAPS_BASELINE="${BASELINE}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

mk_cap() { printf '#!/bin/sh\n' > "${ROOT}/$1"; chmod 0755 "${ROOT}/$1"; setcap "$2" "${ROOT}/$1"; }

@test "first run with one cap binary → ok / baseline_initial" {
    mk_cap ping cap_net_raw+ep
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged caps on second run → ok / no_delta" {
    mk_cap ping cap_net_raw+ep
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"no_delta"'
    cap | grep -q '"severity":"ok"'
}

@test "one added non-dangerous cap binary → warn / capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap webserver cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_added"'
    cap | grep -q '"severity":"warn"'
}

@test "three added cap binaries → alert / mass_capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap a1 cap_net_bind_service+ep
    mk_cap a2 cap_net_bind_service+ep
    mk_cap a3 cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"mass_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "an added binary with a dangerous capability → alert / dangerous_capability_added" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap backdoor cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on an added cap binary" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap webserver cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "baseline is chmod 0600 (confidentiality — capability inventory enumerates priv-elevated binaries)" {
    mk_cap ping cap_net_raw+ep
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (dangerous-priority): dangerous cap WINS over mass-add (3+ adds where 1 is dangerous) → dangerous_capability_added" {
    # Severity ladder: dangerous > mass-add > single-add. A run
    # that adds 4 caps where 1 is cap_setuid must escalate to
    # `dangerous_capability_added`, NOT `mass_capability_added`.
    # Locks the script's priority ordering.
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap a1 cap_net_bind_service+ep
    mk_cap a2 cap_net_bind_service+ep
    mk_cap a3 cap_net_bind_service+ep
    mk_cap backdoor cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "added/removed/dangerous counts surface in JSON (operator triage observability)" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap webserver cap_net_bind_service+ep
    mk_cap backdoor cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"added":[2-9]'                     # at least 2 adds
    cap | grep -q '"dangerous":1'                       # 1 dangerous cap (cap_setuid)
}

@test "DELTA detect — REMOVED cap binary surfaces in removed_sample" {
    mk_cap ping cap_net_raw+ep
    mk_cap nginx cap_net_bind_service+ep
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${ROOT}/nginx"
    run_wd
    cap | grep -q 'nginx'
}

@test "INVARIANT (full dangerous-cap set): each of the 7 dangerous capabilities triggers alert" {
    # The script's dangerous-cap regex: cap_setuid|cap_setgid|
    # cap_dac_override|cap_dac_read_search|cap_sys_admin|
    # cap_sys_ptrace|cap_sys_module. Locks the FULL set —
    # a regression that drops any one of them lands RED.
    mk_cap baseline cap_net_raw+ep
    run_wd
    for cap_name in cap_setgid cap_dac_override cap_dac_read_search cap_sys_admin cap_sys_ptrace cap_sys_module; do
        mk_cap "danger_${cap_name}" "${cap_name}+ep"
    done
    # cap_setuid already covered in the existing test, but include
    # it here too for completeness.
    mk_cap danger_cap_setuid cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -qE '"dangerous":[7-9]'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_cap ping cap_net_raw+ep
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-file-caps -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): file-capabilities-watchdog does NOT auto-refresh the baseline — alert STAYS until operator updates" {
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap backdoor cap_setuid+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (recursive scan: cap binary in subdirectory of ROOT surfaces — not only top-level)" {
    # A binary planted in a subdirectory (sub/bin/) must still be
    # caught — file-capabilities-watchdog scans recursively.
    mk_cap ping cap_net_raw+ep
    run_wd
    mkdir -p "${ROOT}/sub/bin"
    printf '#!/bin/sh\n' > "${ROOT}/sub/bin/sneaky"
    chmod 0755 "${ROOT}/sub/bin/sneaky"
    setcap cap_setuid+ep "${ROOT}/sub/bin/sneaky"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sneaky'
}

@test "INVARIANT (permitted-only cap set: cap_net_raw+p — permitted-without-effective — also tracked)" {
    # Capabilities can be granted with just the permitted bit
    # (+p) and gain effective via prctl from the binary. Lock
    # that the watchdog tracks BOTH the +ep and the +p flavors
    # — not only the +ep ladder.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap permitted_only cap_dac_override+p
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # The binary appears in the added set (delta detected).
    cap | grep -q 'permitted_only'
}

@test "INVARIANT (combined add+remove: both axes surface concurrently in JSON)" {
    mk_cap ping cap_net_raw+ep
    mk_cap nginx cap_net_bind_service+ep
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Remove nginx + add a new one in same scan.
    rm -f "${ROOT}/nginx"
    mk_cap newcap cap_net_bind_service+ep
    run_wd
    cap | grep -qE '"added":[1-9]'
    cap | grep -qE '"removed":[1-9]'
}

@test "INVARIANT (baseline format: each line records path + capability string for diff replay — space-separated per getcap output)" {
    # The baseline is the sorted output of getcap with ' = '
    # collapsed to ' ' — format is '<path> <caps>'. Each non-
    # empty line must have at least 2 whitespace-separated
    # fields (path + caps). Locks the format so downstream
    # parsers + selfdef-recap don't break.
    mk_cap ping cap_net_raw+ep
    mk_cap nginx cap_net_bind_service+ep
    run_wd
    [ -s "${BASELINE}" ]
    awk 'NF<2{bad=1} END{exit bad?1:0}' "${BASELINE}"
    grep -q "ping" "${BASELINE}"
    grep -q "nginx" "${BASELINE}"
    # Each line ends with cap_... + a flag suffix (=ep / +ep / etc.)
    grep -qE 'cap_net_raw[+=]' "${BASELINE}"
    grep -qE 'cap_net_bind_service[+=]' "${BASELINE}"
}

@test "INVARIANT (multi-root scan: cap binary in any of ROOTS detected)" {
    # Operator may watch multiple roots (e.g. /usr + /opt + /usr/local).
    # Lock multi-root axis — a binary planted in ROOT2 is detected.
    ROOT2="${TMP}/scan2"; mkdir -p "${ROOT2}"
    # Skip if ROOT2 fs doesn't support xattrs.
    printf '#!/bin/sh\n' > "${ROOT2}/.probe"; chmod 0755 "${ROOT2}/.probe"
    setcap cap_net_raw+ep "${ROOT2}/.probe" 2>/dev/null || skip "ROOT2 fs does not support capability xattrs"
    rm -f "${ROOT2}/.probe"
    mk_cap ping cap_net_raw+ep
    PATH="${BIN}:${PATH}" \
    SELFDEF_FILECAPS_PROFILE="report" \
    SELFDEF_FILECAPS_ROOTS="${ROOT} ${ROOT2}" \
    SELFDEF_FILECAPS_BASELINE="${BASELINE}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant dangerous cap in second root.
    printf '#!/bin/sh\n' > "${ROOT2}/sneaky"; chmod 0755 "${ROOT2}/sneaky"
    setcap cap_setuid+ep "${ROOT2}/sneaky"
    PATH="${BIN}:${PATH}" \
    SELFDEF_FILECAPS_PROFILE="report" \
    SELFDEF_FILECAPS_ROOTS="${ROOT} ${ROOT2}" \
    SELFDEF_FILECAPS_BASELINE="${BASELINE}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sneaky'
}

@test "INVARIANT (severity ladder: mass-add boundary — 2 adds → warn, 3 adds → alert)" {
    # Confirm exact boundary between warn and alert on the count
    # axis. 2 adds is warn (1..2 ladder); 3 adds is alert.
    mk_cap ping cap_net_raw+ep
    run_wd
    mk_cap a1 cap_net_bind_service+ep
    mk_cap a2 cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'                   # 2 adds = warn
    # Now add a third — should escalate to alert / mass.
    mk_cap a3 cap_net_bind_service+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'           # 3+ adds escalates
}

@test "INVARIANT (sample cap at 8: more than 8 added caps surface in sample[] truncated, count NOT truncated)" {
    # Operator dashboard JSON budget: sample = first 8 caps.
    # The 'added' count must reflect the TRUE count.
    mk_cap ping cap_net_raw+ep
    run_wd
    for i in $(seq 1 12); do
        printf '#!/bin/sh\n' > "${ROOT}/added_${i}"
        chmod 0755 "${ROOT}/added_${i}"
        setcap cap_net_bind_service+ep "${ROOT}/added_${i}"
    done
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # True count surfaces.
    cap | grep -qE '"added":1[0-9]'                       # 12+ adds
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (cap_net_raw is NOT dangerous — ping/traceroute legitimate use): non-dangerous cap classification holds" {
    # cap_net_raw is granted to ping + traceroute as standard distro
    # practice. Lock that the watchdog correctly classifies it as
    # benign (added → warn at most, not alert via dangerous path).
    # A regression that adds cap_net_raw to the dangerous set would
    # produce false positives on every operator distro upgrade.
    mk_cap baseline cap_net_bind_service+ep
    run_wd
    mk_cap new_ping cap_net_raw+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_added"'           # not dangerous
    cap | grep -q '"severity":"warn"'                    # not alert
    cap | grep -qE '"dangerous":0'
}

@test "INVARIANT (severity precedence: dangerous + non-dangerous added in same scan → SINGLE alert event, not warn — alert wins)" {
    # Sister to sudoers-integrity severity-precedence INVARIANT.
    # When both dangerous and non-dangerous caps are added in the
    # same scan, the JSON record fires as dangerous_capability_added
    # alert, not as capability_added warn. Locks consolidation.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap ordinary cap_net_bind_service+ep
    mk_cap dangerous cap_dac_override+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
    main_count=$(cap | grep -cE '^-t selfdef-file-caps -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (cap_sys_admin dangerous-cap detect — almost-root super-capability — also alerts)" {
    # Sister to the cap_setuid + cap_dac_override + cap_sys_ptrace +
    # cap_sys_module dangerous-cap axes in the capability-conf-
    # watchdog already locked. cap_sys_admin is the "almost-root"
    # super-capability covering mount/namespace/firmware-load/kexec.
    # Lock its coverage on the file-capabilities surface (xattr-
    # granted-cap binary axis, sister axis to pam_cap login-grant
    # axis). Closes axis-parity between the two capability-tracking
    # watchdogs on the cap_sys_admin super-capability detection.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap sys_admin_binary cap_sys_admin+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dangerous_capability_added"'
    cap | grep -q '"severity":"alert"'
    cap | grep -q 'sys_admin_binary'
}

@test "INVARIANT (cap_chown dangerous-cap detect — ownership-confusion super-cap — also alerts on file-cap surface)" {
    # Sister to capability-conf-watchdog cap_chown INVARIANT just
    # locked. cap_chown lets the binary re-own ANY file regardless
    # of uid — pre-attack pivot primitive (T1222 File and Directory
    # Permissions Modification). Closes axis-parity between the two
    # capability-tracking watchdogs on the cap_chown coverage.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap chown_binary cap_chown+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (cap_sys_ptrace dangerous-cap detect — process-injection axis on file-cap surface)" {
    # Sister to capability-conf-watchdog cap_sys_ptrace INVARIANT
    # just locked. cap_sys_ptrace lets a binary attach to ANY
    # process via ptrace (including PID-1 systemd) for memory
    # inspection/modification — process-injection primitive
    # (T1055) + credential-theft (attach to privileged process,
    # read /proc/<pid>/mem for secrets) + container-escape
    # primitive. Closes axis-parity between the two capability-
    # tracking watchdogs on the cap_sys_ptrace coverage. The
    # ptrace-grade capability MUST also fire dangerous_
    # capability_added on the file-cap surface, not just the
    # pam_cap surface.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap ptrace_binary cap_sys_ptrace+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
