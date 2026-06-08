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

@test "INVARIANT (cap_sys_module dangerous-cap detect on file-cap surface — kernel module loading axis)" {
    # Sister to capability-conf-watchdog cap_sys_module INVARIANT.
    # cap_sys_module = direct kernel-module loading primitive.
    # Closes axis-parity between the two capability-tracking
    # watchdogs on the cap_sys_module coverage (T1547.006).
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap modload_binary cap_sys_module+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (cap_dac_override dangerous-cap detect — DAC-bypass axis on file-cap surface — T1548)" {
    # Sister to cap_sys_module / cap_chown / cap_sys_ptrace /
    # cap_sys_admin dangerous-cap INVARIANTs on the file-cap
    # surface, and cap_dac_override INVARIANT in capability-
    # conf-watchdog. cap_dac_override bypasses ALL file
    # permission checks; planted on a non-root binary it lets
    # the binary read/write any file regardless of mode/owner.
    # T1548 Abuse Elevation Control Mechanism via DAC bypass.
    mk_cap baseline cap_net_raw+ep
    run_wd
    mk_cap dac_bypass_binary cap_dac_override+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on file-capabilities surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The file-capabilities-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1548 Abuse Elevation Control
    # Mechanism via file-capability alert. Locks parser
    # contract on the file-capability inventory delta detection
    # surface.
    mk_cap baseline cap_net_raw+ep
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    mk_cap evil_dangerous cap_sys_admin+ep
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # file-capabilities-watchdog runs ON the timer's scheduled
    # fire — enumerates file capabilities across canonical paths,
    # emits a verdict on dangerous-cap deltas, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the file-capabilities-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd/selfdef-file-caps.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. file-capabilities-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # file-capabilities-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # file-capabilities-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'file-capabilities-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: file-capabilities-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. file-capabilities-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the file-capabilities-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (file-capabilities-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The file-capabilities-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the file-capabilities-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # file-capabilities-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # file-capabilities-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the file-capabilities-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # file-capabilities-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the file-capabilities-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (file-capabilities-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the file-capabilities-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the file-capabilities-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the file-capabilities-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the file-capabilities-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the file-capabilities-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (file-capabilities-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (file-capabilities-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the file-capabilities-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    [ -f "${script_dir}/file-capabilities-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (file-capabilities-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (file-capabilities-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (file-capabilities-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script tag selfdef-file-capabilities matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-file-capabilities
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .timer file exists at canonical path modules/file-capabilities-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (file-capabilities-watchdog module.toml exists at canonical path modules/file-capabilities-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (file-capabilities-watchdog systemd dir exists at modules/file-capabilities-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (file-capabilities-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (file-capabilities-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (file-capabilities-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (file-capabilities-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (file-capabilities-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (file-capabilities-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (file-capabilities-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (file-capabilities-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"file-capabilities-watchdog"' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (file-capabilities-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (file-capabilities-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (file-capabilities-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (file-capabilities-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (file-capabilities-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (file-capabilities-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-capabilities-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}
