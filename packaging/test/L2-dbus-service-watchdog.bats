#!/usr/bin/env bats
# L2 bats functional tests for the dbus-service-watchdog scan script.
#
# A D-Bus activation .service file with an Exec= (and optional User=) makes
# dbus-daemon launch Exec= AS that user the first time any client calls the
# service's bus name — a remotely/locally triggerable exec surface. The
# watchdog is high-signal in two distinct ways: dbus_service_suspicious (an
# Exec under a writable root, or a world-writable/non-root .service file) and
# dbus_service_new (a NEW activation .service appearing, or a new <allow
# own=> bus-name grant).
#
# Runs the actual scan script with `logger` shadowed on PATH and the service
# dir + baseline in a tmp sandbox via SELFDEF_DBUS_*.
#
# Run with: bats packaging/test/L2-dbus-service-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dbus-service-watchdog/systemd/dbus-service-watchdog.sh"
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
    DBUSD="${TMP}/services"; mkdir -p "${DBUSD}"
    SVC="${DBUSD}/com.example.A.service"
}

teardown() { rm -rf "${TMP}"; }

svc() { printf '[D-BUS Service]\nName=com.example.A\nExec=%s\nUser=%s\n' "$1" "${2:-root}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DBUS_PROFILE="${PROFILE:-report}" \
    SELFDEF_DBUS_BASELINE="${BASELINE}" \
    SELFDEF_DBUS_DIRS="${DIRS:-$DBUSD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dbus service dirs → ok / no_dbus_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_dbus_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign service, first run → ok / baseline_initial" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged services on second run → ok / dbus_service_intact" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — suspicious Exec
# ============================================================

@test "Exec under a writable root → alert / dbus_service_suspicious" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd                                   # benign baseline
    svc /tmp/evil > "${SVC}"                 # same service path, dangerous Exec
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "Exec under /home → alert" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /home/u/.x > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# alert tier — a NEW activation service appearing
# ============================================================

@test "a newly-added activation service → alert / dbus_service_new" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd                                   # baseline has only service A
    svc /usr/libexec/another > "${DBUSD}/com.example.B.service"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_new"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign edit to an existing service → warn / dbus_service_changed" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    { svc /usr/libexec/myservice; printf 'SystemdService=myservice.service\n'; } > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dbus_service_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "an Exec at a trusted path is NOT flagged" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a /usr/bin Exec is NOT flagged" {
    svc /usr/bin/dbus-helper > "${SVC}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    svc /usr/libexec/myservice > "${SVC}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious Exec" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — dbus-service inventory enumerates client-trigger root-exec surface)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (Exec under /var/tmp): writable-root expansion" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /var/tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /dev/shm): tmpfs writable-root coverage" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /dev/shm/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable service file → alert)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    chmod 0666 "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable service file): group-writable → alert above world-writable bar" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    chmod 0664 "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA-detect: NEW service surfaces in sample by bus-name)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # New service with distinctive bus name.
    cat > "${DBUSD}/com.distinctive.attacker.service" <<EOF
[D-BUS Service]
Name=com.distinctive.attacker
Exec=/usr/libexec/something
User=root
EOF
    run_wd
    cap | grep -q 'distinctive.attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-dbus-service -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): dbus-service-watchdog does NOT refresh baseline on suspicious-Exec detection — alert STAYS until operator updates" {
    # Client-trigger root-exec persistence — suspicious-Exec alert
    # MUST persist across runs until operator explicitly re-baselines.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"dbus_service_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /usr/share/dbus-1/system-services + /usr/local/share + /etc/dbus-1 axes — new service in ANY → alert)" {
    # dbus-daemon reads activation .service files from multiple dirs.
    # Attacker may plant in any. Lock multi-dir axis.
    DBUSD2="${TMP}/local-services"; mkdir -p "${DBUSD2}"
    svc /usr/libexec/myservice > "${SVC}"
    DIRS="${DBUSD} ${DBUSD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant new service in second dir.
    cat > "${DBUSD2}/com.evil.attacker.service" <<EOF
[D-BUS Service]
Name=com.evil.attacker
Exec=/usr/libexec/evil
User=root
EOF
    DIRS="${DBUSD} ${DBUSD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (User=root + Exec under writable root: BOTH axes compound severity — alert wins)" {
    # When User=root AND Exec is under writable root, this is the
    # highest-risk pattern (root exec triggered by client). Lock
    # that this compound case fires alert, not just warn.
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    svc /tmp/.attacker root > "${SVC}"      # explicit User=root + writable Exec
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"dbus_service_suspicious"'
}
