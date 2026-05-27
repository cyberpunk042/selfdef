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

@test "enforce profile exits non-zero on a suspicious Exec" {
    svc /usr/libexec/myservice > "${SVC}"
    run_wd
    svc /tmp/evil > "${SVC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
