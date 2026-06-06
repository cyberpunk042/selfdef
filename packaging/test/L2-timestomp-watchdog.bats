#!/usr/bin/env bats
# L2 bats functional tests for the timestomp-watchdog scan script.
#
# Scans binary/config roots for timestamp-manipulation anomalies — FUTURE
# (mtime after now), EPOCH (mtime before 2001 on a system file), or
# MTIME>CTIME — the tells of `touch`-based timestomping (T1070.006). Stateless
# count ladder:
#   ok    → 0 anomalies
#   warn  → 1..3 anomalies
#   alert → 4+ anomalies OR any anomaly in a core bin dir
#
# Run with: bats packaging/test/L2-timestomp-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/timestomp-watchdog/systemd/timestomp-watchdog.sh"

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
    ROOT="${TMP}/scan"; mkdir -p "${ROOT}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_TIMESTOMP_PROFILE="${PROFILE:-report}" \
    SELFDEF_TIMESTOMP_ROOTS="${ROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "no timestamp anomalies → ok / no_timestamp_anomaly" {
    printf 'x' > "${ROOT}/normal"            # mtime = now
    run_wd
    cap | grep -q '"event":"no_timestamp_anomaly"'
    cap | grep -q '"severity":"ok"'
}

@test "one future-dated file → warn / timestamp_anomaly" {
    printf 'x' > "${ROOT}/normal"
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    run_wd
    cap | grep -q '"event":"timestamp_anomaly"'
    cap | grep -q '"severity":"warn"'
}

@test "one pre-2001 (epoch) file → warn" {
    printf 'x' > "${ROOT}/old"; touch -d "1995-06-01" "${ROOT}/old"
    run_wd
    cap | grep -q '"severity":"warn"'
}

@test "a normal recent file is NOT flagged" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q '"severity":"ok"'
    ! cap | grep -q '"severity":"warn"'
}

@test "4+ anomalies → alert / timestomp_anomaly" {
    for i in $(seq 1 4); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestomp_anomaly"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a timestamp anomaly" {
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
}

@test "boundary: 3 anomalies → warn (1..3 INCLUSIVE on the high end)" {
    for i in $(seq 1 3); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestamp_anomaly"'
    cap | grep -q '"severity":"warn"'
}

@test "boundary: 4 anomalies → alert (just over the warn ceiling — locks >=4 cutoff)" {
    for i in $(seq 1 4); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"event":"timestomp_anomaly"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (FUTURE anomaly type): mtime > now+1day classified as FUTURE" {
    printf 'x' > "${ROOT}/future-stomped"
    touch -d "2099-01-01" "${ROOT}/future-stomped"
    run_wd
    cap | grep -q 'FUTURE:'
}

@test "INVARIANT (EPOCH anomaly type): mtime < 2001-01-01 classified as EPOCH" {
    printf 'x' > "${ROOT}/old-stomped"
    touch -d "1995-06-01" "${ROOT}/old-stomped"
    run_wd
    cap | grep -q 'EPOCH:'
}

@test "INVARIANT (1-day skew tolerance): mtime slightly in the future is NOT flagged (within 1d clock-skew window)" {
    # The script's future_cutoff = now + 86400 (1 day tolerance).
    # An mtime that's only 1 hour in the future must NOT trigger.
    printf 'x' > "${ROOT}/slightly-future"
    touch -d "$(date -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" "${ROOT}/slightly-future"
    run_wd
    # Either ok severity OR the file isn't in the sample.
    cap | grep -q '"event":"no_timestamp_anomaly"'
}

@test "anomalies + core_bin_anomalies counts surface in JSON (operator triage observability)" {
    for i in $(seq 1 3); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    run_wd
    cap | grep -q '"anomalies":3'
    # No /bin /sbin /usr/bin /usr/sbin in this scan → core_bin_anomalies=0.
    cap | grep -q '"core_bin_anomalies":0'
}

@test "sample of anomalies (up to 8) surfaces in 'sample' field for operator triage" {
    printf 'x' > "${ROOT}/very-distinctive-stomp-name"
    touch -d "2099-01-01" "${ROOT}/very-distinctive-stomp-name"
    run_wd
    cap | grep -q 'very-distinctive-stomp-name'
}

@test "profile field surfaces in JSON (echo of operator-set SELFDEF_TIMESTOMP_PROFILE)" {
    printf 'x' > "${ROOT}/normal"
    run_wd
    cap | grep -q '"profile":"report"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'x' > "${ROOT}/stomped"; touch -d "2099-01-01" "${ROOT}/stomped"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-timestomp -- ')
    [ "${main_count}" = "1" ]
}

@test "report profile exits 0 even on alert severity (findings are advisory)" {
    for i in $(seq 1 5); do printf 'x' > "${ROOT}/s${i}"; touch -d "2099-01-0${i}" "${ROOT}/s${i}"; done
    PROFILE=report run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}
