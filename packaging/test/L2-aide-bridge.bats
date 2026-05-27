#!/usr/bin/env bats
# L2 bats functional tests for the aide-bridge aide-check.sh wrapper.
#
# Wraps `aide --check`: maps AIDE's exit bitmask + summary table to a
# severity (ok=no diff, warn=adds only, alert=removals/changes, high=internal
# error / missing config). Drives the wrapper with a fake `aide` binary
# (SELFDEF_AIDE_BIN) emitting a controlled summary + exit code, and `logger`
# shadowed on PATH.
#
# Run with: bats packaging/test/L2-aide-bridge.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aide-bridge/systemd/aide-check.sh"

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
    CONF="${TMP}/aide.conf"; printf '# aide config\n' > "${CONF}"
    FAKE_AIDE="${TMP}/aide"
}

teardown() { rm -rf "${TMP}"; }

# mk_aide <rc> <summary-stdout>
mk_aide() {
    { printf '#!/usr/bin/env bash\n'; printf 'cat <<'\''OUT'\''\n%s\nOUT\n' "$2"; printf 'exit %s\n' "$1"; } > "${FAKE_AIDE}"
    chmod +x "${FAKE_AIDE}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_AIDE_PROFILE="${PROFILE:-baseline}" \
    SELFDEF_AIDE_BIN="${FAKE_AIDE}" \
    SELFDEF_AIDE_CONF="${CONF_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "missing aide config → high / config_missing" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"config_missing"'
    cap | grep -q '"severity":"high"'
}

@test "no differences (rc 0) → ok / no_diff" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    cap | grep -q '"event":"no_diff"'
    cap | grep -q '"severity":"ok"'
}

@test "adds only → warn / diff_added_only" {
    mk_aide 1 "Added entries: 3
Removed entries: 0
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_added_only"'
    cap | grep -q '"severity":"warn"'
}

@test "removals/changes → alert / diff_changed_or_removed" {
    mk_aide 6 "Added entries: 0
Removed entries: 1
Changed entries: 2"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "aide internal error (rc >= 8) → high / aide_internal_error" {
    mk_aide 8 "fatal: database read error"
    run_wd
    cap | grep -q '"event":"aide_internal_error"'
    cap | grep -q '"severity":"high"'
}

@test "enforce profile exits non-zero on a diff" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
