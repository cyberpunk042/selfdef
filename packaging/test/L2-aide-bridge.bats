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

@test "bitmask added/removed/changed surface in JSON (operator can verify the AIDE rc semantics)" {
    # rc 7 = 1|2|4 = added + removed + changed bits all set.
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added_bit":1'
    cap | grep -q '"removed_bit":1'
    cap | grep -q '"changed_bit":1'
    cap | grep -q '"aide_rc":7'
}

@test "summary-table counts surface in JSON (operator triage observability)" {
    mk_aide 7 "Added entries: 5
Removed entries: 3
Changed entries: 11"
    run_wd
    cap | grep -q '"added":5'
    cap | grep -q '"removed":3'
    cap | grep -q '"changed":11'
}

@test "profile field surfaces in JSON (echo of operator-set --profile)" {
    mk_aide 0 "AIDE found NO differences"
    PROFILE=enforce run_wd
    cap | grep -q '"profile":"enforce"'
}

@test "INVARIANT (removals+changes win over adds): rc=3 (added+removed) → alert (not warn — removals tip the severity)" {
    # rc 3 = 1|2 = added + removed bits set. The script's severity
    # ladder: if removed>0 OR changed>0 → alert. The presence of
    # adds alongside the removal must NOT downgrade to warn.
    mk_aide 3 "Added entries: 2
Removed entries: 1
Changed entries: 0"
    run_wd
    cap | grep -q '"event":"diff_changed_or_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (parse-defensive): missing summary table → all counts default to 0 + still emit JSON" {
    # AIDE versions differ in summary-table format; the script
    # falls back to 0 counts when the awk patterns don't match.
    # The wrapper must still emit a valid JSON record (not crash).
    mk_aide 1 "AIDE 0.16 — unusual output format with no Added entries: header"
    run_wd
    cap | grep -q '"tag":"selfdef-aide"'
    cap | grep -q '"added":0'
    cap | grep -q '"removed":0'
    cap | grep -q '"changed":0'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_aide 0 "AIDE found NO differences"
    run_wd
    # The wrapper emits two logger calls: one with tag
    # `selfdef-aide` (the JSON record) and one with tag
    # `selfdef-aide-detail` (the head of AIDE output). Count
    # only the main `-t selfdef-aide --` line, distinct from
    # `-t selfdef-aide-detail --`.
    main_count=$(cap | grep -cE '^-t selfdef-aide -- ')
    [ "${main_count}" = "1" ]
}

@test "baseline profile exits 0 even on alert severity (findings are operator-pull advisory)" {
    mk_aide 6 "Removed entries: 1
Changed entries: 2"
    PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline profile exits 0 even on high severity (config_missing is advisory in baseline mode)" {
    CONF_V="${TMP}/nonexistent" \
        PROFILE=baseline run run_wd
    [ "${status}" = "0" ]
}
