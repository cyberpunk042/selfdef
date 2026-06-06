#!/usr/bin/env bats
# L2 bats functional tests for the modules-load-watchdog scan script.
#
# /etc/modules-load.d/*.conf (and /etc/modules) lists kernel modules to load
# at boot. A world-writable / non-root config lets any user queue an
# arbitrary module load at next boot (T1547.006 kernel-module persistence).
# Severity:
#   ok    → no delta
#   warn  → a module-to-load added/removed, or a file changed
#   alert → a config file world-writable or non-root-owned
#
# Run with: bats packaging/test/L2-modules-load-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/modules-load-watchdog/systemd/modules-load-watchdog.sh"

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
    CONFD="${TMP}/modules-load.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/net.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODLOAD_PROFILE="${PROFILE:-report}" \
    SELFDEF_MODLOAD_BASELINE="${BASELINE}" \
    SELFDEF_MODLOAD_DIRS="${DIRS_V:-$CONFD}" \
    SELFDEF_MODLOAD_ETC_MODULES="${TMP}/no-etc-modules" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'overlay\nbr_netfilter\n' > "${CONF}"
}

@test "no modules-load config → ok / no_modules_load" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_modules_load"'
    cap | grep -q '"severity":"ok"'
}

@test "benign modules-load conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged modules-load conf on second run → ok / modules_load_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a world-writable config → alert / modules_load_writable_config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"modules_load_writable_config"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign module-to-load change → warn / modules_load_changed" {
    seed_benign
    run_wd
    printf 'overlay\nbr_netfilter\nip_tables\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"modules_load_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned config is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a world-writable config" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — modules-load inventory enumerates kernel-module load surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (group-writable): a group-writable (0664) config → alert too (more than just world-writable)" {
    # Locks the script's writable-detection scope. Some scripts
    # check only `-perm -0002` (world-writable); a regression
    # might let group-writable slide. Test the intent.
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Group-writable IS a finding per the canonical
    # config-file-permission discipline.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect): ADDED config file (attacker drops a new modules-load.d/.conf) → warn/alert" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Attacker drops a NEW config file dropping a backdoor module.
    printf 'evil_module\n' > "${CONFD}/backdoor.conf"
    run_wd
    cap | grep -qE '"event":"modules_load_(changed|writable_config)"'
}

@test "INVARIANT (DELTA detect): REMOVED config file → warn" {
    seed_benign
    cat > "${CONFD}/other.conf" <<'EOF'
ip_tables
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFD}/other.conf"
    run_wd
    cap | grep -qE '"event":"modules_load_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "INVARIANT (added module-to-load): a new module name surfaces in the delta sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'overlay\nbr_netfilter\nbackdoor_rootkit\n' > "${CONF}"
    run_wd
    cap | grep -q 'backdoor_rootkit'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-modules-load -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (pre-existing world-writable): baseline_initial fires alert if any config is already world-writable at install-time" {
    # Operator sees existing risk at install time.
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}
