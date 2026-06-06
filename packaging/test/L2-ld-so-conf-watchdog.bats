#!/usr/bin/env bats
# L2 bats functional tests for the ld-so-conf-watchdog scan script.
#
# /etc/ld.so.conf{,.d/*.conf} list the DIRECTORIES the glibc dynamic loader
# searches for shared libraries. An attacker who adds a writable dir (and
# makes it earlier in the order) hijacks the SO search for every
# dynamically-linked program — a persistent code-exec foothold. A genuinely
# distinct watchdog: besides the writable-dir alert it also alerts on a
# search PATH being REMOVED (ld_so_conf_path_removed), and falls back to an
# on-disk `-d && -w && mode` check for arbitrary world-writable dirs.
#
# SDD-063: this module was migrated off its per-module case-statement
# writable policy onto the shared selfdef_is_writable_dir helper, so a bare
# writable root (an ld.so.conf entry of exactly `/tmp`) is flagged too.
#
# Run with: bats packaging/test/L2-ld-so-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ld-so-conf-watchdog/systemd/ld-so-conf-watchdog.sh"
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
    CONF="${TMP}/ld.so.conf"
    DROPIN="${TMP}/ld.so.conf.d"; mkdir -p "${DROPIN}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LDSOCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_LDSOCONF_BASELINE="${BASELINE}" \
    SELFDEF_LDSOCONF_MAIN="${CONF}" \
    SELFDEF_LDSOCONF_DIR="${DROPIN}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "benign search-path dirs, first run → ok / baseline_initial" {
    printf '/opt/app/lib\n/usr/local/customlib\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / ld_so_conf_intact" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ld_so_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — writable search dir (incl. SDD-063 bare root)
# ============================================================

@test "search-path dir under a writable root → alert / ld_so_conf_writable_path" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf '/opt/app/lib\n/tmp/evil/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ld_so_conf_writable_path"'
    cap | grep -q '"severity":"alert"'
}

@test "bare writable root as a search dir → alert (SDD-063 consolidated)" {
    printf '/opt/app/lib\n/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "search-path dir under /home → alert" {
    printf '/home/user/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# distinct: a removed search path is itself an alert
# ============================================================

@test "a search path removed after baseline → alert / ld_so_conf_path_removed" {
    printf '/opt/app/lib\n/opt/other/lib\n' > "${CONF}"
    run_wd
    printf '/opt/app/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ld_so_conf_path_removed"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign dir added after baseline → warn / ld_so_conf_changed" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd
    printf '/opt/app/lib\n/opt/extra/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ld_so_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard non-writable search dirs are NOT flagged" {
    printf '/opt/app/lib\n/usr/local/customlib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "an include directive is skipped (not flagged)" {
    printf 'include /etc/ld.so.conf.d/*.conf\n/opt/app/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable dir is NOT flagged" {
    printf '# /tmp/evil/lib\n/opt/app/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-063 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/tmp/evil/lib\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '/opt/app/lib\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — ld.so.conf inventory enumerates dynamic-linker search-path)" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (search-path dir under /var/tmp): writable-root expansion" {
    printf '/var/tmp/evil/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (search-path dir under /dev/shm): tmpfs writable-root expansion" {
    printf '/dev/shm/evil/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bare /var/tmp — SDD-063 consolidated bare-root)" {
    printf '/var/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bare /dev/shm — SDD-063 consolidated bare-root)" {
    printf '/dev/shm\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bare /home — SDD-063 consolidated bare-root)" {
    printf '/home\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ld.so.conf.d drop-in also scanned — not only main conf)" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd
    printf '/tmp/dropin-evil/lib\n' > "${DROPIN}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '/opt/app/lib\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ld-so-conf -- ')
    [ "${main_count}" = "1" ]
}
