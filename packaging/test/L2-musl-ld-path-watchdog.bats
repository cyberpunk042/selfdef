#!/usr/bin/env bats
# L2 bats functional tests for the musl-ld-path-watchdog scan script.
#
# On musl-libc systems (Alpine — the most common container base),
# /etc/ld-musl-<arch>.path is the ENTIRE library search path the musl
# loader uses. A prepended writable directory makes the loader resolve
# shared libraries from there first, hijacking libc/library loads for every
# dynamically-linked binary (T1574.006 dynamic linker hijacking). Entries
# are newline- or colon-separated.
#
# Notably this LOCKS a special case the SDD-061 D-6 migration preserved: the
# compound writable check keeps an extra bare-root exact-match clause
# (`^/(tmp|var/tmp|dev/shm|home)$`, no trailing slash) ALONGSIDE the shared
# selfdef_is_writable_path (which requires a trailing component) — so a path
# entry that is exactly `/tmp` is still flagged.
#
# Runs the actual scan script with `logger` shadowed on PATH and the path
# file + baseline in a tmp sandbox via SELFDEF_MUSL_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-musl-ld-path-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd/musl-ld-path-watchdog.sh"
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
    CONF="${TMP}/ld-musl-x86_64.path"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MUSL_PROFILE="${PROFILE:-report}" \
    SELFDEF_MUSL_BASELINE="${BASELINE}" \
    SELFDEF_MUSL_FILES="${FILES:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no musl path file present → ok / no_musl_path" {
    FILES="${TMP}/nonexistent.path" run_wd
    cap | grep -q '"event":"no_musl_path"'
    cap | grep -q '"severity":"ok"'
}

@test "benign search path, first run → ok / baseline_initial" {
    printf '/lib\n/usr/lib\n/usr/local/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged path on second run → ok / musl_path_intact" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"musl_path_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED bare-root exact-match clause
# ============================================================

@test "library dir under a writable root → alert" {
    printf '/tmp/evil/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare writable root (exactly /tmp, no trailing slash) → alert (preserved compound clause)" {
    printf '/lib\n/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "colon-separated path with one writable dir → alert" {
    printf '/lib:/usr/lib:/dev/shm/x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign dir added after baseline → warn / musl_path_changed" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    printf '/lib\n/usr/lib\n/opt/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"musl_path_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard library dirs are NOT flagged" {
    printf '/lib\n/usr/lib\n/usr/local/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable dir line is NOT flagged" {
    printf '/lib\n# /tmp/evil/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/tmp/evil/lib\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — musl-ld-path inventory enumerates dynamic-linker hijack surface)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (preserved bare /var/tmp exact-match clause)" {
    printf '/lib\n/var/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved bare /dev/shm exact-match clause)" {
    printf '/lib\n/dev/shm\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved bare /home exact-match clause)" {
    printf '/lib\n/home\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (path entry under /var/tmp/<subdir>): trailing-slash form" {
    printf '/lib\n/var/tmp/attacker/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (path entry under /home/<user>/lib): user-writable hijack coverage" {
    printf '/lib\n/home/user/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable path file → alert)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-musl-ld-path -- ')
    [ "${main_count}" = "1" ]
}
