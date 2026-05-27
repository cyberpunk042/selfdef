#!/usr/bin/env bats
# L2 bats functional tests for the pkcs11-modules-watchdog scan script.
#
# Every p11-kit consumer (GnuPG/gpgsm, ssh-agent/ssh with PKCS#11,
# NSS-using browsers, libp11) loads the shared object named in each
# /etc/pkcs11/modules/*.module file's `module:` line. A planted .module
# with `module: /tmp/evil.so` loads attacker code into a broad set of
# security-sensitive, often credential-handling processes whenever they
# enumerate PKCS#11 modules (T1574). Distinct p11-kit `key: value` format.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# modules dir + baseline in a tmp sandbox via SELFDEF_PKCS11_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-pkcs11-modules-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd/pkcs11-modules-watchdog.sh"
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
    MODDIR="${TMP}/modules"; mkdir -p "${MODDIR}"
    MOD="${MODDIR}/opensc.module"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_PKCS11_PROFILE="${PROFILE:-report}" \
    SELFDEF_PKCS11_BASELINE="${BASELINE}" \
    SELFDEF_PKCS11_DIRS="${DIRS:-$MODDIR}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no pkcs11 modules dir → ok / no_pkcs11_modules" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_pkcs11_modules"'
    cap | grep -q '"severity":"ok"'
}

@test "benign module, first run → ok / baseline_initial" {
    printf 'module: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged modules on second run → ok / pkcs11_modules_intact" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pkcs11_modules_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "module: .so under a writable root → alert" {
    printf 'module: /tmp/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash module: path → alert" {
    printf 'module: sub/dir/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign module added after baseline → warn / pkcs11_modules_changed" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    printf 'module: /usr/lib/libtpm2_pkcs11.so\n' > "${MODDIR}/tpm2.module"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"pkcs11_modules_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "module: .so under /usr/lib is NOT flagged (no alert)" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a bare-basename module name (resolved via module dir) is NOT flagged" {
    printf 'module: opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable module line is NOT flagged" {
    printf '# module: /tmp/evil.so\nmodule: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'module: /tmp/evil.so\n' > "${MOD}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}
