#!/usr/bin/env bats
# L2 bats functional tests for the krb5-plugins-watchdog scan script.
#
# Third watchdog functional-severity suite, covering a DETECTION
# MECHANISM distinct from the exec/directive watchdogs: this one is
# PATH-based, not pattern-based. A krb5.conf [plugins] stanza loads a
# shared object via `module = NAME:/path/to/plugin.so`; MIT krb5 then
# dlopen()s that .so into every process using GSSAPI/preauth — so a
# module path under a writable root (or a relative path) is a code-
# load primitive (T1574/T1546). There is no injection-pattern scan
# here; alert = writable/relative .so OR world-writable/non-root config.
#
# Also exercises both config grammars the scanner must handle: the
# own-line form and the inline `subsection = { module = ... }` form
# (the compact-brace case fixed in this module's history), plus the
# comment-skip guard.
#
# Run with: bats packaging/test/L2-krb5-plugins-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/krb5-plugins-watchdog/systemd/krb5-plugins-watchdog.sh"
# SDD-061 D-6: scan script now sources the shared module-lib.
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
    CONF="${TMP}/krb5.conf"
    EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KRB5_PROFILE="${PROFILE:-report}" \
    SELFDEF_KRB5_BASELINE="${BASELINE}" \
    SELFDEF_KRB5_DIRS="${EMPTY}" \
    SELFDEF_KRB5_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no krb5 config present → ok / no_krb5_config" {
    run_wd
    cap | grep -q '"event":"no_krb5_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign plugin .so, first run → ok / baseline_initial" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / krb5_plugins_intact" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"krb5_plugins_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "inline-brace module .so under a writable root → alert" {
    printf '[plugins]\n  kdcpreauth = { module = evil:/tmp/evil.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "own-line module .so under a writable root → alert" {
    printf '[plugins]\nmodule = evil:/dev/shm/p.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-path module .so → alert" {
    printf '[plugins]\n  clpreauth = { module = rel:sub/dir/p.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign plugin added after baseline → warn / krb5_plugins_changed" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n  kdcpreauth = { module = otp:/usr/lib/krb5/plugins/preauth/otp.so }\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"krb5_plugins_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "module .so under /usr/lib64 is NOT flagged (no alert)" {
    printf '[plugins]\n  kdb = { module = db2:/usr/lib64/krb5/plugins/kdb/db2.so }\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable module line is NOT flagged" {
    printf '[plugins]\n# kdcpreauth = { module = evil:/tmp/evil.so }\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# SDD-061 D-6 — shared-lib dependency fails loud
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# enforce profile
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '[plugins]\n  kdcpreauth = { module = evil:/tmp/evil.so }\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}
