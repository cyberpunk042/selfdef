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

@test "INVARIANT (module .so under /var/tmp): writable-root expansion" {
    printf '[plugins]\n  kdcpreauth = { module = evil:/var/tmp/p.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module .so under /home): user-writable hijack coverage" {
    printf '[plugins]\n  kdcpreauth = { module = evil:/home/user/p.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable krb5.conf → alert)" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable krb5.conf): group-writable → alert above world-writable bar" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (multi-plugin compound: one benign + one suspicious — suspicious wins)" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n  kdcpreauth = { module = evil:/tmp/evil.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-krb5-plugins -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): krb5-plugins-watchdog does NOT refresh baseline on suspicious-path detection — alert STAYS until operator updates" {
    # T1574/T1546 GSSAPI/preauth dlopen-load primitive — suspicious-path
    # alert MUST persist across runs until operator explicitly re-baselines.
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    run_wd
    printf '[plugins]\n  kdcpreauth = { module = evil:/tmp/evil.so }\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: krb5.conf + krb5.conf.d/*.conf drop-in axes — suspicious .so in ANY → alert)" {
    # MIT krb5 reads BOTH /etc/krb5.conf AND /etc/krb5.conf.d/*.conf.
    # Attacker may plant in either. Lock multi-file axis.
    CONF2="${TMP}/krb5-dropin.conf"
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KRB5_PROFILE="report" \
    SELFDEF_KRB5_BASELINE="${BASELINE}" \
    SELFDEF_KRB5_DIRS="${EMPTY}" \
    SELFDEF_KRB5_FILES="${CONF} ${CONF2}" \
    bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant suspicious .so in drop-in.
    printf '[plugins]\n  kdcpreauth = { module = evil:/tmp/evil.so }\n' > "${CONF2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_KRB5_PROFILE="report" \
    SELFDEF_KRB5_BASELINE="${BASELINE}" \
    SELFDEF_KRB5_DIRS="${EMPTY}" \
    SELFDEF_KRB5_FILES="${CONF} ${CONF2}" \
    bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (writable-root expansion: /dev/shm .so → alert (tmpfs-backed code-load))" {
    # /dev/shm is tmpfs, world-writable on most distros. Lock coverage.
    printf '[plugins]\n  kdcpreauth = { module = evil:/dev/shm/p.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'module    =    evil:/tmp/evil.so' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep-based
    # detection. Lock whitespace-tolerant parser.
    printf '[plugins]\n  kdcpreauth = { module    =    evil:/tmp/evil.so }\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing world-writable krb5.conf): baseline_initial fires alert at install-time" {
    # Sister to every other watchdog pre-existing-world-writable
    # baseline_initial INVARIANT across the brain. The install-time-
    # vet contract: if krb5.conf is ALREADY world-writable when
    # selfdef first installs the watchdog, the first run MUST raise
    # alert (or at least warn) — not silently baseline a broken
    # security posture. Closes the install-time-vet axis on the
    # GSSAPI/preauth dlopen-load surface (T1574/T1546 — any process
    # using GSSAPI dlopen()s the module .so, so a world-writable
    # krb5.conf lets a non-root attacker swap in their own .so to
    # execute in every GSSAPI-aware daemon).
    printf '[plugins]\n  clpreauth = { module = pkinit:/usr/lib/krb5/plugins/preauth/pkinit.so }\n' > "${CONF}"
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (relative-with-slash path 'sub/dir/p.so' → alert: PWD-at-exec attacker primitive)" {
    # Sister to many other watchdog's relative-with-slash
    # INVARIANT across the brain (syslog-ng, dnf-plugins, others).
    # A module path with embedded slashes BUT no leading slash
    # (e.g. 'sub/dir/p.so' instead of '/sub/dir/p.so') is NOT a
    # fully-qualified absolute path — krb5 will resolve it
    # relative to the CWD of the daemon at dlopen time. An
    # attacker who can affect the daemon's CWD (PWD-at-exec
    # primitive — via working-directory env-vars, chdir-by-
    # init-script, or systemd WorkingDirectory= injection) gets
    # to control where the .so loads from. Lock detection of the
    # relative-with-slash variant — same threat as a relative
    # bare-name but a stealthier presentation.
    printf '[plugins]\n  kdcpreauth = { module = evil:sub/dir/p.so }\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
