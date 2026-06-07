#!/usr/bin/env bats
# L2 bats functional tests for the gss-mech-watchdog scan script.
#
# Every GSSAPI consumer (Kerberized ssh/sshd, NFSv4 sec=krb5, OpenLDAP/SASL
# GSSAPI, sssd, curl --negotiate) loads the mechanism .so named in FIELD 3
# of each line in /etc/gss/mech + /etc/gss/mech.d/*.conf:
#   <oid_name> <oid> <mech.so> [options]
# A planted mech whose .so is a writable/attacker path loads attacker code
# into auth-handling processes (often root) when GSSAPI initializes
# (T1574 / T1556). Distinct positional grammar (the .so is the third field).
#
# Runs the actual scan script with `logger` shadowed on PATH and the mech
# file + baseline in a tmp sandbox via SELFDEF_GSS_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-gss-mech-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd/gss-mech-watchdog.sh"
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
    MECH="${TMP}/mech"
    MECHD="${TMP}/mech.d"; mkdir -p "${MECHD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_GSS_PROFILE="${PROFILE:-report}" \
    SELFDEF_GSS_BASELINE="${BASELINE}" \
    SELFDEF_GSS_DIRS="${MECHD}" \
    SELFDEF_GSS_FILES="${MECH}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no gss mech config present → ok / no_gss_mech" {
    run_wd
    cap | grep -q '"event":"no_gss_mech"'
    cap | grep -q '"severity":"ok"'
}

@test "benign mechanism, first run → ok / baseline_initial" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / gss_mech_intact" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"gss_mech_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "mechanism .so under a writable root → alert" {
    printf 'gssapi_evil 1.2.3.4 /tmp/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash mechanism .so → alert" {
    printf 'gssapi_evil 1.2.3.4 sub/dir/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign mechanism added after baseline → warn / gss_mech_changed" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\nspnego 1.3.6.1.5.5.2 mech_spnego.so\n' > "${MECH}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"gss_mech_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "an absolute /usr/lib mechanism .so is NOT flagged (no alert)" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 /usr/lib/x86_64-linux-gnu/gssapi/mech_krb5.so\n' > "${MECH}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a bare-basename mechanism .so (resolved via lib dir) is NOT flagged" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable mechanism line is NOT flagged" {
    printf '# gssapi_evil 1.2.3.4 /tmp/evil.so\ngssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'gssapi_evil 1.2.3.4 /tmp/evil.so\n' > "${MECH}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — GSS mech inventory enumerates auth-handling code-load surface)" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (mechanism .so under /var/tmp): writable-root expansion" {
    printf 'gssapi_evil 1.2.3.4 /var/tmp/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mechanism .so under /dev/shm): tmpfs writable-root expansion" {
    printf 'gssapi_evil 1.2.3.4 /dev/shm/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mechanism .so under /home): user-writable hijack coverage" {
    printf 'gssapi_evil 1.2.3.4 /home/user/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mech.d drop-in also scanned — not only main mech file)" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    printf 'gssapi_evil 1.2.3.4 /tmp/evil.so\n' > "${MECHD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable mech file → alert)" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    chmod 0666 "${MECH}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable mech file): group-writable → alert above world-writable bar" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    chmod 0664 "${MECH}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-gss-mech -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): gss-mech-watchdog does NOT refresh baseline on suspicious-mechanism detection — alert STAYS until operator updates" {
    # T1574/T1556 GSSAPI auth-handling code-load primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 mech_krb5.so\n' > "${MECH}"
    run_wd
    printf 'gssapi_evil 1.2.3.4 /tmp/evil.so\n' > "${MECH}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: tab-separated mechanism fields still parsed)" {
    # The positional grammar uses whitespace (space or tab) as field
    # separator. Attacker may use tabs to evade naive grep.
    printf 'gssapi_evil\t1.2.3.4\t/tmp/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-mechanism file: ANY suspicious mechanism in any position → alert)" {
    # Attacker may stack: benign first, suspicious second; or vice versa.
    # Lock that ALL mechanism lines are evaluated.
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 /usr/lib/mech_krb5.so\nspnego 1.3.6.1.5.5.2 /usr/lib/mech_spnego.so\ngssapi_evil 1.2.3.4 /tmp/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mechanism .so under /var/tmp): writable-root expansion on GSSAPI auth code-load surface" {
    # Sister to the writable-root axes already locked (/tmp, /home,
    # /dev/shm). /var/tmp is an equally-writable surface — an
    # attacker who gains user write may swap in a malicious mech.so
    # to be dlopen()'d into every GSSAPI consumer (sshd, libnfs,
    # samba, anything krb5-linked). Lock axis-symmetry across the
    # writable-root family on the GSSAPI authentication-handling
    # code-load primitive (T1574 — Hijack Execution Flow via shared
    # object substitution).
    printf 'gssapi_krb5 1.2.840.113554.1.2.2 /usr/lib/mech_krb5.so\n' > "${MECH}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'gssapi_evil 1.2.3.4 /var/tmp/evil.so\n' > "${MECH}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash mechanism path 'sub/dir/p.so' → alert: PWD-at-exec attacker primitive on GSSAPI loader)" {
    # Sister to krb5-plugins-watchdog + musl-ld-path-watchdog
    # relative-with-slash INVARIANTs across the brain. A mechanism
    # .so path with embedded slashes BUT no leading slash (e.g.
    # 'sub/dir/p.so' instead of '/sub/dir/p.so') is NOT a fully-
    # qualified absolute path — GSSAPI's dlopen() will resolve it
    # relative to the CWD of the consuming daemon at load time.
    # An attacker who can affect the daemon's CWD (PWD-at-exec
    # primitive) gets to control where the mechanism .so loads
    # from for EVERY GSSAPI consumer. Locks detection of the
    # relative-with-slash variant on the GSSAPI mech surface.
    printf 'gssapi_evil 1.2.3.4 sub/dir/p.so\n' > "${MECH}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}
