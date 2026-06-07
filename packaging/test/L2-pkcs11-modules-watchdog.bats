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

@test "baseline is chmod 0600 (confidentiality — pkcs11 inventory enumerates credential-handling code-load surface)" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (module .so under /var/tmp): writable-root expansion" {
    printf 'module: /var/tmp/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module .so under /dev/shm): tmpfs writable-root expansion" {
    printf 'module: /dev/shm/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module .so under /home): user-writable hijack coverage" {
    printf 'module: /home/user/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable .module file → alert)" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    chmod 0666 "${MOD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable .module file): group-writable → alert above world-writable bar" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    chmod 0664 "${MOD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-pkcs11-modules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): pkcs11-modules-watchdog does NOT refresh baseline on suspicious-module detection — alert STAYS until operator updates" {
    # T1574 credential-handling code-load primitive — alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd
    printf 'module: /tmp/evil.so\n' > "${MOD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/pkcs11/modules + /usr/share/p11-kit/modules axes — suspicious module in EITHER → alert)" {
    MODDIR2="${TMP}/share-p11-kit-modules"; mkdir -p "${MODDIR2}"
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    DIRS="${MODDIR} ${MODDIR2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'module: /tmp/evil.so\n' > "${MODDIR2}/evil.module"
    DIRS="${MODDIR} ${MODDIR2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'module:    /tmp/evil.so' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces between 'module:' and the path to
    # evade naive grep.
    printf 'module:    /tmp/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multiple module: lines per .module file: ANY suspicious entry → alert)" {
    # A .module file may contain MULTIPLE module: directives. Each must
    # be evaluated; ANY suspicious entry triggers alert (not just first).
    printf 'module: /usr/lib/opensc-pkcs11.so\nmodule: /tmp/evil.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module under /home: user-writable hijack on PKCS#11 credential-handler dlopen surface)" {
    # Sister to the /tmp + /var/tmp + /dev/shm writable-root axes
    # already locked. /home is the user-writable surface — an
    # attacker with regular user account can drop a malicious
    # PKCS#11 provider .so into their home and have it dlopen()'d
    # into every consumer that walks the p11-kit module dirs
    # (Firefox, browser-based smart card auth, GnuTLS, SSH agent
    # forwarders). Locks axis-symmetry across the writable-root
    # family on the PKCS#11 credential-handler dlopen-load surface
    # (T1574 — Hijack Execution Flow via shared object substitution
    # specifically on cryptographic-credential APIs).
    printf 'module: /home/user/.evil-pkcs11.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-with-slash module path 'sub/dir/p.so' → alert: PWD-at-exec attacker primitive on PKCS#11 loader)" {
    # Sister to krb5-plugins-watchdog + musl-ld-path-watchdog +
    # gss-mech-watchdog + nm-vpn-plugin-watchdog relative-with-
    # slash INVARIANTs already locked. A module path with
    # embedded slashes BUT no leading slash (e.g. 'sub/dir/p.so'
    # instead of '/sub/dir/p.so') is NOT a fully-qualified
    # absolute path — p11-kit's dlopen() will resolve it
    # relative to the CWD of the consuming process at load time.
    # An attacker who can affect the consumer's CWD (PWD-at-exec
    # primitive — via systemd WorkingDirectory= injection) gets
    # to control where the PKCS#11 .so loads from. Locks
    # detection of the relative-with-slash variant on the PKCS#11
    # credential-handler surface.
    printf 'module: sub/dir/p.so\n' > "${MOD}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (module under /var/tmp — writable-root axis-symmetric expansion on PKCS#11 credential-handler dlopen surface)" {
    # Sister to /home module writable-root + relative-with-slash
    # INVARIANTs already locked. /var/tmp is writable by ALL
    # users AND persists across reboots — attackers prefer for
    # boot-survival persistence. p11-kit / consuming PKCS#11
    # applications (browsers, ssh, openvpn) dlopen the planted
    # .so AS the consuming process which means smartcard /
    # YubiKey / HSM operations may be intercepted at credential
    # access time. T1574 Hijack Execution Flow via PKCS#11
    # module substitution. Closes /var/tmp axis on PKCS#11
    # writable-root coverage.
    printf 'module: /var/tmp/.evil-pkcs11.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}
