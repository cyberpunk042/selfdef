#!/usr/bin/env bats
# L2 bats functional tests for the openssl-conf-watchdog scan script.
#
# Covers the libcrypto-wide engine/provider load surface: the OpenSSL
# config (read by EVERY OpenSSL-using process — openssl CLI, curl, wget,
# libcrypto/libssl daemons) can load code via
#   dynamic_path = /path/engine.so    (ENGINE, OpenSSL 1.x)
#   module       = /path/provider.so  (PROVIDER, OpenSSL 3.x)
#   .include       /path/extra.cnf     (pulls in another config)
# A planted directive pointing at a writable/attacker .so (or a relative-
# with-slash path) is a near-ubiquitous code-execution foothold (T1574).
# Distinct key=value + `.include` grammar.
#
# Runs the actual scan script with `logger` shadowed on PATH and config/
# baseline in a tmp sandbox via SELFDEF_OPENSSL_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-openssl-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/openssl-conf-watchdog/systemd/openssl-conf-watchdog.sh"
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
    CONF="${TMP}/openssl.cnf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_OPENSSL_PROFILE="${PROFILE:-report}" \
    SELFDEF_OPENSSL_BASELINE="${BASELINE}" \
    SELFDEF_OPENSSL_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no openssl config present → ok / no_openssl_conf" {
    run_wd
    cap | grep -q '"event":"no_openssl_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign engine + provider, first run → ok / baseline_initial" {
    printf 'dynamic_path = /usr/lib/engines-3/afalg.so\nmodule = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / openssl_conf_intact" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openssl_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "dynamic_path engine .so under a writable root → alert" {
    printf 'dynamic_path = /tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "module provider .so under a writable root → alert" {
    printf 'module = /dev/shm/mods/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test ".include pulling a config from a writable root → alert" {
    printf '.include /var/tmp/extra.cnf\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash module path → alert" {
    printf 'module = sub/dir/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign directive added after baseline → warn / openssl_conf_changed" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    printf 'module = /usr/lib/ossl-modules/legacy.so\ndynamic_path = /usr/lib/engines-3/afalg.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openssl_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "engine/provider .so under /usr/lib is NOT flagged (no alert)" {
    printf 'dynamic_path = /usr/lib/engines-3/afalg.so\nmodule = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable module line is NOT flagged" {
    printf '# module = /tmp/evil.so\nmodule = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'module = /tmp/evil.so\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — openssl-conf inventory enumerates libcrypto-wide code-load surface)" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (dynamic_path under /var/tmp): writable-root expansion on ENGINE axis" {
    printf 'dynamic_path = /var/tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module under /var/tmp): writable-root expansion on PROVIDER axis" {
    printf 'module = /var/tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (.include under /tmp): writable-root expansion on include axis" {
    printf '.include /tmp/extra.cnf\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (.include under /dev/shm): tmpfs writable-root coverage" {
    printf '.include /dev/shm/extra.cnf\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (module under /home): user-writable hijack coverage" {
    printf 'module = /home/user/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable openssl.cnf → alert)" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-openssl-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: openssl-conf-watchdog does NOT refresh baseline on suspicious-engine/provider detection — alert STAYS until operator updates)" {
    # T1574 libcrypto-wide ENGINE/PROVIDER code-load primitive —
    # alert MUST persist across runs until operator explicitly
    # re-baselines. Sister to gss-mech, ld-preload, nm-vpn-plugin,
    # openvpn-config, musl-ld-path, sudo-conf, sshd-config —
    # active-injection class never auto-trusts.
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd
    printf 'module = /tmp/evil.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'module=/tmp/evil.so' without spaces around equals → still flagged)" {
    # OpenSSL config grammar tolerates no-space-around-equals. An
    # attacker may use that form to evade naive 'module = '
    # whitespace-sensitive grep. Locks whitespace-tolerant parser.
    printf 'module=/tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: a second openssl.cnf in SELFDEF_OPENSSL_FILES ALSO scanned)" {
    # Multiple openssl configs may live on the host (per-user vs
    # system vs per-application). All must be enumerated.
    CONF2="${TMP}/openssl-extra.cnf"
    printf 'module = /usr/lib/ossl-modules/legacy.so\n' > "${CONF}"
    printf 'module = /tmp/extra-evil.so\n' > "${CONF2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_OPENSSL_PROFILE="report" \
    SELFDEF_OPENSSL_BASELINE="${BASELINE}" \
    SELFDEF_OPENSSL_FILES="${CONF} ${CONF2}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (engine .so under /home — user-writable hijack on OpenSSL engine dlopen surface)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain. /home is the user-writable
    # surface — an attacker with regular user account can drop
    # a malicious OpenSSL engine .so into their home and have
    # it dlopen()'d into EVERY OpenSSL-using daemon (sshd, nginx,
    # openvpn, postgres, every TLS client). Locks axis-symmetry
    # across the writable-root family on the OpenSSL engine
    # dlopen-load surface (T1574 — Hijack Execution Flow via
    # shared object substitution; OpenSSL engines run AS the
    # consuming process with full TLS-key access).
    printf 'engine_id = evil\ndynamic_path = /home/user/.evil-engine.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named engine path surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a new
    # engine or provider definition pointing at an attacker-
    # controlled .so, the engine NAME or path MUST surface in
    # the JSON sample so operator dashboard routes triage to
    # the right code-load surface (T1574 Hijack Execution Flow
    # via OpenSSL engine substitution; engine runs AS consuming
    # process with full TLS-key access).
    printf 'engine_id = legit\ndynamic_path = /usr/lib/engines-3/legit.so\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'engine_id = distinctive_attacker_engine\ndynamic_path = /tmp/.evil-engine.so\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive_attacker_engine\|/tmp/.evil-engine'
}

@test "INVARIANT (provider .so under /dev/shm — tmpfs in-RAM writable-root on libcrypto provider dlopen surface)" {
    # Sister to /tmp + /var/tmp + /home provider .so writable-
    # root INVARIANTs already locked. /dev/shm is the canonical
    # tmpfs in-RAM writable-root that survives no on-disk
    # forensic trace. libcrypto provider dlopen MUST recognize
    # /dev/shm provider .so paths — locks axis-symmetric tmpfs
    # writable-root coverage on T1574 OpenSSL-provider Hijack
    # Execution Flow surface; provider runs in-process AS the
    # consuming process with full TLS-key access.
    printf '[providers]\nmodule=/dev/shm/.evil-provider.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (provider .so under /var/tmp — persistent writable-root axis-symmetric expansion on libcrypto provider dlopen surface)" {
    # Sister to /dev/shm + /home provider .so writable-root.
    # /var/tmp persistent + writable across reboots.
    printf '[providers]\nmodule=/var/tmp/.evil-provider.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on openssl-conf surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The openssl-conf-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 OpenSSL-provider/engine Hijack
    # Execution Flow alert. Locks parser contract on the
    # openssl.cnf detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[providers]\nmodule=/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf '[providers]\nmodule=/tmp/.evil-provider.so\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # openssl-conf-watchdog runs ON the timer's scheduled fire —
    # scans /etc/ssl/openssl.cnf for engine/provider .so paths
    # in writable roots, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the openssl-conf-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/openssl-conf-watchdog/systemd/selfdef-openssl-conf.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. openssl-conf-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # openssl-conf-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # openssl-conf-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/openssl-conf-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'openssl-conf-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
