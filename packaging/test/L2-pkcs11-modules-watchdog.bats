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

@test "INVARIANT (module under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on PKCS#11 credential-handler dlopen surface)" {
    # Sister to /home + /var/tmp module writable-root + relative-
    # with-slash INVARIANTs already locked. /dev/shm is the
    # canonical tmpfs in-RAM writable-root that survives no on-
    # disk forensic trace. p11-kit / consuming PKCS#11
    # applications (browsers, ssh, openvpn) dlopen the planted
    # .so AS the consuming process which means smartcard /
    # YubiKey / HSM operations may be intercepted at credential
    # access time. T1574 Hijack Execution Flow via PKCS#11
    # module substitution. Closes /dev/shm tmpfs axis on PKCS#11
    # writable-root coverage symmetric to /tmp + /var/tmp +
    # /home.
    printf 'module: /dev/shm/.evil-pkcs11.so\n' > "${MOD}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. Multi-
    # module scenario locks consolidation discipline.
    printf 'module: /tmp/.evil1.so\nmodule: /var/tmp/.evil2.so\nmodule: /dev/shm/.evil3.so\n' > "${MOD}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-pkcs11-modules -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on pkcs11-modules surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The pkcs11-modules-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 Hijack Execution Flow via PKCS#11
    # module substitution alert. Locks parser contract on the
    # /etc/pkcs11/modules + /usr/share/p11-kit/modules detection
    # surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'module: /usr/lib/opensc-pkcs11.so\n' > "${MOD}"
    run_wd                                              # ok / baseline
    printf 'module: /tmp/.evil-pkcs11.so\n' > "${MOD}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # pkcs11-modules-watchdog runs ON the timer's scheduled fire
    # — scans /etc/pkcs11/modules for module .so paths in
    # writable roots, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the pkcs11-modules-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd/selfdef-pkcs11-modules.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pkcs11-modules-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # pkcs11-modules-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # pkcs11-modules-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'pkcs11-modules-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: pkcs11-modules-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. pkcs11-modules-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the pkcs11-modules-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (pkcs11-modules-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the pkcs11-modules-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # pkcs11-modules-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # pkcs11-modules-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the pkcs11-modules-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # pkcs11-modules-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the pkcs11-modules-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (pkcs11-modules-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the pkcs11-modules-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # pkcs11-modules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the pkcs11-modules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the pkcs11-modules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the pkcs11-modules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the pkcs11-modules-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (pkcs11-modules-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the pkcs11-modules-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/pkcs11-modules-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}
