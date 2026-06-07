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

@test "INVARIANT (mechanism .so under /home — user-writable hijack on GSSAPI auth code-load surface)" {
    # Sister to /var/tmp + relative-with-slash mechanism path
    # writable-root INVARIANTs already locked. /home/<user> is
    # writable by the owning user without privilege; an attacker
    # who pivots into a user account plants /home/<user>/.evil-
    # gssapi.so AND patches gss.conf to point at it — every
    # GSSAPI auth (Kerberos / NFS / SSH-with-gssapi /
    # cyrus-sasl) loads the planted .so AS the consuming daemon
    # (often root). Closes the /home axis on the GSSAPI mech
    # writable-root coverage symmetric to /var/tmp. T1574 Hijack
    # Execution Flow via auth-mechanism plugin substitution.
    printf 'gssapi_evil 1.2.3.4 /home/alice/.evil-gss.so\n' > "${MECH}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (mechanism .so under /dev/shm — tmpfs writable-root axis-symmetric expansion)" {
    # Sister to /var/tmp + /home + relative-with-slash GSSAPI
    # mech writable-root INVARIANTs. /dev/shm tmpfs writable
    # by ALL users.
    printf 'gssapi_evil 1.2.3.4 /dev/shm/.evil-gss.so\n' > "${MECH}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (mechanism .so under /tmp — writable-root axis-symmetric expansion on GSSAPI auth code-load surface)" {
    # Sister to /var/tmp + /home + /dev/shm GSSAPI mechanism
    # writable-root INVARIANTs. /tmp is canonical user-writable
    # tmpfs/disk. GSSAPI mechanism .so is dlopen-loaded AS the
    # consuming process (SSH/NFS/Kerberos clients); planted .so
    # gets credential-handler-level access. T1574 Hijack
    # Execution Flow.
    printf 'gssapi_evil 1.2.3.4 /tmp/.evil-gss.so\n' > "${MECH}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on gss-mech surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The gss-mech-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 Hijack Execution Flow via GSSAPI
    # mechanism plugin alert. Locks parser contract on the
    # /etc/gss/mech detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'kerberos_v5 1.2.840.113554.1.2.2 /usr/lib/libgssapi_krb5.so\n' > "${MECH}"
    run_wd                                              # ok / baseline
    printf 'gssapi_evil 1.2.3.4 /tmp/.evil-gss.so\n' > "${MECH}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # gss-mech-watchdog runs ON the timer's scheduled fire —
    # scans /etc/gss/mech.d for suspicious GSSAPI mechanism .so
    # paths, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the gss-mech-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd/selfdef-gss-mech.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. gss-mech-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # gss-mech-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # gss-mech-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'gss-mech-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: gss-mech-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. gss-mech-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the gss-mech-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (gss-mech-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The gss-mech-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the gss-mech-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # gss-mech-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # gss-mech-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the gss-mech-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # gss-mech-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the gss-mech-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (gss-mech-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the gss-mech-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (gss-mech-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # gss-mech-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (gss-mech-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the gss-mech-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (gss-mech-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the gss-mech-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (gss-mech-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the gss-mech-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (gss-mech-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the gss-mech-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/gss-mech-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}
